package externalsource

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/simplexai-labs/linger/apps/teamhub/internal/composio"
	"github.com/simplexai-labs/linger/apps/teamhub/internal/feishu"
	idgen "github.com/simplexai-labs/linger/apps/teamhub/internal/ids"
	"github.com/simplexai-labs/linger/apps/teamhub/internal/secretbox"
)

// FeishuMailAppKey is the catalog key of Feishu Mail. Composio has no Feishu
// toolkit and Feishu serves mail to enterprise custom apps only, so TeamHub
// authorizes these connections itself with the deployment's custom app.
const FeishuMailAppKey = "feishu_mail"

// feishuToolkit is the toolkit slug Feishu upstreams and connections record.
const feishuToolkit = "feishu"

const (
	// feishuLinkLifetime bounds one consent attempt. A code lasts five
	// minutes, but signing in to Feishu may take the user longer.
	feishuLinkLifetime = 15 * time.Minute
	// feishuAccessRefreshAhead refreshes an access token this long before it
	// expires, so a call never starts with one about to lapse.
	feishuAccessRefreshAhead = 10 * time.Minute
	// feishuRefreshRenewAhead renews a refresh token this long before it
	// expires. The six-hourly reconcile then keeps an idle connection alive.
	feishuRefreshRenewAhead = 2 * 24 * time.Hour
	feishuStateDomain       = "feishu-oauth-state"
)

var (
	// ErrFeishuAppRejected reports App ID and App Secret Feishu refused.
	ErrFeishuAppRejected = errors.New("Feishu rejected the app credentials")
	// ErrFeishuAuthorizationRejected reports a code Feishu would not exchange.
	ErrFeishuAuthorizationRejected = errors.New("Feishu rejected the authorization")
	// ErrFeishuNoRefreshToken reports an authorization without a refresh
	// token: the app lacks offline_access or its refresh switch is off.
	ErrFeishuNoRefreshToken = errors.New("the Feishu authorization has no refresh token")

	errFeishuUpstreamGone    = errors.New("the Feishu upstream no longer exists")
	errFeishuNotAuthorized   = errors.New("the Feishu upstream is not authorized yet")
	errFeishuAppChanged      = errors.New("the Feishu upstream was authorized for another app")
	errFeishuTokenSuperseded = errors.New("another refresh replaced the Feishu token first")
)

// FeishuScopesMissingError reports an authorization that lacks mail scopes:
// the custom app does not offer them yet, or its new version is unapproved.
type FeishuScopesMissingError struct{ Scopes []string }

func (e *FeishuScopesMissingError) Error() string {
	return "the Feishu authorization lacks scopes: " + strings.Join(e.Scopes, " ")
}

// FeishuAppStatus describes the deployment's Feishu custom app without its
// secret, and what its console needs.
type FeishuAppStatus struct {
	Configured  bool
	CanSave     bool
	Region      string
	AppID       string
	RedirectURL string
	Scopes      []string
}

type feishuCatalog struct {
	client      *feishu.Client
	renderer    mailRenderer
	keyBox      *secretbox.Box
	signingKey  []byte
	redirectURL string
	mu          sync.RWMutex
	app         feishu.App
}

// FeishuRedirectURL is the Web page Feishu returns the consent result to. The
// person who creates the custom app adds it to the app's redirect allowlist.
func FeishuRedirectURL(publicWebURL string) string {
	return strings.TrimRight(publicWebURL, "/") + "/oauth/feishu-complete"
}

// ConfigureFeishu enables Feishu Mail. Each deployment brings its own Feishu
// custom app, which a person enters on the chat card that asks for Feishu
// Mail; until then, and without keyBox to seal secrets, it is unavailable.
// renderer turns synced mail into Wiki documents.
func (s *Service) ConfigureFeishu(ctx context.Context, client *feishu.Client, renderer mailRenderer, keyBox *secretbox.Box, signingKey []byte, redirectURL string) {
	s.feishu = &feishuCatalog{client: client, renderer: renderer, keyBox: keyBox, signingKey: signingKey, redirectURL: redirectURL}
	if err := s.loadFeishuApp(ctx); err != nil {
		s.logger.Error("load the Feishu custom app", "error", err)
	}
}

func (s *Service) feishuApp() (feishu.App, bool) {
	if s.feishu == nil || s.feishu.keyBox == nil {
		return feishu.App{}, false
	}
	s.feishu.mu.RLock()
	defer s.feishu.mu.RUnlock()
	return s.feishu.app, s.feishu.app.ID != ""
}

// FeishuConfigured reports whether the deployment has a Feishu custom app.
func (s *Service) FeishuConfigured() bool {
	_, ok := s.feishuApp()
	return ok
}

// FeishuAppSavable reports whether a Feishu custom app can be saved here.
func (s *Service) FeishuAppSavable() bool {
	return s.feishu != nil && s.feishu.keyBox != nil
}

// ConnectionProvidersConfigured reports whether any connection provider
// works: Composio, or the Feishu custom app.
func (s *Service) ConnectionProvidersConfigured() bool {
	return s.ProviderConfigured() || s.FeishuConfigured()
}

// FeishuApp reports the saved custom app and the settings its console needs.
func (s *Service) FeishuApp() FeishuAppStatus {
	if s.feishu == nil {
		return FeishuAppStatus{Scopes: []string{}}
	}
	app, configured := s.feishuApp()
	return FeishuAppStatus{
		Configured: configured, CanSave: s.FeishuAppSavable(),
		Region: string(app.Region), AppID: app.ID,
		RedirectURL: s.feishu.redirectURL, Scopes: feishu.RequestedScopes(),
	}
}

// SaveFeishuApp checks the custom app's credentials with Feishu, then seals,
// saves, and applies them. Connections authorized with another app expire at
// their next check and ask to be reauthorized.
func (s *Service) SaveFeishuApp(ctx context.Context, region, appID, appSecret string) (FeishuAppStatus, error) {
	app := feishu.App{Region: feishu.Region(region), ID: strings.TrimSpace(appID), Secret: strings.TrimSpace(appSecret)}
	switch {
	case s.feishu == nil:
		return FeishuAppStatus{}, ErrUnavailable
	case s.feishu.keyBox == nil:
		return FeishuAppStatus{}, ErrManagedKeyStorageMissing
	case !app.Region.Valid() || app.ID == "" || len(app.ID) > 128 || app.Secret == "" || len(app.Secret) > 512:
		return FeishuAppStatus{}, ErrInvalid
	}
	if err := s.feishu.client.CheckApp(ctx, app); err != nil {
		if feishu.IsAppRejected(err) {
			return FeishuAppStatus{}, ErrFeishuAppRejected
		}
		return FeishuAppStatus{}, errors.Join(ErrUnavailable, err)
	}
	sealed, err := s.feishu.keyBox.Seal([]byte(app.Secret))
	if err != nil {
		return FeishuAppStatus{}, err
	}
	if _, err = s.pool.Exec(ctx, `INSERT INTO feishu_app_settings(region,app_id,app_secret_ciphertext) VALUES($1,$2,$3)
		ON CONFLICT(singleton) DO UPDATE SET region=excluded.region,app_id=excluded.app_id,app_secret_ciphertext=excluded.app_secret_ciphertext,updated_at=now()`,
		string(app.Region), app.ID, sealed); err != nil {
		return FeishuAppStatus{}, err
	}
	s.feishu.mu.Lock()
	s.feishu.app = app
	s.feishu.mu.Unlock()
	return s.FeishuApp(), nil
}

func (s *Service) loadFeishuApp(ctx context.Context) error {
	if s.feishu.keyBox == nil {
		return nil
	}
	var region, appID string
	var sealed []byte
	err := s.pool.QueryRow(ctx, `SELECT region,app_id,app_secret_ciphertext FROM feishu_app_settings`).Scan(&region, &appID, &sealed)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil
	}
	if err != nil {
		return err
	}
	secret, err := s.feishu.keyBox.Open(sealed)
	if err != nil {
		return errors.New("open the saved Feishu app secret: check TEAMHUB_SECRET_ENCRYPTION_KEY")
	}
	s.feishu.mu.Lock()
	s.feishu.app = feishu.App{Region: feishu.Region(region), ID: appID, Secret: string(secret)}
	s.feishu.mu.Unlock()
	return nil
}

type feishuState struct {
	UpstreamID string `json:"u"`
	ExpiresAt  int64  `json:"e"`
}

// createFeishuLinkInTx records the upstream a consent will fill, with the
// PKCE verifier its code exchange needs, and returns its consent page.
func (s *Service) createFeishuLinkInTx(ctx context.Context, tx pgx.Tx, accountID string) (composio.Link, error) {
	app, ok := s.feishuApp()
	if !ok {
		return composio.Link{}, ErrUnavailable
	}
	verifier, err := feishu.NewCodeVerifier()
	if err != nil {
		return composio.Link{}, err
	}
	sealedVerifier, err := s.feishu.keyBox.Seal([]byte(verifier))
	if err != nil {
		return composio.Link{}, err
	}
	upstreamID := idgen.New("feishu_upstream")
	expiresAt := time.Now().UTC().Add(feishuLinkLifetime).Truncate(time.Second)
	state, err := secretbox.Sign(s.feishu.signingKey, feishuStateDomain, feishuState{UpstreamID: upstreamID, ExpiresAt: expiresAt.Unix()})
	if err != nil {
		return composio.Link{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO external_connection_upstreams(upstream_id,account_id,user_id,toolkit_slug,auth_config_id) VALUES($1,$2,$2,$3,$4)`, upstreamID, accountID, feishuToolkit, app.ID); err != nil {
		return composio.Link{}, err
	}
	if _, err = tx.Exec(ctx, `INSERT INTO feishu_upstream_tokens(upstream_id,region,app_id,code_verifier_ciphertext) VALUES($1,$2,$3,$4)`, upstreamID, string(app.Region), app.ID, sealedVerifier); err != nil {
		return composio.Link{}, err
	}
	return composio.Link{
		AuthConfigID: app.ID, ConnectedAccountID: upstreamID, ExpiresAt: expiresAt,
		RedirectURL: s.feishu.client.AuthorizeURL(app, s.feishu.redirectURL, state, feishu.CodeChallenge(verifier)),
	}, nil
}

// CompleteFeishuAuthorization exchanges the code a returning consent page
// carries for the user's tokens, then checks the connection or
// reauthorization waiting on them. The signed state names the upstream and
// the PKCE verifier binds the code to it, so the page needs no session: the
// user may finish consent in a browser that is not signed in to Linger.
func (s *Service) CompleteFeishuAuthorization(ctx context.Context, state, code string) error {
	if s.feishu == nil {
		return ErrUnavailable
	}
	var payload feishuState
	code = strings.TrimSpace(code)
	if code == "" || len(code) > 1024 || !secretbox.Verify(s.feishu.signingKey, feishuStateDomain, state, &payload) || payload.UpstreamID == "" {
		return ErrInvalid
	}
	if time.Now().Unix() > payload.ExpiresAt {
		return ErrConflict
	}
	app, ok := s.feishuApp()
	if !ok {
		return ErrUnavailable
	}
	var accountID, region, appID string
	var sealedVerifier []byte
	var authorized bool
	err := s.pool.QueryRow(ctx, `SELECT upstream.account_id,token.region,token.app_id,token.code_verifier_ciphertext,token.access_token_ciphertext IS NOT NULL
		FROM feishu_upstream_tokens token JOIN external_connection_upstreams upstream USING (upstream_id) WHERE token.upstream_id=$1`, payload.UpstreamID).
		Scan(&accountID, &region, &appID, &sealedVerifier, &authorized)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	if err != nil {
		return err
	}
	// A reloaded callback page finds the code already exchanged.
	if authorized {
		return s.CompleteConnectionAuthorization(ctx, accountID, payload.UpstreamID)
	}
	if region != string(app.Region) || appID != app.ID {
		return ErrConflict
	}
	verifier, err := s.feishu.keyBox.Open(sealedVerifier)
	if err != nil {
		return err
	}
	token, err := s.feishu.client.ExchangeCode(ctx, app, code, string(verifier), s.feishu.redirectURL)
	switch {
	case errors.Is(err, feishu.ErrNoRefreshToken):
		return ErrFeishuNoRefreshToken
	case err != nil && (feishu.IsAuthFailure(err) || feishu.IsAppRejected(err)):
		return errors.Join(ErrFeishuAuthorizationRejected, err)
	case err != nil:
		return errors.Join(ErrUnavailable, err)
	}
	if missing := token.MissingMailScopes(); len(missing) > 0 {
		return &FeishuScopesMissingError{Scopes: missing}
	}
	sealed, err := s.sealFeishuToken(token)
	if err != nil {
		return err
	}
	if _, err = s.pool.Exec(ctx, `UPDATE feishu_upstream_tokens SET access_token_ciphertext=$2,refresh_token_ciphertext=$3,access_expires_at=$4,refresh_expires_at=$5,scopes=$6,authorized_at=now(),updated_at=now()
		WHERE upstream_id=$1 AND access_token_ciphertext IS NULL`, payload.UpstreamID, sealed.access, sealed.refresh, token.AccessExpiresAt, token.RefreshExpiresAt, token.Scopes); err != nil {
		return err
	}
	return s.CompleteConnectionAuthorization(ctx, accountID, payload.UpstreamID)
}

type sealedFeishuToken struct{ access, refresh []byte }

func (s *Service) sealFeishuToken(token feishu.Token) (sealedFeishuToken, error) {
	access, err := s.feishu.keyBox.Seal([]byte(token.AccessToken))
	if err != nil {
		return sealedFeishuToken{}, err
	}
	refresh, err := s.feishu.keyBox.Seal([]byte(token.RefreshToken))
	return sealedFeishuToken{access: access, refresh: refresh}, err
}

// feishuAccessToken returns a usable access token of upstreamID. It refreshes
// first when the access token is about to expire or, with renew, when the
// refresh token is. Feishu accepts each refresh token once, so refreshes of
// one upstream run under one lock and replace the stored tokens only if no
// other refresh replaced them first.
func (s *Service) feishuAccessToken(ctx context.Context, upstreamID string, renew bool) (feishu.Region, string, error) {
	app, ok := s.feishuApp()
	if !ok {
		return "", "", ErrUnavailable
	}
	var accessToken string
	err := s.withManagedLock(ctx, "feishu-token:"+upstreamID, func() error {
		var region, appID string
		var sealedAccess, sealedRefresh []byte
		var accessExpiresAt, refreshExpiresAt *time.Time
		err := s.pool.QueryRow(ctx, `SELECT region,app_id,access_token_ciphertext,refresh_token_ciphertext,access_expires_at,refresh_expires_at FROM feishu_upstream_tokens WHERE upstream_id=$1`, upstreamID).
			Scan(&region, &appID, &sealedAccess, &sealedRefresh, &accessExpiresAt, &refreshExpiresAt)
		if errors.Is(err, pgx.ErrNoRows) {
			return errFeishuUpstreamGone
		}
		if err != nil {
			return err
		}
		if sealedAccess == nil {
			return errFeishuNotAuthorized
		}
		if region != string(app.Region) || appID != app.ID {
			return errFeishuAppChanged
		}
		now := time.Now()
		if accessExpiresAt.After(now.Add(feishuAccessRefreshAhead)) && (!renew || refreshExpiresAt.After(now.Add(feishuRefreshRenewAhead))) {
			plain, err := s.feishu.keyBox.Open(sealedAccess)
			accessToken = string(plain)
			return err
		}
		refreshToken, err := s.feishu.keyBox.Open(sealedRefresh)
		if err != nil {
			return err
		}
		token, err := s.feishu.client.Refresh(ctx, app, string(refreshToken))
		if err != nil {
			return err
		}
		sealed, err := s.sealFeishuToken(token)
		if err != nil {
			return err
		}
		tag, err := s.pool.Exec(ctx, `UPDATE feishu_upstream_tokens SET access_token_ciphertext=$2,refresh_token_ciphertext=$3,access_expires_at=$4,refresh_expires_at=$5,scopes=$6,updated_at=now()
			WHERE upstream_id=$1 AND refresh_token_ciphertext=$7`, upstreamID, sealed.access, sealed.refresh, token.AccessExpiresAt, token.RefreshExpiresAt, token.Scopes, sealedRefresh)
		if err != nil {
			return err
		}
		if tag.RowsAffected() != 1 {
			return errFeishuTokenSuperseded
		}
		accessToken = token.AccessToken
		return nil
	})
	return app.Region, accessToken, err
}

// feishuConnection is the connection lifecycle of a Feishu upstream: its
// status is its stored authorization, and revoking it forgets the tokens.
// Feishu has no token revocation API; the user can also remove the app's
// authorization in Feishu.
type feishuConnection struct{ service *Service }

func (c feishuConnection) Status(ctx context.Context, upstreamID string) (composio.ConnectionStatus, error) {
	_, _, err := c.service.feishuAccessToken(ctx, upstreamID, true)
	switch {
	case err == nil:
		return composio.ConnectionActive, nil
	case errors.Is(err, errFeishuNotAuthorized):
		return composio.ConnectionPending, nil
	case errors.Is(err, errFeishuAppChanged) || errors.Is(err, feishu.ErrNoRefreshToken) || feishu.IsAuthFailure(err):
		return composio.ConnectionExpired, nil
	default:
		return "", err
	}
}

func (c feishuConnection) Identify(ctx context.Context, upstreamID string, status composio.ConnectionStatus) (connectionIdentity, error) {
	if status != composio.ConnectionActive {
		return connectionIdentity{}, nil
	}
	region, accessToken, err := c.service.feishuAccessToken(ctx, upstreamID, false)
	if err != nil {
		return connectionIdentity{}, err
	}
	address, err := c.service.feishu.client.PrimaryMailbox(ctx, region, accessToken)
	if err != nil {
		return connectionIdentity{}, err
	}
	return connectionIdentity{Label: address, PrincipalKey: FeishuMailAppKey + ":" + address}, nil
}

func (c feishuConnection) Revoke(ctx context.Context, upstreamID string) error {
	_, err := c.service.pool.Exec(ctx, `DELETE FROM feishu_upstream_tokens WHERE upstream_id=$1`, upstreamID)
	return err
}

// isFeishuApp reports whether TeamHub authorizes appKey itself.
func isFeishuApp(appKey string) bool { return appKey == FeishuMailAppKey }

// createLinkInTx records the upstream a new authorization fills and returns
// its consent page: TeamHub's own for Feishu, a Composio Connect Link
// otherwise. managedConfigID is the Composio auth config, unused for Feishu.
func (s *Service) createLinkInTx(ctx context.Context, tx pgx.Tx, accountID, appKey, managedConfigID string) (composio.Link, error) {
	if isFeishuApp(appKey) {
		return s.createFeishuLinkInTx(ctx, tx, accountID)
	}
	return s.createManagedLinkInTx(ctx, tx, accountID, toolkitForApp(appKey), managedConfigID)
}

// feishuUpstreamGone reports a Feishu upstream that is already forgotten.
func feishuUpstreamGone(err error) bool { return errors.Is(err, errFeishuUpstreamGone) }
