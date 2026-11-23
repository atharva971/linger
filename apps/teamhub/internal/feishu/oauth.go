package feishu

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"
)

// OfflineAccessScope makes the token response carry a refresh token.
const OfflineAccessScope = "offline_access"

// MailScopes are the user scopes every Feishu mail feature needs: reading the
// mailbox profile and messages, sending, drafts and moving mail. An admin
// enables them once on the custom app, so they cover the whole feature.
var MailScopes = []string{
	"mail:user_mailbox:readonly",
	"mail:user_mailbox.folder:read",
	"mail:user_mailbox.message:readonly",
	"mail:user_mailbox.message.subject:read",
	"mail:user_mailbox.message.address:read",
	"mail:user_mailbox.message.body:read",
	"mail:user_mailbox.message:send",
	"mail:user_mailbox.message:modify",
}

// RequestedScopes is the authorize request's scope list.
func RequestedScopes() []string {
	return append([]string{OfflineAccessScope}, MailScopes...)
}

// Token is one user authorization. Feishu rotates the refresh token: each
// refresh invalidates the one it used, so the newest must be stored before
// the next refresh.
type Token struct {
	AccessToken      string
	RefreshToken     string
	AccessExpiresAt  time.Time
	RefreshExpiresAt time.Time
	// Scopes are the scopes the user granted, including earlier grants.
	Scopes []string
}

// MissingMailScopes lists the mail scopes token lacks. A token response that
// reports no scopes is not judged.
func (t Token) MissingMailScopes() []string {
	if len(t.Scopes) == 0 {
		return nil
	}
	missing := []string{}
	for _, scope := range MailScopes {
		if !slices.Contains(t.Scopes, scope) {
			missing = append(missing, scope)
		}
	}
	return missing
}

// NewCodeVerifier returns a PKCE code verifier.
func NewCodeVerifier() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

// CodeChallenge is the S256 challenge of verifier.
func CodeChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// AuthorizeURL is the consent page a user opens to authorize the app. The
// redirect URI must be on the app's redirect allowlist.
func (c *Client) AuthorizeURL(app App, redirectURI, state, codeChallenge string) string {
	return queryURL(c.endpoints(app.Region).accounts+"/open-apis/authen/v1/authorize", url.Values{
		"client_id":             {app.ID},
		"response_type":         {"code"},
		"redirect_uri":          {redirectURI},
		"scope":                 {strings.Join(RequestedScopes(), " ")},
		"state":                 {state},
		"code_challenge":        {codeChallenge},
		"code_challenge_method": {"S256"},
		"prompt":                {"consent"},
	})
}

type tokenResponse struct {
	AccessToken           string `json:"access_token"`
	ExpiresIn             int64  `json:"expires_in"`
	RefreshToken          string `json:"refresh_token"`
	RefreshTokenExpiresIn int64  `json:"refresh_token_expires_in"`
	Scope                 string `json:"scope"`
}

// ExchangeCode trades an authorization code for the user's tokens.
func (c *Client) ExchangeCode(ctx context.Context, app App, code, codeVerifier, redirectURI string) (Token, error) {
	return c.token(ctx, app, "code exchange", map[string]string{
		"grant_type": "authorization_code", "client_id": app.ID, "client_secret": app.Secret,
		"code": code, "code_verifier": codeVerifier, "redirect_uri": redirectURI,
	})
}

// Refresh trades refreshToken for new tokens. The refresh token is single
// use: once Feishu accepts it, only the returned one works.
func (c *Client) Refresh(ctx context.Context, app App, refreshToken string) (Token, error) {
	return c.token(ctx, app, "token refresh", map[string]string{
		"grant_type": "refresh_token", "client_id": app.ID, "client_secret": app.Secret, "refresh_token": refreshToken,
	})
}

func (c *Client) token(ctx context.Context, app App, operation string, body map[string]string) (Token, error) {
	if !app.Region.Valid() {
		return Token{}, errors.New("unknown Feishu region")
	}
	now := time.Now().UTC()
	var response tokenResponse
	if err := c.call(ctx, operation, http.MethodPost, c.endpoints(app.Region).open+"/open-apis/authen/v2/oauth/token", "", body, &response); err != nil {
		return Token{}, err
	}
	if response.AccessToken == "" || response.ExpiresIn <= 0 {
		return Token{}, errors.New("the Feishu token response has no access token")
	}
	if response.RefreshToken == "" || response.RefreshTokenExpiresIn <= 0 {
		return Token{}, ErrNoRefreshToken
	}
	return Token{
		AccessToken: response.AccessToken, RefreshToken: response.RefreshToken,
		AccessExpiresAt:  now.Add(time.Duration(response.ExpiresIn) * time.Second),
		RefreshExpiresAt: now.Add(time.Duration(response.RefreshTokenExpiresIn) * time.Second),
		Scopes:           strings.Fields(response.Scope),
	}, nil
}

// ErrNoRefreshToken reports a token response without a refresh token: the
// app does not offer offline_access, or its refresh switch is off.
var ErrNoRefreshToken = errors.New("the Feishu token response has no refresh token")
