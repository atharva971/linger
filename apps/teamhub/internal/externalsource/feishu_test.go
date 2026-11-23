package externalsource

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/simplexai-labs/linger/apps/teamhub/internal/composio"
	"github.com/simplexai-labs/linger/apps/teamhub/internal/feishu"
	"github.com/simplexai-labs/linger/apps/teamhub/internal/secretbox"
)

func feishuService(t *testing.T, app feishu.App) *Service {
	t.Helper()
	box, err := secretbox.New("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
	if err != nil {
		t.Fatal(err)
	}
	service := New(nil, &composio.Client{})
	service.feishu = &feishuCatalog{
		client: feishu.New(feishu.Config{}), keyBox: box, signingKey: []byte("signing-key"),
		redirectURL: FeishuRedirectURL("https://linger.example/"), app: app,
	}
	return service
}

func TestFeishuMailIsAvailableOnlyWithItsOwnApp(t *testing.T) {
	service := feishuService(t, feishu.App{})
	app, ok := service.catalogApp(FeishuMailAppKey)
	if !ok || app.Availability != AppAvailabilityUnavailable || len(app.Capabilities) != 0 || app.SupportsReauthorization {
		t.Fatalf("Feishu Mail without an app = %+v", app)
	}
	if _, err := service.connectionAdapter(FeishuMailAppKey); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("adapter without an app: %v", err)
	}
	if service.ConnectionProvidersConfigured() {
		t.Fatal("a provider is configured without Composio or a Feishu app")
	}

	service = feishuService(t, feishu.App{Region: feishu.RegionFeishu, ID: "cli_test", Secret: "secret"})
	app, _ = service.catalogApp(FeishuMailAppKey)
	if app.Availability != AppAvailabilityAvailable || !slices.Contains(app.Capabilities, "connect") || !app.SupportsReauthorization || app.LogoURL != "" {
		t.Fatalf("Feishu Mail with an app = %+v", app)
	}
	if slices.Contains(app.Capabilities, "personal_wiki_import") {
		t.Fatal("Feishu Mail must not be offered as a Profile source")
	}
	adapter, err := service.connectionAdapter(FeishuMailAppKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := adapter.(feishuConnection); !ok {
		t.Fatalf("adapter = %T, want feishuConnection", adapter)
	}
	if !service.ConnectionProvidersConfigured() || service.ProviderConfigured() {
		t.Fatal("the Feishu app alone must configure connections but not Composio")
	}
	// Composio apps stay unavailable: the Feishu app does not configure them.
	if gmail, _ := service.catalogApp("gmail"); gmail.Availability != AppAvailabilityUnavailable {
		t.Fatalf("gmail with only a Feishu app = %+v", gmail)
	}
}

func TestFeishuMailNeedsAKeyBoxToSealTokens(t *testing.T) {
	service := feishuService(t, feishu.App{Region: feishu.RegionLark, ID: "cli_test", Secret: "secret"})
	service.feishu.keyBox = nil
	if service.FeishuConfigured() {
		t.Fatal("Feishu Mail is configured without a key box to seal user tokens")
	}
	if app, _ := service.catalogApp(FeishuMailAppKey); app.Availability != AppAvailabilityUnavailable {
		t.Fatalf("Feishu Mail without a key box = %+v", app)
	}
}

func TestCompleteFeishuAuthorizationChecksTheSignedState(t *testing.T) {
	service := feishuService(t, feishu.App{Region: feishu.RegionFeishu, ID: "cli_test", Secret: "secret"})
	ctx := context.Background()
	forged, err := secretbox.Sign([]byte("another-key"), feishuStateDomain, feishuState{UpstreamID: "feishu_upstream_x", ExpiresAt: time.Now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.CompleteFeishuAuthorization(ctx, forged, "code"); !errors.Is(err, ErrInvalid) {
		t.Fatalf("forged state: %v", err)
	}
	expired, err := secretbox.Sign(service.feishu.signingKey, feishuStateDomain, feishuState{UpstreamID: "feishu_upstream_x", ExpiresAt: time.Now().Add(-time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.CompleteFeishuAuthorization(ctx, expired, "code"); !errors.Is(err, ErrConflict) {
		t.Fatalf("expired state: %v", err)
	}
	valid, err := secretbox.Sign(service.feishu.signingKey, feishuStateDomain, feishuState{UpstreamID: "feishu_upstream_x", ExpiresAt: time.Now().Add(time.Minute).Unix()})
	if err != nil {
		t.Fatal(err)
	}
	if err := service.CompleteFeishuAuthorization(ctx, valid, " "); !errors.Is(err, ErrInvalid) {
		t.Fatalf("empty code: %v", err)
	}
}

func TestFeishuFailuresMapToConnectionOutcomes(t *testing.T) {
	revoked := &feishu.APIError{Operation: "token refresh", HTTPStatus: 400, OAuthError: "invalid_grant"}
	if code, _, fail := connectionIdentityFailurePolicy(FeishuMailAppKey, revoked); code != "provider_auth_failed" || !fail {
		t.Fatalf("revoked refresh = %s %v", code, fail)
	}
	if code, retry, fail := connectionIdentityFailurePolicy(FeishuMailAppKey, &feishu.RateLimitError{RetryAfter: 2 * time.Minute}); code != "provider_rate_limited" || retry != 2*time.Minute || fail {
		t.Fatalf("rate limit = %s %s %v", code, retry, fail)
	}
	if !upstreamGone(errFeishuUpstreamGone) {
		t.Fatal("a forgotten Feishu upstream must count as revoked")
	}
	if class := connectionCheckErrorClass(&feishu.APIError{HTTPStatus: 502}); class != "http_502" {
		t.Fatalf("class = %s", class)
	}
}
