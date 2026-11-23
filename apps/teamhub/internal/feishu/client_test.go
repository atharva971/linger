package feishu

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestAuthorizeURLCarriesPKCEAndEveryMailScope(t *testing.T) {
	client := New(Config{})
	app := App{Region: RegionLark, ID: "cli_test", Secret: "secret"}
	raw := client.AuthorizeURL(app, "https://linger.example/oauth/feishu-complete", "signed-state", CodeChallenge("verifier"))
	parsed, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Host != "accounts.larksuite.com" || parsed.Path != "/open-apis/authen/v1/authorize" {
		t.Fatalf("authorize URL = %s", raw)
	}
	query := parsed.Query()
	if query.Get("client_id") != "cli_test" || query.Get("state") != "signed-state" || query.Get("code_challenge_method") != "S256" {
		t.Fatalf("authorize query = %v", query)
	}
	if query.Get("code_challenge") != CodeChallenge("verifier") || query.Get("code_challenge") == "verifier" {
		t.Fatalf("code challenge = %q", query.Get("code_challenge"))
	}
	scopes := strings.Fields(query.Get("scope"))
	if scopes[0] != OfflineAccessScope || len(scopes) != len(MailScopes)+1 {
		t.Fatalf("scopes = %v", scopes)
	}
}

func TestExchangeCodeReadsTokensAndGrantedScopes(t *testing.T) {
	var body map[string]string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/open-apis/authen/v2/oauth/token" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(`{"code":0,"access_token":"u-access","expires_in":7200,"refresh_token":"ur-refresh","refresh_token_expires_in":604800,"token_type":"Bearer","scope":"offline_access mail:user_mailbox:readonly"}`))
	}))
	defer server.Close()
	before := time.Now()
	token, err := New(Config{BaseURL: server.URL}).ExchangeCode(context.Background(), App{Region: RegionFeishu, ID: "cli_test", Secret: "secret"}, "code-1", "verifier-1", "https://linger.example/oauth/feishu-complete")
	if err != nil {
		t.Fatal(err)
	}
	if body["grant_type"] != "authorization_code" || body["code"] != "code-1" || body["code_verifier"] != "verifier-1" || body["client_secret"] != "secret" {
		t.Fatalf("request body = %v", body)
	}
	if token.AccessToken != "u-access" || token.RefreshToken != "ur-refresh" {
		t.Fatalf("token = %+v", token)
	}
	if token.AccessExpiresAt.Before(before.Add(2*time.Hour-time.Second)) || token.RefreshExpiresAt.Before(before.Add(7*24*time.Hour-time.Second)) {
		t.Fatalf("expiries = %v %v", token.AccessExpiresAt, token.RefreshExpiresAt)
	}
	missing := token.MissingMailScopes()
	if len(missing) != len(MailScopes)-1 {
		t.Fatalf("missing = %v", missing)
	}
}

func TestTokenWithoutRefreshTokenIsRefused(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"code":0,"access_token":"u-access","expires_in":7200}`))
	}))
	defer server.Close()
	_, err := New(Config{BaseURL: server.URL}).Refresh(context.Background(), App{Region: RegionFeishu, ID: "cli", Secret: "s"}, "ur-old")
	if !errors.Is(err, ErrNoRefreshToken) {
		t.Fatalf("err = %v", err)
	}
}

func TestRefreshRejectionIsAnAuthFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"code":20064,"error":"invalid_grant","error_description":"refresh token revoked"}`))
	}))
	defer server.Close()
	_, err := New(Config{BaseURL: server.URL}).Refresh(context.Background(), App{Region: RegionFeishu, ID: "cli", Secret: "s"}, "ur-old")
	if !IsAuthFailure(err) {
		t.Fatalf("err = %v", err)
	}
	if status, ok := ErrorStatus(err); !ok || status != http.StatusBadRequest {
		t.Fatalf("status = %d %v", status, ok)
	}
}

func TestRateLimitAndServerFailureAreNotRejections(t *testing.T) {
	status := http.StatusTooManyRequests
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(status)
	}))
	defer server.Close()
	client := New(Config{BaseURL: server.URL})
	app := App{Region: RegionFeishu, ID: "cli", Secret: "s"}
	var limited *RateLimitError
	if _, err := client.Refresh(context.Background(), app, "ur-token"); !errors.As(err, &limited) || limited.RetryAfter != 30*time.Second {
		t.Fatalf("err = %v", err)
	}
	status = http.StatusBadGateway
	if _, err := client.Refresh(context.Background(), app, "ur-token"); err == nil || IsAppRejected(err) || IsAuthFailure(err) {
		t.Fatalf("err = %v", err)
	}
}

func TestCheckAppRejection(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/open-apis/auth/v3/tenant_access_token/internal" {
			t.Fatalf("path = %s", r.URL.Path)
		}
		_, _ = w.Write([]byte(`{"code":10014,"msg":"app secret invalid"}`))
	}))
	defer server.Close()
	err := New(Config{BaseURL: server.URL}).CheckApp(context.Background(), App{Region: RegionFeishu, ID: "cli", Secret: "wrong"})
	if !IsAppRejected(err) {
		t.Fatalf("err = %v", err)
	}
}

func TestPrimaryMailboxUsesTheUserToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/open-apis/mail/v1/user_mailboxes/me/profile" || r.Header.Get("Authorization") != "Bearer u-access" {
			t.Fatalf("request = %s %s", r.URL.Path, r.Header.Get("Authorization"))
		}
		_, _ = w.Write([]byte(`{"code":0,"data":{"primary_email_address":" Zhang@Example.COM "}}`))
	}))
	defer server.Close()
	address, err := New(Config{BaseURL: server.URL}).PrimaryMailbox(context.Background(), RegionFeishu, "u-access")
	if err != nil || address != "zhang@example.com" {
		t.Fatalf("address = %q err = %v", address, err)
	}
}
