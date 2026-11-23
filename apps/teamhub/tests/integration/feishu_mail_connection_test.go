package integration_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/simplexai-labs/linger/apps/teamhub/internal/app"
	"github.com/simplexai-labs/linger/apps/teamhub/internal/config"
	"github.com/simplexai-labs/linger/apps/teamhub/internal/feishu"
)

// fakeFeishu serves the Open Platform calls Feishu Mail connections make: the
// app check, the code exchange with PKCE, refreshes that rotate the refresh
// token, and the mailbox profile.
type fakeFeishu struct {
	t      *testing.T
	server *httptest.Server
	mu     sync.Mutex
	// codes maps an issued authorization code to its PKCE challenge and the
	// scopes its token grants.
	codes         map[string]fakeFeishuCode
	access        map[string]bool
	refresh       map[string]bool
	issued        int
	refreshes     int
	rejectRefresh bool
	// The mailbox: its messages by ID and folder, saved drafts by ID, the
	// drafts sent, and the moves made.
	mail    map[string]map[string]any
	folders map[string][]string
	drafts  map[string][]byte
	sent    []string
	moves   []map[string]any
}

// fakeFeishuMessage is one message of the fake mailbox, received hoursAgo.
func fakeFeishuMessage(id, from, subject, body string, hoursAgo float64, state int) map[string]any {
	encoded := func(text string) string { return base64.URLEncoding.EncodeToString([]byte(text)) }
	return map[string]any{
		"message_id": id, "thread_id": "thread_" + id, "subject": subject, "message_state": state,
		"internal_date": strconv.FormatInt(time.Now().Add(-time.Duration(hoursAgo*float64(time.Hour))).UnixMilli(), 10),
		"head_from":     map[string]any{"mail_address": from}, "to": []any{map[string]any{"mail_address": "zhang@example.com"}},
		"label_ids": []string{"UNREAD"}, "body_preview": encoded(body), "body_plain_text": encoded(body),
	}
}

type fakeFeishuCode struct {
	challenge string
	scopes    []string
}

func newFakeFeishu(t *testing.T) *fakeFeishu {
	t.Helper()
	fake := &fakeFeishu{t: t, codes: map[string]fakeFeishuCode{}, access: map[string]bool{}, refresh: map[string]bool{}, drafts: map[string][]byte{},
		mail: map[string]map[string]any{
			"msg_1":       fakeFeishuMessage("msg_1", "alice@example.com", "Quarterly plan", "Can we meet?", 1, 1),
			"msg_receipt": fakeFeishuMessage("msg_receipt", "no-reply@shop.example.com", "Your receipt", "Paid", 2, 1),
			"msg_old":     fakeFeishuMessage("msg_old", "carol@example.com", "Old news", "Long ago", 240, 1),
			"msg_sent":    fakeFeishuMessage("msg_sent", "zhang@example.com", "Re: Quarterly plan", "Friday works", 0.5, 2),
		},
		folders: map[string][]string{"INBOX": {"msg_1", "msg_receipt", "msg_old"}, "SENT": {"msg_sent"}},
	}
	fake.server = httptest.NewServer(http.HandlerFunc(fake.serveHTTP))
	registerIntegrationServerCleanup(t, fake.server)
	return fake
}

func (f *fakeFeishu) issueCode(code, challenge string, scopes []string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.codes[code] = fakeFeishuCode{challenge: challenge, scopes: scopes}
}

func (f *fakeFeishu) refreshCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.refreshes
}

func (f *fakeFeishu) setRejectRefresh(reject bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rejectRefresh = reject
}

func (f *fakeFeishu) serveHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	write := func(status int, body any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(body)
	}
	if mailPath, ok := strings.CutPrefix(r.URL.Path, "/open-apis/mail/v1/user_mailboxes/me/"); ok && mailPath != "profile" {
		if !f.access[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")] {
			write(http.StatusUnauthorized, map[string]any{"code": 99991668, "msg": "invalid access token"})
			return
		}
		f.serveMail(r, mailPath, write)
		return
	}
	var body map[string]string
	if r.Method == http.MethodPost {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	switch r.URL.Path {
	case "/open-apis/authen/v2/oauth/token":
		if body["client_id"] != "cli_test" || body["client_secret"] != "secret" {
			write(http.StatusUnauthorized, map[string]any{"code": 20002, "error": "invalid_client"})
			return
		}
		var scopes []string
		switch body["grant_type"] {
		case "authorization_code":
			issued, ok := f.codes[body["code"]]
			sum := sha256.Sum256([]byte(body["code_verifier"]))
			if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != issued.challenge {
				write(http.StatusBadRequest, map[string]any{"code": 20050, "error": "invalid_grant"})
				return
			}
			delete(f.codes, body["code"])
			scopes = issued.scopes
		case "refresh_token":
			if f.rejectRefresh || !f.refresh[body["refresh_token"]] {
				write(http.StatusBadRequest, map[string]any{"code": 20064, "error": "invalid_grant"})
				return
			}
			delete(f.refresh, body["refresh_token"])
			f.refreshes++
			scopes = feishu.RequestedScopes()
		default:
			write(http.StatusBadRequest, map[string]any{"code": 20001, "error": "unsupported_grant_type"})
			return
		}
		f.issued++
		access, refresh := fmt.Sprintf("u-%d", f.issued), fmt.Sprintf("ur-%d", f.issued)
		f.access[access], f.refresh[refresh] = true, true
		write(http.StatusOK, map[string]any{
			"code": 0, "access_token": access, "expires_in": 7200, "refresh_token": refresh,
			"refresh_token_expires_in": 604800, "token_type": "Bearer", "scope": strings.Join(scopes, " "),
		})
	case "/open-apis/mail/v1/user_mailboxes/me/profile":
		if !f.access[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")] {
			write(http.StatusUnauthorized, map[string]any{"code": 99991668, "msg": "invalid access token"})
			return
		}
		write(http.StatusOK, map[string]any{"code": 0, "data": map[string]any{"primary_email_address": "Zhang@Example.com"}})
	default:
		f.t.Errorf("unexpected Feishu request %s %s", r.Method, r.URL.Path)
		write(http.StatusNotFound, map[string]any{"code": 404})
	}
}

// serveMail answers the mail API with one inbox message and the drafts the
// test saves.
func (f *fakeFeishu) serveMail(r *http.Request, path string, write func(int, any)) {
	var body map[string]any
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	switch {
	case r.Method == http.MethodGet && path == "messages":
		ids, ok := f.folders[r.URL.Query().Get("folder_id")]
		if !ok {
			write(http.StatusBadRequest, map[string]any{"code": 1230001, "msg": "folder_id required"})
			return
		}
		write(http.StatusOK, map[string]any{"code": 0, "data": map[string]any{"items": ids, "has_more": false}})
	case r.Method == http.MethodPost && path == "messages/batch_get":
		ids, _ := body["message_ids"].([]any)
		messages := make([]any, 0, len(ids))
		for _, id := range ids {
			if message, ok := f.mail[fmt.Sprint(id)]; ok {
				messages = append(messages, message)
			}
		}
		write(http.StatusOK, map[string]any{"code": 0, "data": map[string]any{"messages": messages}})
	case r.Method == http.MethodGet && strings.HasPrefix(path, "messages/"):
		message, ok := f.mail[strings.TrimPrefix(path, "messages/")]
		if !ok {
			write(http.StatusNotFound, map[string]any{"code": 1234008, "msg": "message not found"})
			return
		}
		write(http.StatusOK, map[string]any{"code": 0, "data": map[string]any{"message": message}})
	case r.Method == http.MethodPost && path == "drafts":
		raw, err := base64.URLEncoding.DecodeString(fmt.Sprint(body["raw"]))
		if err != nil {
			write(http.StatusBadRequest, map[string]any{"code": 1230001, "msg": "raw must be base64url"})
			return
		}
		id := fmt.Sprintf("draft_%d", len(f.drafts)+1)
		f.drafts[id] = raw
		write(http.StatusOK, map[string]any{"code": 0, "data": map[string]any{"draft": map[string]any{"id": id}}})
	case r.Method == http.MethodGet && strings.HasPrefix(path, "drafts/"):
		id := strings.TrimPrefix(path, "drafts/")
		write(http.StatusOK, map[string]any{"code": 0, "data": map[string]any{"draft": map[string]any{
			"id": id, "message": map[string]any{"message_id": "draft_message_" + id, "raw": base64.URLEncoding.EncodeToString(f.drafts[id])},
		}}})
	case r.Method == http.MethodPost && strings.HasPrefix(path, "drafts/") && strings.HasSuffix(path, "/send"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "drafts/"), "/send")
		f.sent = append(f.sent, id)
		write(http.StatusOK, map[string]any{"code": 0, "data": map[string]any{"message_id": "sent_" + id, "thread_id": "thread_sent"}})
	case r.Method == http.MethodPost && path == "messages/batch_modify":
		f.moves = append(f.moves, body)
		write(http.StatusOK, map[string]any{"code": 0})
	default:
		f.t.Errorf("unexpected Feishu mail request %s %s", r.Method, path)
		write(http.StatusNotFound, map[string]any{"code": 404})
	}
}

func (f *fakeFeishu) sentDrafts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.sent)
}

func TestFeishuMailConnectsRefreshesAndDisconnectsWithoutComposio(t *testing.T) {
	allowParallelIntegrationTest(t)
	databaseURL := newIntegrationDatabase(t)
	pool, err := pgxpool.New(context.Background(), databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	fake := newFakeFeishu(t)
	cfg := config.ForTest(func(c *config.Config) {
		c.DatabaseURL = databaseURL
		c.SessionTTL = time.Hour
		c.CookieName = "teamhub_session"
		c.ArtifactStorageRoot = t.TempDir()
		withFeishuApp(c, fake, 7)
	})
	application, err := newIntegrationApp(context.Background(), cfg, starting(app.JobQueue))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(application.Close)
	server := httptest.NewServer(application.Handler())
	registerIntegrationServerCleanup(t, server)
	env := &testEnv{t: t, databaseURL: databaseURL, pool: pool, server: server}
	alice := env.login("alice", alicePassword)

	// The server's Feishu app makes Feishu Mail available without Composio.
	var catalog struct {
		Apps []struct {
			Key          string `json:"key"`
			Availability string `json:"availability"`
		} `json:"apps"`
	}
	status, _, body := env.request(alice, http.MethodGet, "/v0/external-apps", nil, "")
	if status != http.StatusOK {
		t.Fatalf("list apps status=%d body=%s", status, body)
	}
	decode(t, body, &catalog)
	if i := slices.IndexFunc(catalog.Apps, func(app struct {
		Key          string `json:"key"`
		Availability string `json:"availability"`
	}) bool {
		return app.Key == "feishu_mail"
	}); i < 0 || catalog.Apps[i].Availability != "available" || strings.Contains(string(body), "cli_test") {
		t.Fatalf("catalog = %s", body)
	}

	connect := func(key string) (string, string, string) {
		t.Helper()
		status, _, body := env.request(alice, http.MethodPost, "/v0/external-connections", map[string]string{"app_key": "feishu_mail"}, key)
		if status != http.StatusCreated {
			t.Fatalf("create status=%d body=%s", status, body)
		}
		var connection struct {
			ID         string `json:"id"`
			Status     string `json:"status"`
			ConnectURL string `json:"connect_url"`
		}
		decode(t, body, &connection)
		consent, err := url.Parse(connection.ConnectURL)
		if err != nil || connection.Status != "pending" || consent.Path != "/open-apis/authen/v1/authorize" {
			t.Fatalf("connection = %s", body)
		}
		query := consent.Query()
		if query.Get("client_id") != "cli_test" || query.Get("code_challenge_method") != "S256" || !strings.Contains(query.Get("scope"), feishu.OfflineAccessScope) {
			t.Fatalf("consent page = %s", connection.ConnectURL)
		}
		return connection.ID, query.Get("state"), query.Get("code_challenge")
	}

	// An authorization that lacks a mail scope is refused and names it; a
	// browser without a Linger session may hand the code over.
	_, limitedState, limitedChallenge := connect("feishu-limited")
	fake.issueCode("code-limited", limitedChallenge, []string{feishu.OfflineAccessScope, "mail:user_mailbox:readonly"})
	status, _, body = env.request(http.DefaultClient, http.MethodPost, "/v0/external-connection-completions/feishu", map[string]string{"state": limitedState, "code": "code-limited"}, "")
	if status != http.StatusBadRequest || !strings.Contains(string(body), "FEISHU_SCOPES_MISSING") || !strings.Contains(string(body), "mail:user_mailbox.message:send") {
		t.Fatalf("limited authorization status=%d body=%s", status, body)
	}

	connectionID, state, challenge := connect("feishu-full")
	fake.issueCode("code-full", challenge, feishu.RequestedScopes())
	status, _, body = env.request(http.DefaultClient, http.MethodPost, "/v0/external-connection-completions/feishu", map[string]string{"state": "tampered" + state, "code": "code-full"}, "")
	if status != http.StatusBadRequest {
		t.Fatalf("tampered state status=%d body=%s", status, body)
	}
	status, _, body = env.request(http.DefaultClient, http.MethodPost, "/v0/external-connection-completions/feishu", map[string]string{"state": state, "code": "code-full"}, "")
	if status != http.StatusNoContent {
		t.Fatalf("complete status=%d body=%s", status, body)
	}
	var revision int64
	connectionState := func() (string, string) {
		var current, label string
		if err := pool.QueryRow(context.Background(), `SELECT status,coalesce(identity_label,''),revision FROM external_connections WHERE id=$1`, connectionID).Scan(&current, &label, &revision); err != nil {
			t.Fatal(err)
		}
		return current, label
	}
	if !waitForExternalSource(func() bool {
		current, label := connectionState()
		return current == "active" && label == "zhang@example.com"
	}) {
		current, label := connectionState()
		t.Fatalf("connection did not become active: status=%s label=%s", current, label)
	}
	var principal, toolkit, authConfig string
	if err := pool.QueryRow(context.Background(), `SELECT remote_principal_key,toolkit_slug,auth_config_id FROM external_connections WHERE id=$1`, connectionID).Scan(&principal, &toolkit, &authConfig); err != nil {
		t.Fatal(err)
	}
	if principal != "feishu_mail:zhang@example.com" || toolkit != "feishu" || authConfig != "cli_test" {
		t.Fatalf("principal=%s toolkit=%s auth_config=%s", principal, toolkit, authConfig)
	}
	var sealedAccess []byte
	if err := pool.QueryRow(context.Background(), `SELECT token.access_token_ciphertext FROM feishu_upstream_tokens token JOIN external_connections connection ON connection.upstream_connection_id=token.upstream_id WHERE connection.id=$1`, connectionID).Scan(&sealedAccess); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealedAccess, []byte("u-")) {
		t.Fatal("the access token is stored unsealed")
	}

	// An expiring access token is refreshed at the next check; Feishu rotates
	// the refresh token, so the stored one is replaced.
	checkNow := func() {
		t.Helper()
		if _, err := pool.Exec(context.Background(), `UPDATE feishu_upstream_tokens SET access_expires_at=now()-interval '1 minute' WHERE upstream_id=(SELECT upstream_connection_id FROM external_connections WHERE id=$1)`, connectionID); err != nil {
			t.Fatal(err)
		}
		connectionState()
		status, _, body := env.request(alice, http.MethodPost, "/v0/external-connections/"+connectionID+"/status-checks", map[string]int64{"expected_revision": revision}, "")
		if status != http.StatusOK && status != http.StatusCreated && status != http.StatusAccepted {
			t.Fatalf("status check status=%d body=%s", status, body)
		}
	}
	checkNow()
	if !waitForExternalSource(func() bool { return fake.refreshCount() == 1 }) {
		t.Fatalf("refreshes = %d", fake.refreshCount())
	}
	if !waitForExternalSource(func() bool {
		var requested bool
		_ = pool.QueryRow(context.Background(), `SELECT status_check_requested_at IS NOT NULL FROM external_connections WHERE id=$1`, connectionID).Scan(&requested)
		current, _ := connectionState()
		return !requested && current == "active"
	}) {
		t.Fatal("the refreshed connection did not settle active")
	}

	// A refresh Feishu refuses means the user must authorize again.
	fake.setRejectRefresh(true)
	checkNow()
	if !waitForExternalSource(func() bool { current, _ := connectionState(); return current == "expired" }) {
		current, _ := connectionState()
		t.Fatalf("connection status after a refused refresh = %s", current)
	}

	// Disconnecting forgets the tokens.
	status, _, body = env.request(alice, http.MethodPost, "/v0/external-connections/"+connectionID+"/disconnects", map[string]int64{"expected_revision": revision}, "")
	if status != http.StatusOK && status != http.StatusAccepted {
		t.Fatalf("disconnect status=%d body=%s", status, body)
	}
	if !waitForExternalSource(func() bool {
		current, _ := connectionState()
		var tokens int
		_ = pool.QueryRow(context.Background(), `SELECT count(*) FROM feishu_upstream_tokens token JOIN external_connections connection ON connection.upstream_connection_id=token.upstream_id WHERE connection.id=$1`, connectionID).Scan(&tokens)
		return current == "revoked" && tokens == 0
	}) {
		current, _ := connectionState()
		t.Fatalf("connection after disconnect = %s", current)
	}
}
