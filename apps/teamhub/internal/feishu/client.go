// Package feishu calls the Feishu and Lark Open Platform for connected apps
// TeamHub authorizes itself, without Composio: the OAuth exchange with a
// deployment's enterprise custom app and the user-identity mail APIs.
package feishu

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Region names the Open Platform an app belongs to: Feishu in mainland China
// or Lark elsewhere. The two serve the same APIs on different domains.
type Region string

// The Open Platform regions.
const (
	RegionFeishu Region = "feishu"
	RegionLark   Region = "lark"
)

// Valid reports whether r is a known region.
func (r Region) Valid() bool { return r == RegionFeishu || r == RegionLark }

// App is a deployment's enterprise custom app. Feishu serves its mail APIs to
// custom apps only, so each deployment brings its own.
type App struct {
	Region Region
	ID     string
	Secret string
}

type endpoints struct{ open, accounts string }

var regionEndpoints = map[Region]endpoints{
	RegionFeishu: {open: "https://open.feishu.cn", accounts: "https://accounts.feishu.cn"},
	RegionLark:   {open: "https://open.larksuite.com", accounts: "https://accounts.larksuite.com"},
}

// Config configures a Client. BaseURL, when set, replaces both the API and the
// accounts origin of every region; tests point it at a fake Open Platform.
type Config struct {
	BaseURL    string
	HTTPClient *http.Client
}

// Client calls the Open Platform. It holds no credentials: each call names
// the app and, for user calls, the user access token.
type Client struct {
	baseURL string
	http    *http.Client
}

// New builds a Client.
func New(config Config) *Client {
	client := config.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	return &Client{baseURL: strings.TrimRight(config.BaseURL, "/"), http: client}
}

func (c *Client) endpoints(region Region) endpoints {
	if c.baseURL != "" {
		return endpoints{open: c.baseURL, accounts: c.baseURL}
	}
	return regionEndpoints[region]
}

// APIError is an Open Platform refusal: the HTTP status, the platform's
// numeric code, and the OAuth error of a token request. Message is the
// platform's text, kept for logs only.
type APIError struct {
	Operation  string
	HTTPStatus int
	Code       int
	OAuthError string
	Message    string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("Feishu %s failed: http_status=%d code=%d", e.Operation, e.HTTPStatus, e.Code)
}

// RateLimitError reports a call the Open Platform throttled.
type RateLimitError struct {
	Operation  string
	RetryAfter time.Duration
}

func (e *RateLimitError) Error() string { return "Feishu " + e.Operation + " was rate limited" }

// Platform codes that mean the user's authorization no longer works: the
// refresh token was revoked or already used, the yearly reauthorization is
// due, or the access token is invalid or expired.
var authFailureCodes = []int{20037, 20064, 20073, 99991668, 99991677}

// IsAuthFailure reports whether err means the user must authorize again.
func IsAuthFailure(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	return apiErr.OAuthError == "invalid_grant" || slices.Contains(authFailureCodes, apiErr.Code)
}

// IsAppRejected reports whether the Open Platform answered a request made
// with the app's own credentials with a refusal rather than a server failure.
func IsAppRejected(err error) bool {
	var apiErr *APIError
	return errors.As(err, &apiErr) && (apiErr.OAuthError == "invalid_client" || apiErr.HTTPStatus < http.StatusInternalServerError)
}

// ErrorStatus returns the HTTP status of an Open Platform refusal.
func ErrorStatus(err error) (int, bool) {
	var apiErr *APIError
	if errors.As(err, &apiErr) && apiErr.HTTPStatus != 0 {
		return apiErr.HTTPStatus, true
	}
	return 0, false
}

// envelope is the common shape of Open Platform responses; token responses
// add the OAuth fields at the top level.
type envelope struct {
	Code             int             `json:"code"`
	Msg              string          `json:"msg"`
	Error            string          `json:"error"`
	ErrorDescription string          `json:"error_description"`
	Data             json.RawMessage `json:"data"`
}

// call sends one request and decodes a successful response into result. A
// non-2xx status or a nonzero platform code is an *APIError; 429 is a
// *RateLimitError.
func (c *Client) call(ctx context.Context, operation, method, endpoint, bearer string, body any, result any) error {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, endpoint, reader)
	if err != nil {
		return err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json; charset=utf-8")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := c.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, 8<<20))
	if err != nil {
		return err
	}
	if response.StatusCode == http.StatusTooManyRequests {
		return &RateLimitError{Operation: operation, RetryAfter: retryAfter(response.Header)}
	}
	var decoded envelope
	decodeErr := json.Unmarshal(raw, &decoded)
	if response.StatusCode < 200 || response.StatusCode > 299 || decodeErr == nil && (decoded.Code != 0 || decoded.Error != "") {
		apiErr := &APIError{Operation: operation, HTTPStatus: response.StatusCode, Code: decoded.Code, OAuthError: decoded.Error, Message: decoded.Msg}
		if apiErr.Message == "" {
			apiErr.Message = decoded.ErrorDescription
		}
		return apiErr
	}
	if decodeErr != nil {
		return fmt.Errorf("decode Feishu %s response: %w", operation, decodeErr)
	}
	if result == nil {
		return nil
	}
	return json.Unmarshal(raw, result)
}

func retryAfter(header http.Header) time.Duration {
	seconds, err := strconv.Atoi(strings.TrimSpace(header.Get("Retry-After")))
	if err != nil || seconds <= 0 {
		return time.Minute
	}
	return time.Duration(seconds) * time.Second
}

// CheckApp asks the Open Platform for a tenant access token with the app's
// credentials: the cheapest call that proves the App ID and Secret.
func (c *Client) CheckApp(ctx context.Context, app App) error {
	if !app.Region.Valid() {
		return errors.New("unknown Feishu region")
	}
	endpoint := c.endpoints(app.Region).open + "/open-apis/auth/v3/tenant_access_token/internal"
	return c.call(ctx, "app check", http.MethodPost, endpoint, "", map[string]string{"app_id": app.ID, "app_secret": app.Secret}, nil)
}

// PrimaryMailbox returns the address of the authorized user's primary
// mailbox, the identity of a mail connection.
func (c *Client) PrimaryMailbox(ctx context.Context, region Region, accessToken string) (string, error) {
	var response struct {
		Data struct {
			PrimaryEmailAddress string `json:"primary_email_address"`
		} `json:"data"`
	}
	endpoint := c.endpoints(region).open + "/open-apis/mail/v1/user_mailboxes/me/profile"
	if err := c.call(ctx, "mailbox profile", http.MethodGet, endpoint, accessToken, nil, &response); err != nil {
		return "", err
	}
	address := strings.ToLower(strings.TrimSpace(response.Data.PrimaryEmailAddress))
	if address == "" {
		return "", errors.New("the Feishu mailbox has no primary address")
	}
	return address, nil
}

func queryURL(base string, values url.Values) string {
	return base + "?" + values.Encode()
}
