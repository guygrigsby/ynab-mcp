package ynaboauth

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"golang.org/x/oauth2"
)

const (
	syntheticClient   = "synthetic-client"
	syntheticSecret   = "synthetic-client-secret"
	syntheticAccess   = "synthetic-access-token"
	syntheticRefresh  = "synthetic-refresh-token"
	syntheticCode     = "synthetic-code"
	syntheticCallback = "https://connector.example/oauth/ynab/callback"
	syntheticVerifier = "synthetic-verifier-0123456789012345678901234567890123456789"
	syntheticState    = "synthetic-state-012345678901234567890123456789"
	validResponse     = `{"access_token":"synthetic-access-token","refresh_token":"synthetic-refresh-token","token_type":"bearer","expires_in":7200}`
)

var syntheticNow = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func response(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": {"application/json"}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func testClient(t *testing.T, rt http.RoundTripper) *Client {
	t.Helper()
	c, err := newClient(syntheticClient, syntheticSecret, syntheticCallback, rt, func() time.Time { return syntheticNow })
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestConfigurationIsFixedAndHTTPS(t *testing.T) {
	for _, callback := range []string{
		"", "http://connector.example/callback", "//connector.example/callback", "https:///callback", "https://:443/callback",
		"https://user:password@connector.example/callback", "https://connector.example/callback?extra=1",
		"https://connector.example/callback?", "https://connector.example/callback#fragment", "https://connector.example/callback#",
		"https://connector.example:bad/callback", "https://connector.example/\ncallback",
	} {
		t.Run(callback, func(t *testing.T) {
			if _, err := New(syntheticClient, syntheticSecret, callback); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatalf("configuration error = %v", err)
			}
		})
	}
	for _, creds := range [][2]string{{"", syntheticSecret}, {syntheticClient, ""}, {"client\n", syntheticSecret}, {syntheticClient, "secret\n"}} {
		if _, err := New(creds[0], creds[1], syntheticCallback); !errors.Is(err, ErrInvalidConfiguration) {
			t.Fatalf("configuration error = %v", err)
		}
	}
	c, err := New(syntheticClient, syntheticSecret, syntheticCallback)
	if err != nil {
		t.Fatal(err)
	}
	if c.config.Endpoint.AuthURL != authorizeURL || c.config.Endpoint.TokenURL != tokenURL || c.config.Endpoint.AuthStyle != oauth2.AuthStyleInParams {
		t.Fatal("OAuth endpoints or auth style are not pinned")
	}
	if c.http.Timeout != requestLimit || c.http.CheckRedirect == nil {
		t.Fatal("credential HTTP client is not bounded")
	}
	transport := c.http.Transport.(*credentialTransport).base.(*http.Transport)
	if transport.Proxy != nil || !transport.DisableKeepAlives || transport.ForceAttemptHTTP2 || transport.TLSNextProto == nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("credential transport safety policy changed")
	}
}

func TestAuthorizationURLReadOnlyS256AndExactCallback(t *testing.T) {
	c := testClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("authorization URL must not make a network request")
		return nil, nil
	}))
	raw, err := c.AuthorizationURL(syntheticState, syntheticVerifier)
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host != "app.ynab.com" || u.Path != "/oauth/authorize" {
		t.Fatal("unexpected authorization destination")
	}
	want := url.Values{
		"response_type": {"code"}, "client_id": {syntheticClient}, "redirect_uri": {syntheticCallback},
		"scope": {"read-only"}, "state": {syntheticState}, "code_challenge_method": {"S256"},
		"code_challenge": {oauth2.S256ChallengeFromVerifier(syntheticVerifier)},
	}
	if u.RawQuery != want.Encode() {
		t.Fatalf("authorization query = %v", u.Query())
	}
	if strings.Contains(raw, syntheticSecret) || strings.Contains(raw, syntheticVerifier) {
		t.Fatal("authorization URL disclosed a secret or PKCE verifier")
	}
	for _, verifier := range []string{"", strings.Repeat("a", 42), strings.Repeat("a", 129), strings.Repeat("a", 43) + "+", strings.Repeat("a", 43) + "\n"} {
		if _, err := c.AuthorizationURL(syntheticState, verifier); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid verifier error = %v", err)
		}
	}
	for _, state := range []string{"", "short-state", strings.Repeat("a", 513), syntheticState + " "} {
		if _, err := c.AuthorizationURL(state, syntheticVerifier); !errors.Is(err, ErrInvalidInput) {
			t.Fatalf("invalid state error = %v", err)
		}
	}
}

func TestExchangeUsesPKCEFixedDestinationAndOwnedHTTPClient(t *testing.T) {
	calls := 0
	c := testClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != "POST" || r.URL.String() != tokenURL || r.Header.Get("Authorization") != "" || r.GetBody != nil || !r.Close {
			t.Fatal("request guard did not constrain the exchange")
		}
		deadline, ok := r.Context().Deadline()
		if !ok || time.Until(deadline) > requestLimit {
			t.Fatal("missing bounded request deadline")
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		want := url.Values{
			"grant_type": {"authorization_code"}, "code": {syntheticCode}, "code_verifier": {syntheticVerifier},
			"redirect_uri": {syntheticCallback}, "client_id": {syntheticClient}, "client_secret": {syntheticSecret},
		}
		if r.PostForm.Encode() != want.Encode() {
			t.Fatalf("unexpected exchange parameters: %v", r.PostForm)
		}
		return response(http.StatusOK, validResponse), nil
	}))
	unsafeClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("caller-provided HTTP client must be overridden")
		return nil, nil
	})}
	ctx := context.WithValue(context.Background(), oauth2.HTTPClient, unsafeClient)
	credentials, err := c.Exchange(ctx, syntheticCode, syntheticVerifier)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || credentials.AccessToken() != syntheticAccess || credentials.refreshToken != syntheticRefresh || !credentials.ExpiresAt().Equal(syntheticNow.Add(2*time.Hour)) {
		t.Fatalf("unexpected exchange result or attempt count: %d, %v", calls, credentials)
	}
}

func TestRefreshIsExplicitSingleAttemptAndRotatesCompletePair(t *testing.T) {
	calls := 0
	c := testClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		want := url.Values{"grant_type": {"refresh_token"}, "refresh_token": {"synthetic-old-refresh"}, "client_id": {syntheticClient}, "client_secret": {syntheticSecret}}
		if r.PostForm.Encode() != want.Encode() {
			t.Fatalf("unexpected refresh parameters: %v", r.PostForm)
		}
		return response(200, validResponse), nil
	}))
	prior := &Credentials{accessToken: "synthetic-old-access", refreshToken: "synthetic-old-refresh", expiresAt: syntheticNow.Add(time.Hour)}
	got, err := c.Refresh(context.Background(), prior)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || got.AccessToken() != syntheticAccess || got.refreshToken != syntheticRefresh || prior.refreshToken != "synthetic-old-refresh" {
		t.Fatal("refresh did not preserve the prior immutable complete generation")
	}
}

func TestRefreshFailureNeverRetriesOrReturnsUnsafeErrors(t *testing.T) {
	for _, failure := range []struct {
		name string
		rt   roundTripFunc
	}{
		{"transport failure", func(*http.Request) (*http.Response, error) {
			return nil, errors.New(syntheticSecret + syntheticRefresh)
		}},
		{"unauthorized", func(*http.Request) (*http.Response, error) {
			return response(401, `{"error":"invalid_client","error_description":"`+syntheticSecret+`"}`), nil
		}},
		{"invalid grant", func(*http.Request) (*http.Response, error) { return response(400, `{"error":"invalid_grant"}`), nil }},
		{"server failure", func(*http.Request) (*http.Response, error) { return response(500, `{}`), nil }},
		{"ambiguous pair", func(*http.Request) (*http.Response, error) {
			return response(200, `{"access_token":"synthetic-new-token","token_type":"bearer","expires_in":7200}`), nil
		}},
		{"wrong scope", func(*http.Request) (*http.Response, error) {
			return response(200, strings.TrimSuffix(validResponse, "}")+`,"scope":"write"}`), nil
		}},
	} {
		t.Run(failure.name, func(t *testing.T) {
			calls := 0
			c := testClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) { calls++; return failure.rt(r) }))
			prior := &Credentials{accessToken: syntheticAccess, refreshToken: syntheticRefresh, expiresAt: syntheticNow}
			got, err := c.Refresh(context.Background(), prior)
			if got != nil || !errors.Is(err, ErrReconnectRequired) || calls != 1 {
				t.Fatalf("refresh = %v, %v, attempts=%d", got, err, calls)
			}
			assertSanitized(t, err)
		})
	}
}

func TestCredentialsAndClientAreRedacted(t *testing.T) {
	c := testClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) { return response(200, validResponse), nil }))
	credentials, err := c.Exchange(context.Background(), syntheticCode, syntheticVerifier)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{credentials, *credentials, c, *c, []any{credentials, c}, map[string]any{"credentials": credentials, "client": c}} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x"} {
			assertSanitized(t, fmt.Sprintf(format, value))
		}
		if encoded, err := json.Marshal(value); err == nil {
			assertSanitized(t, string(encoded))
		}
		if encoded, err := xml.Marshal(value); err == nil {
			assertSanitized(t, string(encoded))
		}
	}
	var logs bytes.Buffer
	slog.New(slog.NewJSONHandler(&logs, nil)).Info("synthetic-test", "credentials", credentials, "client", c)
	assertSanitized(t, logs.String())
}

func TestInvalidInputAndZeroValuesNeverSend(t *testing.T) {
	c := testClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) { t.Fatal("invalid input reached network"); return nil, nil }))
	for _, code := range []string{"", "code\n", strings.Repeat("x", 4097)} {
		if _, err := c.Exchange(context.Background(), code, syntheticVerifier); !errors.Is(err, ErrInvalidInput) {
			t.Fatal(err)
		}
	}
	if _, err := c.Exchange(context.Background(), syntheticCode, "short-verifier"); !errors.Is(err, ErrInvalidInput) {
		t.Fatal(err)
	}
	for _, credentials := range []*Credentials{nil, {}, {accessToken: syntheticAccess, refreshToken: syntheticRefresh}} {
		if _, err := c.Refresh(context.Background(), credentials); !errors.Is(err, ErrInvalidInput) {
			t.Fatal(err)
		}
	}
	for _, zero := range []*Client{nil, {}} {
		if _, err := zero.AuthorizationURL(syntheticState, syntheticVerifier); !errors.Is(err, ErrInvalidInput) {
			t.Fatal(err)
		}
		if _, err := zero.Exchange(context.Background(), syntheticCode, syntheticVerifier); !errors.Is(err, ErrInvalidInput) {
			t.Fatal(err)
		}
		if _, err := zero.Refresh(context.Background(), nil); !errors.Is(err, ErrInvalidInput) {
			t.Fatal(err)
		}
	}
}

func assertSanitized(t *testing.T, value any) {
	t.Helper()
	raw := fmt.Sprintf("%v %#v", value, value)
	for _, secret := range []string{syntheticAccess, syntheticRefresh, syntheticSecret, syntheticCode, syntheticVerifier} {
		if strings.Contains(raw, secret) {
			t.Fatal("sensitive synthetic marker was exposed")
		}
	}
}
