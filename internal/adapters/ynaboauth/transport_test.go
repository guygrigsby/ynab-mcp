package ynaboauth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestTokenResponseShapeAndScopeFailClosed(t *testing.T) {
	cases := []struct {
		name, body string
		want       error
	}{
		{"valid scope omitted", validResponse, nil},
		{"valid explicit scope", strings.TrimSuffix(validResponse, "}") + `,"scope":"read-only"}`, nil},
		{"valid bearer case", strings.Replace(validResponse, "bearer", "Bearer", 1), nil},
		{"extra fields ignored", strings.TrimSuffix(validResponse, "}") + `,"created_at":1791914400,"extra":{"private":"synthetic-client-secret"}}`, nil},
		{"missing access", `{"refresh_token":"synthetic-refresh","token_type":"bearer","expires_in":7200}`, ErrInvalidResponse},
		{"missing refresh", `{"access_token":"synthetic-access","token_type":"bearer","expires_in":7200}`, ErrInvalidResponse},
		{"missing token type", `{"access_token":"synthetic-access","refresh_token":"synthetic-refresh","expires_in":7200}`, ErrInvalidResponse},
		{"wrong token type", strings.Replace(validResponse, "bearer", "basic", 1), ErrInvalidResponse},
		{"null token", strings.Replace(validResponse, `"synthetic-access-token"`, "null", 1), ErrInvalidResponse},
		{"number token", strings.Replace(validResponse, `"synthetic-access-token"`, "123", 1), ErrInvalidResponse},
		{"whitespace token", strings.Replace(validResponse, syntheticAccess, `unsafe\nheader`, 1), ErrInvalidResponse},
		{"oversized token", strings.Replace(validResponse, syntheticAccess, strings.Repeat("x", maxSecret+1), 1), ErrInvalidResponse},
		{"missing expiration", strings.Replace(validResponse, `,"expires_in":7200`, "", 1), ErrInvalidResponse},
		{"null expiration", strings.Replace(validResponse, "7200", "null", 1), ErrInvalidResponse},
		{"zero expiration", strings.Replace(validResponse, "7200", "0", 1), ErrInvalidResponse},
		{"negative expiration", strings.Replace(validResponse, "7200", "-1", 1), ErrInvalidResponse},
		{"excess expiration", strings.Replace(validResponse, "7200", "86401", 1), ErrInvalidResponse},
		{"overflow expiration", strings.Replace(validResponse, "7200", "999999999999999999999999999", 1), ErrInvalidResponse},
		{"string expiration", strings.Replace(validResponse, "7200", `"7200"`, 1), ErrInvalidResponse},
		{"fraction expiration", strings.Replace(validResponse, "7200", "7200.0", 1), ErrInvalidResponse},
		{"exponent expiration", strings.Replace(validResponse, "7200", "72e2", 1), ErrInvalidResponse},
		{"broader scope", strings.TrimSuffix(validResponse, "}") + `,"scope":"read-only write"}`, ErrScopeMismatch},
		{"unknown scope", strings.TrimSuffix(validResponse, "}") + `,"scope":"write"}`, ErrScopeMismatch},
		{"empty scope", strings.TrimSuffix(validResponse, "}") + `,"scope":""}`, ErrScopeMismatch},
		{"null scope", strings.TrimSuffix(validResponse, "}") + `,"scope":null}`, ErrScopeMismatch},
		{"scope array", strings.TrimSuffix(validResponse, "}") + `,"scope":["read-only"]}`, ErrScopeMismatch},
		{"duplicate access", strings.TrimSuffix(validResponse, "}") + `,"access_token":"other-synthetic-access"}`, ErrInvalidResponse},
		{"duplicate escaped key", strings.TrimSuffix(validResponse, "}") + `,"access_\u0074oken":"other-synthetic-access"}`, ErrInvalidResponse},
		{"duplicate scope", strings.TrimSuffix(validResponse, "}") + `,"scope":"write","scope":"read-only"}`, ErrInvalidResponse},
		{"duplicate unknown", strings.TrimSuffix(validResponse, "}") + `,"extra":null,"extra":null}`, ErrInvalidResponse},
		{"array root", "[" + validResponse + "]", ErrInvalidResponse},
		{"null root", "null", ErrInvalidResponse},
		{"trailing JSON", validResponse + `{}`, ErrInvalidResponse},
		{"truncated", strings.TrimSuffix(validResponse, "}"), ErrInvalidResponse},
		{"error with 200", `{"error":"invalid_grant","error_description":"synthetic-client-secret"}`, ErrReconnectRequired},
		{"both error and tokens", strings.TrimSuffix(validResponse, "}") + `,"error":"invalid_request"}`, ErrTokenRequestFailed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c := testClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
				calls++
				return response(200, tc.body), nil
			}))
			got, err := c.Exchange(context.Background(), syntheticCode, syntheticVerifier)
			if !errors.Is(err, tc.want) || (got == nil) != (tc.want != nil) || calls != 1 {
				t.Fatalf("exchange = %v, %v, attempts=%d; want %v", got, err, calls, tc.want)
			}
			assertSanitized(t, err)
		})
	}
}

func TestRedirectsNeverFollowCredentials(t *testing.T) {
	for _, status := range []int{301, 302, 303, 307, 308} {
		for _, destination := range []string{"https://attacker.invalid/collect", tokenURL, "http://app.ynab.com/oauth/token"} {
			calls := 0
			c := testClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if r.URL.String() != tokenURL {
					t.Fatal("credentials escaped fixed destination")
				}
				res := response(status, "")
				res.Header.Set("Location", destination)
				return res, nil
			}))
			if got, err := c.Exchange(context.Background(), syntheticCode, syntheticVerifier); got != nil || !errors.Is(err, ErrTokenRequestFailed) || calls != 1 {
				t.Fatalf("redirect %d: got=%v error=%v attempts=%d", status, got, err, calls)
			}
		}
	}
}

func TestResponseBoundsContentTypeAndFailureSanitization(t *testing.T) {
	cases := []struct {
		name string
		make func() (*http.Response, error)
	}{
		{"transport error contains secrets", func() (*http.Response, error) { return nil, errors.New(syntheticSecret + syntheticAccess) }},
		{"nil response", func() (*http.Response, error) { return nil, nil }},
		{"missing body", func() (*http.Response, error) { return &http.Response{StatusCode: 200}, nil }},
		{"wrong status", func() (*http.Response, error) { return response(201, validResponse), nil }},
		{"error body contains secrets", func() (*http.Response, error) {
			return response(401, `{"error":"invalid_client","error_description":"`+syntheticSecret+`","error_uri":"https://example.invalid/`+syntheticAccess+`"}`), nil
		}},
		{"large content length", func() (*http.Response, error) {
			r := response(200, validResponse)
			r.ContentLength = maxResponseBytes + 1
			return r, nil
		}},
		{"large body without content length", func() (*http.Response, error) {
			return response(200, strings.Repeat(" ", maxResponseBytes+1)+validResponse), nil
		}},
		{"valid JSON plus oversized whitespace", func() (*http.Response, error) {
			return response(200, validResponse+strings.Repeat(" ", maxResponseBytes)), nil
		}},
		{"HTML response", func() (*http.Response, error) {
			r := response(200, validResponse)
			r.Header.Set("Content-Type", "text/html")
			return r, nil
		}},
		{"form response", func() (*http.Response, error) {
			r := response(200, "access_token="+syntheticAccess)
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			return r, nil
		}},
		{"missing content type", func() (*http.Response, error) {
			r := response(200, validResponse)
			r.Header.Del("Content-Type")
			return r, nil
		}},
		{"unknown content encoding", func() (*http.Response, error) {
			r := response(200, validResponse)
			r.Header.Set("Content-Encoding", "compress")
			return r, nil
		}},
		{"body read error", func() (*http.Response, error) { r := response(200, ""); r.Body = &errorBody{}; return r, nil }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			c := testClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) { calls++; return tc.make() }))
			got, err := c.Exchange(context.Background(), syntheticCode, syntheticVerifier)
			if err == nil || got != nil || calls != 1 {
				t.Fatalf("exchange = %v, %v, attempts=%d", got, err, calls)
			}
			assertSanitized(t, err)
			var raw interface{ Unwrap() error }
			if errors.As(err, &raw) {
				t.Fatal("unsafe error cause escaped the adapter")
			}
		})
	}
}

type errorBody struct{}

func (*errorBody) Read([]byte) (int, error) { return 0, errors.New(syntheticSecret) }
func (*errorBody) Close() error             { return nil }

func TestTransportRejectsAlternateMethodsDestinationsAndGrantTypes(t *testing.T) {
	form := url.Values{"grant_type": {"authorization_code"}, "code": {syntheticCode}, "code_verifier": {syntheticVerifier}, "redirect_uri": {syntheticCallback}, "client_id": {syntheticClient}, "client_secret": {syntheticSecret}}.Encode()
	guard := &credentialTransport{base: roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("unsafe request reached credential network transport")
		return nil, nil
	})}
	for _, tc := range []struct{ method, destination, body string }{
		{"GET", tokenURL, form}, {"PATCH", tokenURL, form}, {"POST", "https://api.ynab.com/v1/plans", form},
		{"POST", "http://app.ynab.com/oauth/token", form}, {"POST", "https://app.ynab.com:443/oauth/token", form},
		{"POST", tokenURL + "?access_token=" + syntheticAccess, form}, {"POST", tokenURL + "#fragment", form},
		{"POST", "https://app.ynab.com.attacker.invalid/oauth/token", form}, {"POST", "https://user:password@app.ynab.com/oauth/token", form},
		{"POST", tokenURL, strings.Replace(form, "authorization_code", "password", 1)},
		{"POST", tokenURL, form + "&scope=write"}, {"POST", tokenURL, form + "&code=second-code"},
		{"POST", tokenURL, strings.Repeat("x", maxRequestBytes+1)}, {"POST", tokenURL, ""},
	} {
		r, err := http.NewRequest(tc.method, tc.destination, strings.NewReader(tc.body))
		if err != nil {
			t.Fatal(err)
		}
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if _, err := guard.RoundTrip(r); err == nil {
			t.Fatal("unsafe request was accepted")
		}
	}
	for _, header := range []string{"Authorization", "Cookie", "Content-Encoding"} {
		r, _ := http.NewRequest("POST", tokenURL, strings.NewReader(form))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set(header, "synthetic-untrusted")
		if _, err := guard.RoundTrip(r); err == nil {
			t.Fatal("unsafe headers were accepted")
		}
	}
	r, _ := http.NewRequest("POST", tokenURL, strings.NewReader(form))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Host = "attacker.invalid"
	if _, err := guard.RoundTrip(r); err == nil {
		t.Fatal("alternate Host header accepted")
	}
}

func TestRequestDeadlineAndConservativeExpiry(t *testing.T) {
	parent, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	parentDeadline, _ := parent.Deadline()
	c := testClient(t, roundTripFunc(func(r *http.Request) (*http.Response, error) {
		deadline, ok := r.Context().Deadline()
		if !ok || !deadline.Equal(parentDeadline) {
			t.Fatal("shorter caller deadline was not preserved")
		}
		return response(200, validResponse), nil
	}))
	nowCalls := 0
	c.now = func() time.Time {
		nowCalls++
		if nowCalls > 1 {
			return syntheticNow.Add(3 * time.Second)
		}
		return syntheticNow
	}
	got, err := c.Exchange(parent, syntheticCode, syntheticVerifier)
	if err != nil || !got.ExpiresAt().Equal(syntheticNow.Add(2*time.Hour)) {
		t.Fatalf("expiry was not conservatively anchored: %v, %v", got, err)
	}
	nowCalls = 0
	c.now = func() time.Time { nowCalls++; return syntheticNow.Add(time.Duration(nowCalls-1) * 3 * time.Hour) }
	if got, err := c.Exchange(parent, syntheticCode, syntheticVerifier); got != nil || !errors.Is(err, ErrInvalidResponse) {
		t.Fatalf("already expired response accepted: %v, %v", got, err)
	}
}

type trackedBody struct {
	io.Reader
	closed bool
}

func (b *trackedBody) Close() error { b.closed = true; return nil }

func TestResponseBodyAlwaysClosed(t *testing.T) {
	for _, status := range []int{200, 307, 400, 500} {
		body := &trackedBody{Reader: strings.NewReader(validResponse)}
		c := testClient(t, roundTripFunc(func(*http.Request) (*http.Response, error) {
			r := response(status, "")
			r.Body = body
			return r, nil
		}))
		_, _ = c.Exchange(context.Background(), syntheticCode, syntheticVerifier)
		if !body.closed {
			t.Fatalf("response body not closed on status %d", status)
		}
	}
}

func FuzzTokenResponseValidation(f *testing.F) {
	for _, seed := range []string{validResponse, "null", `{}`, `{"scope":"write","scope":"read-only"}`, `{"a":[[[1]]]}`} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > maxResponseBytes {
			t.Skip()
		}
		fields, err := uniqueObject([]byte(body))
		if err == nil {
			_, _ = validateToken(fields)
		}
	})
}
