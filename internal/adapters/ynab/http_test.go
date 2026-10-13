package ynab

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/connection"
	"github.com/guygrigsby/ynab-mcp/internal/domain/inquiry"
)

func TestTransportGuardDeniesMutationsAndDestinationChanges(t *testing.T) {
	calls := 0
	g := guardTransport{next: rtFunc(func(*http.Request) (*http.Response, error) { calls++; return response(200, `{}`), nil })}
	for _, method := range []string{"POST", "PATCH", "PUT", "DELETE", "HEAD", "OPTIONS", "CONNECT"} {
		r, _ := http.NewRequest(method, apiOrigin+plansPath, nil)
		if _, err := g.RoundTrip(r); err == nil {
			t.Errorf("allowed method %s", method)
		}
	}
	for _, target := range []string{"http://api.ynab.com/v1/plans", "https://evil.invalid/v1/plans", "https://api.ynab.com.evil.invalid/v1/plans", "https://api.ynab.com:443/v1/plans", "https://user@api.ynab.com/v1/plans", "https://api.ynab.com/v1/budgets", "https://api.ynab.com/v1/plans/../user", "https://api.ynab.com/v1/plans%2fsecret", "https://api.ynab.com/v1/plans#token"} {
		r, _ := http.NewRequest("GET", target, nil)
		if _, err := g.RoundTrip(r); err == nil {
			t.Errorf("allowed destination %s", target)
		}
	}
	r, _ := http.NewRequest("GET", apiOrigin+plansPath, nil)
	r.Host = "evil.invalid"
	if _, err := g.RoundTrip(r); err == nil {
		t.Error("allowed hostile Host")
	}
	if _, err := g.RoundTrip(nil); err == nil {
		t.Error("nil request allowed")
	}
	if calls != 0 {
		t.Fatalf("unsafe traffic escaped %d", calls)
	}
	r, _ = http.NewRequest("GET", apiOrigin+plansPath, nil)
	resp, err := g.RoundTrip(r)
	if err != nil || calls != 1 {
		t.Fatal("guard blocks valid fixed GET")
	}
	resp.Body.Close()
}
func TestConstructorRequiresAdmissionAndCredentials(t *testing.T) {
	for _, tt := range []struct {
		tokens TokenProvider
		quota  QuotaReserver
	}{{nil, nil}, {tokenFunc(fixtureToken), nil}, {nil, &quotaStub{}}} {
		if _, err := New(tt.tokens, tt.quota); err == nil {
			t.Fatal("unsafe production default")
		}
	}
	c, err := New(tokenFunc(fixtureToken), &quotaStub{})
	if err != nil {
		t.Fatal(err)
	}
	transport := c.http.Transport.(guardTransport).next.(*http.Transport)
	if transport.Proxy != nil || !transport.DisableKeepAlives {
		t.Fatal("implicit proxy or transparent transport retry enabled")
	}
}
func TestAllRedirectsDeniedWithoutForwardingBearer(t *testing.T) {
	for _, location := range []string{"https://evil.invalid/capture", "https://api.ynab.com/v1/plans/plan-1/settings", "/v1/plans"} {
		t.Run(location, func(t *testing.T) {
			count := 0
			q := &quotaStub{}
			c, err := newClient(tokenFunc(fixtureToken), q, rtFunc(func(*http.Request) (*http.Response, error) {
				count++
				r := response(302, `sensitive body`)
				r.Header.Set("Location", location)
				return r, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			var out responseDTO
			err = c.get(context.Background(), scope(), plansPath, nil, &out)
			if !errors.Is(err, inquiry.ErrUpstreamUnavailable) || count != 1 || q.calls.Load() != 1 {
				t.Fatalf("redirect followed or retried: %v count=%d", err, count)
			}
			if strings.Contains(err.Error(), "capture") {
				t.Fatal("location leaked")
			}
		})
	}
}
func TestStatusSanitizationNoRetryOrLegacyFallback(t *testing.T) {
	for _, tt := range []struct {
		code int
		want error
	}{{400, inquiry.ErrUpstreamUnavailable}, {401, inquiry.ErrReconnectRequired}, {403, inquiry.ErrUnauthorizedScope}, {404, inquiry.ErrNotFound}, {429, inquiry.ErrRateLimited}, {500, inquiry.ErrUpstreamUnavailable}, {503, inquiry.ErrUpstreamUnavailable}} {
		t.Run(fmt.Sprint(tt.code), func(t *testing.T) {
			count := 0
			q := &quotaStub{}
			c, _ := newClient(tokenFunc(fixtureToken), q, rtFunc(func(*http.Request) (*http.Response, error) {
				count++
				r := response(tt.code, `{"error":{"detail":"sensitive token secret and bank balance"}}`)
				r.Header.Set("Retry-After", "60")
				return r, nil
			}))
			c.now = func() time.Time { return time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC) }
			var out responseDTO
			err := c.get(context.Background(), scope(), plansPath, nil, &out)
			if !errors.Is(err, tt.want) || count != 1 || q.calls.Load() != 1 {
				t.Fatalf("bad status mapping %v count=%d", err, count)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatal("upstream body leaked")
			}
			if tt.code == 429 {
				if q.cooldowns.Load() != 1 || !q.until.Equal(c.now().Add(time.Minute)) {
					t.Fatal("missing durable cooldown")
				}
			}
		})
	}
}
func TestQuotaAndCredentialFailuresFailClosedAndSanitized(t *testing.T) {
	for _, tt := range []struct {
		name  string
		token tokenFunc
		quota *quotaStub
		want  error
	}{{"quota unavailable", tokenFunc(fixtureToken), &quotaStub{err: errors.New("private ledger path")}, inquiry.ErrUpstreamUnavailable}, {"quota limited", tokenFunc(fixtureToken), &quotaStub{err: inquiry.ErrRateLimited}, inquiry.ErrRateLimited}, {"token unavailable", func(context.Context, access.ReadScope) (string, error) { return "", errors.New("secret from provider") }, &quotaStub{}, inquiry.ErrUpstreamUnavailable}, {"reconnect", func(context.Context, access.ReadScope) (string, error) { return "", inquiry.ErrReconnectRequired }, &quotaStub{}, inquiry.ErrReconnectRequired}, {"empty token", func(context.Context, access.ReadScope) (string, error) { return "", nil }, &quotaStub{}, inquiry.ErrReconnectRequired}, {"header injection", func(context.Context, access.ReadScope) (string, error) { return "secret\r\nheader: bad", nil }, &quotaStub{}, inquiry.ErrReconnectRequired}} {
		t.Run(tt.name, func(t *testing.T) {
			count := 0
			c, _ := newClient(tt.token, tt.quota, rtFunc(func(*http.Request) (*http.Response, error) { count++; return nil, errors.New("must not send") }))
			var out responseDTO
			err := c.get(context.Background(), scope(), plansPath, nil, &out)
			if !errors.Is(err, tt.want) || count != 0 {
				t.Fatalf("failed open: %v count=%d", err, count)
			}
		})
	}
	q := &quotaStub{cooldownErr: errors.New("ledger failed")}
	c, _ := newClient(tokenFunc(fixtureToken), q, rtFunc(func(*http.Request) (*http.Response, error) { return response(429, ""), nil }))
	var out responseDTO
	if err := c.get(context.Background(), scope(), plansPath, nil, &out); !errors.Is(err, inquiry.ErrUpstreamUnavailable) {
		t.Fatal("cooldown persistence failure hidden")
	}
}
func TestNetworkErrorSanitizedAndReserved(t *testing.T) {
	q := &quotaStub{}
	c, _ := newClient(tokenFunc(fixtureToken), q, rtFunc(func(*http.Request) (*http.Response, error) {
		return nil, fmt.Errorf("https://api.ynab.com?secret=token")
	}))
	var out responseDTO
	err := c.get(context.Background(), scope(), plansPath, nil, &out)
	if !errors.Is(err, inquiry.ErrUpstreamUnavailable) || strings.Contains(err.Error(), "token") || q.calls.Load() != 1 {
		t.Fatalf("unsafe network failure: %v", err)
	}
}
func TestCancellationAndDeadline(t *testing.T) {
	calls := 0
	q := &quotaStub{}
	c, _ := newClient(tokenFunc(fixtureToken), q, rtFunc(func(r *http.Request) (*http.Response, error) {
		calls++
		<-r.Context().Done()
		return nil, r.Context().Err()
	}))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var out responseDTO
	if err := c.get(ctx, scope(), plansPath, nil, &out); !errors.Is(err, inquiry.ErrUpstreamUnavailable) || calls != 0 || q.calls.Load() != 0 {
		t.Fatal("canceled request sent")
	}
	ctx, cancel = context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err := c.Read(ctx, scope(), inquiry.Query{Tool: inquiry.ListAccounts, BudgetID: "plan-1"})
	if !errors.Is(err, inquiry.ErrUpstreamUnavailable) || time.Since(started) > time.Second || calls != 1 || q.calls.Load() != 1 {
		t.Fatalf("deadline not propagated: %v", err)
	}
}
func gzipBytes(t *testing.T, payload string) []byte {
	t.Helper()
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	if _, err := z.Write([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}
func TestBodyLimitsAfterDecompression(t *testing.T) {
	huge := `{"data":{"unused":"` + strings.Repeat("x", maxResponseBytes) + `"}}`
	for _, tt := range []struct {
		name, body, encoding string
		want                 error
	}{{"plain huge", huge, "", inquiry.ErrNarrowQueryRequired}, {"compressed huge", string(gzipBytes(t, huge)), "gzip", inquiry.ErrNarrowQueryRequired}, {"compressed valid", string(gzipBytes(t, settingsJSON)), "gzip", nil}, {"invalid gzip", "not gzip", "gzip", inquiry.ErrDataInvalid}, {"unsupported encoding", settingsJSON, "br", inquiry.ErrDataInvalid}, {"invalid JSON", "{", "", inquiry.ErrDataInvalid}, {"extra object", `{} {}`, "", inquiry.ErrDataInvalid}} {
		t.Run(tt.name, func(t *testing.T) {
			c, _ := newClient(tokenFunc(fixtureToken), &quotaStub{}, rtFunc(func(*http.Request) (*http.Response, error) {
				r := response(200, tt.body)
				if tt.encoding != "" {
					r.Header.Set("Content-Encoding", tt.encoding)
				}
				return r, nil
			}))
			var out responseDTO
			err := c.get(context.Background(), scope(), plansPath, nil, &out)
			if !errors.Is(err, tt.want) {
				t.Fatalf("got %v want %v", err, tt.want)
			}
		})
	}
}
func TestRetryAfterBounded(t *testing.T) {
	now := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	for _, tt := range []struct {
		value string
		want  time.Duration
	}{{"", time.Hour}, {"invalid", time.Hour}, {"0", time.Hour}, {"-1", time.Hour}, {"60", time.Minute}, {"99999999999", 24 * time.Hour}, {now.Add(2 * time.Hour).Format(http.TimeFormat), 2 * time.Hour}, {now.Add(-time.Minute).Format(http.TimeFormat), time.Hour}} {
		if got := retryDelay(tt.value, now); got != tt.want {
			t.Fatalf("retry %q %v want %v", tt.value, got, tt.want)
		}
	}
}

type trackedBody struct {
	io.Reader
	closed bool
}

func (b *trackedBody) Close() error { b.closed = true; return nil }
func TestBodyClosedOnAllResponses(t *testing.T) {
	for _, code := range []int{200, 302, 401, 403, 404, 429, 500} {
		body := &trackedBody{Reader: strings.NewReader(settingsJSON)}
		c, _ := newClient(tokenFunc(fixtureToken), &quotaStub{}, rtFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: code, Body: body, Header: make(http.Header)}, nil
		}))
		var out responseDTO
		_ = c.get(context.Background(), scope(), plansPath, url.Values{}, &out)
		if !body.closed {
			t.Fatalf("body not closed status %d", code)
		}
	}
}

func TestLifecycleErrorsAreMappedWithoutUpstreamCalls(t *testing.T) {
	for _, tt := range []struct{ from, want error }{{connection.ErrReconnectRequired, inquiry.ErrReconnectRequired}, {access.ErrUnauthorized, inquiry.ErrUnauthorizedScope}, {connection.ErrNotActive, inquiry.ErrUnauthorizedScope}} {
		q := &quotaStub{}
		c, _ := newClient(tokenFunc(func(context.Context, access.ReadScope) (string, error) { return "", tt.from }), q, rtFunc(func(*http.Request) (*http.Response, error) { t.Fatal("unexpected upstream"); return nil, nil }))
		var out responseDTO
		if err := c.get(context.Background(), scope(), plansPath, nil, &out); !errors.Is(err, tt.want) || q.calls.Load() != 0 {
			t.Fatal("incorrect lifecycle normalization", err)
		}
	}
}
