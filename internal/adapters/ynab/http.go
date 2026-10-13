// Package ynab is the anti-corruption adapter for the fixed YNAB read API.
// It deliberately contains no write route or public base-URL override.
package ynab

import (
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
)

const (
	apiOrigin        = "https://api.ynab.com"
	plansPath        = "/v1/plans"
	maxResponseBytes = 8 << 20
	requestTimeout   = 15 * time.Second
)

// TokenProvider is internal infrastructure. The application's read port never
// carries a bearer token. Implementations must return only committed credentials.
type TokenProvider interface {
	AccessToken(context.Context, access.ReadScope) (string, error)
}

// QuotaReserver must be backed by durable, atomic admission in production. There
// is intentionally no default implementation or in-memory production fallback.
// Reservations are conservative: an attempted GET is never refunded.
type QuotaReserver interface {
	Reserve(context.Context, access.ReadScope) error
	RecordCooldown(context.Context, access.ReadScope, time.Time) error
}

type Client struct {
	http   *http.Client
	tokens TokenProvider
	quota  QuotaReserver
	now    func() time.Time
}

func New(tokens TokenProvider, quota QuotaReserver) (*Client, error) {
	// Do not inherit process-global transports, proxy configuration, cookies,
	// redirect behavior, or credentials. Only this fixed-origin transport is used.
	transport := &http.Transport{
		Proxy:           nil,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		// Reused-connection and HTTP/2 transparent retries would bypass the
		// per-attempt reservation. Keep each reserved GET to one fresh HTTP/1 exchange.
		ForceAttemptHTTP2: false, DisableKeepAlives: true,
		TLSNextProto: make(map[string]func(string, *tls.Conn) http.RoundTripper),
		MaxIdleConns: 8, MaxIdleConnsPerHost: 4, MaxConnsPerHost: 4,
		IdleConnTimeout: 90 * time.Second, TLSHandshakeTimeout: 5 * time.Second,
		ResponseHeaderTimeout: 10 * time.Second,
	}
	return newClient(tokens, quota, transport)
}

// newClient is intentionally private. Synthetic tests inject a RoundTripper;
// production callers cannot supply an arbitrary upstream URL or HTTP client.
func newClient(tokens TokenProvider, quota QuotaReserver, rt http.RoundTripper) (*Client, error) {
	if tokens == nil || quota == nil || rt == nil {
		return nil, errors.New("YNAB token provider and durable quota admission are required")
	}
	return &Client{tokens: tokens, quota: quota, now: time.Now, http: &http.Client{
		Transport: guardTransport{next: rt}, Timeout: requestTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("upstream redirect denied") },
	}}, nil
}

type guardTransport struct{ next http.RoundTripper }

func (g guardTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r == nil || r.URL == nil || r.Method != http.MethodGet || r.URL.Scheme != "https" || r.URL.Host != "api.ynab.com" || r.URL.User != nil || r.URL.Opaque != "" || r.URL.Fragment != "" || (r.Host != "" && r.Host != "api.ynab.com") || r.URL.RawPath != "" || path.Clean(r.URL.Path) != r.URL.Path || !(r.URL.Path == plansPath || strings.HasPrefix(r.URL.Path, plansPath+"/")) {
		return nil, errors.New("upstream request denied")
	}
	return g.next.RoundTrip(r)
}

// get makes exactly one reserved GET. There are no automatic HTTP retries at
// application level, no OAuth exchanges, and no legacy-path fallback.
func (c *Client) get(ctx context.Context, scope access.ReadScope, route string, query url.Values, out any) error {
	if ctx.Err() != nil {
		return unavailable()
	}
	token, err := c.tokens.AccessToken(ctx, scope)
	if err != nil {
		if errors.Is(err, reconnect()) {
			return reconnect()
		}
		return unavailable()
	}
	if token == "" || strings.ContainsAny(token, "\r\n") {
		return reconnect()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, apiOrigin+route, nil)
	if err != nil {
		return dataInvalid()
	}
	req.URL.RawQuery = query.Encode()
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	// Explicit encoding makes decompressed-size enforcement independent of the
	// injected transport and the standard transport's transparent gzip handling.
	req.Header.Set("Accept-Encoding", "gzip")
	if err = c.quota.Reserve(ctx, scope); err != nil {
		return quotaDenied(err)
	}
	if ctx.Err() != nil {
		return unavailable()
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return unavailable()
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusUnauthorized:
		return reconnect()
	case resp.StatusCode == http.StatusForbidden:
		return unauthorized()
	case resp.StatusCode == http.StatusNotFound:
		return notFound()
	case resp.StatusCode == http.StatusTooManyRequests:
		until := c.now().UTC().Add(retryDelay(resp.Header.Get("Retry-After"), c.now().UTC()))
		if c.quota.RecordCooldown(ctx, scope, until) != nil {
			return unavailable()
		}
		return rateLimited()
	case resp.StatusCode != http.StatusOK:
		return unavailable()
	}
	var reader io.Reader = resp.Body
	switch strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding"))) {
	case "", "identity":
	case "gzip":
		zr, err := gzip.NewReader(resp.Body)
		if err != nil {
			return dataInvalid()
		}
		defer zr.Close()
		reader = zr
	default:
		return dataInvalid()
	}
	b, err := io.ReadAll(io.LimitReader(reader, maxResponseBytes+1))
	if err != nil {
		if ctx.Err() != nil {
			return unavailable()
		}
		return dataInvalid()
	}
	if len(b) > maxResponseBytes {
		return narrowQuery()
	}
	if ctx.Err() != nil {
		return unavailable()
	}
	// Decode into explicit DTO fields only. Unrecognized fields stay behind the
	// adapter boundary, including import identifiers and bank-statement payees.
	if len(b) == 0 || json.Unmarshal(b, out) != nil {
		return dataInvalid()
	}
	return nil
}

func retryDelay(v string, now time.Time) time.Duration {
	const fallback = time.Hour
	if n, err := strconv.ParseInt(v, 10, 64); err == nil {
		if n <= 0 {
			return fallback
		}
		if n > 24*60*60 {
			return 24 * time.Hour
		}
		return time.Duration(n) * time.Second
	}
	if t, err := http.ParseTime(v); err == nil && t.After(now) {
		d := t.Sub(now)
		if d > 24*time.Hour {
			return 24 * time.Hour
		}
		return d
	}
	return fallback
}
