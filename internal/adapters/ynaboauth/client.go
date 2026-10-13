package ynaboauth

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"golang.org/x/oauth2"

	"github.com/guygrigsby/ynab-mcp/internal/application/credentials"
)

const (
	authorizeURL = "https://app.ynab.com/oauth/authorize"
	tokenURL     = "https://app.ynab.com/oauth/token"
	readOnly     = "read-only"
	requestLimit = 15 * time.Second
	maxSecret    = 8192
)

var (
	ErrInvalidConfiguration = errors.New("invalid YNAB OAuth configuration")
	ErrInvalidInput         = errors.New("invalid YNAB OAuth input")
	ErrInvalidResponse      = errors.New("invalid YNAB OAuth response")
	ErrScopeMismatch        = errors.New("YNAB OAuth read-only scope required")
	ErrTokenRequestFailed   = errors.New("YNAB OAuth token request failed")
	ErrReconnectRequired    = errors.New("YNAB OAuth reconnect required")
)

// Credentials remains an alias for source compatibility. The application owns
// the opaque complete bundle and its narrowly named persistence/OAuth exports.
type Credentials = credentials.CompleteBundle

var _ credentials.OAuth = (*Client)(nil)

// Client owns separate credential HTTP configuration. Its configuration, HTTP
// client and endpoints cannot be changed through MCP or exported options.
type Client struct {
	config *oauth2.Config
	http   *http.Client
	now    func() time.Time
}

func (Client) String() string   { return "[redacted YNAB OAuth client]" }
func (Client) GoString() string { return "[redacted YNAB OAuth client]" }
func (Client) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("[redacted YNAB OAuth client]"))
}
func (Client) LogValue() slog.Value { return slog.StringValue("[redacted YNAB OAuth client]") }

// New constructs a fixed-host OAuth client. The client secret must be supplied
// by an approved protected-secret boundary, never a tool argument. The HTTPS
// callback is trusted configuration and must exactly match its registration.
func New(clientID, clientSecret, callback string) (*Client, error) {
	transport := &http.Transport{
		Proxy:                  nil,
		DialContext:            (&net.Dialer{Timeout: 5 * time.Second}).DialContext,
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
		TLSHandshakeTimeout:    5 * time.Second,
		ResponseHeaderTimeout:  10 * time.Second,
		MaxResponseHeaderBytes: 8192,
		DisableKeepAlives:      true,
		ForceAttemptHTTP2:      false,
		// Avoid HTTP/2 stream replay and reuse-related retries of credential
		// requests. No application retry exists above this transport either.
		TLSNextProto: map[string]func(string, *tls.Conn) http.RoundTripper{},
	}
	return newClient(clientID, clientSecret, callback, transport, time.Now)
}

// Test transport injection is intentionally private; production callers cannot
// replace the upstream destination or credential transport.
func newClient(clientID, clientSecret, callback string, base http.RoundTripper, now func() time.Time) (*Client, error) {
	if !visibleASCII(clientID, 1024) || !visibleASCII(clientSecret, maxSecret) || !validCallback(callback) || base == nil || now == nil {
		return nil, ErrInvalidConfiguration
	}
	return &Client{
		config: &oauth2.Config{
			ClientID: clientID, ClientSecret: clientSecret, RedirectURL: callback,
			Scopes: []string{readOnly},
			Endpoint: oauth2.Endpoint{
				AuthURL: authorizeURL, TokenURL: tokenURL,
				// Explicitly required: autodetection retries failed requests.
				AuthStyle: oauth2.AuthStyleInParams,
			},
		},
		http: &http.Client{
			Transport: &credentialTransport{base: base},
			Timeout:   requestLimit,
			CheckRedirect: func(*http.Request, []*http.Request) error {
				return ErrTokenRequestFailed
			},
		},
		now: now,
	}, nil
}

// AuthorizationURL requests only read-only scope with S256 PKCE. State must be
// freshly random, expiring and owner-session-bound; syntax validation cannot
// establish those properties. The caller owns that single-use state store.
func (c *Client) AuthorizationURL(state, verifier string) (string, error) {
	if !c.ready() || !unreserved(state, 32, 512) || !unreserved(verifier, 43, 128) {
		return "", ErrInvalidInput
	}
	return c.config.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), nil
}

// Exchange makes one token request. The caller must first validate and consume
// the owner-bound state, validate the callback, and provide its saved verifier.
// The flow must have begun with this client's read-only AuthorizationURL; do not
// accept a code from a separately initiated or broader-scope authorization.
// This method does not itself make an unchecked callback safe to accept.
func (c *Client) Exchange(ctx context.Context, code, verifier string) (*Credentials, error) {
	if !c.ready() || ctx == nil || !visibleASCII(code, 4096) || !unreserved(verifier, 43, 128) {
		return nil, ErrInvalidInput
	}
	ctx, cancel := c.requestContext(ctx)
	defer cancel()
	started := c.now().UTC()
	token, err := c.config.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, sanitizedError(err)
	}
	return c.credentials(token, started)
}

// Refresh makes one explicit refresh attempt under the caller's durable
// per-connection coordinator. It never returns or caches a TokenSource. Every
// failure after calling the token endpoint is conservatively reconnect-required:
// even a timeout can follow successful upstream rotation. Do not retry the old
// refresh token, or publish the result before protected persistence and CAS.
func (c *Client) Refresh(ctx context.Context, current *Credentials) (*Credentials, error) {
	if !c.ready() || ctx == nil || current == nil || current.Validate() != nil {
		return nil, ErrInvalidInput
	}
	ctx, cancel := c.requestContext(ctx)
	defer cancel()
	started := c.now().UTC()
	// An empty access token forces one refresh even if the prior access token
	// is still valid. This one-shot source is immediately discarded.
	token, err := c.config.TokenSource(ctx, &oauth2.Token{RefreshToken: current.ExportRefreshTokenForOAuth()}).Token()
	if err != nil {
		return nil, ErrReconnectRequired
	}
	credentials, err := c.credentials(token, started)
	if err != nil {
		return nil, ErrReconnectRequired
	}
	return credentials, nil
}

func (c *Client) ready() bool {
	return c != nil && c.config != nil && c.http != nil && c.now != nil
}

func (c *Client) requestContext(ctx context.Context) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithTimeout(ctx, requestLimit)
	// Never inherit an arbitrary caller-provided oauth2 HTTP client.
	return context.WithValue(ctx, oauth2.HTTPClient, c.http), cancel
}

func (c *Client) credentials(token *oauth2.Token, started time.Time) (*Credentials, error) {
	if token == nil || !visibleASCII(token.AccessToken, maxSecret) || !visibleASCII(token.RefreshToken, maxSecret) || !strings.EqualFold(token.TokenType, "bearer") || token.ExpiresIn < 1 || token.ExpiresIn > maxLifetimeSeconds {
		return nil, ErrInvalidResponse
	}
	expiresAt := started.Add(time.Duration(token.ExpiresIn) * time.Second)
	if !c.now().Before(expiresAt) {
		return nil, ErrInvalidResponse
	}
	bundle, err := credentials.NewOAuthBundle(token.AccessToken, token.RefreshToken, expiresAt, credentials.ReadOnlyScope)
	if err != nil {
		return nil, ErrInvalidResponse
	}
	return &bundle, nil
}

func sanitizedError(err error) error {
	for _, safe := range []error{ErrInvalidResponse, ErrScopeMismatch, ErrReconnectRequired} {
		if errors.Is(err, safe) {
			return safe
		}
	}
	// Do not wrap oauth2.RetrieveError or URL/transport errors: they may hold
	// request credentials, response tokens, or hostile upstream error text.
	return ErrTokenRequestFailed
}

func validCallback(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 2048 || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" {
		return false
	}
	return u.String() == raw
}

func visibleASCII(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for i := range value {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

func unreserved(value string, min, max int) bool {
	if len(value) < min || len(value) > max {
		return false
	}
	for i := range value {
		b := value[i]
		if !(b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z' || b >= '0' && b <= '9' || strings.ContainsRune("-._~", rune(b))) {
			return false
		}
	}
	return true
}
