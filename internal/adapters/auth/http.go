package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"

	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
)

type TokenVerifier interface {
	Verify(context.Context, string) (access.Principal, error)
}

type MiddlewareConfig struct {
	Resource string
	Issuer   string
}

type Middleware struct {
	verifier     TokenVerifier
	metadataURL  string
	metadataPath string
	metadata     []byte
}

type principalContextKey struct{}

// PrincipalFromContext returns a copy without retaining a bearer token. There
// is intentionally no exported setter with which an HTTP adapter can bypass
// verification. Scope slices are copied at the context boundary.
func PrincipalFromContext(ctx context.Context) (access.Principal, bool) {
	p, ok := ctx.Value(principalContextKey{}).(access.Principal)
	if !ok {
		return access.Principal{}, false
	}
	p.Scopes = append([]string(nil), p.Scopes...)
	return p, true
}

func NewMiddleware(config MiddlewareConfig, verifier TokenVerifier) (*Middleware, error) {
	if !validHTTPSURL(config.Resource) || !validHTTPSURL(config.Issuer) || verifier == nil {
		return nil, errors.New("canonical HTTPS resource, issuer and verifier are required")
	}
	resource, _ := url.Parse(config.Resource)
	metadataURL := *resource
	metadataURL.Path = "/.well-known/oauth-protected-resource" + resource.Path
	metadataURL.RawPath = ""
	metadata, err := json.Marshal(struct {
		Resource               string   `json:"resource"`
		AuthorizationServers   []string `json:"authorization_servers"`
		ScopesSupported        []string `json:"scopes_supported"`
		BearerMethodsSupported []string `json:"bearer_methods_supported"`
	}{Resource: config.Resource, AuthorizationServers: []string{config.Issuer}, ScopesSupported: []string{RequiredScope}, BearerMethodsSupported: []string{"header"}})
	if err != nil {
		return nil, errors.New("protected-resource metadata unavailable")
	}
	return &Middleware{verifier: verifier, metadataURL: metadataURL.String(), metadataPath: metadataURL.Path, metadata: metadata}, nil
}

func (m *Middleware) MetadataPath() string { return m.metadataPath }

// MetadataHandler exposes static, non-financial RFC 9728 discovery. It does
// not perform issuer discovery, fetch keys, or consume upstream financial quota.
func (m *Middleware) MetadataHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.Header().Set("Allow", "GET, HEAD")
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "public, max-age=300")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		if r.Method == http.MethodGet {
			_, _ = w.Write(m.metadata)
		}
	})
}

// Wrap authenticates every request reaching the MCP endpoint, including GET,
// DELETE, initialization and tool discovery. Session IDs provide no exemption.
func (m *Middleware) Wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if r.URL.Query().Has("access_token") {
			m.challenge(w, http.StatusBadRequest, "invalid_request")
			return
		}
		headers := r.Header.Values("Authorization")
		if len(headers) == 0 {
			m.challenge(w, http.StatusUnauthorized, "")
			return
		}
		if len(headers) != 1 {
			m.challenge(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		parts := strings.Split(headers[0], " ")
		if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
			m.challenge(w, http.StatusUnauthorized, "invalid_token")
			return
		}
		principal, err := m.verifier.Verify(r.Context(), parts[1])
		if err != nil {
			if errors.Is(err, ErrInsufficientScope) {
				m.challenge(w, http.StatusForbidden, "insufficient_scope")
			} else {
				m.challenge(w, http.StatusUnauthorized, "invalid_token")
			}
			return
		}
		principal.Scopes = append([]string(nil), principal.Scopes...)
		ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
		// Downstream handlers need the verified principal, never the original
		// bearer header. Remove it from the cloned request to reduce accidental
		// logging without modifying the caller's request.
		request := r.Clone(ctx)
		request.Header.Del("Authorization")
		next.ServeHTTP(w, request)
	})
}

func (m *Middleware) challenge(w http.ResponseWriter, status int, code string) {
	challenge := "Bearer resource_metadata=\"" + m.metadataURL + "\", scope=\"" + RequiredScope + "\""
	if code != "" {
		challenge += ", error=\"" + code + "\""
	}
	w.Header().Set("WWW-Authenticate", challenge)
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// No token, JWT claim, key URL, subject, or provider error is reflected.
	http.Error(w, http.StatusText(status), status)
}
