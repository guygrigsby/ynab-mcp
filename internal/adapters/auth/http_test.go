package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
)

type verifierFunc func(context.Context, string) (access.Principal, error)

func (f verifierFunc) Verify(ctx context.Context, token string) (access.Principal, error) {
	return f(ctx, token)
}

func TestEveryMCPRequestRequiresAuthentication(t *testing.T) {
	key, private := testSigningKey(t, "key-1")
	middleware, err := NewMiddleware(MiddlewareConfig{Resource: testResource, Issuer: testIssuer}, testVerifier(t, key))
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	handler := middleware.Wrap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		p, ok := PrincipalFromContext(r.Context())
		if !ok || p.Key.Subject != "synthetic-owner" || !p.HasScope(RequiredScope) {
			t.Fatal("verified principal absent")
		}
		if r.Header.Get("Authorization") != "" {
			t.Fatal("bearer token reached application")
		}
		p.Scopes[0] = "changed"
		again, _ := PrincipalFromContext(r.Context())
		if !again.HasScope(RequiredScope) {
			t.Fatal("context principal scopes mutated")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	valid := signedToken(t, private, jose.EdDSA, key.KeyID, "at+jwt", testClaims(), nil)
	for _, method := range []string{http.MethodPost, http.MethodGet, http.MethodDelete, http.MethodOptions} {
		for _, body := range []string{`{"method":"initialize"}`, `{"method":"tools/list"}`, `{"method":"tools/call"}`} {
			req := httptest.NewRequest(method, testResource, strings.NewReader(body))
			req.Header.Set("Mcp-Session-Id", "old-session")
			denied := httptest.NewRecorder()
			handler.ServeHTTP(denied, req)
			if denied.Code != http.StatusUnauthorized {
				t.Fatalf("%s unauthenticated request returned %d", method, denied.Code)
			}
			req.Header.Set("Authorization", "Bearer "+valid)
			accepted := httptest.NewRecorder()
			handler.ServeHTTP(accepted, req)
			if accepted.Code != http.StatusNoContent {
				t.Fatalf("valid request returned %d: %s", accepted.Code, accepted.Body)
			}
			if req.Header.Get("Authorization") == "" {
				t.Fatal("middleware mutated original request")
			}
		}
	}
	if calls != 12 {
		t.Fatalf("denied request reached handler: %d", calls)
	}
}

func TestBearerFailuresAreSanitizedAndCanonical(t *testing.T) {
	verifier := verifierFunc(func(ctx context.Context, token string) (access.Principal, error) {
		if token == "no-scope" {
			return access.Principal{}, ErrInsufficientScope
		}
		return access.Principal{}, errors.New("SECRET-SHOULD-NOT-LEAK")
	})
	middleware, _ := NewMiddleware(MiddlewareConfig{Resource: testResource, Issuer: testIssuer}, verifier)
	calls := 0
	handler := middleware.Wrap(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls++ }))
	cases := []struct {
		name      string
		headers   []string
		query     string
		status    int
		challenge string
	}{
		{"missing", nil, "", 401, ""},
		{"invalid", []string{"Bearer secret-token"}, "", 401, "invalid_token"},
		{"wrong scheme", []string{"Basic secret-token"}, "", 401, "invalid_token"},
		{"multiple headers", []string{"Bearer one", "Bearer two"}, "", 401, "invalid_token"},
		{"multiple tokens", []string{"Bearer one two"}, "", 401, "invalid_token"},
		{"query token", []string{"Bearer good"}, "?access_token=secret-token", 400, "invalid_request"},
		{"insufficient scope", []string{"Bearer no-scope"}, "", 403, "insufficient_scope"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "https://attacker.example.test/mcp"+tc.query, nil)
			for _, header := range tc.headers {
				req.Header.Add("Authorization", header)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Code != tc.status {
				t.Fatalf("got %d, want %d", rec.Code, tc.status)
			}
			challenge := rec.Header().Get("WWW-Authenticate")
			if !strings.Contains(challenge, `resource_metadata="https://budget.example.test/.well-known/oauth-protected-resource/mcp"`) || !strings.Contains(challenge, `scope="budget:read"`) {
				t.Fatalf("wrong canonical challenge %s", challenge)
			}
			if tc.challenge != "" && !strings.Contains(challenge, `error="`+tc.challenge+`"`) {
				t.Fatalf("wrong error: %s", challenge)
			}
			if tc.challenge == "" && strings.Contains(challenge, "error=") {
				t.Fatal("missing bearer must not invent an invalid-token error")
			}
			for _, secret := range []string{"SECRET-SHOULD-NOT-LEAK", "secret-token", "attacker.example.test"} {
				if strings.Contains(rec.Body.String()+challenge, secret) {
					t.Fatalf("leaked %s", secret)
				}
			}
		})
	}
	if calls != 0 {
		t.Fatal("denied request reached handler")
	}
}

func TestProtectedResourceDiscovery(t *testing.T) {
	verifier := verifierFunc(func(context.Context, string) (access.Principal, error) {
		t.Fatal("discovery invoked authentication")
		return access.Principal{}, ErrInvalidToken
	})
	middleware, err := NewMiddleware(MiddlewareConfig{Resource: testResource, Issuer: testIssuer}, verifier)
	if err != nil {
		t.Fatal(err)
	}
	if middleware.MetadataPath() != "/.well-known/oauth-protected-resource/mcp" {
		t.Fatal(middleware.MetadataPath())
	}
	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
		rec := httptest.NewRecorder()
		middleware.MetadataHandler().ServeHTTP(rec, httptest.NewRequest(method, "https://attacker.example.test"+middleware.MetadataPath(), nil))
		if method == http.MethodPost {
			if rec.Code != 405 {
				t.Fatal(rec.Code)
			}
			continue
		}
		if rec.Code != 200 {
			t.Fatal(rec.Code)
		}
		if method == http.MethodHead {
			if rec.Body.Len() != 0 {
				t.Fatal("HEAD returned a body")
			}
			continue
		}
		var metadata struct {
			Resource string   `json:"resource"`
			Servers  []string `json:"authorization_servers"`
			Scopes   []string `json:"scopes_supported"`
			Methods  []string `json:"bearer_methods_supported"`
		}
		if json.Unmarshal(rec.Body.Bytes(), &metadata) != nil || metadata.Resource != testResource || len(metadata.Servers) != 1 || metadata.Servers[0] != testIssuer || len(metadata.Scopes) != 1 || metadata.Scopes[0] != RequiredScope || len(metadata.Methods) != 1 || metadata.Methods[0] != "header" {
			t.Fatalf("invalid discovery: %s", rec.Body)
		}
	}
	if _, ok := PrincipalFromContext(context.Background()); ok {
		t.Fatal("unverified principal exists")
	}
}
