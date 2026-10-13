package auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const testIssuer = "https://issuer.example.test/"
const testResource = "https://budget.example.test/mcp"

var testNow = time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)

func testSigningKey(t testing.TB, kid string) (jose.JSONWebKey, ed25519.PrivateKey) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return jose.JSONWebKey{Key: public, KeyID: kid, Algorithm: string(jose.EdDSA), Use: "sig"}, private
}

func testClaims() map[string]any {
	return map[string]any{"iss": testIssuer, "sub": "synthetic-owner", "aud": testResource, "exp": testNow.Add(time.Hour).Unix(), "iat": testNow.Add(-time.Minute).Unix(), "nbf": testNow.Add(-time.Minute).Unix(), "scope": RequiredScope, "tenant": "synthetic-tenant"}
}

func signedToken(t testing.TB, key any, alg jose.SignatureAlgorithm, kid, typ string, claims map[string]any, extra map[jose.HeaderKey]any) string {
	t.Helper()
	options := (&jose.SignerOptions{}).WithType(jose.ContentType(typ)).WithHeader("kid", kid)
	for name, value := range extra {
		options.WithHeader(name, value)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, options)
	if err != nil {
		t.Fatal(err)
	}
	token, err := jwt.Signed(signer).Claims(claims).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return token
}

func testVerifier(t testing.TB, keys ...jose.JSONWebKey) *Verifier {
	t.Helper()
	provider, err := NewStaticKeyProvider(keys)
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewVerifier(Config{Issuer: testIssuer, Resource: testResource, Algorithms: []jose.SignatureAlgorithm{jose.EdDSA}, TenantClaim: "tenant", Now: func() time.Time { return testNow }}, provider)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestVerifyAccessToken(t *testing.T) {
	key, private := testSigningKey(t, "key-1")
	v := testVerifier(t, key)
	for _, typ := range []string{"at+jwt", "application/at+jwt"} {
		p, err := v.Verify(context.Background(), signedToken(t, private, jose.EdDSA, key.KeyID, typ, testClaims(), nil))
		if err != nil {
			t.Fatal(err)
		}
		if p.Key.Issuer != testIssuer || p.Key.Subject != "synthetic-owner" || p.Key.Tenant != "synthetic-tenant" || !p.HasScope(RequiredScope) || !p.ExpiresAt.Equal(testNow.Add(time.Hour)) {
			t.Fatalf("unexpected principal: %#v", p)
		}
	}
}

func TestRejectInvalidAccessTokens(t *testing.T) {
	key, private := testSigningKey(t, "key-1")
	_, wrongPrivate := testSigningKey(t, "key-1")
	v := testVerifier(t, key)
	cases := []struct {
		name     string
		edit     func(map[string]any)
		typ, kid string
		key      any
		alg      jose.SignatureAlgorithm
		extra    map[jose.HeaderKey]any
		want     error
	}{
		{name: "wrong issuer", edit: func(c map[string]any) { c["iss"] = "https://untrusted.example.test/" }},
		{name: "wrong audience", edit: func(c map[string]any) { c["aud"] = "https://other.example.test/mcp" }},
		{name: "audience prefix", edit: func(c map[string]any) { c["aud"] = testResource + "/evil" }},
		{name: "missing audience", edit: func(c map[string]any) { delete(c, "aud") }},
		{name: "expired", edit: func(c map[string]any) { c["exp"] = testNow.Add(-time.Second).Unix() }},
		{name: "expiry exact boundary", edit: func(c map[string]any) { c["exp"] = testNow.Unix() }},
		{name: "missing expiry", edit: func(c map[string]any) { delete(c, "exp") }},
		{name: "null expiry", edit: func(c map[string]any) { c["exp"] = nil }},
		{name: "numeric date overflow", edit: func(c map[string]any) { c["nbf"] = 1e100 }},
		{name: "future nbf", edit: func(c map[string]any) { c["nbf"] = testNow.Add(time.Second).Unix() }},
		{name: "future issued at", edit: func(c map[string]any) { c["iat"] = testNow.Add(time.Second).Unix() }},
		{name: "empty subject", edit: func(c map[string]any) { c["sub"] = "" }},
		{name: "missing subject", edit: func(c map[string]any) { delete(c, "sub") }},
		{name: "missing tenant", edit: func(c map[string]any) { delete(c, "tenant") }},
		{name: "non-string tenant", edit: func(c map[string]any) { c["tenant"] = 7 }},
		{name: "missing scope", edit: func(c map[string]any) { delete(c, "scope") }, want: ErrInsufficientScope},
		{name: "scope prefix", edit: func(c map[string]any) { c["scope"] = RequiredScope + ":write" }, want: ErrInsufficientScope},
		{name: "scope tab", edit: func(c map[string]any) { c["scope"] = "other\t" + RequiredScope }},
		{name: "scope empty token", edit: func(c map[string]any) { c["scope"] = "other  " + RequiredScope }},
		{name: "scope array", edit: func(c map[string]any) { c["scope"] = []string{RequiredScope} }},
		{name: "ID token", typ: "JWT"},
		{name: "untyped token", typ: "missing"},
		{name: "unknown kid", kid: "unknown"},
		{name: "wrong signature", key: wrongPrivate},
		{name: "wrong algorithm", key: []byte(strings.Repeat("x", 32)), alg: jose.HS256},
		{name: "untrusted key URL", extra: map[jose.HeaderKey]any{"jku": "https://attacker.example.test/keys"}},
		{name: "untrusted certificate URL", extra: map[jose.HeaderKey]any{"x5u": "https://attacker.example.test/cert"}},
		{name: "subject controls", edit: func(c map[string]any) { c["sub"] = "owner\nname" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := testClaims()
			if tc.edit != nil {
				tc.edit(claims)
			}
			typ := tc.typ
			if typ == "" {
				typ = "at+jwt"
			}
			kid := tc.kid
			if kid == "" {
				kid = key.KeyID
			}
			signerKey := tc.key
			if signerKey == nil {
				signerKey = private
			}
			alg := tc.alg
			if alg == "" {
				alg = jose.EdDSA
			}
			token := signedToken(t, signerKey, alg, kid, typ, claims, tc.extra)
			_, err := v.Verify(context.Background(), token)
			want := tc.want
			if want == nil {
				want = ErrInvalidToken
			}
			if !errors.Is(err, want) {
				t.Fatalf("got %v, want %v", err, want)
			}
			if strings.Contains(err.Error(), token) || strings.Contains(err.Error(), "synthetic-owner") {
				t.Fatal("error contains token data")
			}
		})
	}
}

func TestMissingTypeAndEmbeddedKeyAreRejected(t *testing.T) {
	key, private := testSigningKey(t, "key-1")
	v := testVerifier(t, key)
	for _, options := range []*jose.SignerOptions{
		(&jose.SignerOptions{}).WithHeader("kid", key.KeyID),
		(&jose.SignerOptions{EmbedJWK: true}).WithType("at+jwt").WithHeader("kid", key.KeyID),
	} {
		signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: jose.JSONWebKey{Key: private, KeyID: key.KeyID}}, options)
		if err != nil {
			t.Fatal(err)
		}
		token, err := jwt.Signed(signer).Claims(testClaims()).Serialize()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := v.Verify(context.Background(), token); err != ErrInvalidToken {
			t.Fatalf("accepted confused token: %v", err)
		}
	}
}

func TestNoTenantIsExplicitAndAudienceArrayAllowed(t *testing.T) {
	key, private := testSigningKey(t, "key-1")
	provider, _ := NewStaticKeyProvider([]jose.JSONWebKey{key})
	v, err := NewVerifier(Config{Issuer: testIssuer, Resource: testResource, Algorithms: []jose.SignatureAlgorithm{jose.EdDSA}, Now: func() time.Time { return testNow }}, provider)
	if err != nil {
		t.Fatal(err)
	}
	claims := testClaims()
	claims["aud"] = []string{"https://other.example.test", testResource}
	p, err := v.Verify(context.Background(), signedToken(t, private, jose.EdDSA, key.KeyID, "at+jwt", claims, nil))
	if err != nil || p.Key.Tenant != "" {
		t.Fatalf("tenant absent policy failed: %#v, %v", p, err)
	}
}

func TestTokenLimitsAndCancellation(t *testing.T) {
	key, private := testSigningKey(t, "key-1")
	v := testVerifier(t, key)
	valid := signedToken(t, private, jose.EdDSA, key.KeyID, "at+jwt", testClaims(), nil)
	for _, raw := range []string{"", "opaque-token", "a.b.c.d", " " + valid, valid + "\n", strings.Repeat("x", 20000) + ".e.f"} {
		if _, err := v.Verify(context.Background(), raw); err != ErrInvalidToken {
			t.Fatalf("accepted malformed token: %v", err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := v.Verify(ctx, valid); err != ErrInvalidToken {
		t.Fatal("cancelled token verification succeeded")
	}
}

func TestVerifierConfigFailsClosed(t *testing.T) {
	key, _ := testSigningKey(t, "key-1")
	provider, _ := NewStaticKeyProvider([]jose.JSONWebKey{key})
	base := Config{Issuer: testIssuer, Resource: testResource, Algorithms: []jose.SignatureAlgorithm{jose.EdDSA}}
	cases := []Config{
		{}, {Issuer: "http://issuer.example.test", Resource: testResource, Algorithms: base.Algorithms},
		{Issuer: testIssuer, Resource: "https://budget.example.test/mcp#fragment", Algorithms: base.Algorithms},
		{Issuer: testIssuer, Resource: testResource, Algorithms: []jose.SignatureAlgorithm{jose.HS256}},
		{Issuer: testIssuer, Resource: testResource, Algorithms: []jose.SignatureAlgorithm{jose.EdDSA, jose.EdDSA}},
		{Issuer: testIssuer, Resource: testResource, Algorithms: base.Algorithms, ClockSkew: 2 * time.Minute},
		{Issuer: testIssuer, Resource: testResource, Algorithms: base.Algorithms, MaxTokenBytes: 1},
	}
	for _, config := range cases {
		if _, err := NewVerifier(config, provider); err == nil {
			t.Fatalf("accepted config %#v", config)
		}
	}
	if _, err := NewVerifier(base, nil); err == nil {
		t.Fatal("accepted missing key provider")
	}
}

func FuzzVerifierRejectsMalformedJWT(f *testing.F) {
	key, _ := testSigningKey(f, "key-1")
	v := testVerifier(f, key)
	f.Add("opaque")
	f.Add("eyJhbGciOiJFZERTQSJ9.e30.invalid")
	f.Fuzz(func(t *testing.T, raw string) { _, _ = v.Verify(context.Background(), raw) })
}
