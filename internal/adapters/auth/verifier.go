// Package auth implements the inbound OAuth resource-server boundary. It never
// issues tokens or uses an OIDC ID-token verifier as an access-token verifier.
package auth

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
)

const RequiredScope = "budget:read"

var (
	ErrInvalidToken      = errors.New("invalid access token")
	ErrInsufficientScope = errors.New("insufficient scope")
	ErrKeyUnavailable    = errors.New("trusted verification key unavailable")
)

// KeyProvider returns only administratively trusted public keys. The algorithm
// and kid are selection hints, never destinations or sources of trust.
type KeyProvider interface {
	VerificationKey(context.Context, string, jose.SignatureAlgorithm) (jose.JSONWebKey, error)
}

type Config struct {
	Issuer     string
	Resource   string
	Algorithms []jose.SignatureAlgorithm
	// TenantClaim is a single configured claim name. Empty means the issuer's
	// identity has no tenant; an empty tenant never means "any tenant".
	TenantClaim   string
	ClockSkew     time.Duration
	MaxTokenBytes int
	Now           func() time.Time
}

type Verifier struct {
	config Config
	keys   KeyProvider
}

func NewVerifier(config Config, keys KeyProvider) (*Verifier, error) {
	if !validHTTPSURL(config.Issuer) || !validHTTPSURL(config.Resource) || keys == nil {
		return nil, errors.New("issuer, resource and trusted keys are required")
	}
	if len(config.Algorithms) == 0 || len(config.Algorithms) > 8 {
		return nil, errors.New("explicit signing algorithms are required")
	}
	seen := make(map[jose.SignatureAlgorithm]bool)
	for _, alg := range config.Algorithms {
		if !supportedAlgorithm(alg) || seen[alg] {
			return nil, errors.New("unsupported or duplicate signing algorithm")
		}
		seen[alg] = true
	}
	if config.ClockSkew < 0 || config.ClockSkew > time.Minute {
		return nil, errors.New("clock skew must be between zero and one minute")
	}
	if config.MaxTokenBytes == 0 {
		config.MaxTokenBytes = 16 << 10
	}
	if config.MaxTokenBytes < 256 || config.MaxTokenBytes > 64<<10 {
		return nil, errors.New("invalid access-token size limit")
	}
	if len(config.TenantClaim) > 128 || strings.ContainsAny(config.TenantClaim, " \t\r\n") {
		return nil, errors.New("invalid tenant claim name")
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	config.Algorithms = append([]jose.SignatureAlgorithm(nil), config.Algorithms...)
	return &Verifier{config: config, keys: keys}, nil
}

// Verify accepts compact, signed JWT access tokens only. The explicit at+jwt
// policy prevents ID-token confusion even if issuer, signing key and audience
// happen to overlap. Opaque tokens and providers without this access-token
// profile require a separately reviewed adapter; they are not guessed at here.
func (v *Verifier) Verify(ctx context.Context, raw string) (access.Principal, error) {
	var empty access.Principal
	if ctx.Err() != nil || len(raw) == 0 || len(raw) > v.config.MaxTokenBytes || strings.Count(raw, ".") != 2 || strings.ContainsAny(raw, " \t\r\n") {
		return empty, ErrInvalidToken
	}
	token, err := jwt.ParseSigned(raw, v.config.Algorithms)
	if err != nil || len(token.Headers) != 1 {
		return empty, ErrInvalidToken
	}
	header := token.Headers[0]
	typ, ok := header.ExtraHeaders[jose.HeaderType].(string)
	if !ok || (typ != "at+jwt" && typ != "application/at+jwt") || header.KeyID == "" || len(header.KeyID) > 256 {
		return empty, ErrInvalidToken
	}
	// Never trust embedded keys, key URLs, or certificate URLs. Refusing them
	// also prevents a future refactor from accidentally enabling key injection.
	if header.JSONWebKey != nil || header.ExtraHeaders["jku"] != nil || header.ExtraHeaders["x5u"] != nil {
		return empty, ErrInvalidToken
	}
	alg := jose.SignatureAlgorithm(header.Algorithm)
	key, err := v.keys.VerificationKey(ctx, header.KeyID, alg)
	if err != nil || !usableKey(key, header.KeyID, alg) {
		return empty, ErrInvalidToken
	}
	var claims struct {
		jwt.Claims
		Scope string `json:"scope"`
	}
	var allClaims map[string]any
	if err := token.Claims(key.Key, &claims, &allClaims); err != nil {
		return empty, ErrInvalidToken
	}
	now := v.config.Now()
	if claims.Expiry == nil || claims.Subject == "" || len(claims.Subject) > 1024 || claims.Issuer == "" || !now.Before(claims.Expiry.Time().Add(v.config.ClockSkew)) {
		return empty, ErrInvalidToken
	}
	if err := claims.ValidateWithLeeway(jwt.Expected{Issuer: v.config.Issuer, AnyAudience: jwt.Audience{v.config.Resource}, Time: now}, v.config.ClockSkew); err != nil {
		return empty, ErrInvalidToken
	}
	if claims.NotBefore != nil && !claims.NotBefore.Time().Before(claims.Expiry.Time()) {
		return empty, ErrInvalidToken
	}
	tenant := ""
	if v.config.TenantClaim != "" {
		tenant, ok = allClaims[v.config.TenantClaim].(string)
		if !ok || tenant == "" || len(tenant) > 1024 {
			return empty, ErrInvalidToken
		}
	}
	// RFC 6749 scope-token is printable ASCII excluding space, quote and
	// backslash. Do not turn tabs/newlines into accepted separators.
	scopes := strings.Split(claims.Scope, " ")
	if len(scopes) > 128 {
		return empty, ErrInvalidToken
	}
	seen := make(map[string]bool, len(scopes))
	for _, scope := range scopes {
		if scope == "" {
			if claims.Scope == "" {
				return empty, ErrInsufficientScope
			}
			return empty, ErrInvalidToken
		}
		for _, c := range scope {
			if c < 0x21 || c > 0x7e || c == '"' || c == '\\' {
				return empty, ErrInvalidToken
			}
		}
		seen[scope] = true
	}
	if !seen[RequiredScope] {
		return empty, ErrInsufficientScope
	}
	if ctx.Err() != nil {
		return empty, ErrInvalidToken
	}
	principalKey := access.PrincipalKey{Issuer: claims.Issuer, Subject: claims.Subject, Tenant: tenant}
	if principalKey.Validate() != nil {
		return empty, ErrInvalidToken
	}
	return access.Principal{Key: principalKey, Scopes: append([]string(nil), scopes...), ExpiresAt: claims.Expiry.Time()}, nil
}

func validHTTPSURL(raw string) bool {
	if len(raw) > 2048 {
		return false
	}
	u, err := url.Parse(raw)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.Hostname() != "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.Opaque == "" && !strings.ContainsAny(raw, "\r\n\t ")
}

func supportedAlgorithm(alg jose.SignatureAlgorithm) bool {
	switch alg {
	case jose.RS256, jose.RS384, jose.RS512, jose.PS256, jose.PS384, jose.PS512, jose.ES256, jose.EdDSA:
		return true
	default:
		return false
	}
}
