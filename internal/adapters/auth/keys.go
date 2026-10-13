package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// StaticKeyProvider is useful for an administratively installed public JWKS or
// synthetic tests. It accepts no symmetric or private signing material.
type StaticKeyProvider struct{ keys map[string]jose.JSONWebKey }

func NewStaticKeyProvider(keys []jose.JSONWebKey) (*StaticKeyProvider, error) {
	if len(keys) == 0 || len(keys) > 64 {
		return nil, errors.New("a bounded set of public verification keys is required")
	}
	copyKeys := make(map[string]jose.JSONWebKey, len(keys))
	for _, key := range keys {
		if !validPublicKey(key) || copyKeys[key.KeyID].Key != nil {
			return nil, errors.New("invalid or duplicate public verification key")
		}
		// Own a separate public-key value; later edits to the caller's slice or
		// RSA/EC key cannot silently change the trust boundary.
		data, err := json.Marshal(key)
		if err != nil {
			return nil, errors.New("invalid public verification key")
		}
		var cloned jose.JSONWebKey
		if json.Unmarshal(data, &cloned) != nil {
			return nil, errors.New("invalid public verification key")
		}
		copyKeys[key.KeyID] = cloned
	}
	return &StaticKeyProvider{keys: copyKeys}, nil
}

func (p *StaticKeyProvider) VerificationKey(ctx context.Context, kid string, alg jose.SignatureAlgorithm) (jose.JSONWebKey, error) {
	if ctx.Err() != nil {
		return jose.JSONWebKey{}, ErrKeyUnavailable
	}
	key, ok := p.keys[kid]
	if !ok || !usableKey(key, kid, alg) {
		return jose.JSONWebKey{}, ErrKeyUnavailable
	}
	return key, nil
}

type JWKSConfig struct {
	// URL is a pinned, administratively configured HTTPS URL, not discovery
	// derived from a bearer token. Redirects are always refused.
	URL              string
	HTTPClient       *http.Client
	CacheTTL         time.Duration
	RefreshInterval  time.Duration
	FetchTimeout     time.Duration
	MaxResponseBytes int64
	MaxKeys          int
	Now              func() time.Time
}

type JWKSProvider struct {
	config      JWKSConfig
	client      http.Client
	mu          sync.Mutex
	keys        map[string]jose.JSONWebKey
	expiresAt   time.Time
	lastAttempt time.Time
	attempted   bool
	refreshing  chan struct{}
}

func NewJWKSProvider(config JWKSConfig) (*JWKSProvider, error) {
	if !validHTTPSURL(config.URL) {
		return nil, errors.New("a pinned HTTPS JWKS URL is required")
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = 5 * time.Minute
	}
	if config.RefreshInterval == 0 {
		config.RefreshInterval = 30 * time.Second
	}
	if config.FetchTimeout == 0 {
		config.FetchTimeout = 5 * time.Second
	}
	if config.MaxResponseBytes == 0 {
		config.MaxResponseBytes = 1 << 20
	}
	if config.MaxKeys == 0 {
		config.MaxKeys = 64
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.CacheTTL < time.Second || config.CacheTTL > time.Hour || config.RefreshInterval < time.Second || config.RefreshInterval > config.CacheTTL || config.FetchTimeout <= 0 || config.FetchTimeout > 10*time.Second || config.MaxResponseBytes < 1024 || config.MaxResponseBytes > 1<<20 || config.MaxKeys < 1 || config.MaxKeys > 64 {
		return nil, errors.New("invalid JWKS retrieval limits")
	}
	client := http.Client{}
	if config.HTTPClient != nil {
		client = *config.HTTPClient
	}
	// Public key retrieval never needs ambient browser/session cookies.
	client.Jar = nil
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client.Timeout == 0 || client.Timeout > config.FetchTimeout {
		client.Timeout = config.FetchTimeout
	}
	return &JWKSProvider{config: config, client: client, keys: make(map[string]jose.JSONWebKey)}, nil
}

// VerificationKey coalesces refreshes. An unknown kid can cause at most one
// bounded refresh per interval; random kid traffic cannot turn into unbounded
// issuer traffic or an unbounded negative-key cache. Expired cache entries are
// never used when an issuer is unavailable.
func (p *JWKSProvider) VerificationKey(ctx context.Context, kid string, alg jose.SignatureAlgorithm) (jose.JSONWebKey, error) {
	if ctx.Err() != nil || kid == "" || len(kid) > 256 || !supportedAlgorithm(alg) {
		return jose.JSONWebKey{}, ErrKeyUnavailable
	}
	p.mu.Lock()
	now := p.config.Now()
	if key, ok := p.cached(kid, alg, now); ok {
		p.mu.Unlock()
		return key, nil
	}
	if pending := p.refreshing; pending != nil {
		p.mu.Unlock()
		select {
		case <-ctx.Done():
			return jose.JSONWebKey{}, ErrKeyUnavailable
		case <-pending:
		}
		p.mu.Lock()
		key, ok := p.cached(kid, alg, p.config.Now())
		p.mu.Unlock()
		if ok {
			return key, nil
		}
		return jose.JSONWebKey{}, ErrKeyUnavailable
	}
	// A backward clock jump cannot remove the refresh throttle.
	if p.attempted && now.Sub(p.lastAttempt) < p.config.RefreshInterval {
		p.mu.Unlock()
		return jose.JSONWebKey{}, ErrKeyUnavailable
	}
	p.lastAttempt, p.attempted = now, true
	p.refreshing = make(chan struct{})
	p.mu.Unlock()
	keys, err := p.fetch(ctx)
	p.mu.Lock()
	if err == nil {
		p.keys, p.expiresAt = keys, p.config.Now().Add(p.config.CacheTTL)
	}
	close(p.refreshing)
	p.refreshing = nil
	key, ok := p.cached(kid, alg, p.config.Now())
	p.mu.Unlock()
	if err != nil || !ok {
		return jose.JSONWebKey{}, ErrKeyUnavailable
	}
	return key, nil
}

// cached requires p.mu to be held.
func (p *JWKSProvider) cached(kid string, alg jose.SignatureAlgorithm, now time.Time) (jose.JSONWebKey, bool) {
	key, ok := p.keys[kid]
	return key, ok && now.Before(p.expiresAt) && usableKey(key, kid, alg)
}

func (p *JWKSProvider) fetch(parent context.Context) (map[string]jose.JSONWebKey, error) {
	ctx, cancel := context.WithTimeout(parent, p.config.FetchTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.config.URL, nil)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	req.Header.Set("Accept", "application/jwk-set+json, application/json")
	response, err := p.client.Do(req)
	if err != nil {
		return nil, ErrKeyUnavailable
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength > p.config.MaxResponseBytes {
		return nil, ErrKeyUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, p.config.MaxResponseBytes+1))
	if err != nil || int64(len(data)) > p.config.MaxResponseBytes {
		return nil, ErrKeyUnavailable
	}
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if json.Unmarshal(data, &set) != nil || len(set.Keys) == 0 || len(set.Keys) > p.config.MaxKeys {
		return nil, ErrKeyUnavailable
	}
	keys := make(map[string]jose.JSONWebKey, len(set.Keys))
	for _, raw := range set.Keys {
		var key jose.JSONWebKey
		var policy struct {
			KeyOps *[]string `json:"key_ops"`
		}
		if json.Unmarshal(raw, &key) != nil || json.Unmarshal(raw, &policy) != nil {
			return nil, ErrKeyUnavailable
		}
		if key.Use != "" && key.Use != "sig" {
			continue
		}
		if policy.KeyOps != nil {
			verify := false
			for _, op := range *policy.KeyOps {
				if op == "verify" {
					verify = true
				}
			}
			if !verify {
				continue
			}
		}
		if !validPublicKey(key) {
			return nil, ErrKeyUnavailable
		}
		if _, duplicate := keys[key.KeyID]; duplicate {
			return nil, ErrKeyUnavailable
		}
		keys[key.KeyID] = key
	}
	if len(keys) == 0 {
		return nil, ErrKeyUnavailable
	}
	return keys, nil
}

func validPublicKey(key jose.JSONWebKey) bool {
	if key.KeyID == "" || len(key.KeyID) > 256 || !publicKeyMaterialValid(key) || (key.Use != "" && key.Use != "sig") {
		return false
	}
	if key.Algorithm != "" {
		return usableKey(key, key.KeyID, jose.SignatureAlgorithm(key.Algorithm))
	}
	return true
}

func usableKey(key jose.JSONWebKey, kid string, alg jose.SignatureAlgorithm) bool {
	if !supportedAlgorithm(alg) || !publicKeyMaterialValid(key) || key.KeyID != kid || (key.Use != "" && key.Use != "sig") || (key.Algorithm != "" && key.Algorithm != string(alg)) {
		return false
	}
	switch k := key.Key.(type) {
	case *rsa.PublicKey:
		return k.N != nil && k.N.BitLen() >= 2048 && k.E >= 65537 && k.E%2 == 1 && (alg == jose.RS256 || alg == jose.RS384 || alg == jose.RS512 || alg == jose.PS256 || alg == jose.PS384 || alg == jose.PS512)
	case *ecdsa.PublicKey:
		return alg == jose.ES256 && k.Curve == elliptic.P256()
	case ed25519.PublicKey:
		return alg == jose.EdDSA && len(k) == ed25519.PublicKeySize
	default:
		return false
	}
}

// Check shape before library methods: callers of the injected provider can
// accidentally supply a typed nil interface. Verification itself remains JOSE.
func publicKeyMaterialValid(key jose.JSONWebKey) bool {
	switch k := key.Key.(type) {
	case *rsa.PublicKey:
		return k != nil && k.N != nil && k.N.Sign() > 0 && k.N.BitLen() >= 2048 && k.E >= 65537 && k.E%2 == 1
	case *ecdsa.PublicKey:
		return k != nil && k.Curve == elliptic.P256() && k.X != nil && k.Y != nil && k.Curve.IsOnCurve(k.X, k.Y)
	case ed25519.PublicKey:
		return len(k) == ed25519.PublicKeySize
	default:
		return false
	}
}
