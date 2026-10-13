package auth

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

func TestJWKSCacheRotationUnknownKeyAndOutage(t *testing.T) {
	key1, _ := testSigningKey(t, "key-1")
	key2, _ := testSigningKey(t, "key-2")
	var seconds atomic.Int64
	seconds.Store(testNow.Unix())
	var calls atomic.Int64
	var outage atomic.Bool
	var served atomic.Value
	served.Store(key1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodGet || r.URL.Path != "/trusted-keys" || r.Header.Get("Authorization") != "" {
			t.Error("untrusted JWKS request")
		}
		if outage.Load() {
			http.Error(w, "synthetic private provider failure", 503)
			return
		}
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{served.Load().(jose.JSONWebKey)}})
	}))
	defer server.Close()
	provider, err := NewJWKSProvider(JWKSConfig{URL: server.URL + "/trusted-keys", HTTPClient: server.Client(), Now: func() time.Time { return time.Unix(seconds.Load(), 0) }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.VerificationKey(context.Background(), key1.KeyID, jose.EdDSA); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 50; i++ {
		if _, err := provider.VerificationKey(context.Background(), "unknown", jose.EdDSA); err != ErrKeyUnavailable {
			t.Fatal("accepted unknown key")
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("unknown key burst fetched %d times", calls.Load())
	}
	served.Store(key2)
	seconds.Add(30)
	var group sync.WaitGroup
	for i := 0; i < 32; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := provider.VerificationKey(context.Background(), key2.KeyID, jose.EdDSA); err != nil {
				t.Errorf("rotation failed: %v", err)
			}
		}()
	}
	group.Wait()
	if calls.Load() != 2 {
		t.Fatalf("rotation was not coalesced: %d", calls.Load())
	}
	if _, err := provider.VerificationKey(context.Background(), key1.KeyID, jose.EdDSA); err != ErrKeyUnavailable {
		t.Fatal("removed key remains usable")
	}
	outage.Store(true)
	if _, err := provider.VerificationKey(context.Background(), key2.KeyID, jose.EdDSA); err != nil {
		t.Fatal("still-valid cached trusted key should work")
	}
	seconds.Add(301)
	if _, err := provider.VerificationKey(context.Background(), key2.KeyID, jose.EdDSA); err != ErrKeyUnavailable {
		t.Fatal("expired key accepted through outage")
	}
	if calls.Load() != 3 {
		t.Fatalf("wanted one bounded outage refresh, got %d requests", calls.Load())
	}
	for i := 0; i < 5; i++ {
		_, _ = provider.VerificationKey(context.Background(), key2.KeyID, jose.EdDSA)
	}
	if calls.Load() != 3 {
		t.Fatal("outage retries are unbounded")
	}
}

func TestJWKSRetrievalFailsClosed(t *testing.T) {
	key, _ := testSigningKey(t, "key-1")
	valid, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key}})
	duplicate, _ := json.Marshal(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{key, key}})
	cases := []struct {
		name     string
		status   int
		body     string
		maxKeys  int
		redirect bool
	}{
		{name: "malformed", body: "not json"},
		{name: "null", body: "null"},
		{name: "empty keys", body: `{"keys":[]}`},
		{name: "null key", body: `{"keys":[null]}`},
		{name: "duplicate key", body: string(duplicate)},
		{name: "trailing JSON", body: string(valid) + `{}`},
		{name: "oversize", body: strings.Repeat("x", 1100)},
		{name: "too many keys", body: string(duplicate), maxKeys: 1},
		{name: "provider error", status: http.StatusInternalServerError, body: "synthetic provider secret"},
		{name: "redirect", status: http.StatusFound, redirect: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var redirectCalls atomic.Int64
			target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirectCalls.Add(1); _, _ = w.Write(valid) }))
			defer target.Close()
			server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tc.redirect {
					w.Header().Set("Location", target.URL)
				}
				if tc.status != 0 {
					w.WriteHeader(tc.status)
				}
				_, _ = w.Write([]byte(tc.body))
			}))
			defer server.Close()
			provider, err := NewJWKSProvider(JWKSConfig{URL: server.URL, HTTPClient: server.Client(), MaxResponseBytes: 1024, MaxKeys: tc.maxKeys})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := provider.VerificationKey(context.Background(), key.KeyID, jose.EdDSA); err != ErrKeyUnavailable {
				t.Fatalf("malformed JWKS accepted: %v", err)
			}
			if redirectCalls.Load() != 0 {
				t.Fatal("JWKS followed a redirect")
			}
		})
	}
}

func TestJWKSDeadlineAndWaitingCancellation(t *testing.T) {
	started := make(chan struct{})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { close(started); <-r.Context().Done() }))
	defer server.Close()
	provider, err := NewJWKSProvider(JWKSConfig{URL: server.URL, HTTPClient: server.Client(), FetchTimeout: 75 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := provider.VerificationKey(context.Background(), "key-1", jose.EdDSA); done <- err }()
	<-started
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := provider.VerificationKey(ctx, "key-1", jose.EdDSA); err != ErrKeyUnavailable {
		t.Fatal("cancelled waiter accepted")
	}
	select {
	case err := <-done:
		if err != ErrKeyUnavailable {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("JWKS deadline did not bound request")
	}
}

func TestJWKSConfigRejectsUntrustedURLsAndUnboundedSettings(t *testing.T) {
	for _, raw := range []string{"", "http://issuer.example.test/keys", "https://user:pass@issuer.example.test/keys", "https://issuer.example.test/keys#fragment", "https://issuer.example.test/keys?token=secret"} {
		if _, err := NewJWKSProvider(JWKSConfig{URL: raw}); err == nil {
			t.Fatalf("accepted %q", raw)
		}
	}
	for _, config := range []JWKSConfig{{URL: testIssuer, CacheTTL: 2 * time.Hour}, {URL: testIssuer, RefreshInterval: time.Millisecond}, {URL: testIssuer, FetchTimeout: time.Hour}, {URL: testIssuer, MaxKeys: 1000}, {URL: testIssuer, MaxResponseBytes: 2 << 20}} {
		if _, err := NewJWKSProvider(config); err == nil {
			t.Fatalf("accepted invalid limits: %#v", config)
		}
	}
}

func TestPublicKeyPolicy(t *testing.T) {
	key, private := testSigningKey(t, "key-1")
	rsaWeak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []jose.JSONWebKey{
		{Key: (*rsa.PublicKey)(nil), KeyID: "key-1", Algorithm: string(jose.RS256)},
		{Key: (*ecdsa.PublicKey)(nil), KeyID: "key-1", Algorithm: string(jose.ES256)},
		{Key: private, KeyID: "key-1", Algorithm: string(jose.EdDSA)},
		{Key: []byte("synthetic shared secret"), KeyID: "key-1", Algorithm: string(jose.HS256)},
		{Key: &rsaWeak.PublicKey, KeyID: "key-1", Algorithm: string(jose.RS256)},
		{Key: key.Key, KeyID: "key-1", Algorithm: string(jose.RS256)},
		{Key: key.Key, KeyID: "key-1", Use: "enc"},
		{Key: key.Key},
	} {
		if _, err := NewStaticKeyProvider([]jose.JSONWebKey{bad}); err == nil {
			t.Fatalf("accepted unsafe key type %T", bad.Key)
		}
	}
	if _, err := NewStaticKeyProvider([]jose.JSONWebKey{key, key}); err == nil {
		t.Fatal("accepted duplicate key ID")
	}
	provider, _ := NewStaticKeyProvider([]jose.JSONWebKey{key})
	if _, err := provider.VerificationKey(context.Background(), key.KeyID, jose.RS256); err != ErrKeyUnavailable {
		t.Fatal("key/algorithm confusion")
	}
}

func TestJWKSKeyOperationsPolicy(t *testing.T) {
	key, _ := testSigningKey(t, "key-1")
	encoded, _ := json.Marshal(key)
	for _, operations := range [][]string{{}, {"sign"}, {"verify"}} {
		var document map[string]any
		if err := json.Unmarshal(encoded, &document); err != nil {
			t.Fatal(err)
		}
		document["key_ops"] = operations
		server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []any{document}})
		}))
		provider, err := NewJWKSProvider(JWKSConfig{URL: server.URL, HTTPClient: server.Client()})
		if err != nil {
			t.Fatal(err)
		}
		_, err = provider.VerificationKey(context.Background(), key.KeyID, jose.EdDSA)
		server.Close()
		wantUsable := len(operations) == 1 && operations[0] == "verify"
		if (err == nil) != wantUsable {
			t.Fatalf("key_ops %v gave %v", operations, err)
		}
	}
}
