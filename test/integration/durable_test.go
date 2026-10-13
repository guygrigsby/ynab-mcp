package integration

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/adapters/secrets"
	sqlstate "github.com/guygrigsby/ynab-mcp/internal/adapters/state/sqlite"
	"github.com/guygrigsby/ynab-mcp/internal/application/authorization"
	"github.com/guygrigsby/ynab-mcp/internal/application/credentials"
	"github.com/guygrigsby/ynab-mcp/internal/application/lifecycle"
	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/budget"
	"github.com/guygrigsby/ynab-mcp/internal/domain/connection"
	"github.com/tink-crypto/tink-go/v2/aead"
	"github.com/tink-crypto/tink-go/v2/keyset"
	"github.com/tink-crypto/tink-go/v2/tink"
	"golang.org/x/oauth2"
)

// fileCiphertexts is a test-only durable ciphertext backend. No encryption key
// or plaintext bundle is written to disk. Production key/vault/restore policy
// is deliberately not selected by this helper or by the application.
type fileCiphertexts struct{ dir string }

func (f fileCiphertexts) path(ref connection.CredentialRef) string {
	raw, _ := json.Marshal(ref)
	sum := sha256.Sum256(raw)
	return filepath.Join(f.dir, hex.EncodeToString(sum[:]))
}
func (f fileCiphertexts) Read(ctx context.Context, ref connection.CredentialRef) ([]byte, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	fd, err := os.Open(f.path(ref))
	if errors.Is(err, os.ErrNotExist) {
		return nil, credentials.ErrNotFound
	}
	if err != nil {
		return nil, credentials.ErrUnavailable
	}
	defer fd.Close()
	data, err := io.ReadAll(io.LimitReader(fd, secrets.MaxCiphertextBytes+1))
	if err != nil || len(data) > secrets.MaxCiphertextBytes {
		return nil, credentials.ErrIntegrity
	}
	return data, nil
}
func (f fileCiphertexts) PutIfAbsent(ctx context.Context, ref connection.CredentialRef, data []byte) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	fd, err := os.CreateTemp(f.dir, "candidate-")
	if err != nil {
		return credentials.ErrUnavailable
	}
	temp := fd.Name()
	defer os.Remove(temp)
	if _, err = fd.Write(data); err == nil {
		err = fd.Sync()
	}
	closeErr := fd.Close()
	if err != nil || closeErr != nil {
		return credentials.ErrUnavailable
	}
	if err = os.Link(temp, f.path(ref)); errors.Is(err, os.ErrExist) {
		return credentials.ErrConflict
	} else if err != nil {
		return credentials.ErrUnavailable
	}
	dir, err := os.Open(f.dir)
	if err != nil {
		return credentials.ErrUnavailable
	}
	defer dir.Close()
	if dir.Sync() != nil {
		return credentials.ErrUnavailable
	}
	return nil
}

type syntheticOAuth struct {
	next      credentials.CompleteBundle
	refreshes atomic.Int64
	exchanges atomic.Int64
	callback  string
}

func (o *syntheticOAuth) AuthorizationURL(state, verifier string) (string, error) {
	c := oauth2.Config{ClientID: "synthetic-client", RedirectURL: o.callback, Scopes: []string{"read-only"}, Endpoint: oauth2.Endpoint{AuthURL: "https://app.ynab.com/oauth/authorize"}}
	return c.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), nil
}
func (o *syntheticOAuth) Exchange(context.Context, string, string) (*credentials.CompleteBundle, error) {
	o.exchanges.Add(1)
	copy := o.next
	return &copy, nil
}
func (o *syntheticOAuth) Refresh(context.Context, *credentials.CompleteBundle) (*credentials.CompleteBundle, error) {
	o.refreshes.Add(1)
	copy := o.next
	return &copy, nil
}
func primitive(t *testing.T) tink.AEAD {
	t.Helper()
	key, err := keyset.NewHandle(aead.AES256GCMKeyTemplate())
	if err != nil {
		t.Fatal(err)
	}
	p, err := aead.New(key)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func protected(t *testing.T, dir string, key tink.AEAD) *secrets.EncryptedStore {
	t.Helper()
	s, err := secrets.NewEncryptedStore(fileCiphertexts{dir}, key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}
func bundle(t *testing.T, label string, expiry time.Time) credentials.CompleteBundle {
	t.Helper()
	b, err := credentials.NewOAuthBundle("synthetic-access-"+label, "synthetic-refresh-"+label, expiry, "read-only")
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func grant(t *testing.T, p access.Principal) access.OwnerAccessGrant {
	t.Helper()
	g, err := access.NewOwnerAccessGrant(access.GrantConfig{OwnerID: "owner", PrincipalKey: p.Key, ConnectionID: "connection", ConnectionOwnerID: "owner", BudgetIDs: []budget.BudgetID{"b1"}, Enabled: true, PolicyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	return g
}
func openState(t *testing.T, path string) *sqlstate.Store {
	t.Helper()
	s, err := sqlstate.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestDurableConsentRotationAndReload(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	path := filepath.Join(t.TempDir(), "metadata.db")
	dir := t.TempDir()
	key := primitive(t)
	secret := protected(t, dir, key)
	db := openState(t, path)
	p := access.Principal{Key: access.PrincipalKey{Issuer: issuer, Subject: "owner-sub"}, Scopes: []string{"budget:read"}, ExpiresAt: now.Add(time.Hour)}
	c, err := connection.New("connection", "owner", connection.OAuth)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.Initialize(ctx, grant(t, p), c); err != nil {
		t.Fatal(err)
	}
	first := bundle(t, "initial", now.Add(30*time.Second))
	oauth := &syntheticOAuth{next: first, callback: "https://budget.example/oauth/callback"}
	callback, err := authorization.NewService(authorization.Config{CallbackURL: oauth.callback, SecretProvider: "synthetic"}, db, oauth, secret)
	if err != nil {
		t.Fatal(err)
	}
	const session = "synthetic-authenticated-owner-session-0123456789"
	begin, err := callback.Begin(ctx, authorization.BeginRequest{Principal: p, SessionID: session})
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(begin.AuthorizationURL)
	request := authorization.CallbackRequest{Principal: p, SessionID: session, State: u.Query().Get("state"), Code: "synthetic-code", CallbackURL: oauth.callback}
	if err = callback.Callback(ctx, request); err != nil {
		t.Fatal(err)
	}
	if callback.Callback(ctx, request) == nil || oauth.exchanges.Load() != 1 {
		t.Fatal("authorization code replayed")
	}
	current, err := db.Connections().Load(ctx, "connection")
	if err != nil {
		t.Fatal(err)
	}
	scope := access.ReadScope{OwnerID: "owner", ConnectionID: "connection", AuthorizationLineage: current.State().AuthorizationLineage, PolicyVersion: 1, BudgetID: "b1"}
	if err = db.Close(); err != nil {
		t.Fatal(err)
	}
	db = openState(t, path)
	defer db.Close()
	secret = protected(t, dir, key)
	second := bundle(t, "rotated", now.Add(time.Hour))
	oauth.next = second
	service, err := lifecycle.New(db.Connections(), db, secret, oauth, lifecycle.Config{Provider: "synthetic", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	fail := make(chan error, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := service.AccessToken(ctx, scope)
			if err == nil && token != second.ExportAccessTokenForYNABRead() {
				err = errors.New("wrong committed generation")
			}
			fail <- err
		}()
	}
	wg.Wait()
	close(fail)
	for err := range fail {
		if err != nil {
			t.Fatal(err)
		}
	}
	if oauth.refreshes.Load() != 1 {
		t.Fatal("concurrent refresh not coalesced", oauth.refreshes.Load())
	}
	current, err = db.Connections().Load(ctx, "connection")
	if err != nil || current.State().Generation.Number != 2 || current.State().Status != connection.Active {
		t.Fatal("generation not durably committed", err)
	}
	// Recreate both protected-store and lifecycle instances against persisted
	// ciphertext/control records. Retaining the injected test key models an
	// external key authority, not a key stored in metadata or its backups.
	reloaded := protected(t, dir, key)
	copy, err := reloaded.Read(ctx, current.State().Generation.Reference)
	if err != nil || !copy.Equal(second) {
		t.Fatal("complete bundle did not reload", err)
	}
	restarted, err := lifecycle.New(db.Connections(), db, reloaded, oauth, lifecycle.Config{Provider: "synthetic", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = restarted.AccessToken(ctx, scope); err != nil || oauth.refreshes.Load() != 1 {
		t.Fatal("reload replayed OAuth", err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{first.ExportAccessTokenForYNABRead(), first.ExportRefreshTokenForOAuth(), second.ExportAccessTokenForYNABRead(), second.ExportRefreshTokenForOAuth()} {
		if bytes.Contains(raw, []byte(value)) {
			t.Fatal("plaintext token in metadata")
		}
	}
}
func TestDurableRecoveryNeverReplaysExchange(t *testing.T) {
	for _, phase := range []string{"started-missing", "started-with-candidate", "secret-saved", "committed"} {
		t.Run(phase, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC()
			path := filepath.Join(t.TempDir(), "metadata.db")
			dir := t.TempDir()
			key := primitive(t)
			store := protected(t, dir, key)
			db := openState(t, path)
			principal := access.Principal{Key: access.PrincipalKey{Issuer: issuer, Subject: "owner-sub"}, Scopes: []string{"budget:read"}}
			initial := bundle(t, "old", now.Add(time.Hour))
			ref := connection.CredentialRef{Provider: "synthetic", Location: "initial", ImmutableVersion: "one"}
			if err := store.PutImmutable(ctx, ref, initial); err != nil {
				t.Fatal(err)
			}
			c, _ := connection.New("connection", "owner", connection.OAuth)
			c, err := c.Activate(1, "lineage", connection.PersistedCredential{Reference: ref, AccessExpiresAt: initial.ExpiresAt(), Complete: true, ReadOnly: true}, now)
			if err != nil {
				t.Fatal(err)
			}
			if err = db.Initialize(ctx, grant(t, principal), c); err != nil {
				t.Fatal(err)
			}
			candidate, err := lifecycle.CandidateReference("synthetic", "owner", "connection", "lineage", 1, "attempt")
			if err != nil {
				t.Fatal(err)
			}
			next, err := c.BeginRefresh(c.State().Version, "attempt", candidate, now, now.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if err = db.Connections().CompareAndSwap(ctx, "connection", c.State().Version, next); err != nil {
				t.Fatal(err)
			}
			c = next
			fence := c.State().Attempt.Fence
			next, err = c.MarkRequestStarted(c.State().Version, "attempt", fence, now)
			if err != nil {
				t.Fatal(err)
			}
			if err = db.Connections().CompareAndSwap(ctx, "connection", c.State().Version, next); err != nil {
				t.Fatal(err)
			}
			c = next
			replacement := bundle(t, "new", now.Add(2*time.Hour))
			if phase != "started-missing" {
				if err = store.PutImmutable(ctx, candidate, replacement); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "secret-saved" || phase == "committed" {
				next, err = c.MarkSecretSaved(c.State().Version, "attempt", fence, connection.PersistedCredential{Reference: candidate, AccessExpiresAt: replacement.ExpiresAt(), Complete: true, ReadOnly: true}, now)
				if err != nil {
					t.Fatal(err)
				}
				if err = db.Connections().CompareAndSwap(ctx, "connection", c.State().Version, next); err != nil {
					t.Fatal(err)
				}
				c = next
			}
			if phase == "committed" {
				next, err = c.CommitRefresh(c.State().Version, "attempt", fence)
				if err != nil {
					t.Fatal(err)
				}
				if err = db.Connections().CompareAndSwap(ctx, "connection", c.State().Version, next); err != nil {
					t.Fatal(err)
				}
			}
			// Durable boundaries above stand in for process loss at each checkpoint.
			if err = db.Close(); err != nil {
				t.Fatal(err)
			}
			db = openState(t, path)
			defer db.Close()
			store = protected(t, dir, key)
			oauth := &syntheticOAuth{next: replacement}
			service, err := lifecycle.New(db.Connections(), db, store, oauth, lifecycle.Config{Provider: "synthetic", Now: func() time.Time { return now }})
			if err != nil {
				t.Fatal(err)
			}
			scope := access.ReadScope{OwnerID: "owner", ConnectionID: "connection", AuthorizationLineage: "lineage", PolicyVersion: 1, BudgetID: "b1"}
			err = service.Recover(ctx, scope, lifecycle.StoppedWorkerProof{AttemptID: "attempt", Fence: fence, WorkerStopped: true})
			if phase == "started-missing" {
				if !errors.Is(err, lifecycle.ErrReconnectRequired) {
					t.Fatal("ambiguous outcome not blocked", err)
				}
			} else if err != nil {
				t.Fatal(err)
			}
			current, loadErr := db.Connections().Load(ctx, "connection")
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if phase == "started-missing" {
				if current.State().Status != connection.ReconnectRequired {
					t.Fatal("missing candidate reused")
				}
			} else if current.State().Generation.Number != 2 || current.State().Status != connection.Active {
				t.Fatal("candidate not recovered")
			}
			if oauth.refreshes.Load() != 0 {
				t.Fatal("recovery replayed OAuth")
			}
		})
	}
}
