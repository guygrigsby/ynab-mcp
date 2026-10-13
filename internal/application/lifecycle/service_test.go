package lifecycle

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/application/credentials"
	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/budget"
	"github.com/guygrigsby/ynab-mcp/internal/domain/connection"
)

var errCrash = errors.New("synthetic process interruption")

type testRepo struct {
	mu    sync.Mutex
	state connection.YNABConnection
	grant access.OwnerAccessGrant
	cas   func(connection.YNABConnection) (before, after error)
	loads atomic.Int64
}

func (r *testRepo) Load(ctx context.Context, id access.ConnectionID) (connection.YNABConnection, error) {
	r.loads.Add(1)
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return connection.YNABConnection{}, err
	}
	if r.state.State().ID != id {
		return connection.YNABConnection{}, errors.New("missing")
	}
	return r.state, nil
}
func (r *testRepo) CompareAndSwap(ctx context.Context, id access.ConnectionID, version uint64, next connection.YNABConnection) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	var after error
	if r.cas != nil {
		var before error
		before, after = r.cas(next)
		if before != nil {
			return before
		}
	}
	if r.state.State().ID != id || r.state.State().Version != version {
		return connection.ErrConflict
	}
	r.state = next
	return after
}
func (r *testRepo) CompareAndSwapScoped(ctx context.Context, scope access.ReadScope, version uint64, next connection.YNABConnection) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	state := r.state.State()
	if !r.grant.Enabled() || r.grant.PolicyVersion() != scope.PolicyVersion || r.grant.OwnerID() != scope.OwnerID || r.grant.ConnectionID() != scope.ConnectionID || state.ID != scope.ConnectionID || state.OwnerID != scope.OwnerID || state.AuthorizationLineage != scope.AuthorizationLineage || (scope.BudgetID != "" && !r.grant.AllowsBudget(scope.BudgetID)) {
		return access.ErrUnauthorized
	}
	var after error
	if r.cas != nil {
		var before error
		before, after = r.cas(next)
		if before != nil {
			return before
		}
	}
	if state.Version != version {
		return connection.ErrConflict
	}
	r.state = next
	return after
}
func (r *testRepo) ReadAccessState(ctx context.Context) (access.OwnerAccessGrant, access.ConnectionBinding, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.grant, r.state.Binding(), ctx.Err()
}
func (r *testRepo) current() connection.YNABConnection {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}
func (r *testRepo) mutate(t *testing.T, f func(connection.YNABConnection) (connection.YNABConnection, error)) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	next, err := f(r.state)
	if err != nil {
		t.Fatal(err)
	}
	r.state = next
}
func (r *testRepo) revoke(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	cfg := access.GrantConfig{OwnerID: r.grant.OwnerID(), PrincipalKey: r.grant.PrincipalKey(), ConnectionID: r.grant.ConnectionID(), ConnectionOwnerID: r.grant.OwnerID(), BudgetIDs: r.grant.BudgetIDs(), Enabled: false}
	g, err := r.grant.Replace(r.grant.PolicyVersion(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	r.grant = g
}

type testStore struct {
	mu                sync.Mutex
	values            map[connection.CredentialRef]credentials.CompleteBundle
	read              func(connection.CredentialRef)
	putError          error
	readError         error
	writeDespiteError bool
	puts              atomic.Int64
}

func (s *testStore) Read(ctx context.Context, ref connection.CredentialRef) (credentials.CompleteBundle, error) {
	s.mu.Lock()
	b, ok := s.values[ref]
	err := s.readError
	hook := s.read
	s.mu.Unlock()
	if hook != nil {
		hook(ref)
	}
	if err != nil {
		return credentials.CompleteBundle{}, err
	}
	if !ok {
		return credentials.CompleteBundle{}, credentials.ErrNotFound
	}
	return b, ctx.Err()
}
func (s *testStore) PutImmutable(ctx context.Context, ref connection.CredentialRef, b credentials.CompleteBundle) error {
	s.puts.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if old, ok := s.values[ref]; ok && !old.Equal(b) {
		return credentials.ErrConflict
	}
	if s.putError == nil || s.writeDespiteError {
		s.values[ref] = b
	}
	return s.putError
}

type testOAuth struct {
	calls  atomic.Int64
	bundle credentials.CompleteBundle
	err    error
	hook   func(context.Context)
}

func (o *testOAuth) Refresh(ctx context.Context, _ *credentials.CompleteBundle) (*credentials.CompleteBundle, error) {
	o.calls.Add(1)
	if o.hook != nil {
		o.hook(ctx)
	}
	return &o.bundle, o.err
}

type fixture struct {
	repo    *testRepo
	store   *testStore
	oauth   *testOAuth
	service *Service
	scope   access.ReadScope
	now     time.Time
}

func bundle(t *testing.T, accessToken, refreshToken string, expiry time.Time) credentials.CompleteBundle {
	t.Helper()
	b, err := credentials.NewOAuthBundle(accessToken, refreshToken, expiry, "read-only")
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{now: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
	c, err := connection.New("connection", "owner", connection.OAuth)
	if err != nil {
		t.Fatal(err)
	}
	ref := connection.CredentialRef{Provider: "protected", Location: "initial", ImmutableVersion: "one"}
	old := bundle(t, "initial-access", "initial-refresh", f.now.Add(10*time.Second))
	c, err = c.Activate(c.State().Version, "lineage", connection.PersistedCredential{Reference: ref, AccessExpiresAt: old.ExpiresAt(), Complete: true, ReadOnly: true}, f.now)
	if err != nil {
		t.Fatal(err)
	}
	g, err := access.NewOwnerAccessGrant(access.GrantConfig{OwnerID: "owner", PrincipalKey: access.PrincipalKey{Issuer: "https://issuer.example", Subject: "owner"}, ConnectionID: "connection", ConnectionOwnerID: "owner", BudgetIDs: []budget.BudgetID{"budget"}, Enabled: true, PolicyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	f.repo = &testRepo{state: c, grant: g}
	f.store = &testStore{values: map[connection.CredentialRef]credentials.CompleteBundle{ref: old}}
	f.oauth = &testOAuth{bundle: bundle(t, "new-access", "new-refresh", f.now.Add(time.Hour))}
	f.scope = access.ReadScope{OwnerID: "owner", ConnectionID: "connection", AuthorizationLineage: "lineage", PolicyVersion: 1, BudgetID: "budget"}
	f.service = f.newService(t)
	return f
}
func (f *fixture) newService(t *testing.T) *Service {
	t.Helper()
	svc, err := New(f.repo, f.repo, f.store, f.oauth, Config{Now: func() time.Time { return f.now }, Entropy: bytes.NewReader(bytes.Repeat([]byte{42}, 1024)), WaitLimit: 200 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

func TestRefreshPublishesOnlyDurableCompleteCommittedPair(t *testing.T) {
	f := newFixture(t)
	f.oauth.hook = func(context.Context) {
		state := f.repo.current().State()
		if state.Status != connection.Refreshing || state.Attempt.Phase != connection.RequestStarted {
			t.Error("exchange preceded durable started fence")
		}
	}
	f.service.checkpoint = func(point string) error {
		if point == "before_commit" {
			state := f.repo.current().State()
			if state.Generation.Number != 1 || state.Attempt.Phase != connection.SecretSaved {
				t.Error("published generation before secret proof")
			}
			b, err := f.store.Read(context.Background(), state.Attempt.CandidateRef)
			if err != nil || !b.Equal(f.oauth.bundle) {
				t.Error("missing full immutable candidate")
			}
		}
		return nil
	}
	token, err := f.service.AccessToken(context.Background(), f.scope)
	if err != nil || token != "new-access" {
		t.Fatalf("token result: %q, %v", token, err)
	}
	state := f.repo.current().State()
	if state.Status != connection.Active || state.Generation.Number != 2 || state.Attempt.Phase != connection.Committed || f.oauth.calls.Load() != 1 {
		t.Fatal("rotation was not committed exactly once")
	}
}

func TestCrashRecoveryNeverReplaysRefresh(t *testing.T) {
	cases := []struct {
		point       string
		phase       connection.RefreshPhase
		calls       int64
		recoverable bool
	}{
		{"before_prepared", "", 0, true},
		{"after_prepared", connection.Prepared, 0, true},
		{"before_request_started", connection.Prepared, 0, true},
		{"after_request_started", connection.RequestStarted, 0, false},
		{"before_exchange", connection.RequestStarted, 0, false},
		{"after_exchange", connection.RequestStarted, 1, false},
		{"before_candidate_write", connection.RequestStarted, 1, false},
		{"after_candidate_write", connection.RequestStarted, 1, true},
		{"before_secret_saved", connection.RequestStarted, 1, true},
		{"after_secret_saved", connection.SecretSaved, 1, true},
		{"before_commit", connection.SecretSaved, 1, true},
		{"after_commit", connection.Committed, 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.point, func(t *testing.T) {
			f := newFixture(t)
			f.service.checkpoint = func(point string) error {
				if point == tc.point {
					return errCrash
				}
				return nil
			}
			if err := f.service.refresh(context.Background(), f.scope); !errors.Is(err, errCrash) {
				t.Fatalf("wanted interruption, got %v", err)
			}
			state := f.repo.current().State()
			if tc.phase != "" && (state.Attempt == nil || state.Attempt.Phase != tc.phase) {
				t.Fatalf("unexpected durable phase %v", state.Attempt)
			}
			if f.oauth.calls.Load() != tc.calls {
				t.Fatal("unexpected exchange count")
			}
			f.now = f.now.Add(2 * time.Minute)
			restarted := f.newService(t)
			proof := StoppedWorkerProof{}
			if state.Attempt != nil {
				proof = StoppedWorkerProof{state.Attempt.ID, state.Attempt.Fence, true}
			}
			err := restarted.Recover(context.Background(), f.scope, proof)
			if tc.recoverable && err != nil {
				t.Fatalf("recovery: %v", err)
			}
			if !tc.recoverable && !errors.Is(err, ErrReconnectRequired) {
				t.Fatalf("uncertain exchange should require consent: %v", err)
			}
			if f.oauth.calls.Load() != tc.calls {
				t.Fatal("recovery replayed a refresh")
			}
			state = f.repo.current().State()
			if tc.recoverable && state.Status != connection.Active {
				t.Fatal("recoverable candidate not made active")
			}
			if !tc.recoverable && state.Status != connection.ReconnectRequired {
				t.Fatal("missing candidate was not failed closed")
			}
			if tc.recoverable && tc.calls == 1 && state.Generation.Number != 2 {
				t.Fatal("persisted candidate not adopted")
			}
			if tc.recoverable {
				if err = restarted.Recover(context.Background(), f.scope, proof); err != nil {
					t.Fatalf("repeated recovery: %v", err)
				}
			}
		})
	}
}

func TestPreparedRecoveryRequiresStoppedWorkerAndExpiredLease(t *testing.T) {
	f := newFixture(t)
	f.service.checkpoint = func(p string) error {
		if p == "after_prepared" {
			return errCrash
		}
		return nil
	}
	_ = f.service.refresh(context.Background(), f.scope)
	a := f.repo.current().State().Attempt
	s := f.newService(t)
	for _, proof := range []StoppedWorkerProof{{}, {a.ID, a.Fence, false}, {"other", a.Fence, true}, {a.ID, a.Fence + 1, true}, {a.ID, a.Fence, true}} {
		if err := s.Recover(context.Background(), f.scope, proof); err == nil {
			t.Fatal("reclaimed live or unproven worker")
		}
	}
	f.now = f.now.Add(2 * time.Minute)
	if err := s.Recover(context.Background(), f.scope, StoppedWorkerProof{a.ID, a.Fence, false}); err == nil {
		t.Fatal("lease expiry alone reclaimed worker")
	}
	if err := s.Recover(context.Background(), f.scope, StoppedWorkerProof{a.ID, a.Fence, true}); err != nil {
		t.Fatal(err)
	}
	if f.oauth.calls.Load() != 0 || f.repo.current().State().Attempt.Phase != connection.Abandoned {
		t.Fatal("bad prepared abandonment")
	}
}

func TestLostCASAcknowledgementsReconcileWithoutDuplicateExchange(t *testing.T) {
	for _, phase := range []connection.RefreshPhase{connection.Prepared, connection.RequestStarted, connection.SecretSaved, connection.Committed} {
		t.Run(string(phase), func(t *testing.T) {
			f := newFixture(t)
			hit := false
			f.repo.cas = func(next connection.YNABConnection) (error, error) {
				if !hit && next.State().Attempt != nil && next.State().Attempt.Phase == phase {
					hit = true
					return nil, errors.New("lost acknowledgement")
				}
				return nil, nil
			}
			if err := f.service.refresh(context.Background(), f.scope); err != nil {
				t.Fatal(err)
			}
			if !hit || f.oauth.calls.Load() != 1 || f.repo.current().State().Generation.Number != 2 {
				t.Fatal("lost ack not safely reconciled")
			}
		})
	}
}

func TestUncertainCASWithoutCommitDoesNotAuthorizeNextEffect(t *testing.T) {
	for _, phase := range []connection.RefreshPhase{connection.Prepared, connection.RequestStarted, connection.SecretSaved, connection.Committed} {
		t.Run(string(phase), func(t *testing.T) {
			f := newFixture(t)
			hit := false
			f.repo.cas = func(next connection.YNABConnection) (error, error) {
				if !hit && next.State().Attempt != nil && next.State().Attempt.Phase == phase {
					hit = true
					return errors.New("uncertain storage outcome"), nil
				}
				return nil, nil
			}
			if err := f.service.refresh(context.Background(), f.scope); !errors.Is(err, ErrUnavailable) {
				t.Fatalf("uncertainty hidden: %v", err)
			}
			want := int64(0)
			if phase == connection.SecretSaved || phase == connection.Committed {
				want = 1
			}
			if f.oauth.calls.Load() != want {
				t.Fatal("effect followed unacknowledged transition")
			}
			if f.repo.current().State().Generation.Number != 1 {
				t.Fatal("premature publication")
			}
		})
	}
}

func TestUncertainProviderOrSecretOutcomesNeverRetryExchange(t *testing.T) {
	for _, kind := range []string{"provider-error", "invalid-bundle", "missing-secret", "lost-secret-ack", "unreadable-secret"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			switch kind {
			case "provider-error":
				f.oauth.err = errors.New("provider response containing secret")
			case "invalid-bundle":
				f.oauth.bundle = credentials.CompleteBundle{}
			case "missing-secret":
				f.store.putError = errors.New("write failed")
			case "lost-secret-ack":
				f.store.putError = errors.New("lost ack")
				f.store.writeDespiteError = true
			case "unreadable-secret":
				f.service.checkpoint = func(p string) error {
					if p == "after_candidate_write" {
						f.store.mu.Lock()
						f.store.readError = credentials.ErrUnavailable
						f.store.mu.Unlock()
					}
					return nil
				}
			}
			err := f.service.refresh(context.Background(), f.scope)
			if kind == "lost-secret-ack" {
				if err != nil || f.repo.current().State().Generation.Number != 2 {
					t.Fatal("exact readback did not resolve lost store ack")
				}
			} else if kind == "unreadable-secret" {
				if !errors.Is(err, ErrUnavailable) || f.repo.current().State().Attempt.Phase != connection.RequestStarted {
					t.Fatal("unreadable outcome discarded recoverable candidate")
				}
			} else if !errors.Is(err, ErrReconnectRequired) {
				t.Fatalf("unsafe failure classification %v", err)
			}
			if f.oauth.calls.Load() != 1 {
				t.Fatal("exchange retried")
			}
			if kind != "lost-secret-ack" && kind != "unreadable-secret" {
				_, _ = f.service.AccessToken(context.Background(), f.scope)
				if f.oauth.calls.Load() != 1 {
					t.Fatal("old refresh replayed after error")
				}
			}
		})
	}
}

func TestConcurrentReadersCoalesceWithBoundedIndependentWaiters(t *testing.T) {
	f := newFixture(t)
	started := make(chan struct{})
	release := make(chan struct{})
	f.oauth.hook = func(context.Context) { close(started); <-release }
	var wg sync.WaitGroup
	results := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			token, err := f.service.AccessToken(context.Background(), f.scope)
			if err == nil && token != "new-access" {
				err = errors.New("wrong token")
			}
			results <- err
		}()
	}
	<-started
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Millisecond)
	defer cancel()
	if token, err := f.service.AccessToken(ctx, f.scope); err == nil || token != "" {
		t.Fatal("bounded waiter received uncommitted token")
	}
	if f.oauth.calls.Load() != 1 {
		t.Fatal("concurrent exchange")
	}
	close(release)
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if f.oauth.calls.Load() != 1 {
		t.Fatal("duplicate rotation")
	}
}

func TestUnknownExternalAttemptWaitsAndNeverStealsLease(t *testing.T) {
	f := newFixture(t)
	f.service.checkpoint = func(p string) error {
		if p == "after_prepared" {
			return errCrash
		}
		return nil
	}
	_ = f.service.refresh(context.Background(), f.scope)
	f.now = f.now.Add(2 * time.Minute)
	s := f.newService(t)
	s.config.WaitLimit = 15 * time.Millisecond
	if token, err := s.AccessToken(context.Background(), f.scope); token != "" || !errors.Is(err, ErrRefreshInProgress) {
		t.Fatal("external attempt did not stay fenced")
	}
	if f.oauth.calls.Load() != 0 || f.repo.current().State().Attempt.Phase != connection.Prepared {
		t.Fatal("lease expiry triggered unauthorized reclaim")
	}
}

func TestDisableReconnectAndPolicyRacesCannotPublish(t *testing.T) {
	for _, kind := range []string{"disable", "reconnect", "revoke"} {
		for _, point := range []string{"after_prepared", "after_request_started", "after_exchange", "after_candidate_write", "after_secret_saved", "before_commit"} {
			t.Run(kind+"/"+point, func(t *testing.T) {
				f := newFixture(t)
				f.service.checkpoint = func(p string) error {
					if p != point {
						return nil
					}
					switch kind {
					case "disable":
						f.repo.mutate(t, func(c connection.YNABConnection) (connection.YNABConnection, error) {
							return c.Disable(c.State().Version)
						})
					case "reconnect":
						f.repo.mutate(t, func(c connection.YNABConnection) (connection.YNABConnection, error) {
							ref := connection.CredentialRef{Provider: "protected", Location: "new-consent", ImmutableVersion: "two"}
							return c.Activate(c.State().Version, "new-lineage", connection.PersistedCredential{Reference: ref, AccessExpiresAt: f.now.Add(time.Hour), Complete: true, ReadOnly: true}, f.now)
						})
					case "revoke":
						f.repo.revoke(t)
					}
					return nil
				}
				if err := f.service.refresh(context.Background(), f.scope); err == nil {
					t.Fatal("race allowed refresh publication")
				}
				state := f.repo.current().State()
				if state.Attempt != nil && state.Attempt.Phase == connection.Committed {
					t.Fatal("old attempt committed after revocation")
				}
				if token, err := f.service.AccessToken(context.Background(), f.scope); token != "" || err == nil {
					t.Fatal("old scope released token after revocation")
				}
			})
		}
	}
}

func TestCommittedReadValidatesIdentityPolicyExpiryAndStoreProof(t *testing.T) {
	for _, kind := range []string{"owner", "connection", "lineage", "policy", "budget", "missing", "wrong-expiry", "invalid", "revoked-during-read", "disabled-during-read"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			scope := f.scope
			f.service.config.RefreshSkew = time.Nanosecond
			ref := f.repo.current().State().Generation.Reference
			switch kind {
			case "owner":
				scope.OwnerID = "other"
			case "connection":
				scope.ConnectionID = "other"
			case "lineage":
				scope.AuthorizationLineage = "other"
			case "policy":
				scope.PolicyVersion++
			case "budget":
				scope.BudgetID = "other"
			case "missing":
				delete(f.store.values, ref)
			case "wrong-expiry":
				f.store.values[ref] = bundle(t, "wrong-access", "wrong-refresh", f.now.Add(time.Hour))
			case "invalid":
				f.store.values[ref] = credentials.CompleteBundle{}
			case "revoked-during-read":
				f.store.read = func(connection.CredentialRef) { f.repo.revoke(t) }
			case "disabled-during-read":
				f.store.read = func(connection.CredentialRef) {
					f.repo.mutate(t, func(c connection.YNABConnection) (connection.YNABConnection, error) {
						return c.Disable(c.State().Version)
					})
				}
			}
			if token, err := f.service.AccessToken(context.Background(), scope); token != "" || err == nil {
				t.Fatal("invalid binding released credentials")
			}
			if f.oauth.calls.Load() != 0 {
				t.Fatal("invalid proof reached OAuth")
			}
		})
	}
}

func TestCandidateProofMismatchRequiresReconnect(t *testing.T) {
	for _, kind := range []string{"missing", "expired", "wrong-expiry", "invalid", "wrong-reference"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			f.service.checkpoint = func(p string) error {
				if p == "after_secret_saved" {
					return errCrash
				}
				return nil
			}
			_ = f.service.refresh(context.Background(), f.scope)
			ref := f.repo.current().State().Attempt.CandidateRef
			switch kind {
			case "missing":
				delete(f.store.values, ref)
			case "expired":
				f.now = f.now.Add(2 * time.Hour)
			case "wrong-expiry":
				f.store.values[ref] = bundle(t, "other-access", "other-refresh", f.now.Add(2*time.Hour))
			case "invalid":
				f.store.values[ref] = credentials.CompleteBundle{}
			case "wrong-reference":
				f.repo.mutate(t, func(c connection.YNABConnection) (connection.YNABConnection, error) {
					state := c.State()
					state.Attempt.CandidateRef.Location = "unrelated"
					return connection.Restore(state)
				})
			}
			if err := f.newService(t).Recover(context.Background(), f.scope, StoppedWorkerProof{}); !errors.Is(err, ErrReconnectRequired) {
				t.Fatalf("invalid recovery proof: %v", err)
			}
			if f.repo.current().State().Generation.Number != 1 || f.oauth.calls.Load() != 1 {
				t.Fatal("invalid candidate published or exchange replayed")
			}
		})
	}
}

func TestCandidateReferenceIsDeterministicAndFullyBound(t *testing.T) {
	base, err := CandidateReference("protected", "owner", "connection", "lineage", 1, "attempt")
	if err != nil {
		t.Fatal(err)
	}
	again, _ := CandidateReference("protected", "owner", "connection", "lineage", 1, "attempt")
	if again != base {
		t.Fatal("nondeterministic candidate")
	}
	refs := []connection.CredentialRef{}
	for _, x := range []struct {
		owner   access.OwnerID
		id      access.ConnectionID
		lineage string
		base    uint64
		attempt string
	}{{"other", "connection", "lineage", 1, "attempt"}, {"owner", "other", "lineage", 1, "attempt"}, {"owner", "connection", "other", 1, "attempt"}, {"owner", "connection", "lineage", 2, "attempt"}, {"owner", "connection", "lineage", 1, "other"}} {
		ref, err := CandidateReference("protected", x.owner, x.id, x.lineage, x.base, x.attempt)
		if err != nil {
			t.Fatal(err)
		}
		refs = append(refs, ref)
	}
	for _, ref := range refs {
		if ref == base {
			t.Fatal("candidate did not bind all metadata")
		}
	}
}

func TestFreshShortLivedTokenDoesNotCauseRefreshLoop(t *testing.T) {
	f := newFixture(t)
	f.oauth.bundle = bundle(t, "short-access", "short-refresh", f.now.Add(20*time.Second))
	token, err := f.service.AccessToken(context.Background(), f.scope)
	if err != nil || token != "short-access" || f.oauth.calls.Load() != 1 {
		t.Fatalf("refresh loop: %q %v %d", token, err, f.oauth.calls.Load())
	}
}

func TestEntropyFailureNeverBeginsAttempt(t *testing.T) {
	f := newFixture(t)
	f.service.config.Entropy = bytes.NewReader(nil)
	if err := f.service.refresh(context.Background(), f.scope); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if f.repo.current().State().Attempt != nil || f.oauth.calls.Load() != 0 {
		t.Fatal("attempt began without secure entropy")
	}
}

func TestRecoveryCannotClassifyLiveExchangeAsAmbiguous(t *testing.T) {
	f := newFixture(t)
	started, release := make(chan struct{}), make(chan struct{})
	f.oauth.hook = func(context.Context) { close(started); <-release }
	done := make(chan error, 1)
	go func() { _, err := f.service.AccessToken(context.Background(), f.scope); done <- err }()
	<-started
	a := f.repo.current().State().Attempt
	for _, service := range []*Service{f.service, f.newService(t)} {
		for _, proof := range []StoppedWorkerProof{{}, {"wrong", a.Fence, true}, {a.ID, a.Fence + 1, true}} {
			if err := service.Recover(context.Background(), f.scope, proof); !errors.Is(err, ErrRefreshInProgress) {
				t.Errorf("live attempt classified as ambiguous: %v", err)
			}
		}
	}
	// The in-process flight is positive evidence against even a mistaken supplied
	// stopped-worker claim. Another process needs independently verified proof.
	if err := f.service.Recover(context.Background(), f.scope, StoppedWorkerProof{a.ID, a.Fence, true}); !errors.Is(err, ErrRefreshInProgress) {
		t.Errorf("known-live worker was reclaimed: %v", err)
	}
	if f.repo.current().State().Attempt.Phase != connection.RequestStarted {
		t.Error("recovery changed live attempt")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if f.oauth.calls.Load() != 1 || f.repo.current().State().Generation.Number != 2 {
		t.Fatal("live exchange was not allowed to commit exactly once")
	}
}

func TestCancelledInitiatorDoesNotCancelOrReplaySharedAttempt(t *testing.T) {
	f := newFixture(t)
	started, release := make(chan struct{}), make(chan struct{})
	f.oauth.hook = func(ctx context.Context) {
		close(started)
		<-release
		if ctx.Err() != nil {
			t.Error("waiter cancellation cancelled shared operation")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	initiator := make(chan error, 1)
	go func() { _, err := f.service.AccessToken(ctx, f.scope); initiator <- err }()
	<-started
	cancel()
	if err := <-initiator; !errors.Is(err, ErrRefreshInProgress) {
		t.Fatalf("cancelled waiter result: %v", err)
	}
	follower := make(chan error, 1)
	go func() { _, err := f.service.AccessToken(context.Background(), f.scope); follower <- err }()
	close(release)
	if err := <-follower; err != nil {
		t.Fatal(err)
	}
	if f.oauth.calls.Load() != 1 {
		t.Fatal("cancellation replayed shared exchange")
	}
}

func TestMultipleCoordinatorsShareOnlyOneDurableAttempt(t *testing.T) {
	f := newFixture(t)
	other := f.newService(t)
	started, release := make(chan struct{}), make(chan struct{})
	f.oauth.hook = func(context.Context) { close(started); <-release }
	first := make(chan error, 1)
	go func() { _, err := f.service.AccessToken(context.Background(), f.scope); first <- err }()
	<-started
	second := make(chan error, 1)
	go func() { _, err := other.AccessToken(context.Background(), f.scope); second <- err }()
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if err := <-second; err != nil {
		t.Fatal(err)
	}
	if f.oauth.calls.Load() != 1 || f.repo.current().State().Generation.Number != 2 {
		t.Fatal("coordinators duplicated unresolved attempt")
	}
}

func TestConfigurationAndReferenceInputFailClosed(t *testing.T) {
	f := newFixture(t)
	for _, config := range []Config{{RefreshSkew: -1}, {WaitLimit: -1}, {WaitLimit: 6 * time.Minute}, {OperationLimit: -1}, {OperationLimit: 2 * time.Minute, Lease: time.Minute}, {Lease: 6 * time.Minute}, {Provider: "bad\nprovider"}} {
		if _, err := New(f.repo, f.repo, f.store, f.oauth, config); !errors.Is(err, ErrConfiguration) {
			t.Fatal("invalid config accepted")
		}
	}
	if _, err := New(nil, f.repo, f.store, f.oauth, Config{}); !errors.Is(err, ErrConfiguration) {
		t.Fatal("nil state accepted")
	}
	if _, err := New(f.repo, nil, f.store, f.oauth, Config{}); !errors.Is(err, ErrConfiguration) {
		t.Fatal("nil policy accepted")
	}
	if _, err := CandidateReference("protected", "", "connection", "lineage", 1, "attempt"); err == nil {
		t.Fatal("empty owner accepted")
	}
	if _, err := CandidateReference("bad\nprovider", "owner", "connection", "lineage", 1, "attempt"); err == nil {
		t.Fatal("invalid provider accepted")
	}
	if _, err := f.service.AccessToken(nil, f.scope); !errors.Is(err, ErrUnavailable) {
		t.Fatal("nil context accepted")
	}
	if err := f.service.Recover(nil, f.scope, StoppedWorkerProof{}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("nil recovery context accepted")
	}
}
