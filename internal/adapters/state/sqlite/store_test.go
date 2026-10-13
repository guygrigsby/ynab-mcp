package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/application/ports"
	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/admission"
	"github.com/guygrigsby/ynab-mcp/internal/domain/budget"
	"github.com/guygrigsby/ynab-mcp/internal/domain/connection"
)

var testTime = time.Date(2026, 10, 13, 12, 0, 0, 123456789, time.UTC)
var testContext = context.Background()

func synthetic(t *testing.T) (access.OwnerAccessGrant, connection.YNABConnection) {
	t.Helper()
	g, err := access.NewOwnerAccessGrant(access.GrantConfig{OwnerID: "owner", ConnectionID: "conn", ConnectionOwnerID: "owner", PrincipalKey: access.PrincipalKey{Issuer: "https://issuer.example", Subject: "subject"}, BudgetIDs: []budget.BudgetID{"budget-a", "budget-b"}, Enabled: true, PolicyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	c, err := connection.New("conn", "owner", connection.OAuth)
	if err != nil {
		t.Fatal(err)
	}
	return g, c
}

func activeConnection(t *testing.T, c connection.YNABConnection) connection.YNABConnection {
	t.Helper()
	next, err := c.Activate(c.State().Version, "lineage", connection.PersistedCredential{Reference: connection.CredentialRef{Provider: "synthetic", Location: "bundle", ImmutableVersion: "version-1"}, AccessExpiresAt: testTime.Add(time.Hour), Complete: true, ReadOnly: true}, testTime)
	if err != nil {
		t.Fatal(err)
	}
	return next
}

func openFixture(t *testing.T, active bool) (*Store, string, access.OwnerAccessGrant, connection.YNABConnection) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "metadata.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	g, c := synthetic(t)
	if active {
		c = activeConnection(t, c)
	}
	if err := s.Initialize(testContext, g, c); err != nil {
		t.Fatal(err)
	}
	return s, path, g, c
}

func mustExec(t *testing.T, s *Store, query string, args ...any) {
	t.Helper()
	if _, err := s.db.ExecContext(testContext, query, args...); err != nil {
		t.Fatal(err)
	}
}

func TestInitializeIsExplicitAtomicAndSingleOwner(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, _, err := s.ReadAccessState(testContext); !errors.Is(err, ErrUninitialized) {
		t.Fatalf("empty store: %v", err)
	}
	g, c := synthetic(t)
	mustExec(t, s, `CREATE TRIGGER inject_failure BEFORE INSERT ON allowed_budgets WHEN NEW.budget_id='budget-b' BEGIN SELECT RAISE(ABORT,'synthetic error'); END`)
	if err := s.Initialize(testContext, g, c); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("want rollback failure: %v", err)
	}
	for _, table := range []string{"owners", "connections", "access_grants", "allowed_budgets"} {
		var count int
		if err := s.db.QueryRow("SELECT count(*) FROM " + table).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s partially initialized count=%d err=%v", table, count, err)
		}
	}
	mustExec(t, s, "DROP TRIGGER inject_failure")
	if err := s.Initialize(testContext, g, c); err != nil {
		t.Fatal(err)
	}
	if err := s.Initialize(testContext, g, c); !errors.Is(err, ErrAlreadyInitialized) {
		t.Fatalf("second init: %v", err)
	}
	if _, err := s.db.Exec("INSERT INTO owners VALUES(2,'other','https://issuer.example','other','n:',1,1)"); err == nil {
		t.Fatal("multiple owner allowed")
	}
	if _, err := s.db.Exec("UPDATE access_grants SET connection_id='foreign'"); err == nil {
		t.Fatal("foreign connection allowed")
	}
	if _, err := s.db.Exec("UPDATE connections SET owner_id='foreign'"); err == nil {
		t.Fatal("foreign owner allowed")
	}
}

func TestGrantReplacementAtomicRollbackVersionsAndCopies(t *testing.T) {
	s, _, g, _ := openFixture(t, true)
	config := grantConfig(g)
	config.BudgetIDs = []budget.BudgetID{"replacement"}
	config.AllowNotes = true
	next, err := g.Replace(1, config)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceGrant(testContext, 0, next); !errors.Is(err, access.ErrVersionConflict) {
		t.Fatal(err)
	}
	if err := s.ReplaceGrant(testContext, 1, g); !errors.Is(err, access.ErrVersionConflict) {
		t.Fatal(err)
	}
	mustExec(t, s, `CREATE TRIGGER inject_failure BEFORE INSERT ON allowed_budgets BEGIN SELECT RAISE(ABORT,'synthetic error'); END`)
	if err := s.ReplaceGrant(testContext, 1, next); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	got, _, err := s.ReadAccessState(testContext)
	if err != nil || got.PolicyVersion() != 1 || got.AllowNotes() || !reflect.DeepEqual(got.BudgetIDs(), g.BudgetIDs()) {
		t.Fatalf("partial policy update: %#v %v", grantConfig(got), err)
	}
	mustExec(t, s, "DROP TRIGGER inject_failure")
	if err := s.ReplaceGrant(testContext, 1, next); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceGrant(testContext, 1, next); !errors.Is(err, access.ErrVersionConflict) {
		t.Fatal(err)
	}
	got, _, err = s.ReadAccessState(testContext)
	if err != nil {
		t.Fatal(err)
	}
	ids := got.BudgetIDs()
	ids[0] = "mutated"
	again, _, _ := s.ReadAccessState(testContext)
	if again.BudgetIDs()[0] != "replacement" {
		t.Fatal("returned metadata aliases storage")
	}
	config = grantConfig(again)
	config.Enabled = false
	config.BudgetIDs = nil
	disabled, _ := again.Replace(2, config)
	if err := s.ReplaceGrant(testContext, 2, disabled); err != nil {
		t.Fatal(err)
	}
	got, _, err = s.ReadAccessState(testContext)
	if err != nil || got.Enabled() || len(got.BudgetIDs()) != 0 {
		t.Fatal("disabled empty grant not persisted", err)
	}
}

func TestGrantRejectsForeignOwnershipAndExcessiveAllowlist(t *testing.T) {
	s, _, g, _ := openFixture(t, false)
	config := grantConfig(g)
	config.ConnectionID = "foreign"
	config.PolicyVersion = 2
	next, _ := access.NewOwnerAccessGrant(config)
	if err := s.ReplaceGrant(testContext, 1, next); !errors.Is(err, access.ErrInvalidGrant) {
		t.Fatal(err)
	}
	config = grantConfig(g)
	config.PolicyVersion = 2
	config.BudgetIDs = nil
	for i := 0; i < maxAllowedBudgets+1; i++ {
		config.BudgetIDs = append(config.BudgetIDs, budget.BudgetID(fmt.Sprintf("budget-%d", i)))
	}
	next, _ = access.NewOwnerAccessGrant(config)
	if err := s.ReplaceGrant(testContext, 1, next); !errors.Is(err, access.ErrInvalidGrant) {
		t.Fatal(err)
	}
}

func TestConsistentGrantReadAcrossConcurrentReplacements(t *testing.T) {
	s, path, _, _ := openFixture(t, true)
	other, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			g, _, err := other.ReadAccessState(testContext)
			if err != nil {
				t.Error(err)
				return
			}
			cfg := grantConfig(g)
			cfg.BudgetIDs = []budget.BudgetID{budget.BudgetID(fmt.Sprintf("v%d", g.PolicyVersion()+1))}
			next, _ := g.Replace(g.PolicyVersion(), cfg)
			if err := other.ReplaceGrant(testContext, g.PolicyVersion(), next); err != nil {
				t.Error(err)
				return
			}
		}
	}()
	for i := 0; i < 200; i++ {
		g, b, err := s.ReadAccessState(testContext)
		if err != nil {
			t.Fatal(err)
		}
		if g.PolicyVersion() > 1 && !reflect.DeepEqual(g.BudgetIDs(), []budget.BudgetID{budget.BudgetID(fmt.Sprintf("v%d", g.PolicyVersion()))}) {
			t.Fatal("torn allowlist/policy read")
		}
		if b.ConnectionID != g.ConnectionID() || b.OwnerID != g.OwnerID() {
			t.Fatal("torn connection ownership")
		}
	}
	wg.Wait()
}

func TestConnectionCASFencingTransitionsOwnershipAndCopy(t *testing.T) {
	s, _, _, c := openFixture(t, true)
	prepared, err := c.BeginRefresh(c.State().Version, "attempt", connection.CredentialRef{Provider: "synthetic", Location: "candidate", ImmutableVersion: "version-2"}, testTime, testTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Connections().CompareAndSwap(testContext, "conn", c.State().Version, prepared); err != nil {
		t.Fatal(err)
	}
	if err := s.Connections().CompareAndSwap(testContext, "conn", c.State().Version, prepared); !errors.Is(err, connection.ErrConflict) {
		t.Fatal(err)
	}
	loaded, err := s.Connections().Load(testContext, "conn")
	if err != nil {
		t.Fatal(err)
	}
	mutable := loaded.State()
	mutable.Attempt.ID = "mutated"
	again, _ := s.Connections().Load(testContext, "conn")
	if again.State().Attempt.ID != "attempt" {
		t.Fatal("mutable returned attempt aliases stored state")
	}
	for name, change := range map[string]func(*connection.State){
		"owner":               func(s *connection.State) { s.OwnerID = "foreign" },
		"id":                  func(s *connection.State) { s.ID = "foreign" },
		"skip phase":          func(s *connection.State) { s.Status = connection.Active; s.Attempt = nil },
		"generation rollback": func(s *connection.State) { s.Generation.Number = 0; s.Status = connection.ReconnectRequired },
	} {
		t.Run(name, func(t *testing.T) {
			state := loaded.State()
			state.Version++
			change(&state)
			next, err := connection.Restore(state)
			if err != nil {
				return
			}
			if err := s.Connections().CompareAndSwap(testContext, "conn", loaded.State().Version, next); !errors.Is(err, connection.ErrInvalidState) {
				t.Fatalf("unsafe transition: %v", err)
			}
		})
	}
	disabled, _ := loaded.Disable(loaded.State().Version)
	if err := s.Connections().CompareAndSwap(testContext, "conn", loaded.State().Version, disabled); err != nil {
		t.Fatal(err)
	}
	started, _ := loaded.MarkRequestStarted(loaded.State().Version, "attempt", loaded.State().Attempt.Fence, testTime)
	if err := s.Connections().CompareAndSwap(testContext, "conn", loaded.State().Version, started); !errors.Is(err, connection.ErrConflict) {
		t.Fatal(err)
	}
}

func expectation(g access.OwnerAccessGrant, c connection.YNABConnection) ports.AuthorizationExpectation {
	return ports.AuthorizationExpectation{OwnerID: g.OwnerID(), ConnectionID: g.ConnectionID(), PrincipalKey: g.PrincipalKey(), PolicyVersion: g.PolicyVersion(), ConnectionVersion: c.State().Version, ConnectionStatus: c.State().Status}
}

func TestAuthorizedActivationAtomicPolicyFence(t *testing.T) {
	s, _, g, c := openFixture(t, false)
	next := activeConnection(t, c)
	e := expectation(g, c)
	bad := e
	bad.PrincipalKey.Subject = "other"
	if err := s.CompareAndSwapAuthorized(testContext, bad, next); !errors.Is(err, access.ErrUnauthorized) {
		t.Fatal(err)
	}
	config := grantConfig(g)
	config.BudgetIDs = []budget.BudgetID{"budget-b"}
	replaced, _ := g.Replace(1, config)
	if err := s.ReplaceGrant(testContext, 1, replaced); err != nil {
		t.Fatal(err)
	}
	if err := s.CompareAndSwapAuthorized(testContext, e, next); !errors.Is(err, access.ErrUnauthorized) {
		t.Fatal(err)
	}
	e = expectation(replaced, c)
	if err := s.CompareAndSwapAuthorized(testContext, e, next); err != nil {
		t.Fatal(err)
	}
	if err := s.CompareAndSwapAuthorized(testContext, e, next); !errors.Is(err, connection.ErrConflict) {
		t.Fatal(err)
	}
}

func TestScopedRefreshCASChecksWholeScopeAndPolicyRace(t *testing.T) {
	s, _, g, c := openFixture(t, true)
	scope := access.ReadScope{OwnerID: g.OwnerID(), ConnectionID: g.ConnectionID(), PolicyVersion: g.PolicyVersion(), AuthorizationLineage: c.State().AuthorizationLineage, BudgetID: "budget-a"}
	next, err := c.BeginRefresh(c.State().Version, "scoped-attempt", connection.CredentialRef{Provider: "synthetic", Location: "candidate", ImmutableVersion: "v2"}, testTime, testTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*access.ReadScope){
		"owner":      func(s *access.ReadScope) { s.OwnerID = "foreign" },
		"connection": func(s *access.ReadScope) { s.ConnectionID = "foreign" },
		"policy":     func(s *access.ReadScope) { s.PolicyVersion++ },
		"lineage":    func(s *access.ReadScope) { s.AuthorizationLineage = "foreign" },
		"budget":     func(s *access.ReadScope) { s.BudgetID = "foreign" },
	} {
		t.Run(name, func(t *testing.T) {
			bad := scope
			mutate(&bad)
			if err := s.Connections().CompareAndSwapScoped(testContext, bad, c.State().Version, next); !errors.Is(err, access.ErrUnauthorized) {
				t.Fatal(err)
			}
		})
	}
	if err := s.Connections().CompareAndSwapScoped(testContext, scope, c.State().Version, next); err != nil {
		t.Fatal(err)
	}
	started, err := next.MarkRequestStarted(next.State().Version, "scoped-attempt", next.State().Attempt.Fence, testTime)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Connections().CompareAndSwapScoped(testContext, scope, next.State().Version, started); err != nil {
		t.Fatal(err)
	}
	proof := connection.PersistedCredential{Reference: started.State().Attempt.CandidateRef, AccessExpiresAt: testTime.Add(2 * time.Hour), Complete: true, ReadOnly: true}
	saved, err := started.MarkSecretSaved(started.State().Version, "scoped-attempt", started.State().Attempt.Fence, proof, testTime)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Connections().CompareAndSwapScoped(testContext, scope, started.State().Version, saved); err != nil {
		t.Fatal(err)
	}
	committed, err := saved.CommitRefresh(saved.State().Version, "scoped-attempt", saved.State().Attempt.Fence)
	if err != nil {
		t.Fatal(err)
	}
	cfg := grantConfig(g)
	cfg.Enabled = false
	disabled, _ := g.Replace(1, cfg)
	if err := s.ReplaceGrant(testContext, 1, disabled); err != nil {
		t.Fatal(err)
	}
	if err := s.Connections().CompareAndSwapScoped(testContext, scope, saved.State().Version, committed); !errors.Is(err, access.ErrUnauthorized) {
		t.Fatal(err)
	}
	current, err := s.Connections().Load(testContext, "conn")
	if err != nil {
		t.Fatal(err)
	}
	if current.State().Generation.Number != 1 || current.State().Status != connection.Refreshing {
		t.Fatal("revoked refresh generation became active")
	}
}

func TestCompleteRefreshTransitionAndListScope(t *testing.T) {
	s, _, g, c := openFixture(t, true)
	scope := access.ReadScope{OwnerID: g.OwnerID(), ConnectionID: g.ConnectionID(), PolicyVersion: g.PolicyVersion(), AuthorizationLineage: c.State().AuthorizationLineage}
	p, err := c.BeginRefresh(c.State().Version, "attempt", connection.CredentialRef{Provider: "synthetic", Location: "candidate", ImmutableVersion: "v2"}, testTime, testTime.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	started, err := p.MarkRequestStarted(p.State().Version, "attempt", p.State().Attempt.Fence, testTime)
	if err != nil {
		t.Fatal(err)
	}
	saved, err := started.MarkSecretSaved(started.State().Version, "attempt", started.State().Attempt.Fence, connection.PersistedCredential{Reference: started.State().Attempt.CandidateRef, AccessExpiresAt: testTime.Add(2 * time.Hour), Complete: true, ReadOnly: true}, testTime)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := saved.CommitRefresh(saved.State().Version, "attempt", saved.State().Attempt.Fence)
	if err != nil {
		t.Fatal(err)
	}
	for _, next := range []connection.YNABConnection{p, started, saved, committed} {
		if err := s.Connections().CompareAndSwapScoped(testContext, scope, c.State().Version, next); err != nil {
			t.Fatal(err)
		}
		c = next
	}
	current, err := s.Connections().Load(testContext, "conn")
	if err != nil {
		t.Fatal(err)
	}
	if current.State().Generation.Number != 2 || current.State().Status != connection.Active || current.State().Attempt.Phase != connection.Committed {
		t.Fatal("valid generation not committed")
	}
}

func TestRefreshAmbiguityAndPreparedAbandonTransitions(t *testing.T) {
	for _, phase := range []string{"abandon", "ambiguous"} {
		t.Run(phase, func(t *testing.T) {
			s, _, _, c := openFixture(t, true)
			prepared, err := c.BeginRefresh(c.State().Version, "attempt", connection.CredentialRef{Provider: "synthetic", Location: "candidate", ImmutableVersion: "v2"}, testTime, testTime.Add(time.Minute))
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Connections().CompareAndSwap(testContext, "conn", c.State().Version, prepared); err != nil {
				t.Fatal(err)
			}
			c = prepared
			var next connection.YNABConnection
			if phase == "abandon" {
				next, err = c.AbandonPrepared(c.State().Version, "attempt", c.State().Attempt.Fence, true, testTime.Add(time.Minute))
			} else {
				started, e := c.MarkRequestStarted(c.State().Version, "attempt", c.State().Attempt.Fence, testTime)
				if e != nil {
					t.Fatal(e)
				}
				if e := s.Connections().CompareAndSwap(testContext, "conn", c.State().Version, started); e != nil {
					t.Fatal(e)
				}
				c = started
				next, err = c.MarkAmbiguous(c.State().Version, "attempt", c.State().Attempt.Fence)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := s.Connections().CompareAndSwap(testContext, "conn", c.State().Version, next); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestColdQuotaDurableFullHourAndReopen(t *testing.T) {
	s, path, _, _ := openFixture(t, true)
	if _, err := s.Quotas().Load(testContext, "conn"); !errors.Is(err, admission.ErrUntrustedLedger) {
		t.Fatal(err)
	}
	if _, err := s.Quotas().Reserve(testContext, "conn", "first", testTime); !errors.Is(err, admission.ErrCooldown) {
		t.Fatal(err)
	}
	w, err := s.Quotas().Load(testContext, "conn")
	if err != nil {
		t.Fatal(err)
	}
	if !w.State().CooldownUntil.Equal(testTime.Add(time.Hour+time.Second)) || len(w.State().Reservations) != 0 {
		t.Fatal("cold ledger admitted calls")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.Quotas().Reserve(testContext, "conn", "second", testTime.Add(time.Hour)); !errors.Is(err, admission.ErrCooldown) {
		t.Fatal(err)
	}
	admit := testTime.Add(time.Hour + time.Second)
	if _, err := reopened.Quotas().Reserve(testContext, "conn", "second", admit); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.Quotas().Reserve(testContext, "conn", "second", admit); !errors.Is(err, admission.ErrDuplicateReservation) {
		t.Fatal(err)
	}
}

func warmQuota(t *testing.T, s *Store) time.Time {
	t.Helper()
	if _, err := s.Quotas().Reserve(testContext, "conn", "cold", testTime); !errors.Is(err, admission.ErrCooldown) {
		t.Fatal(err)
	}
	return testTime.Add(time.Hour + time.Second)
}

func TestQuotaConcurrentStoresCannotOverAdmit(t *testing.T) {
	s, path, _, _ := openFixture(t, true)
	now := warmQuota(t, s)
	stores := []*Store{s}
	for i := 0; i < 7; i++ {
		other, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer other.Close()
		stores = append(stores, other)
	}
	var accepted atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 256; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_, err := stores[i%len(stores)].Quotas().Reserve(testContext, "conn", fmt.Sprintf("attempt-%d", i), now)
			if err == nil {
				accepted.Add(1)
			} else if !errors.Is(err, admission.ErrRateLimited) {
				t.Errorf("unexpected admission failure: %v", err)
			}
		}(i)
	}
	wg.Wait()
	if accepted.Load() != 180 {
		t.Fatalf("admitted %d", accepted.Load())
	}
	w, err := s.Quotas().Load(testContext, "conn")
	if err != nil {
		t.Fatal(err)
	}
	if len(w.State().Reservations) != 180 || w.State().Version != 181 {
		t.Fatal("durable count/version differs from admission")
	}
	if _, err := s.Quotas().Reserve(testContext, "conn", "rollback", now.Add(-time.Nanosecond)); !errors.Is(err, admission.ErrClockRollback) {
		t.Fatal(err)
	}
	boundary := now.Add(time.Hour + time.Second)
	if _, err := s.Quotas().Reserve(testContext, "conn", "boundary", boundary); !errors.Is(err, admission.ErrRateLimited) {
		t.Fatal(err)
	}
	if _, err := s.Quotas().Reserve(testContext, "conn", "expired", boundary.Add(time.Nanosecond)); err != nil {
		t.Fatal(err)
	}
	w, _ = s.Quotas().Load(testContext, "conn")
	if len(w.State().Reservations) != 1 {
		t.Fatal("old reservations not pruned")
	}
}

func TestQuotaRollbackCooldownCancellationAndRotation(t *testing.T) {
	s, _, _, c := openFixture(t, true)
	now := warmQuota(t, s)
	mustExec(t, s, `CREATE TRIGGER inject_failure BEFORE UPDATE ON quota_windows BEGIN SELECT RAISE(ABORT,'synthetic error'); END`)
	if _, err := s.Quotas().Reserve(testContext, "conn", "failed", now); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	w, _ := s.Quotas().Load(testContext, "conn")
	if len(w.State().Reservations) != 0 {
		t.Fatal("failed reservation partly persisted")
	}
	mustExec(t, s, "DROP TRIGGER inject_failure")
	if _, err := s.Quotas().Reserve(testContext, "conn", "admitted", now); err != nil {
		t.Fatal(err)
	}
	cancelled, cancel := context.WithCancel(testContext)
	cancel()
	until := now.Add(2 * time.Hour)
	if err := s.Quotas().RecordCooldown(cancelled, "conn", until, now); err != nil {
		t.Fatal(err)
	}
	if err := s.Quotas().RecordCooldown(testContext, "conn", now.Add(time.Minute), now); err != nil {
		t.Fatal(err)
	}
	w, _ = s.Quotas().Load(testContext, "conn")
	if !w.State().CooldownUntil.Equal(until) {
		t.Fatal("cooldown shortened")
	}
	if err := s.Quotas().RecordCooldown(testContext, "conn", until, now.Add(-time.Nanosecond)); !errors.Is(err, admission.ErrClockRollback) {
		t.Fatal(err)
	}
	state := w.State()
	state.Reservations[0].AttemptID = "changed"
	loaded, _ := s.Quotas().Load(testContext, "conn")
	if loaded.State().Reservations[0].AttemptID != "admitted" {
		t.Fatal("returned quota aliases storage")
	}
	proof := connection.PersistedCredential{Reference: connection.CredentialRef{Provider: "synthetic", Location: "reconnected", ImmutableVersion: "v2"}, AccessExpiresAt: now.Add(4 * time.Hour), ReadOnly: true, Complete: true}
	reconnected, err := c.Activate(c.State().Version, "new-lineage", proof, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Connections().CompareAndSwap(testContext, "conn", c.State().Version, reconnected); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Quotas().Reserve(testContext, "conn", "after-reconnect", now); !errors.Is(err, admission.ErrCooldown) {
		t.Fatal(err)
	}
}

func TestMetadataCorruptionFailsClosed(t *testing.T) {
	for name, mutate := range map[string]func(string) string{
		"malformed": func(string) string { return "{broken" },
		"unknown field": func(raw string) string {
			return strings.TrimSuffix(raw, "}") + `,"AccessToken":"synthetic-forbidden-field"}`
		},
		"duplicate field":    func(raw string) string { return strings.TrimSuffix(raw, "}") + `,"Version":2}` },
		"missing field":      func(string) string { return `{"ID":"conn"}` },
		"mismatched version": func(raw string) string { return strings.Replace(raw, `"Version":2`, `"Version":9`, 1) },
	} {
		t.Run(name, func(t *testing.T) {
			s, _, _, _ := openFixture(t, true)
			var raw string
			if err := s.db.QueryRow("SELECT metadata FROM connections").Scan(&raw); err != nil {
				t.Fatal(err)
			}
			mustExec(t, s, "UPDATE connections SET metadata=?", mutate(raw))
			if _, err := s.Connections().Load(testContext, "conn"); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("decoded corrupt metadata: %v", err)
			}
			if _, _, err := s.ReadAccessState(testContext); !errors.Is(err, ErrCorrupt) {
				t.Fatal(err)
			}
		})
	}
	for _, raw := range []string{`{"Key":"conn"}`, `{"Key":"other","Version":1}`, `not-json`} {
		t.Run("quota "+raw, func(t *testing.T) {
			s, _, _, _ := openFixture(t, true)
			now := warmQuota(t, s)
			mustExec(t, s, "UPDATE quota_windows SET metadata=?", raw)
			if _, err := s.Quotas().Load(testContext, "conn"); !errors.Is(err, admission.ErrUntrustedLedger) {
				t.Fatal(err)
			}
			if _, err := s.Quotas().Reserve(testContext, "conn", "denied", now); !errors.Is(err, admission.ErrUntrustedLedger) {
				t.Fatal(err)
			}
			if err := s.Quotas().RecordCooldown(testContext, "conn", now.Add(time.Hour), now); !errors.Is(err, admission.ErrUntrustedLedger) {
				t.Fatal(err)
			}
		})
	}
}

func TestVersionOverflowFailsClosed(t *testing.T) {
	s, _, g, c := openFixture(t, false)
	cfg := grantConfig(g)
	cfg.PolicyVersion = math.MaxInt64
	g, _ = access.NewOwnerAccessGrant(cfg)
	mustExec(t, s, "UPDATE owners SET policy_version=?", int64(math.MaxInt64))
	cfg.PolicyVersion = uint64(math.MaxInt64) + 1
	next, _ := access.NewOwnerAccessGrant(cfg)
	if err := s.ReplaceGrant(testContext, g.PolicyVersion(), next); err == nil {
		t.Fatal("grant overflow accepted")
	}
	state := c.State()
	state.Version = math.MaxInt64
	c, _ = connection.Restore(state)
	raw, _ := encodeConnection(c)
	mustExec(t, s, "UPDATE connections SET state_version=?,metadata=?", int64(math.MaxInt64), raw)
	disabled, _ := c.Disable(c.State().Version)
	if err := s.Connections().CompareAndSwap(testContext, "conn", c.State().Version, disabled); !errors.Is(err, connection.ErrConflict) {
		t.Fatal(err)
	}
}

func TestOpenReadOnlyDoesNotWriteAndRejectsAllMutations(t *testing.T) {
	s, path, g, c := openFixture(t, true)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	infoBefore, _ := os.Stat(path)
	ro, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ro.ReadAccessState(testContext); err != nil {
		t.Fatal(err)
	}
	if err := ro.Initialize(testContext, g, c); !errors.Is(err, ErrReadOnly) {
		t.Fatal(err)
	}
	cfg := grantConfig(g)
	cfg.Enabled = false
	next, _ := g.Replace(1, cfg)
	if err := ro.ReplaceGrant(testContext, 1, next); !errors.Is(err, ErrReadOnly) {
		t.Fatal(err)
	}
	disabled, _ := c.Disable(c.State().Version)
	if err := ro.Connections().CompareAndSwap(testContext, "conn", c.State().Version, disabled); !errors.Is(err, ErrReadOnly) {
		t.Fatal(err)
	}
	if _, err := ro.Quotas().Reserve(testContext, "conn", "deny", testTime); !errors.Is(err, ErrReadOnly) {
		t.Fatal(err)
	}
	if err := ro.Quotas().RecordCooldown(testContext, "conn", testTime.Add(time.Hour), testTime); !errors.Is(err, ErrReadOnly) {
		t.Fatal(err)
	}
	if err := ro.Close(); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(path)
	infoAfter, _ := os.Stat(path)
	if !reflect.DeepEqual(before, after) || !infoBefore.ModTime().Equal(infoAfter.ModTime()) {
		t.Fatal("read-only inspection modified file")
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Fatal("read-only inspection created sidecar")
	}
}

func TestPrivateRollbackJournalAndCancelledAdmission(t *testing.T) {
	s, path, _, _ := openFixture(t, true)
	now := warmQuota(t, s)
	tx, err := s.db.BeginTx(testContext, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(testContext, "UPDATE owners SET policy_version=2"); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path + "-journal")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0077 != 0 {
		t.Fatal("rollback journal not private")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(testContext)
	cancel()
	if _, err := s.Quotas().Reserve(ctx, "conn", "cancelled", now); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	w, err := s.Quotas().Load(testContext, "conn")
	if err != nil {
		t.Fatal(err)
	}
	if len(w.State().Reservations) != 0 {
		t.Fatal("cancelled call acquired a reservation")
	}
}

func TestUnknownQuotaKeyCannotCreateOrReuseLedger(t *testing.T) {
	s, _, _, _ := openFixture(t, true)
	if _, err := s.Quotas().Reserve(testContext, "foreign", "attempt", testTime); !errors.Is(err, ErrUninitialized) {
		t.Fatal(err)
	}
	if err := s.Quotas().RecordCooldown(testContext, "foreign", testTime.Add(time.Hour), testTime); !errors.Is(err, ErrUninitialized) {
		t.Fatal(err)
	}
	var count int
	if err := s.db.QueryRow("SELECT count(*) FROM quota_windows").Scan(&count); err != nil || count != 0 {
		t.Fatal("foreign ledger created", err)
	}
}

func TestColdCooldownCreatesConservativeWindowAndBackupWithoutQuota(t *testing.T) {
	s, path, _, _ := openFixture(t, true)
	if err := s.Quotas().RecordCooldown(testContext, "conn", testTime.Add(time.Minute), testTime); err != nil {
		t.Fatal(err)
	}
	w, err := s.Quotas().Load(testContext, "conn")
	if err != nil {
		t.Fatal(err)
	}
	if !w.State().CooldownUntil.Equal(testTime.Add(time.Hour + time.Second)) {
		t.Fatal("cold cooldown permits early admission")
	}
	mustExec(t, s, "DELETE FROM quota_windows")
	s.Close()
	restored, err := OpenRestored(path, testTime)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	w, err = restored.Quotas().Load(testContext, "conn")
	if err != nil {
		t.Fatal(err)
	}
	if !w.State().CooldownUntil.Equal(testTime.Add(time.Hour + time.Second)) {
		t.Fatal("backup without quota permits early admission")
	}
}

func TestOpenPathsSchemaAndPermissions(t *testing.T) {
	for _, path := range []string{"", ":memory:", "file:synthetic?mode=memory"} {
		if s, err := Open(path); err == nil {
			s.Close()
			t.Fatal("accepted non-file path")
		}
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "metadata.db")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0600 {
		t.Fatal("new file not private")
	}
	link := filepath.Join(dir, "link.db")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); !errors.Is(err, ErrInvalidPath) {
		t.Fatal(err)
	}
	if _, err := Open(dir); !errors.Is(err, ErrInvalidPath) {
		t.Fatal(err)
	}
	mustExec(t, s, "PRAGMA user_version=2")
	s.Close()
	if _, err := Open(path); !errors.Is(err, ErrSchema) {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); !errors.Is(err, ErrInvalidPath) {
		t.Fatal(err)
	}
	info, _ = os.Stat(path)
	if info.Mode().Perm() != 0644 {
		t.Fatal("existing permissions silently changed")
	}
	other := filepath.Join(t.TempDir(), "unrelated.db")
	f, err := os.OpenFile(other, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f.Close()
	db, err := sql.Open("sqlite", other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE unrelated(x INTEGER)"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if _, err := Open(other); !errors.Is(err, ErrSchema) {
		t.Fatal(err)
	}
}

func TestExplicitBackupRestoreRequiresReconnectAndConservativeQuota(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(fmt.Sprint(disabled), func(t *testing.T) {
			s, path, g, c := openFixture(t, true)
			now := warmQuota(t, s)
			if _, err := s.Quotas().Reserve(testContext, "conn", "before-backup", now); err != nil {
				t.Fatal(err)
			}
			until := now.Add(4 * time.Hour)
			if err := s.Quotas().RecordCooldown(testContext, "conn", until, now); err != nil {
				t.Fatal(err)
			}
			if disabled {
				next, _ := c.Disable(c.State().Version)
				if err := s.Connections().CompareAndSwap(testContext, "conn", c.State().Version, next); err != nil {
					t.Fatal(err)
				}
				cfg := grantConfig(g)
				cfg.Enabled = false
				ng, _ := g.Replace(1, cfg)
				if err := s.ReplaceGrant(testContext, 1, ng); err != nil {
					t.Fatal(err)
				}
			}
			s.Close()
			restored, err := OpenRestored(path, testTime)
			if err != nil {
				t.Fatal(err)
			}
			defer restored.Close()
			got, binding, err := restored.ReadAccessState(testContext)
			if err != nil {
				t.Fatal(err)
			}
			if binding.Active {
				t.Fatal("backup credential still active")
			}
			conn, err := restored.Connections().Load(testContext, "conn")
			if err != nil {
				t.Fatal(err)
			}
			want := connection.ReconnectRequired
			if disabled {
				want = connection.Disabled
			}
			if conn.State().Status != want || got.Enabled() == disabled {
				t.Fatal("restore changed administrative disabled state")
			}
			w, err := restored.Quotas().Load(testContext, "conn")
			if err != nil {
				t.Fatal(err)
			}
			if !w.State().CooldownUntil.Equal(until) || !w.State().LastObserved.Equal(now) {
				t.Fatal("restore weakened prior clock/cooldown")
			}
			if _, err := restored.Quotas().Reserve(testContext, "conn", "restored", now); !errors.Is(err, admission.ErrCooldown) {
				t.Fatal(err)
			}
		})
	}
}

func TestCorruptBackupRollsBackReconnectAndLeavesNoUsableStore(t *testing.T) {
	s, path, _, c := openFixture(t, true)
	warmQuota(t, s)
	mustExec(t, s, "UPDATE quota_windows SET metadata='malformed'")
	s.Close()
	if restored, err := OpenRestored(path, testTime); restored != nil || !errors.Is(err, admission.ErrUntrustedLedger) {
		if restored != nil {
			restored.Close()
		}
		t.Fatalf("corrupt backup opened: %v", err)
	}
	ro, err := OpenReadOnly(path)
	if err != nil {
		t.Fatal(err)
	}
	defer ro.Close()
	got, err := ro.Connections().Load(testContext, "conn")
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.State(), c.State()) {
		t.Fatal("failed restore committed only part of recovery transaction")
	}
}
