package application

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/adapters/memory"
	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/budget"
	"github.com/guygrigsby/ynab-mcp/internal/domain/inquiry"
)

type state struct {
	mu      sync.Mutex
	grant   access.OwnerAccessGrant
	binding access.ConnectionBinding
}

func (s *state) ReadAccessState(context.Context) (access.OwnerAccessGrant, access.ConnectionBinding, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.grant, s.binding, nil
}
func (s *state) disable() { s.mu.Lock(); defer s.mu.Unlock(); s.binding.Active = false }

type gateway struct {
	calls atomic.Int64
	fn    func(context.Context, access.ReadScope, inquiry.Query) (inquiry.ReadResult, error)
}

func (g *gateway) Read(ctx context.Context, s access.ReadScope, q inquiry.Query) (inquiry.ReadResult, error) {
	g.calls.Add(1)
	return g.fn(ctx, s, q)
}
func fixture(t *testing.T) (*state, *gateway, *ReadService, access.Principal) {
	t.Helper()
	p := access.Principal{Key: access.PrincipalKey{Issuer: "https://issuer.example", Subject: "owner-sub"}, Scopes: []string{"budget:read"}}
	grant, err := access.NewOwnerAccessGrant(access.GrantConfig{OwnerID: "owner", ConnectionID: "connection", ConnectionOwnerID: "owner", PrincipalKey: p.Key, BudgetIDs: []budget.BudgetID{"b1"}, Enabled: true, PolicyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	st := &state{grant: grant, binding: access.ConnectionBinding{OwnerID: "owner", ConnectionID: "connection", AuthorizationLineage: "lineage", Active: true}}
	g := &gateway{fn: func(context.Context, access.ReadScope, inquiry.Query) (inquiry.ReadResult, error) {
		return result(`{"id":"a1"}`, `{"id":"a2"}`), nil
	}}
	store, err := memory.NewSnapshotStore(memory.Options{})
	if err != nil {
		t.Fatal(err)
	}
	svc, err := NewReadService(st, g, store)
	if err != nil {
		t.Fatal(err)
	}
	return st, g, svc, p
}
func result(items ...string) inquiry.ReadResult {
	now := time.Now().UTC()
	r := inquiry.ReadResult{ObservedFrom: now, ObservedAt: now, Coverage: inquiry.Coverage{CollectionComplete: true}}
	for _, s := range items {
		r.Items = append(r.Items, json.RawMessage(s))
	}
	return r
}
func TestDeniedCallsNeverReachUpstream(t *testing.T) {
	_, g, s, p := fixture(t)
	for _, q := range []inquiry.Query{{Tool: "list_accounts", BudgetID: "foreign"}, {Tool: "delete_transaction", BudgetID: "b1"}, {Tool: "list_accounts", BudgetID: "b1", IncludeNotes: true}} {
		if _, err := s.Read(context.Background(), p, q); err == nil {
			t.Fatal("allowed denied query")
		}
	}
	p.Key.Subject = "another-owner"
	if _, err := s.Read(context.Background(), p, inquiry.Query{Tool: "list_accounts", BudgetID: "b1"}); err == nil {
		t.Fatal("allowed foreign owner")
	}
	if g.calls.Load() != 0 {
		t.Fatal("denied query called upstream")
	}
}
func TestListFiltersBeforeSnapshot(t *testing.T) {
	_, g, s, p := fixture(t)
	g.fn = func(context.Context, access.ReadScope, inquiry.Query) (inquiry.ReadResult, error) {
		return result(`{"id":"foreign","name":"PRIVATE"}`, `{"id":"b1","name":"Allowed"}`), nil
	}
	page, err := s.Read(context.Background(), p, inquiry.Query{Tool: "list_budgets"})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 {
		t.Fatal("unfiltered plans")
	}
	var v budget.BudgetView
	_ = json.Unmarshal(page.Items[0], &v)
	if v.ID != "b1" {
		t.Fatal("foreign plan leaked")
	}
}
func TestRevocationDuringFetchPreventsDisclosure(t *testing.T) {
	st, g, s, p := fixture(t)
	g.fn = func(context.Context, access.ReadScope, inquiry.Query) (inquiry.ReadResult, error) {
		st.disable()
		return result(`{"id":"a1"}`), nil
	}
	page, err := s.Read(context.Background(), p, inquiry.Query{Tool: "list_accounts", BudgetID: "b1"})
	if !errors.Is(err, inquiry.ErrUnauthorizedScope) || len(page.Items) != 0 {
		t.Fatal("revoked data disclosed", err)
	}
}
func TestCursorReadsNoUpstreamAndReauthorizes(t *testing.T) {
	st, g, s, p := fixture(t)
	q := inquiry.Query{Tool: "list_accounts", BudgetID: "b1", Limit: 1}
	page, err := s.Read(context.Background(), p, q)
	if err != nil {
		t.Fatal(err)
	}
	q.Cursor = page.Metadata.NextCursor
	if q.Cursor == "" {
		t.Fatal("missing cursor")
	}
	next, err := s.Read(context.Background(), p, q)
	if err != nil || len(next.Items) != 1 || g.calls.Load() != 1 {
		t.Fatal("cursor refetched", err)
	}
	st.disable()
	if _, err := s.Read(context.Background(), p, q); !errors.Is(err, inquiry.ErrUnauthorizedScope) {
		t.Fatal("cursor bypassed revocation", err)
	}
}
func TestConcurrentIdenticalReadsCoalesce(t *testing.T) {
	_, g, s, p := fixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	g.fn = func(context.Context, access.ReadScope, inquiry.Query) (inquiry.ReadResult, error) {
		select {
		case <-entered:
		default:
			close(entered)
		}
		<-release
		return result(`{"id":"a1"}`), nil
	}
	var wg sync.WaitGroup
	errs := make(chan error, 10)
	q := inquiry.Query{Tool: "list_accounts", BudgetID: "b1"}
	for range 10 {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := s.Read(context.Background(), p, q); errs <- err }()
	}
	<-entered
	// Wait until every caller has entered the bounded service queue; no timing
	// assumption about the upstream transport is required.
	deadline := time.Now().Add(time.Second)
	for len(s.queue) < 10 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if len(s.queue) != 10 {
		t.Fatal("callers did not enter")
	}
	close(release)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if g.calls.Load() != 1 {
		t.Fatal("identical reads were not coalesced", g.calls.Load())
	}
}
