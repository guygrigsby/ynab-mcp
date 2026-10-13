package upstream

import (
	"context"
	"errors"
	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/admission"
	"github.com/guygrigsby/ynab-mcp/internal/domain/budget"
	"github.com/guygrigsby/ynab-mcp/internal/domain/inquiry"
	"testing"
	"time"
)

type state struct {
	g access.OwnerAccessGrant
	b access.ConnectionBinding
}

func (s *state) ReadAccessState(context.Context) (access.OwnerAccessGrant, access.ConnectionBinding, error) {
	return s.g, s.b, nil
}

type ledger struct {
	calls     int
	err       error
	ids       map[string]bool
	key       admission.QuotaKey
	cancelled bool
}

func (l *ledger) Load(context.Context, admission.QuotaKey) (admission.QuotaWindow, error) {
	return admission.QuotaWindow{}, nil
}
func (l *ledger) Reserve(ctx context.Context, k admission.QuotaKey, id string, now time.Time) (admission.Reservation, error) {
	l.calls++
	l.key = k
	if l.ids[id] {
		panic("reused attempt")
	}
	l.ids[id] = true
	return admission.Reservation{AttemptID: id, ReservedAt: now}, l.err
}
func (l *ledger) RecordCooldown(ctx context.Context, k admission.QuotaKey, until, now time.Time) error {
	l.calls++
	l.cancelled = ctx.Err() != nil
	l.key = k
	return l.err
}
func setup(t *testing.T) (*QuotaAdmission, *state, *ledger, access.ReadScope) {
	t.Helper()
	g, err := access.NewOwnerAccessGrant(access.GrantConfig{OwnerID: "owner", ConnectionID: "connection", ConnectionOwnerID: "owner", PrincipalKey: access.PrincipalKey{Issuer: "https://issuer.example", Subject: "subject"}, BudgetIDs: []budget.BudgetID{"budget"}, Enabled: true, PolicyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	s := &state{g: g, b: access.ConnectionBinding{OwnerID: "owner", ConnectionID: "connection", AuthorizationLineage: "lineage", Active: true}}
	l := &ledger{ids: map[string]bool{}}
	q, _ := NewQuotaAdmission(s, l)
	return q, s, l, access.ReadScope{OwnerID: "owner", ConnectionID: "connection", AuthorizationLineage: "lineage", PolicyVersion: 1, BudgetID: "budget"}
}
func TestReservedEachAttemptStableConnection(t *testing.T) {
	q, _, l, s := setup(t)
	for range 3 {
		if err := q.Reserve(context.Background(), s); err != nil {
			t.Fatal(err)
		}
	}
	if l.calls != 3 || len(l.ids) != 3 || l.key != "connection" {
		t.Fatal("reservation mismatch")
	}
}
func TestDeniedScopeNoReservation(t *testing.T) {
	q, st, l, s := setup(t)
	for _, mutate := range []func(*access.ReadScope){func(s *access.ReadScope) { s.OwnerID = "other" }, func(s *access.ReadScope) { s.BudgetID = "other" }, func(s *access.ReadScope) { s.AuthorizationLineage = "other" }, func(s *access.ReadScope) { s.PolicyVersion++ }} {
		bad := s
		mutate(&bad)
		if !errors.Is(q.Reserve(context.Background(), bad), inquiry.ErrUnauthorizedScope) {
			t.Fatal("foreign scope")
		}
	}
	st.b.Active = false
	if !errors.Is(q.Reserve(context.Background(), s), inquiry.ErrUnauthorizedScope) || l.calls != 0 {
		t.Fatal("unauthorized reservation")
	}
}
func TestCooldownPersistsAfterCancellationAndRevocation(t *testing.T) {
	q, st, l, s := setup(t)
	st.b.Active = false
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := q.RecordCooldown(ctx, s, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if l.calls != 1 || l.cancelled {
		t.Fatal("cooldown lost on cancellation")
	}
}
func TestSanitizedFailures(t *testing.T) {
	q, _, l, s := setup(t)
	l.err = errors.New("private database path")
	if !errors.Is(q.Reserve(context.Background(), s), inquiry.ErrUpstreamUnavailable) {
		t.Fatal("raw error")
	}
	l.err = admission.ErrCooldown
	if !errors.Is(q.Reserve(context.Background(), s), inquiry.ErrRateLimited) {
		t.Fatal("cooldown")
	}
}
