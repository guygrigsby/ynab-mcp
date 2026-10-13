// Package application sequences authorization, bounded upstream reads and
// immutable snapshots. It does not know about HTTP, MCP or any database.
package application

import (
	"context"
	"encoding/json"
	"errors"
	"sync"

	"github.com/guygrigsby/ynab-mcp/internal/application/ports"
	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/budget"
	"github.com/guygrigsby/ynab-mcp/internal/domain/inquiry"
)

// ReadService has a bounded admission queue and coalesces identical authorized
// in-flight queries. It never uses a cursor or MCP session as authorization.
type ReadService struct {
	state     ports.AccessStateRepository
	upstream  ports.YNABReadGateway
	snapshots ports.SnapshotStore
	queue     chan struct{}
	active    chan struct{}
	mu        sync.Mutex
	flights   map[string]*flight
}
type flight struct {
	done chan struct{}
	page inquiry.Page
	err  error
}

func NewReadService(state ports.AccessStateRepository, upstream ports.YNABReadGateway, snapshots ports.SnapshotStore) (*ReadService, error) {
	if state == nil || upstream == nil || snapshots == nil {
		return nil, errors.New("all read service ports are required")
	}
	return &ReadService{state: state, upstream: upstream, snapshots: snapshots, queue: make(chan struct{}, 32), active: make(chan struct{}, 2), flights: make(map[string]*flight)}, nil
}

func (s *ReadService) authorize(ctx context.Context, p access.Principal, q inquiry.Query) (access.OwnerAccessGrant, access.ReadScope, error) {
	g, b, err := s.state.ReadAccessState(ctx)
	if err != nil {
		return access.OwnerAccessGrant{}, access.ReadScope{}, inquiry.ErrUnauthorizedScope
	}
	var scope access.ReadScope
	if q.Tool == "list_budgets" {
		scope, err = g.AuthorizeList(p, b)
	} else {
		scope, err = g.Authorize(p, q.BudgetID, b)
	}
	if err != nil || q.IncludeNotes && !g.AllowNotes() {
		return access.OwnerAccessGrant{}, access.ReadScope{}, inquiry.ErrUnauthorizedScope
	}
	return g, scope, nil
}

func (s *ReadService) Read(ctx context.Context, p access.Principal, q inquiry.Query) (inquiry.Page, error) {
	var zero inquiry.Page
	// Even invalid/guessed tools cannot skip authorization. Query validation below
	// prevents unknown operations from reaching the gateway.
	q, err := q.Normalize()
	if err != nil {
		return zero, inquiry.ErrInvalidQuery
	}
	grant, scope, err := s.authorize(ctx, p, q)
	if err != nil {
		return zero, err
	}
	select {
	case s.queue <- struct{}{}:
		defer func() { <-s.queue }()
	default:
		return zero, inquiry.ErrRateLimited
	}
	var page inquiry.Page
	if q.Cursor != "" {
		page, err = s.snapshots.Read(ctx, scope, q)
	} else {
		page, err = s.fetch(ctx, scope, grant, q)
	}
	if err != nil {
		return zero, err
	}
	// Revocation while a network call or snapshot lookup was in flight invalidates
	// the entire response, even if asynchronous cache cleanup has not happened.
	_, current, err := s.authorize(ctx, p, q)
	if err != nil || current != scope {
		return zero, inquiry.ErrUnauthorizedScope
	}
	if err := ctx.Err(); err != nil {
		return zero, err
	}
	return page, nil
}

func (s *ReadService) fetch(ctx context.Context, scope access.ReadScope, grant access.OwnerAccessGrant, q inquiry.Query) (inquiry.Page, error) {
	var zero inquiry.Page
	encoded, err := json.Marshal(struct {
		Owner      access.OwnerID
		Connection access.ConnectionID
		Lineage    string
		Version    uint64
		Budget     budget.BudgetID
		Query      inquiry.Query
	}{scope.OwnerID, scope.ConnectionID, scope.AuthorizationLineage, scope.PolicyVersion, scope.BudgetID, q})
	if err != nil {
		return zero, inquiry.ErrInvalidQuery
	}
	key := string(encoded)
	s.mu.Lock()
	if f, ok := s.flights[key]; ok {
		s.mu.Unlock()
		select {
		case <-ctx.Done():
			return zero, ctx.Err()
		case <-f.done:
			return clonePage(f.page), f.err
		}
	}
	f := &flight{done: make(chan struct{})}
	s.flights[key] = f
	s.mu.Unlock()
	defer func() { s.mu.Lock(); delete(s.flights, key); close(f.done); s.mu.Unlock() }()
	select {
	case s.active <- struct{}{}:
		defer func() { <-s.active }()
	case <-ctx.Done():
		f.err = ctx.Err()
		return zero, f.err
	}
	result, err := s.upstream.Read(ctx, scope, q)
	if err != nil {
		f.err = err
		return zero, err
	}
	if q.Tool == "list_budgets" {
		allowed := map[budget.BudgetID]bool{}
		for _, id := range grant.BudgetIDs() {
			allowed[id] = true
		}
		filtered := make([]json.RawMessage, 0, len(result.Items))
		for _, item := range result.Items {
			var v budget.BudgetView
			if json.Unmarshal(item, &v) != nil || budget.ValidateID(string(v.ID)) != nil {
				f.err = inquiry.ErrDataInvalid
				return zero, f.err
			}
			if allowed[v.ID] {
				filtered = append(filtered, item)
			}
		}
		result.Items = filtered
	}
	f.page, f.err = s.snapshots.Publish(ctx, scope, q, result)
	return clonePage(f.page), f.err
}

func clonePage(p inquiry.Page) inquiry.Page {
	out := p
	out.Items = make([]json.RawMessage, len(p.Items))
	for i, item := range p.Items {
		out.Items[i] = append(json.RawMessage(nil), item...)
	}
	out.Metadata.Warnings = append([]string(nil), p.Metadata.Warnings...)
	return out
}
