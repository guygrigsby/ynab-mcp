package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"reflect"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/application/ports"
	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/connection"
)

type connectionRepository struct{ store *Store }

var _ ports.ScopedConnectionRepository = connectionRepository{}

func (r connectionRepository) Load(ctx context.Context, id access.ConnectionID) (connection.YNABConnection, error) {
	return loadConnection(ctx, r.store.db, id)
}

func loadConnection(ctx context.Context, q querier, id access.ConnectionID) (connection.YNABConnection, error) {
	var owner, raw string
	var version int64
	err := q.QueryRowContext(ctx, "SELECT owner_id,state_version,substr(metadata,1,65537) FROM connections WHERE connection_id=?", id).Scan(&owner, &version, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return connection.YNABConnection{}, ErrUninitialized
	}
	if err != nil {
		return connection.YNABConnection{}, dbError(ctx, err)
	}
	return decodeConnection(raw, id, access.OwnerID(owner), version)
}

func encodeConnection(c connection.YNABConnection) (string, error) {
	s := c.State()
	if s.Version > math.MaxInt64 {
		return "", connection.ErrInvalidState
	}
	valid, err := connection.Restore(s)
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(valid.State())
	if err != nil || len(data) > maxMetadataBytes {
		return "", connection.ErrInvalidState
	}
	return string(data), nil
}

func decodeConnection(raw string, id access.ConnectionID, owner access.OwnerID, version int64) (connection.YNABConnection, error) {
	if len(raw) > maxMetadataBytes || version <= 0 {
		return connection.YNABConnection{}, ErrCorrupt
	}
	var state connection.State
	if err := json.Unmarshal([]byte(raw), &state); err != nil {
		return connection.YNABConnection{}, ErrCorrupt
	}
	c, err := connection.Restore(state)
	if err != nil || state.ID != id || state.OwnerID != owner || state.Version != uint64(version) {
		return connection.YNABConnection{}, ErrCorrupt
	}
	// A canonical round trip rejects duplicate/unknown/missing fields, trailing
	// values and unexpected timestamp representations instead of guessing intent.
	canonical, err := encodeConnection(c)
	if err != nil || canonical != raw {
		return connection.YNABConnection{}, ErrCorrupt
	}
	return c, nil
}

func (r connectionRepository) CompareAndSwap(ctx context.Context, id access.ConnectionID, expected uint64, next connection.YNABConnection) error {
	return r.store.write(ctx, func(tx *sql.Tx) error {
		current, err := loadConnection(ctx, tx, id)
		if err != nil {
			return err
		}
		return swapConnection(ctx, tx, id, expected, current, next)
	})
}

func (r connectionRepository) CompareAndSwapScoped(ctx context.Context, scope access.ReadScope, expected uint64, next connection.YNABConnection) error {
	return r.store.write(ctx, func(tx *sql.Tx) error {
		g, current, err := readAuthorization(ctx, tx)
		if err != nil {
			return err
		}
		state := current.State()
		if !g.Enabled() || g.OwnerID() != scope.OwnerID || g.ConnectionID() != scope.ConnectionID || g.PolicyVersion() != scope.PolicyVersion || state.OwnerID != scope.OwnerID || state.ID != scope.ConnectionID || state.AuthorizationLineage != scope.AuthorizationLineage || scope.BudgetID != "" && !g.AllowsBudget(scope.BudgetID) {
			return access.ErrUnauthorized
		}
		return swapConnection(ctx, tx, scope.ConnectionID, expected, current, next)
	})
}

func swapConnection(ctx context.Context, tx *sql.Tx, id access.ConnectionID, expected uint64, current, next connection.YNABConnection) error {
	if expected == 0 || expected >= math.MaxInt64 || current.State().Version != expected || next.State().Version != expected+1 {
		return connection.ErrConflict
	}
	if next.State().ID != id || !validTransition(current, next) {
		return connection.ErrInvalidState
	}
	raw, err := encodeConnection(next)
	if err != nil {
		return err
	}
	r, err := tx.ExecContext(ctx, "UPDATE connections SET state_version=?,metadata=? WHERE connection_id=? AND owner_id=? AND state_version=?", next.State().Version, raw, id, current.State().OwnerID, expected)
	if err != nil {
		return dbError(ctx, err)
	}
	if n, err := r.RowsAffected(); err != nil || n != 1 {
		return connection.ErrConflict
	}
	return nil
}

// Validate the transition, not only its destination. Restore is intentionally
// available to adapters, so accepting arbitrary valid destinations would bypass
// fencing and permit generation rollback or resurrection of a disabled lineage.
func validTransition(current, next connection.YNABConnection) bool {
	a, b := current.State(), next.State()
	if a.ID != b.ID || a.OwnerID != b.OwnerID || a.Mode != b.Mode || a.RequestedScope != b.RequestedScope {
		return false
	}
	match := func(c connection.YNABConnection, err error) bool {
		return err == nil && reflect.DeepEqual(c.State(), b)
	}
	if b.Status == connection.Disabled {
		return match(current.Disable(a.Version))
	}
	if b.Status == connection.ReconnectRequired {
		if match(current.RequireReconnect(a.Version)) {
			return true
		}
		if a.Attempt != nil {
			return match(current.MarkAmbiguous(a.Version, a.Attempt.ID, a.Attempt.Fence))
		}
		return false
	}
	if b.Status == connection.Active && b.Attempt == nil && b.AuthorizationLineage != a.AuthorizationLineage {
		if a.Status == connection.Disabled || a.Status == connection.Refreshing {
			return false
		}
		// Activation's clock/protected-write proof is provided by the application.
		// Reconstruct only its metadata transition without reading any credential.
		now := b.Generation.AccessExpiresAt.Add(-time.Nanosecond)
		if a.Mode == connection.PersonalToken {
			now = time.Unix(1, 0).UTC()
		}
		p := connection.PersistedCredential{Reference: b.Generation.Reference, AccessExpiresAt: b.Generation.AccessExpiresAt, Complete: true, ReadOnly: true}
		return match(current.Activate(a.Version, b.AuthorizationLineage, p, now))
	}
	if a.Status == connection.Active && b.Status == connection.Refreshing && b.Attempt != nil {
		at := b.Attempt
		return match(current.BeginRefresh(a.Version, at.ID, at.CandidateRef, at.StartedAt, at.LeaseExpiresAt))
	}
	if a.Status == connection.Refreshing && a.Attempt != nil && b.Attempt != nil {
		at := a.Attempt
		switch b.Attempt.Phase {
		case connection.RequestStarted:
			return match(current.MarkRequestStarted(a.Version, at.ID, at.Fence, at.StartedAt))
		case connection.SecretSaved:
			p := connection.PersistedCredential{Reference: b.Attempt.CandidateRef, AccessExpiresAt: b.Attempt.CandidateExpiry, Complete: true, ReadOnly: true}
			return match(current.MarkSecretSaved(a.Version, at.ID, at.Fence, p, at.StartedAt))
		case connection.Committed:
			return match(current.CommitRefresh(a.Version, at.ID, at.Fence))
		case connection.Abandoned:
			return match(current.AbandonPrepared(a.Version, at.ID, at.Fence, true, at.LeaseExpiresAt))
		}
	}
	return false
}
