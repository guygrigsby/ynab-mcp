package sqlite

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/domain/admission"
	"github.com/guygrigsby/ynab-mcp/internal/domain/connection"
)

// OpenRestored is mandatory when opening a restored/copy-of-backup database.
// An ordinary file cannot prove its own freshness. Before returning the Store,
// this API atomically blocks old credential use and imposes full-window quota
// backoff. Reauthorization is then required; disabled states remain disabled.
// This does not restore secrets or assert that a backup is authoritative.
func OpenRestored(path string, now time.Time) (*Store, error) {
	if now.IsZero() {
		return nil, ErrCorrupt
	}
	s, err := Open(path)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = s.write(ctx, func(tx *sql.Tx) error {
		_, c, err := readAuthorization(ctx, tx)
		if errors.Is(err, ErrUninitialized) {
			return nil
		}
		if err != nil {
			return err
		}
		state := c.State()
		if state.Status != connection.Disabled && state.Status != connection.Unconnected && state.Status != connection.ReconnectRequired {
			next, err := c.RequireReconnect(state.Version)
			if err != nil {
				return err
			}
			if err := swapConnection(ctx, tx, state.ID, state.Version, c, next); err != nil {
				return err
			}
		}
		key := admission.QuotaKey(state.ID)
		prior, err := loadQuota(ctx, tx, key)
		missing := errors.Is(err, sql.ErrNoRows)
		if err != nil && !missing {
			return err
		}
		clock := now
		if !missing && prior.State().LastObserved.After(clock) {
			clock = prior.State().LastObserved
		}
		next, err := admission.Restart(key, clock, admission.DefaultPolicy())
		if err != nil {
			return err
		}
		if missing {
			return insertQuota(ctx, tx, next)
		}
		p, n := prior.State(), next.State()
		if p.Version >= math.MaxInt64 {
			return admission.ErrConflict
		}
		n.Version = p.Version + 1
		if p.CooldownUntil.After(n.CooldownUntil) {
			n.CooldownUntil = p.CooldownUntil
		}
		next, err = admission.Restore(n, admission.DefaultPolicy())
		if err != nil {
			return err
		}
		return swapQuota(ctx, tx, p.Version, next)
	})
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	return s, nil
}
