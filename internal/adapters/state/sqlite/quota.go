package sqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/application/ports"
	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/admission"
	"github.com/guygrigsby/ynab-mcp/internal/domain/budget"
)

type quotaRepository struct{ store *Store }

var _ ports.QuotaRepository = quotaRepository{}

// Quota keys are the immutable connection ID, never a token, token hash,
// generation, authorization lineage, URL or budget ID.
func (r quotaRepository) Load(ctx context.Context, key admission.QuotaKey) (admission.QuotaWindow, error) {
	w, err := loadQuota(ctx, r.store.db, key)
	if errors.Is(err, sql.ErrNoRows) {
		return admission.QuotaWindow{}, admission.ErrUntrustedLedger
	}
	return w, err
}

func loadQuota(ctx context.Context, q querier, key admission.QuotaKey) (admission.QuotaWindow, error) {
	if budget.ValidateID(string(key)) != nil {
		return admission.QuotaWindow{}, admission.ErrUntrustedLedger
	}
	var raw string
	var version int64
	err := q.QueryRowContext(ctx, "SELECT version,substr(metadata,1,65537) FROM quota_windows WHERE quota_key=?", key).Scan(&version, &raw)
	if errors.Is(err, sql.ErrNoRows) {
		return admission.QuotaWindow{}, sql.ErrNoRows
	}
	if err != nil {
		return admission.QuotaWindow{}, dbError(ctx, err)
	}
	var state admission.State
	if version <= 0 || len(raw) > maxMetadataBytes || json.Unmarshal([]byte(raw), &state) != nil || state.Key != key || state.Version != uint64(version) {
		return admission.QuotaWindow{}, admission.ErrUntrustedLedger
	}
	w, err := admission.Restore(state, admission.DefaultPolicy())
	if err != nil {
		return admission.QuotaWindow{}, admission.ErrUntrustedLedger
	}
	canonical, err := encodeQuota(w)
	if err != nil || canonical != raw {
		return admission.QuotaWindow{}, admission.ErrUntrustedLedger
	}
	return w, nil
}

func encodeQuota(w admission.QuotaWindow) (string, error) {
	s := w.State()
	if s.Version > math.MaxInt64 {
		return "", admission.ErrUntrustedLedger
	}
	valid, err := admission.Restore(s, admission.DefaultPolicy())
	if err != nil {
		return "", err
	}
	data, err := json.Marshal(valid.State())
	if err != nil || len(data) > maxMetadataBytes {
		return "", admission.ErrUntrustedLedger
	}
	return string(data), nil
}

func insertQuota(ctx context.Context, tx *sql.Tx, w admission.QuotaWindow) error {
	raw, err := encodeQuota(w)
	if err != nil {
		return err
	}
	state := w.State()
	if _, err := tx.ExecContext(ctx, "INSERT INTO quota_windows(quota_key,version,metadata) VALUES(?,?,?)", state.Key, state.Version, raw); err != nil {
		return dbError(ctx, err)
	}
	return nil
}

func swapQuota(ctx context.Context, tx *sql.Tx, expected uint64, w admission.QuotaWindow) error {
	if expected == 0 || expected >= math.MaxInt64 || w.State().Version != expected+1 {
		return admission.ErrConflict
	}
	raw, err := encodeQuota(w)
	if err != nil {
		return err
	}
	r, err := tx.ExecContext(ctx, "UPDATE quota_windows SET version=?,metadata=? WHERE quota_key=? AND version=?", w.State().Version, raw, w.State().Key, expected)
	if err != nil {
		return dbError(ctx, err)
	}
	if n, err := r.RowsAffected(); err != nil || n != 1 {
		return admission.ErrConflict
	}
	return nil
}

func (r quotaRepository) Reserve(ctx context.Context, key admission.QuotaKey, id string, now time.Time) (admission.Reservation, error) {
	if now.IsZero() || budget.ValidateID(string(key)) != nil || budget.ValidateID(id) != nil {
		return admission.Reservation{}, admission.ErrUntrustedLedger
	}
	var reservation admission.Reservation
	cold := false
	err := r.store.write(ctx, func(tx *sql.Tx) error {
		w, err := loadQuota(ctx, tx, key)
		if errors.Is(err, sql.ErrNoRows) {
			// A missing ledger is never initialized as an empty usable window.
			if _, err := loadConnection(ctx, tx, access.ConnectionID(key)); err != nil {
				return err
			}
			w, err = admission.Restart(key, now, admission.DefaultPolicy())
			if err != nil {
				return err
			}
			if err := insertQuota(ctx, tx, w); err != nil {
				return err
			}
			cold = true
			return nil // Commit restart backoff even though this attempt is denied.
		}
		if err != nil {
			return err
		}
		next, err := w.Reserve(w.State().Version, id, now)
		if err != nil {
			return err
		}
		if err := swapQuota(ctx, tx, w.State().Version, next); err != nil {
			return err
		}
		reservation = admission.Reservation{AttemptID: id, ReservedAt: now}
		return nil
	})
	if err != nil {
		return admission.Reservation{}, err
	}
	if cold {
		return admission.Reservation{}, admission.ErrCooldown
	}
	return reservation, nil
}

func (r quotaRepository) RecordCooldown(ctx context.Context, key admission.QuotaKey, until, now time.Time) error {
	if now.IsZero() || until.Before(now) || budget.ValidateID(string(key)) != nil {
		return admission.ErrUntrustedLedger
	}
	// A cancelled failed GET must not discard authoritative 429 cooldown. The
	// detached write is bounded and contains no upstream/credential I/O.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 5*time.Second)
	defer cancel()
	return r.store.write(ctx, func(tx *sql.Tx) error {
		w, err := loadQuota(ctx, tx, key)
		missing := errors.Is(err, sql.ErrNoRows)
		if missing {
			if _, err := loadConnection(ctx, tx, access.ConnectionID(key)); err != nil {
				return err
			}
			w, err = admission.Restart(key, now, admission.DefaultPolicy())
		}
		if err != nil {
			return err
		}
		next, err := w.WithCooldown(w.State().Version, until, now)
		if err != nil {
			return err
		}
		if missing {
			return insertQuota(ctx, tx, next)
		}
		return swapQuota(ctx, tx, w.State().Version, next)
	})
}
