// Package admission defines conservative rolling-window quota admission.
// Each successful Reserve must be committed atomically before sending a GET.
package admission

import (
	"errors"
	"math"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/domain/budget"
)

var (
	ErrRateLimited          = errors.New("local upstream quota exhausted")
	ErrCooldown             = errors.New("upstream cooldown active")
	ErrUntrustedLedger      = errors.New("quota ledger missing or corrupt")
	ErrClockRollback        = errors.New("quota clock moved backwards")
	ErrDuplicateReservation = errors.New("attempt already reserved")
	ErrConflict             = errors.New("quota version conflict")
)

type QuotaKey string
type Policy struct {
	Limit       int
	Window      time.Duration
	ClockSafety time.Duration
}

func DefaultPolicy() Policy { return Policy{Limit: 180, Window: time.Hour, ClockSafety: time.Second} }
func (p Policy) Validate() error {
	if p.Limit < 1 || p.Limit > 180 || p.Window != time.Hour || p.ClockSafety < 0 || p.ClockSafety > time.Minute {
		return ErrUntrustedLedger
	}
	return nil
}

type Reservation struct {
	AttemptID  string
	ReservedAt time.Time
}
type State struct {
	Key           QuotaKey
	Version       uint64
	LastObserved  time.Time
	CooldownUntil time.Time
	Reservations  []Reservation
}
type QuotaWindow struct {
	state  State
	policy Policy
}

// Restart creates a safe replacement when a ledger cannot be trusted. Admission
// remains blocked for a full upstream window; restarting cannot reset quota.
func Restart(key QuotaKey, now time.Time, p Policy) (QuotaWindow, error) {
	return Restore(State{Key: key, Version: 1, LastObserved: now, CooldownUntil: now.Add(p.Window + p.ClockSafety)}, p)
}

// Restore requires authoritative, complete durable accounting, not a stale backup.
func Restore(s State, p Policy) (QuotaWindow, error) {
	if p.Validate() != nil || budget.ValidateID(string(s.Key)) != nil || s.Version == 0 || s.LastObserved.IsZero() || len(s.Reservations) > p.Limit {
		return QuotaWindow{}, ErrUntrustedLedger
	}
	seen := map[string]bool{}
	for _, r := range s.Reservations {
		if budget.ValidateID(r.AttemptID) != nil || r.ReservedAt.IsZero() || r.ReservedAt.After(s.LastObserved) || seen[r.AttemptID] {
			return QuotaWindow{}, ErrUntrustedLedger
		}
		seen[r.AttemptID] = true
	}
	s.Reservations = append([]Reservation(nil), s.Reservations...)
	return QuotaWindow{state: s, policy: p}, nil
}
func (w QuotaWindow) State() State {
	s := w.state
	s.Reservations = append([]Reservation(nil), s.Reservations...)
	return s
}
func (w QuotaWindow) Reserve(expected uint64, id string, now time.Time) (QuotaWindow, error) {
	if expected != w.state.Version || expected == math.MaxUint64 {
		return w, ErrConflict
	}
	if w.policy.Validate() != nil || w.state.LastObserved.IsZero() {
		return w, ErrUntrustedLedger
	}
	if budget.ValidateID(id) != nil {
		return w, ErrUntrustedLedger
	}
	if now.Before(w.state.LastObserved) {
		return w, ErrClockRollback
	}
	if now.Before(w.state.CooldownUntil) {
		return w, ErrCooldown
	}
	for _, r := range w.state.Reservations {
		if r.AttemptID == id {
			return w, ErrDuplicateReservation
		}
	}
	cutoff := now.Add(-w.policy.Window - w.policy.ClockSafety)
	s := w.State()
	s.Reservations = nil
	for _, r := range w.state.Reservations {
		if !r.ReservedAt.Before(cutoff) {
			s.Reservations = append(s.Reservations, r)
		}
	}
	if len(s.Reservations) >= w.policy.Limit {
		return w, ErrRateLimited
	}
	s.Version++
	s.LastObserved = now
	s.Reservations = append(s.Reservations, Reservation{AttemptID: id, ReservedAt: now})
	return Restore(s, w.policy)
}

// WithCooldown only extends a cooldown, including while caller cancellation is
// pending. The repository must persist this independently of the failed request.
func (w QuotaWindow) WithCooldown(expected uint64, until, now time.Time) (QuotaWindow, error) {
	if expected != w.state.Version || expected == math.MaxUint64 {
		return w, ErrConflict
	}
	if now.Before(w.state.LastObserved) {
		return w, ErrClockRollback
	}
	if until.Before(now) {
		return w, ErrUntrustedLedger
	}
	s := w.State()
	s.Version++
	s.LastObserved = now
	if until.After(s.CooldownUntil) {
		s.CooldownUntil = until
	}
	return Restore(s, w.policy)
}

// RetryAt is local conservative guidance, not the provider's exact remaining quota.
func (w QuotaWindow) RetryAt(now time.Time) time.Time {
	if w.policy.Validate() != nil || w.state.LastObserved.IsZero() {
		return now.Add(time.Hour + time.Minute)
	}
	retry := now
	if w.state.CooldownUntil.After(retry) {
		retry = w.state.CooldownUntil
	}
	if len(w.state.Reservations) >= w.policy.Limit {
		earliest := w.state.Reservations[0].ReservedAt
		for _, r := range w.state.Reservations[1:] {
			if r.ReservedAt.Before(earliest) {
				earliest = r.ReservedAt
			}
		}
		next := earliest.Add(w.policy.Window + w.policy.ClockSafety + time.Nanosecond)
		if next.After(retry) {
			retry = next
		}
	}
	return retry
}
