package admission

import (
	"fmt"
	"testing"
	"time"
)

func ledger(t *testing.T, limit int) (QuotaWindow, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	p := DefaultPolicy()
	p.Limit = limit
	w, err := Restore(State{Key: "connection-1", Version: 1, LastObserved: now}, p)
	if err != nil {
		t.Fatal(err)
	}
	return w, now
}
func TestReservationsCountRetriesAndSurviveCrash(t *testing.T) {
	w, now := ledger(t, 2)
	for i := 1; i <= 2; i++ {
		var err error
		w, err = w.Reserve(w.State().Version, fmt.Sprintf("attempt-%d", i), now)
		if err != nil {
			t.Fatal(err)
		}
	}
	restored, err := Restore(w.State(), DefaultPolicyWithLimit(2))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restored.Reserve(restored.State().Version, "attempt-3", now); err != ErrRateLimited {
		t.Fatal("restart lost reservations")
	}
	if _, err := w.Reserve(w.State().Version, "attempt-1", now); err != ErrDuplicateReservation {
		t.Fatal("same reservation reused for another send")
	}
	if _, err := w.Reserve(w.State().Version-1, "attempt-3", now); err != ErrConflict {
		t.Fatal("non-atomic admission")
	}
}
func DefaultPolicyWithLimit(limit int) Policy { p := DefaultPolicy(); p.Limit = limit; return p }
func TestConservativeWindowBoundaryAndRollback(t *testing.T) {
	w, now := ledger(t, 1)
	w, err := w.Reserve(w.State().Version, "attempt-1", now)
	if err != nil {
		t.Fatal(err)
	}
	boundary := now.Add(time.Hour + time.Second)
	if _, err := w.Reserve(w.State().Version, "attempt-2", boundary); err != ErrRateLimited {
		t.Fatal("boundary reservation pruned early")
	}
	if !w.RetryAt(now).Equal(boundary.Add(time.Nanosecond)) {
		t.Fatal(w.RetryAt(now))
	}
	if _, err := w.Reserve(w.State().Version, "attempt-2", now.Add(-time.Second)); err != ErrClockRollback {
		t.Fatal("clock rollback granted admission")
	}
	w, err = w.Reserve(w.State().Version, "attempt-2", boundary.Add(time.Nanosecond))
	if err != nil || len(w.State().Reservations) != 1 {
		t.Fatal(err)
	}
	if _, err := w.Reserve(w.State().Version, "attempt-3", boundary); err != ErrClockRollback {
		t.Fatal(err)
	}
}
func TestMissingLedgerBackoffAndCooldownNeverShortens(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	w, err := Restart("connection-1", now, DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Reserve(w.State().Version, "attempt-1", now.Add(time.Minute)); err != ErrCooldown {
		t.Fatal("missing ledger bypassed quota")
	}
	until := now.Add(2 * time.Hour)
	w, err = w.WithCooldown(w.State().Version, until, now)
	if err != nil {
		t.Fatal(err)
	}
	w, err = w.WithCooldown(w.State().Version, now.Add(time.Minute), now)
	if err != nil || !w.State().CooldownUntil.Equal(until) {
		t.Fatal("cooldown shortened")
	}
	if _, err := w.Reserve(w.State().Version, "attempt-2", until); err != nil {
		t.Fatal(err)
	}
}
func TestLedgerRejectsCorruptionAndCopiesState(t *testing.T) {
	w, now := ledger(t, 2)
	w, err := w.Reserve(w.State().Version, "attempt-1", now)
	if err != nil {
		t.Fatal(err)
	}
	s := w.State()
	s.Reservations[0].AttemptID = "changed"
	if w.State().Reservations[0].AttemptID != "attempt-1" {
		t.Fatal("mutable ledger")
	}
	s = w.State()
	s.Reservations = append(s.Reservations, s.Reservations[0])
	if _, err := Restore(s, DefaultPolicy()); err != ErrUntrustedLedger {
		t.Fatal("duplicate ledger accepted")
	}
	s = w.State()
	s.Reservations[0].ReservedAt = now.Add(time.Second)
	if _, err := Restore(s, DefaultPolicy()); err != ErrUntrustedLedger {
		t.Fatal("future reservation accepted")
	}
	if _, err := Restore(State{}, DefaultPolicy()); err != ErrUntrustedLedger {
		t.Fatal("empty ledger accepted")
	}
	if (QuotaWindow{}).RetryAt(now).Before(now.Add(time.Hour)) {
		t.Fatal("zero ledger unsafe guidance")
	}
}
