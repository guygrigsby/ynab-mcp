package connection

import (
	"errors"
	"testing"
	"time"
)

func active(t *testing.T) (YNABConnection, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	c, err := New("connection-1", "owner-1", OAuth)
	if err != nil {
		t.Fatal(err)
	}
	c, err = c.Activate(c.State().Version, "lineage-1", PersistedCredential{Reference: CredentialRef{"test", "connection-1/generation-1", "1"}, AccessExpiresAt: now.Add(time.Hour), Complete: true, ReadOnly: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	return c, now
}
func prepared(t *testing.T) (YNABConnection, time.Time, uint64) {
	t.Helper()
	c, now := active(t)
	c, err := c.BeginRefresh(c.State().Version, "attempt-1", CredentialRef{"test", "connection-1/attempt-1", "1"}, now, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	return c, now, c.State().Attempt.Fence
}
func started(t *testing.T) (YNABConnection, time.Time, uint64) {
	t.Helper()
	c, now, fence := prepared(t)
	c, err := c.MarkRequestStarted(c.State().Version, "attempt-1", fence, now)
	if err != nil {
		t.Fatal(err)
	}
	return c, now, fence
}
func saved(t *testing.T) (YNABConnection, time.Time, uint64) {
	t.Helper()
	c, now, fence := started(t)
	c, err := c.MarkSecretSaved(c.State().Version, "attempt-1", fence, PersistedCredential{Reference: c.State().Attempt.CandidateRef, AccessExpiresAt: now.Add(2 * time.Hour), Complete: true, ReadOnly: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	return c, now, fence
}
func TestRefreshCommitOnlyAfterDurableCompleteBundle(t *testing.T) {
	c, now, fence := prepared(t)
	oldRef := c.State().Generation.Reference
	if _, err := c.ReadGeneration(now); !errors.Is(err, ErrNotActive) {
		t.Fatal("refreshing read permitted")
	}
	if _, err := c.CommitRefresh(c.State().Version, "attempt-1", fence); err != ErrConflict {
		t.Fatal("unpersisted generation committed")
	}
	c, err := c.MarkRequestStarted(c.State().Version, "attempt-1", fence, now)
	if err != nil {
		t.Fatal(err)
	}
	p := PersistedCredential{Reference: c.State().Attempt.CandidateRef, AccessExpiresAt: now.Add(time.Hour), ReadOnly: true}
	if _, err := c.MarkSecretSaved(c.State().Version, "attempt-1", fence, p, now); err != ErrInvalidState {
		t.Fatal("incomplete candidate accepted")
	}
	p.Complete = true
	p.ReadOnly = false
	if _, err := c.MarkSecretSaved(c.State().Version, "attempt-1", fence, p, now); err != ErrInvalidState {
		t.Fatal("broader scope accepted")
	}
	p.ReadOnly = true
	c, err = c.MarkSecretSaved(c.State().Version, "attempt-1", fence, p, now)
	if err != nil {
		t.Fatal(err)
	}
	if c.State().Generation.Reference != oldRef {
		t.Fatal("candidate exposed before CAS")
	}
	expected := c.State().Version
	c, err = c.CommitRefresh(expected, "attempt-1", fence)
	if err != nil {
		t.Fatal(err)
	}
	if c.State().Generation.Number != 2 || c.State().Status != Active || c.State().Generation.Reference == oldRef {
		t.Fatal(c.State())
	}
	if gen, err := c.ReadGeneration(now); err != nil || gen.Number != 2 {
		t.Fatal(gen, err)
	}
	again, err := c.CommitRefresh(expected, "attempt-1", fence)
	if err != nil || again.State().Version != c.State().Version {
		t.Fatal("lost acknowledgment not idempotent", err)
	}
}
func TestRefreshFencingAndDisableWins(t *testing.T) {
	c, now, fence := saved(t)
	if _, err := c.CommitRefresh(c.State().Version, "attempt-1", fence+1); err != ErrConflict {
		t.Fatal(err)
	}
	if _, err := c.CommitRefresh(c.State().Version-1, "attempt-1", fence); err != ErrConflict {
		t.Fatal(err)
	}
	disabled, err := c.Disable(c.State().Version)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := disabled.CommitRefresh(disabled.State().Version, "attempt-1", fence); err != ErrConflict {
		t.Fatal("late refresh bypassed disable")
	}
	if _, err := disabled.ReadGeneration(now); err != ErrNotActive {
		t.Fatal(err)
	}
	reconnected, err := c.Activate(c.State().Version, "lineage-2", PersistedCredential{Reference: CredentialRef{"test", "reconnected", "2"}, AccessExpiresAt: now.Add(time.Hour), ReadOnly: true, Complete: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reconnected.CommitRefresh(reconnected.State().Version, "attempt-1", fence); err != ErrConflict {
		t.Fatal("late refresh bypassed reconnect")
	}
	if reconnected.Binding().AuthorizationLineage == c.Binding().AuthorizationLineage {
		t.Fatal("lineage not replaced")
	}
}
func TestOneRefreshAndNoUncertainReplay(t *testing.T) {
	c, now, fence := prepared(t)
	if _, err := c.BeginRefresh(c.State().Version, "attempt-2", CredentialRef{"test", "attempt-2", "1"}, now, now.Add(time.Minute)); err != ErrNotActive {
		t.Fatal("second unresolved refresh permitted")
	}
	if _, err := c.AbandonPrepared(c.State().Version, "attempt-1", fence, false, now.Add(time.Hour)); err != ErrConflict {
		t.Fatal("lease stole live worker")
	}
	recovered, err := c.AbandonPrepared(c.State().Version, "attempt-1", fence, true, now.Add(time.Minute))
	if err != nil || recovered.State().Status != Active {
		t.Fatal(err)
	}
	c, now, fence = started(t)
	if _, err := c.MarkRequestStarted(c.State().Version, "attempt-1", fence, now.Add(time.Hour)); err != ErrConflict {
		t.Fatal("OAuth exchange replay permitted")
	}
	if _, err := c.AbandonPrepared(c.State().Version, "attempt-1", fence, true, now.Add(time.Hour)); err != ErrConflict {
		t.Fatal("started refresh reclaimed")
	}
	c, err = c.MarkAmbiguous(c.State().Version, "attempt-1", fence)
	if err != nil || c.State().Status != ReconnectRequired {
		t.Fatal(err)
	}
	if _, err := c.ReadGeneration(now); err != ErrNotActive {
		t.Fatal(err)
	}
	if _, err := c.BeginRefresh(c.State().Version, "attempt-2", CredentialRef{"test", "attempt-2", "1"}, now, now.Add(time.Minute)); err != ErrNotActive {
		t.Fatal("ambiguous token retried")
	}
}
func TestRecoveryStateImmutableAndValidated(t *testing.T) {
	c, now, fence := started(t)
	s := c.State()
	s.Attempt.Phase = Prepared
	if c.State().Attempt.Phase != RequestStarted {
		t.Fatal("getter mutated internal state")
	}
	s = c.State()
	copy, err := Restore(s)
	if err != nil {
		t.Fatal(err)
	}
	s.Attempt.Phase = Prepared
	if copy.State().Attempt.Phase != RequestStarted {
		t.Fatal("restore retained pointer")
	}
	s = copy.State()
	s.Status = Active
	if _, err := Restore(s); err != ErrInvalidState {
		t.Fatal("active unresolved exchange accepted")
	}
	p := PersistedCredential{Reference: copy.State().Attempt.CandidateRef, AccessExpiresAt: now.Add(time.Hour), Complete: true, ReadOnly: true}
	copy, err = copy.MarkSecretSaved(copy.State().Version, "attempt-1", fence, p, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal("saved candidate could not reconcile after lease", err)
	}
}
func TestExpiryAndPersonalTokenCannotRefresh(t *testing.T) {
	c, now := active(t)
	if _, err := c.ReadGeneration(now.Add(time.Hour)); err != ErrNotActive {
		t.Fatal("expired token usable")
	}
	p, err := New("personal-1", "owner-1", PersonalToken)
	if err != nil {
		t.Fatal(err)
	}
	p, err = p.Activate(p.State().Version, "personal-lineage", PersistedCredential{Reference: CredentialRef{"test", "personal", "1"}, Complete: true}, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.BeginRefresh(p.State().Version, "attempt-1", CredentialRef{"test", "refresh", "1"}, now, now.Add(time.Minute)); err != ErrNotActive {
		t.Fatal("personal token refresh invented")
	}
}
