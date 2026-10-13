// Package connection models credential rotation without storing credential content.
// Callers persist each returned state using compare-and-swap before performing I/O.
package connection

import (
	"errors"
	"math"
	"strings"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/budget"
)

var (
	ErrInvalidState      = errors.New("invalid connection state")
	ErrConflict          = errors.New("connection version or fence conflict")
	ErrReconnectRequired = errors.New("connection requires reauthorization")
	ErrNotActive         = errors.New("connection not active")
)

type AuthMode string

const (
	OAuth         AuthMode = "oauth"
	PersonalToken AuthMode = "personal_token"
)

type Status string

const (
	Unconnected       Status = "unconnected"
	Active            Status = "active"
	Refreshing        Status = "refreshing"
	ReconnectRequired Status = "reconnect_required"
	Disabled          Status = "disabled"
)

type RefreshPhase string

const (
	Prepared       RefreshPhase = "prepared"
	RequestStarted RefreshPhase = "request_started"
	SecretSaved    RefreshPhase = "secret_saved"
	Committed      RefreshPhase = "committed"
	Abandoned      RefreshPhase = "abandoned"
	Ambiguous      RefreshPhase = "ambiguous"
)

type CredentialRef struct {
	Provider         string
	Location         string
	ImmutableVersion string
}

func (r CredentialRef) Validate() error {
	for _, v := range []string{r.Provider, r.Location, r.ImmutableVersion} {
		if len(v) == 0 || len(v) > 2048 || strings.ContainsAny(v, "\x00\r\n") {
			return ErrInvalidState
		}
	}
	return nil
}

type CredentialGeneration struct {
	Number          uint64
	Reference       CredentialRef
	AccessExpiresAt time.Time
}

// PersistedCredential is the application layer's proof that a complete credential
// bundle has been validated and durably stored; it contains no secret material.
type PersistedCredential struct {
	Reference       CredentialRef
	AccessExpiresAt time.Time
	Complete        bool
	ReadOnly        bool
}
type RefreshAttempt struct {
	ID                   string
	BaseGeneration       uint64
	Fence                uint64
	AuthorizationLineage string
	CandidateRef         CredentialRef
	Phase                RefreshPhase
	StartedAt            time.Time
	LeaseExpiresAt       time.Time
	CandidateExpiry      time.Time
}
type State struct {
	ID                   access.ConnectionID
	OwnerID              access.OwnerID
	Mode                 AuthMode
	Status               Status
	AuthorizationLineage string
	RequestedScope       string
	Version              uint64
	Generation           CredentialGeneration
	Attempt              *RefreshAttempt
}
type YNABConnection struct{ state State }

func New(id access.ConnectionID, owner access.OwnerID, mode AuthMode) (YNABConnection, error) {
	s := State{ID: id, OwnerID: owner, Mode: mode, Status: Unconnected, Version: 1}
	if mode == OAuth {
		s.RequestedScope = "read-only"
	}
	return Restore(s)
}

// Restore validates metadata. Restored backups additionally require application
// reconciliation against the protected store before reads may resume.
func Restore(s State) (YNABConnection, error) {
	if budget.ValidateID(string(s.ID)) != nil || budget.ValidateID(string(s.OwnerID)) != nil || s.Version == 0 || s.Mode != OAuth && s.Mode != PersonalToken || s.Mode == OAuth && s.RequestedScope != "read-only" {
		return YNABConnection{}, ErrInvalidState
	}
	switch s.Status {
	case Unconnected:
		if s.Generation.Number != 0 || s.Attempt != nil {
			return YNABConnection{}, ErrInvalidState
		}
	case Active, Refreshing, ReconnectRequired, Disabled:
	default:
		return YNABConnection{}, ErrInvalidState
	}
	if s.Status == Active || s.Status == Refreshing {
		if s.Generation.Number == 0 || s.Generation.Reference.Validate() != nil || budget.ValidateID(s.AuthorizationLineage) != nil || s.Mode == OAuth && s.Generation.AccessExpiresAt.IsZero() {
			return YNABConnection{}, ErrInvalidState
		}
	}
	if s.Status == Refreshing && (s.Attempt == nil || s.Mode != OAuth) {
		return YNABConnection{}, ErrInvalidState
	}
	if s.Attempt != nil {
		a := *s.Attempt
		if budget.ValidateID(a.ID) != nil || a.Fence == 0 || a.Fence > s.Version || a.BaseGeneration == 0 || a.CandidateRef.Validate() != nil || a.AuthorizationLineage != s.AuthorizationLineage || a.StartedAt.IsZero() || !a.LeaseExpiresAt.After(a.StartedAt) {
			return YNABConnection{}, ErrInvalidState
		}
		switch a.Phase {
		case Prepared, RequestStarted, SecretSaved, Committed, Abandoned, Ambiguous:
		default:
			return YNABConnection{}, ErrInvalidState
		}
		if s.Status == Refreshing && (a.Phase != Prepared && a.Phase != RequestStarted && a.Phase != SecretSaved || a.BaseGeneration != s.Generation.Number) {
			return YNABConnection{}, ErrInvalidState
		}
		if s.Status == Active && a.Phase != Committed && a.Phase != Abandoned {
			return YNABConnection{}, ErrInvalidState
		}
		if a.Phase == Committed && (a.BaseGeneration == math.MaxUint64 || s.Generation.Number != a.BaseGeneration+1 || s.Generation.Reference != a.CandidateRef) {
			return YNABConnection{}, ErrInvalidState
		}
		if a.Phase == Abandoned && s.Generation.Number != a.BaseGeneration {
			return YNABConnection{}, ErrInvalidState
		}
		if (a.Phase == SecretSaved || a.Phase == Committed) && a.CandidateExpiry.IsZero() {
			return YNABConnection{}, ErrInvalidState
		}
		s.Attempt = &a
	}
	return YNABConnection{state: s}, nil
}
func (c YNABConnection) State() State {
	s := c.state
	if s.Attempt != nil {
		a := *s.Attempt
		s.Attempt = &a
	}
	return s
}
func (c YNABConnection) Binding() access.ConnectionBinding {
	return access.ConnectionBinding{OwnerID: c.state.OwnerID, ConnectionID: c.state.ID, AuthorizationLineage: c.state.AuthorizationLineage, Active: c.state.Status == Active}
}
func (c YNABConnection) ReadGeneration(now time.Time) (CredentialGeneration, error) {
	if c.state.Status != Active {
		return CredentialGeneration{}, ErrNotActive
	}
	if c.state.Mode == OAuth && !now.Before(c.state.Generation.AccessExpiresAt) {
		return CredentialGeneration{}, ErrNotActive
	}
	return c.state.Generation, nil
}
func (c YNABConnection) expected(v uint64) error {
	if c.state.Version != v || v == math.MaxUint64 {
		return ErrConflict
	}
	return nil
}
func validateProof(p PersistedCredential, mode AuthMode, now time.Time) error {
	if now.IsZero() || !p.Complete || p.Reference.Validate() != nil || mode == OAuth && (!p.ReadOnly || !p.AccessExpiresAt.After(now)) {
		return ErrInvalidState
	}
	return nil
}

// Activate is administrative initial consent/reconnect. Every call needs a fresh
// lineage and a durably stored generation; reconnect invalidates all old reads.
func (c YNABConnection) Activate(expected uint64, lineage string, p PersistedCredential, now time.Time) (YNABConnection, error) {
	if err := c.expected(expected); err != nil {
		return c, err
	}
	if budget.ValidateID(lineage) != nil || lineage == c.state.AuthorizationLineage || c.state.Generation.Number > 0 && p.Reference == c.state.Generation.Reference || now.IsZero() || c.state.Generation.Number == math.MaxUint64 {
		return c, ErrInvalidState
	}
	if err := validateProof(p, c.state.Mode, now); err != nil {
		return c, err
	}
	s := c.State()
	s.Status = Active
	s.AuthorizationLineage = lineage
	s.Version++
	s.Generation = CredentialGeneration{Number: s.Generation.Number + 1, Reference: p.Reference, AccessExpiresAt: p.AccessExpiresAt}
	s.Attempt = nil
	return Restore(s)
}
func (c YNABConnection) BeginRefresh(expected uint64, id string, candidate CredentialRef, now, leaseUntil time.Time) (YNABConnection, error) {
	if err := c.expected(expected); err != nil {
		return c, err
	}
	if c.state.Status != Active || c.state.Mode != OAuth {
		return c, ErrNotActive
	}
	if budget.ValidateID(id) != nil || candidate.Validate() != nil || candidate == c.state.Generation.Reference || now.IsZero() || !leaseUntil.After(now) || leaseUntil.Sub(now) > 5*time.Minute || c.state.Generation.Number == math.MaxUint64 {
		return c, ErrInvalidState
	}
	if c.state.Attempt != nil && c.state.Attempt.ID == id {
		return c, ErrConflict
	}
	s := c.State()
	s.Version++
	s.Status = Refreshing
	s.Attempt = &RefreshAttempt{ID: id, BaseGeneration: s.Generation.Number, Fence: s.Version, AuthorizationLineage: s.AuthorizationLineage, CandidateRef: candidate, Phase: Prepared, StartedAt: now, LeaseExpiresAt: leaseUntil}
	return Restore(s)
}
func (c YNABConnection) attempt(expected uint64, id string, fence uint64, phase RefreshPhase) error {
	if err := c.expected(expected); err != nil {
		return err
	}
	a := c.state.Attempt
	if c.state.Status != Refreshing || a == nil || a.ID != id || a.Fence != fence || a.Phase != phase || a.AuthorizationLineage != c.state.AuthorizationLineage || a.BaseGeneration != c.state.Generation.Number {
		return ErrConflict
	}
	return nil
}
func (c YNABConnection) MarkRequestStarted(expected uint64, id string, fence uint64, now time.Time) (YNABConnection, error) {
	if err := c.attempt(expected, id, fence, Prepared); err != nil {
		return c, err
	}
	if now.Before(c.state.Attempt.StartedAt) || !now.Before(c.state.Attempt.LeaseExpiresAt) {
		return c, ErrConflict
	}
	s := c.State()
	s.Version++
	s.Attempt.Phase = RequestStarted
	return Restore(s)
}
func (c YNABConnection) MarkSecretSaved(expected uint64, id string, fence uint64, p PersistedCredential, now time.Time) (YNABConnection, error) {
	if err := c.attempt(expected, id, fence, RequestStarted); err != nil {
		return c, err
	}
	if p.Reference != c.state.Attempt.CandidateRef || now.Before(c.state.Attempt.StartedAt) {
		return c, ErrConflict
	}
	if err := validateProof(p, c.state.Mode, now); err != nil {
		return c, err
	}
	s := c.State()
	s.Version++
	s.Attempt.Phase = SecretSaved
	s.Attempt.CandidateExpiry = p.AccessExpiresAt
	return Restore(s)
}
func (c YNABConnection) CommitRefresh(expected uint64, id string, fence uint64) (YNABConnection, error) {
	a := c.state.Attempt
	// A lost commit acknowledgment is resolved by recognizing the committed pointer.
	if c.state.Status == Active && a != nil && a.ID == id && a.Fence == fence && a.Phase == Committed && c.state.Generation.Number == a.BaseGeneration+1 && c.state.Generation.Reference == a.CandidateRef {
		return c, nil
	}
	if err := c.attempt(expected, id, fence, SecretSaved); err != nil {
		return c, err
	}
	s := c.State()
	s.Version++
	s.Generation = CredentialGeneration{Number: s.Generation.Number + 1, Reference: s.Attempt.CandidateRef, AccessExpiresAt: s.Attempt.CandidateExpiry}
	s.Status = Active
	s.Attempt.Phase = Committed
	return Restore(s)
}

// AbandonPrepared requires explicit evidence that the previous worker has stopped.
// A started exchange can never be reclaimed, even after its lease expires.
func (c YNABConnection) AbandonPrepared(expected uint64, id string, fence uint64, workerStopped bool, now time.Time) (YNABConnection, error) {
	if err := c.attempt(expected, id, fence, Prepared); err != nil {
		return c, err
	}
	if !workerStopped || now.Before(c.state.Attempt.LeaseExpiresAt) {
		return c, ErrConflict
	}
	s := c.State()
	s.Version++
	s.Status = Active
	s.Attempt.Phase = Abandoned
	return Restore(s)
}
func (c YNABConnection) MarkAmbiguous(expected uint64, id string, fence uint64) (YNABConnection, error) {
	if err := c.attempt(expected, id, fence, RequestStarted); err != nil {
		return c, err
	}
	s := c.State()
	s.Version++
	s.Status = ReconnectRequired
	s.Attempt.Phase = Ambiguous
	return Restore(s)
}
func (c YNABConnection) Disable(expected uint64) (YNABConnection, error) {
	if err := c.expected(expected); err != nil {
		return c, err
	}
	s := c.State()
	s.Version++
	s.Status = Disabled
	return Restore(s)
}
func (c YNABConnection) RequireReconnect(expected uint64) (YNABConnection, error) {
	if err := c.expected(expected); err != nil {
		return c, err
	}
	s := c.State()
	s.Version++
	s.Status = ReconnectRequired
	return Restore(s)
}
