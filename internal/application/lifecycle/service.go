// Package lifecycle coordinates the durable OAuth rotation state machine. It
// owns no HTTP endpoint and never exposes credential bundles to financial ports.
package lifecycle

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"reflect"
	"strconv"
	"sync"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/application/credentials"
	"github.com/guygrigsby/ynab-mcp/internal/application/ports"
	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/budget"
	"github.com/guygrigsby/ynab-mcp/internal/domain/connection"
)

var (
	ErrConfiguration     = errors.New("invalid credential lifecycle configuration")
	ErrUnavailable       = errors.New("credential lifecycle unavailable")
	ErrRefreshInProgress = errors.New("credential refresh in progress")
	ErrReconnectRequired = connection.ErrReconnectRequired
)

// OAuthGateway performs exactly one request and must never automatically retry
// a refresh, including transport errors and uncertain responses.
type OAuthGateway interface {
	Refresh(context.Context, *credentials.CompleteBundle) (*credentials.CompleteBundle, error)
}

// Config is trusted bootstrap configuration, never an MCP argument. Entropy
// defaults to crypto/rand.Reader; deterministic readers are for synthetic tests.
type Config struct {
	Provider       string
	Now            func() time.Time
	Entropy        io.Reader
	RefreshSkew    time.Duration
	WaitLimit      time.Duration
	OperationLimit time.Duration
	Lease          time.Duration
}

type flight struct {
	done chan struct{}
	err  error
}

type Service struct {
	repo      ports.ScopedConnectionRepository
	access    ports.AccessStateRepository
	store     credentials.Store
	oauth     OAuthGateway
	config    Config
	mu        sync.Mutex
	flights   map[access.ConnectionID]*flight
	entropyMu sync.Mutex
	// A private fault seam lets tests simulate process loss at durable boundaries.
	checkpoint func(string) error
}

func New(repo ports.ScopedConnectionRepository, policy ports.AccessStateRepository, store credentials.Store, oauth OAuthGateway, config Config) (*Service, error) {
	if config.Provider == "" {
		config.Provider = "protected"
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.Entropy == nil {
		config.Entropy = rand.Reader
	}
	if config.RefreshSkew == 0 {
		config.RefreshSkew = time.Minute
	}
	if config.WaitLimit == 0 {
		config.WaitLimit = 20 * time.Second
	}
	if config.OperationLimit == 0 {
		config.OperationLimit = 30 * time.Second
	}
	if config.Lease == 0 {
		config.Lease = time.Minute
	}
	ref := connection.CredentialRef{Provider: config.Provider, Location: "test", ImmutableVersion: "test"}
	if repo == nil || policy == nil || store == nil || oauth == nil || ref.Validate() != nil || config.RefreshSkew < 0 || config.WaitLimit <= 0 || config.WaitLimit > 5*time.Minute || config.OperationLimit <= 0 || config.OperationLimit > config.Lease || config.Lease > 5*time.Minute {
		return nil, ErrConfiguration
	}
	return &Service{repo: repo, access: policy, store: store, oauth: oauth, config: config, flights: make(map[access.ConnectionID]*flight)}, nil
}

// CandidateReference binds one immutable candidate to the complete connection
// identity, authorization lineage, base generation and unique attempt. Length
// framing prevents ambiguous concatenations; the purpose prefix separates it
// from initial authorization writes.
func CandidateReference(provider string, owner access.OwnerID, id access.ConnectionID, lineage string, base uint64, attempt string) (connection.CredentialRef, error) {
	if budget.ValidateID(string(owner)) != nil || budget.ValidateID(string(id)) != nil || budget.ValidateID(lineage) != nil || budget.ValidateID(attempt) != nil || base == 0 {
		return connection.CredentialRef{}, ErrConfiguration
	}
	h := sha256.New()
	for _, value := range []string{"ynab-oauth-refresh-v1", string(owner), string(id), lineage, strconv.FormatUint(base, 10), attempt} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(value))
	}
	ref := connection.CredentialRef{Provider: provider, Location: "oauth-refresh/" + hex.EncodeToString(h.Sum(nil)), ImmutableVersion: attempt}
	if ref.Validate() != nil {
		return connection.CredentialRef{}, ErrConfiguration
	}
	return ref, nil
}

func (s *Service) point(name string) error {
	if s.checkpoint != nil {
		return s.checkpoint(name)
	}
	return nil
}
func (s *Service) now() time.Time { return s.config.Now().UTC() }

func validScope(scope access.ReadScope) bool {
	return budget.ValidateID(string(scope.OwnerID)) == nil && budget.ValidateID(string(scope.ConnectionID)) == nil && budget.ValidateID(scope.AuthorizationLineage) == nil && scope.PolicyVersion > 0 && (scope.BudgetID == "" || budget.ValidateID(string(scope.BudgetID)) == nil)
}

func (s *Service) policy(ctx context.Context, scope access.ReadScope, active bool) error {
	grant, binding, err := s.access.ReadAccessState(ctx)
	if err != nil {
		return ErrUnavailable
	}
	if !grant.Enabled() || grant.OwnerID() != scope.OwnerID || grant.ConnectionID() != scope.ConnectionID || grant.PolicyVersion() != scope.PolicyVersion || (scope.BudgetID != "" && !grant.AllowsBudget(scope.BudgetID)) || binding.OwnerID != scope.OwnerID || binding.ConnectionID != scope.ConnectionID || binding.AuthorizationLineage != scope.AuthorizationLineage {
		return access.ErrUnauthorized
	}
	if binding.Active != active {
		return connection.ErrConflict
	}
	return nil
}

func (s *Service) load(ctx context.Context, scope access.ReadScope) (connection.YNABConnection, error) {
	if !validScope(scope) {
		return connection.YNABConnection{}, access.ErrUnauthorized
	}
	c, err := s.repo.Load(ctx, scope.ConnectionID)
	if err != nil {
		return connection.YNABConnection{}, ErrUnavailable
	}
	state := c.State()
	if state.ID != scope.ConnectionID || state.OwnerID != scope.OwnerID || state.AuthorizationLineage != scope.AuthorizationLineage {
		return connection.YNABConnection{}, access.ErrUnauthorized
	}
	if state.Status == connection.ReconnectRequired {
		return c, ErrReconnectRequired
	}
	if state.Status != connection.Active && state.Status != connection.Refreshing {
		return c, connection.ErrNotActive
	}
	if state.Mode != connection.OAuth {
		return c, connection.ErrNotActive
	}
	if err := s.policy(ctx, scope, state.Status == connection.Active); err != nil {
		return c, err
	}
	return c, nil
}

func (s *Service) unchanged(ctx context.Context, scope access.ReadScope, want connection.YNABConnection) error {
	actual, err := s.load(ctx, scope)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(actual.State(), want.State()) {
		return connection.ErrConflict
	}
	return nil
}

// persist resolves every uncertain acknowledgement by rereading authoritative
// metadata. Only the exact intended state counts as acknowledgement; a conflict
// never authorizes I/O using a stale state. No transaction contains external I/O.
func (s *Service) persist(ctx context.Context, scope access.ReadScope, before, next connection.YNABConnection) (connection.YNABConnection, error) {
	old := before.State()
	err := s.repo.CompareAndSwapScoped(ctx, scope, old.Version, next)
	if err == nil {
		return next, nil
	}
	actual, readErr := s.repo.Load(ctx, old.ID)
	if readErr != nil {
		return connection.YNABConnection{}, ErrUnavailable
	}
	if reflect.DeepEqual(actual.State(), next.State()) {
		return actual, nil
	}
	if errors.Is(err, connection.ErrConflict) {
		return actual, connection.ErrConflict
	}
	if errors.Is(err, access.ErrUnauthorized) {
		return actual, access.ErrUnauthorized
	}
	return actual, ErrUnavailable
}

func validBundle(bundle credentials.CompleteBundle, expiry time.Time) bool {
	return bundle.Validate() == nil && bundle.ReadOnly() && bundle.ExpiresAt().Equal(expiry)
}

// committed also validates expired pairs: the refresh credential may still be
// needed, but the caller must separately check expiry before releasing a token.
func (s *Service) committed(ctx context.Context, scope access.ReadScope, c connection.YNABConnection) (credentials.CompleteBundle, error) {
	state := c.State()
	if state.Status != connection.Active {
		return credentials.CompleteBundle{}, connection.ErrNotActive
	}
	bundle, err := s.store.Read(ctx, state.Generation.Reference)
	if err != nil {
		if errors.Is(err, credentials.ErrNotFound) || errors.Is(err, credentials.ErrIntegrity) {
			return credentials.CompleteBundle{}, s.reconnect(ctx, scope, c)
		}
		return credentials.CompleteBundle{}, ErrUnavailable
	}
	if !validBundle(bundle, state.Generation.AccessExpiresAt) {
		return credentials.CompleteBundle{}, s.reconnect(ctx, scope, c)
	}
	if err = s.unchanged(ctx, scope, c); err != nil {
		return credentials.CompleteBundle{}, err
	}
	return bundle, nil
}

// AccessToken implements the fixed-host read adapter's internal token boundary.
// Waiters share work per connection but independently revalidate their scope and
// the committed generation. Cancellation of a waiter cannot restart an exchange.
func (s *Service) AccessToken(ctx context.Context, scope access.ReadScope) (string, error) {
	if ctx == nil {
		return "", ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.WaitLimit)
	defer cancel()
	var firstGeneration uint64
	for {
		if ctx.Err() != nil {
			return "", ErrRefreshInProgress
		}
		c, err := s.load(ctx, scope)
		if errors.Is(err, connection.ErrConflict) {
			continue
		}
		if err != nil {
			return "", err
		}
		if firstGeneration == 0 {
			firstGeneration = c.State().Generation.Number
		}
		if c.State().Status == connection.Active {
			bundle, err := s.committed(ctx, scope, c)
			if errors.Is(err, connection.ErrConflict) {
				continue
			}
			if err != nil {
				return "", err
			}
			if bundle.ExpiresAt().After(s.now().Add(s.config.RefreshSkew)) || c.State().Generation.Number > firstGeneration && bundle.ExpiresAt().After(s.now()) {
				if _, err = c.ReadGeneration(s.now()); err != nil {
					continue
				}
				if err = s.unchanged(ctx, scope, c); errors.Is(err, connection.ErrConflict) {
					continue
				} else if err != nil {
					return "", err
				}
				return bundle.ExportAccessTokenForYNABRead(), nil
			}
		}
		f := s.join(ctx, scope, c.State().Status == connection.Active)
		if f == nil {
			// Another process owns the durable attempt. Never reclaim its token
			// exchange merely because this process has no in-memory worker.
			timer := time.NewTimer(10 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return "", ErrRefreshInProgress
			case <-timer.C:
			}
			continue
		}
		select {
		case <-ctx.Done():
			return "", ErrRefreshInProgress
		case <-f.done:
			if f.err != nil && !errors.Is(f.err, connection.ErrConflict) {
				return "", f.err
			}
		}
	}
}

func (s *Service) join(ctx context.Context, scope access.ReadScope, start bool) *flight {
	s.mu.Lock()
	defer s.mu.Unlock()
	if f := s.flights[scope.ConnectionID]; f != nil {
		return f
	}
	if !start {
		return nil
	}
	f := &flight{done: make(chan struct{})}
	s.flights[scope.ConnectionID] = f
	work, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.config.OperationLimit)
	go func() {
		defer cancel()
		f.err = s.refresh(work, scope)
		s.mu.Lock()
		delete(s.flights, scope.ConnectionID)
		close(f.done)
		s.mu.Unlock()
	}()
	return f
}

func (s *Service) newAttempt() (string, error) {
	s.entropyMu.Lock()
	defer s.entropyMu.Unlock()
	var bytes [32]byte
	if _, err := io.ReadFull(s.config.Entropy, bytes[:]); err != nil {
		return "", ErrUnavailable
	}
	return base64.RawURLEncoding.EncodeToString(bytes[:]), nil
}

func (s *Service) refresh(ctx context.Context, scope access.ReadScope) error {
	c, err := s.load(ctx, scope)
	if err != nil {
		return err
	}
	if c.State().Status != connection.Active {
		return connection.ErrConflict
	}
	current, err := s.committed(ctx, scope, c)
	if err != nil {
		return err
	}
	if current.ExpiresAt().After(s.now().Add(s.config.RefreshSkew)) {
		return nil
	}
	id, err := s.newAttempt()
	if err != nil {
		return err
	}
	state := c.State()
	ref, err := CandidateReference(s.config.Provider, state.OwnerID, state.ID, state.AuthorizationLineage, state.Generation.Number, id)
	if err != nil {
		return err
	}
	now := s.now()
	next, err := c.BeginRefresh(state.Version, id, ref, now, now.Add(s.config.Lease))
	if err != nil {
		return err
	}
	if err = s.point("before_prepared"); err != nil {
		return err
	}
	c, err = s.persist(ctx, scope, c, next)
	if err != nil {
		return err
	}
	if err = s.point("after_prepared"); err != nil {
		return err
	}
	if err = s.unchanged(ctx, scope, c); err != nil {
		return err
	}
	state = c.State()
	a := state.Attempt
	next, err = c.MarkRequestStarted(state.Version, id, a.Fence, s.now())
	if err != nil {
		return err
	}
	if err = s.point("before_request_started"); err != nil {
		return err
	}
	c, err = s.persist(ctx, scope, c, next)
	if err != nil {
		return err
	}
	if err = s.point("after_request_started"); err != nil {
		return err
	}
	if err = s.unchanged(ctx, scope, c); err != nil {
		return err
	}
	if !s.now().Before(a.LeaseExpiresAt) {
		return s.reconnect(ctx, scope, c)
	}
	if err = s.point("before_exchange"); err != nil {
		return err
	}
	rotated, exchangeErr := s.oauth.Refresh(ctx, &current)
	if err = s.point("after_exchange"); err != nil {
		return err
	}
	// A single uncertain response permanently ends use of the old refresh
	// credential. Even an apparently retryable provider error is not retried.
	if exchangeErr != nil || rotated == nil || rotated.Validate() != nil || !rotated.ReadOnly() || !rotated.ExpiresAt().After(s.now()) {
		return s.reconnect(ctx, scope, c)
	}
	if err = s.unchanged(ctx, scope, c); err != nil {
		return err
	}
	if err = s.point("before_candidate_write"); err != nil {
		return err
	}
	putErr := s.store.PutImmutable(ctx, ref, *rotated)
	if err = s.point("after_candidate_write"); err != nil {
		return err
	}
	// A lost secret-store ACK is resolved only by exact readback, never by
	// performing the OAuth exchange again or overwriting a different pair.
	saved, readErr := s.store.Read(ctx, ref)
	if readErr != nil {
		if errors.Is(readErr, credentials.ErrNotFound) || errors.Is(readErr, credentials.ErrIntegrity) {
			return s.reconnect(ctx, scope, c)
		}
		return ErrUnavailable
	}
	if !saved.Equal(*rotated) || !validBundle(saved, rotated.ExpiresAt()) {
		return s.reconnect(ctx, scope, c)
	}
	_ = putErr // Successful exact readback is authoritative even after lost ACK.
	if err = s.unchanged(ctx, scope, c); err != nil {
		return err
	}
	return s.adopt(ctx, scope, c, saved)
}

func (s *Service) reconnect(ctx context.Context, scope access.ReadScope, c connection.YNABConnection) error {
	if err := s.unchanged(ctx, scope, c); err != nil {
		return err
	}
	state := c.State()
	var next connection.YNABConnection
	var err error
	if state.Status == connection.Refreshing && state.Attempt.Phase == connection.RequestStarted {
		next, err = c.MarkAmbiguous(state.Version, state.Attempt.ID, state.Attempt.Fence)
	} else {
		next, err = c.RequireReconnect(state.Version)
	}
	if err != nil {
		return err
	}
	if _, err = s.persist(ctx, scope, c, next); err != nil {
		return err
	}
	return ErrReconnectRequired
}

func (s *Service) adopt(ctx context.Context, scope access.ReadScope, c connection.YNABConnection, bundle credentials.CompleteBundle) error {
	state := c.State()
	a := state.Attempt
	if a == nil || !validBundle(bundle, bundle.ExpiresAt()) || !bundle.ExpiresAt().After(s.now()) {
		return s.reconnect(ctx, scope, c)
	}
	if a.Phase == connection.RequestStarted {
		proof := connection.PersistedCredential{Reference: a.CandidateRef, AccessExpiresAt: bundle.ExpiresAt(), Complete: true, ReadOnly: true}
		next, err := c.MarkSecretSaved(state.Version, a.ID, a.Fence, proof, s.now())
		if err != nil {
			return err
		}
		if err = s.point("before_secret_saved"); err != nil {
			return err
		}
		c, err = s.persist(ctx, scope, c, next)
		if err != nil {
			return err
		}
		if err = s.point("after_secret_saved"); err != nil {
			return err
		}
	}
	if err := s.unchanged(ctx, scope, c); err != nil {
		return err
	}
	state = c.State()
	a = state.Attempt
	if a.Phase != connection.SecretSaved || !a.CandidateExpiry.Equal(bundle.ExpiresAt()) || !bundle.ExpiresAt().After(s.now()) {
		return s.reconnect(ctx, scope, c)
	}
	next, err := c.CommitRefresh(state.Version, a.ID, a.Fence)
	if err != nil {
		return err
	}
	if err = s.point("before_commit"); err != nil {
		return err
	}
	c, err = s.persist(ctx, scope, c, next)
	if err != nil {
		return err
	}
	if err = s.point("after_commit"); err != nil {
		return err
	}
	return s.unchanged(ctx, scope, c)
}

// StoppedWorkerProof is supplied by trusted recovery orchestration after proving
// that the named worker can no longer execute. Elapsed time alone is not proof.
type StoppedWorkerProof struct {
	AttemptID     string
	Fence         uint64
	WorkerStopped bool
}

// Recover never calls OAuth. Prepared attempts can be abandoned only after the
// lease expired AND the exact worker is proven stopped. Started attempts adopt
// only a validated immutable candidate. A missing pair requires proof that the
// exact worker stopped before recovery can require fresh consent. Revoked policy
// keeps recovery blocked until an owner completes separately authorized consent.
func (s *Service) Recover(ctx context.Context, scope access.ReadScope, proof StoppedWorkerProof) error {
	if ctx == nil {
		return ErrUnavailable
	}
	ctx, cancel := context.WithTimeout(ctx, s.config.OperationLimit)
	defer cancel()
	c, err := s.load(ctx, scope)
	if err != nil {
		return err
	}
	state := c.State()
	if state.Status == connection.Active {
		_, err = s.committed(ctx, scope, c)
		return err
	}
	a := state.Attempt
	if a == nil {
		return ErrUnavailable
	}
	s.mu.Lock()
	live := s.flights[scope.ConnectionID] != nil
	s.mu.Unlock()
	if live {
		return ErrRefreshInProgress
	}
	stopped := proof.WorkerStopped && proof.AttemptID == a.ID && proof.Fence == a.Fence
	if a.Phase == connection.Prepared {
		if !stopped {
			return ErrRefreshInProgress
		}
		next, err := c.AbandonPrepared(state.Version, a.ID, a.Fence, true, s.now())
		if err != nil {
			return err
		}
		_, err = s.persist(ctx, scope, c, next)
		return err
	}
	ref, err := CandidateReference(a.CandidateRef.Provider, state.OwnerID, state.ID, state.AuthorizationLineage, a.BaseGeneration, a.ID)
	if err != nil || ref != a.CandidateRef {
		return s.reconnect(ctx, scope, c)
	}
	bundle, err := s.store.Read(ctx, a.CandidateRef)
	if err != nil {
		if a.Phase == connection.RequestStarted && errors.Is(err, credentials.ErrNotFound) && !stopped {
			return ErrRefreshInProgress
		}
		if errors.Is(err, credentials.ErrNotFound) || errors.Is(err, credentials.ErrIntegrity) {
			return s.reconnect(ctx, scope, c)
		}
		return ErrUnavailable
	}
	if bundle.Validate() != nil || !bundle.ReadOnly() || !bundle.ExpiresAt().After(s.now()) {
		return s.reconnect(ctx, scope, c)
	}
	if a.Phase == connection.SecretSaved && !bundle.ExpiresAt().Equal(a.CandidateExpiry) {
		return s.reconnect(ctx, scope, c)
	}
	if err = s.unchanged(ctx, scope, c); err != nil {
		return err
	}
	return s.adopt(ctx, scope, c, bundle)
}
