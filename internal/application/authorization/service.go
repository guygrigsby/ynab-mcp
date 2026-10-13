// Package authorization owns the private, owner-session-bound YNAB consent
// flow. It exposes no HTTP handler, MCP tool, login, or client registration.
package authorization

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"math"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/application/credentials"
	"github.com/guygrigsby/ynab-mcp/internal/application/ports"
	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/connection"
	"golang.org/x/oauth2"
)

var (
	ErrInvalidConfiguration = errors.New("invalid authorization configuration")
	ErrUnauthorized         = errors.New("owner authorization required")
	ErrInvalidCallback      = errors.New("invalid or expired authorization callback")
	ErrBusy                 = errors.New("authorization capacity unavailable")
	ErrUnavailable          = errors.New("authorization unavailable; restart consent")
)

const maxTTL = 10 * time.Minute

// OAuthExchange is the separate fixed-destination, read-only credential client.
// Exchange must make at most one token request; the service never retries it.
type OAuthExchange interface {
	AuthorizationURL(state, verifier string) (string, error)
	Exchange(context.Context, string, string) (*credentials.CompleteBundle, error)
}

// Config is trusted composition configuration, never an MCP or request argument.
// Zero limits select conservative defaults. SecretProvider names an approved
// protected-store namespace; setting it does not select or provision a backend.
type Config struct {
	CallbackURL          string
	SecretProvider       string
	TTL                  time.Duration
	MaxPending           int
	MaxPendingPerSession int
	MaxAttempts          int
}

// BeginRequest requires an independently authenticated, nonexpired principal and
// a cryptographically random server-authenticated session identifier (32..512
// visible ASCII bytes). A client-supplied OAuth state or MCP session is not an
// authenticated session. A future HTTP adapter must enforce that distinction.
type BeginRequest struct {
	Principal access.Principal `json:"-"`
	SessionID string           `json:"-"`
}

// CallbackURL is the actual, trusted HTTPS origin plus escaped callback path,
// excluding the query. A future adapter must not construct it from unvalidated
// forwarding/Host headers. Code and state must each be one unambiguous parameter.
type CallbackRequest struct {
	Principal   access.Principal `json:"-"`
	SessionID   string           `json:"-"`
	State       string           `json:"-"`
	Code        string           `json:"-"`
	CallbackURL string           `json:"-"`
}

type BeginResult struct {
	AuthorizationURL string    `json:"-"`
	ExpiresAt        time.Time `json:"expires_at"`
}

func (BeginRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("[redacted authorization request]"))
}
func (BeginRequest) LogValue() slog.Value {
	return slog.StringValue("[redacted authorization request]")
}
func (CallbackRequest) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("[redacted authorization callback]"))
}
func (CallbackRequest) LogValue() slog.Value {
	return slog.StringValue("[redacted authorization callback]")
}
func (BeginResult) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("[redacted authorization result]"))
}
func (BeginResult) LogValue() slog.Value { return slog.StringValue("[redacted authorization result]") }

type pending struct {
	expected ports.AuthorizationExpectation
	session  [32]byte
	verifier string
	lineage  string
	created  time.Time
	expires  time.Time
	attempts int
}

// Service keeps a bounded ephemeral state/PKCE map. Restart deliberately loses
// every pending flow. Verifiers never enter repositories, logs, or tool results.
// The single-process in-flight gate complements the durable activation CAS.
// Keeping the mutable core behind a pointer also makes accidental by-value
// formatting redacted without copying a mutex.
type Service struct{ *serviceState }

type serviceState struct {
	config     Config
	repository ports.AuthorizationRepository
	oauth      OAuthExchange
	secrets    credentials.Store
	now        func() time.Time
	mu         sync.Mutex
	states     map[[32]byte]pending
	active     map[access.ConnectionID][32]byte
	lastNow    time.Time
}

func (Service) Format(s fmt.State, _ rune) {
	_, _ = s.Write([]byte("[redacted authorization service]"))
}
func (Service) LogValue() slog.Value { return slog.StringValue("[redacted authorization service]") }
func (Service) MarshalJSON() ([]byte, error) {
	return json.Marshal("[redacted authorization service]")
}

func NewService(config Config, repository ports.AuthorizationRepository, oauth OAuthExchange, secrets credentials.Store) (*Service, error) {
	if config.TTL == 0 {
		config.TTL = maxTTL
	}
	if config.MaxPending == 0 {
		config.MaxPending = 128
	}
	if config.MaxPendingPerSession == 0 {
		config.MaxPendingPerSession = 2
	}
	if config.MaxAttempts == 0 {
		config.MaxAttempts = 3
	}
	if !validCallback(config.CallbackURL) || !visibleASCII(config.SecretProvider, 128) || config.TTL <= 0 || config.TTL > maxTTL || config.MaxPending < 1 || config.MaxPending > 1024 || config.MaxPendingPerSession < 1 || config.MaxPendingPerSession > config.MaxPending || config.MaxAttempts < 1 || config.MaxAttempts > 5 || repository == nil || oauth == nil || secrets == nil {
		return nil, ErrInvalidConfiguration
	}
	return &Service{&serviceState{config: config, repository: repository, oauth: oauth, secrets: secrets, now: time.Now, states: make(map[[32]byte]pending), active: make(map[access.ConnectionID][32]byte)}}, nil
}

func (s *Service) Begin(ctx context.Context, request BeginRequest) (BeginResult, error) {
	var zero BeginResult
	if s == nil || s.serviceState == nil || ctx == nil || ctx.Err() != nil {
		return zero, ErrUnavailable
	}
	now := s.now().UTC()
	if !validPrincipal(request.Principal, now) || !validSession(request.SessionID) {
		return zero, ErrUnauthorized
	}
	grant, current, err := s.repository.ReadAuthorizationState(ctx)
	if err != nil || !authorized(grant, current, request.Principal) {
		return zero, ErrUnauthorized
	}
	state, err := randomID()
	if err != nil {
		return zero, ErrUnavailable
	}
	lineage, err := randomID()
	if err != nil {
		return zero, ErrUnavailable
	}
	verifier := oauth2.GenerateVerifier()
	redirect, err := s.oauth.AuthorizationURL(state, verifier)
	if err != nil || !validAuthorizationURL(redirect, s.config.CallbackURL, state, verifier) {
		return zero, ErrUnavailable
	}
	entry := pending{expected: expectation(grant, current), session: sha256.Sum256([]byte(request.SessionID)), verifier: verifier, lineage: lineage, created: now, expires: now.Add(s.config.TTL)}
	key := sha256.Sum256([]byte(state))
	s.mu.Lock()
	defer s.mu.Unlock()
	latest := s.now().UTC()
	if latest.Before(now) || !latest.Before(entry.expires) || !s.observeTime(latest) || !validPrincipal(request.Principal, latest) || ctx.Err() != nil {
		return zero, ErrUnavailable
	}
	s.prune(latest)
	if len(s.states)+len(s.active) >= s.config.MaxPending {
		return zero, ErrBusy
	}
	count := 0
	for _, item := range s.states {
		if item.session == entry.session {
			count++
		}
	}
	for _, session := range s.active {
		if session == entry.session {
			count++
		}
	}
	if count >= s.config.MaxPendingPerSession {
		return zero, ErrBusy
	}
	if _, exists := s.states[key]; exists {
		return zero, ErrUnavailable
	}
	s.states[key] = entry
	return BeginResult{AuthorizationURL: redirect, ExpiresAt: entry.expires}, nil
}

// Callback consumes the pending state before the uncertain token exchange. Every
// subsequent failure requires new consent; neither the code nor verifier is
// replayed. It publishes only a complete, immutable, exactly read-back bundle
// through the policy-fenced Activate CAS. Failed commits leave safe orphan refs;
// this service never deletes secrets or guesses that an uncertain commit worked.
func (s *Service) Callback(ctx context.Context, request CallbackRequest) error {
	if s == nil || s.serviceState == nil || ctx == nil || ctx.Err() != nil {
		return ErrUnavailable
	}
	entry, err := s.consume(request, s.now().UTC())
	if err != nil {
		return err
	}
	defer func() { s.mu.Lock(); delete(s.active, entry.expected.ConnectionID); s.mu.Unlock() }()
	current, err := s.revalidate(ctx, request.Principal, entry)
	if err != nil {
		return err
	}
	ref, err := candidateReference(s.config.SecretProvider, current.State(), entry.lineage)
	if err != nil {
		return ErrUnavailable
	}
	bundle, err := s.oauth.Exchange(ctx, request.Code, entry.verifier)
	if err != nil || bundle == nil || bundle.Validate() != nil || !bundle.ReadOnly() || !bundle.ExpiresAt().After(s.now().UTC()) {
		return ErrUnavailable
	}
	// A revoked/changed policy, disabled/reconnected connection, expired session,
	// or expired flow cannot turn a late exchange result into an active credential.
	if _, err := s.revalidate(ctx, request.Principal, entry); err != nil {
		return err
	}
	if err := s.secrets.PutImmutable(ctx, ref, *bundle); err != nil {
		return ErrUnavailable
	}
	stored, err := s.secrets.Read(ctx, ref)
	if err != nil || stored.Validate() != nil || !stored.Equal(*bundle) {
		return ErrUnavailable
	}
	current, err = s.revalidate(ctx, request.Principal, entry)
	if err != nil {
		return err
	}
	now := s.now().UTC()
	next, err := current.Activate(entry.expected.ConnectionVersion, entry.lineage, connection.PersistedCredential{Reference: ref, AccessExpiresAt: stored.ExpiresAt(), Complete: true, ReadOnly: stored.ReadOnly()}, now)
	if err != nil {
		return ErrUnavailable
	}
	if err := s.repository.CompareAndSwapAuthorized(ctx, entry.expected, next); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (s *Service) consume(request CallbackRequest, now time.Time) (pending, error) {
	var zero pending
	if len(request.State) != 43 || !unreserved(request.State) {
		return zero, ErrInvalidCallback
	}
	key := sha256.Sum256([]byte(request.State))
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.observeTime(now) {
		return zero, ErrInvalidCallback
	}
	s.prune(now)
	entry, exists := s.states[key]
	if !exists {
		return zero, ErrInvalidCallback
	}
	entry.attempts++
	// Every known-state presentation is bounded, including incorrect owner,
	// session, path and code presentations. Unknown states allocate nothing.
	s.states[key] = entry
	var session [32]byte
	validBoundSession := validSession(request.SessionID)
	if validBoundSession {
		session = sha256.Sum256([]byte(request.SessionID))
	}
	if entry.attempts > s.config.MaxAttempts || !validBoundSession || subtle.ConstantTimeCompare(session[:], entry.session[:]) != 1 || !validPrincipal(request.Principal, now) || request.Principal.Key != entry.expected.PrincipalKey || request.CallbackURL != s.config.CallbackURL || !visibleASCII(request.Code, 4096) || now.Before(entry.created) || !now.Before(entry.expires) {
		if entry.attempts >= s.config.MaxAttempts {
			delete(s.states, key)
		}
		return zero, ErrInvalidCallback
	}
	if _, busy := s.active[entry.expected.ConnectionID]; busy {
		if entry.attempts >= s.config.MaxAttempts {
			delete(s.states, key)
		}
		return zero, ErrBusy
	}
	delete(s.states, key)
	s.active[entry.expected.ConnectionID] = entry.session
	return entry, nil
}

func (s *Service) revalidate(ctx context.Context, principal access.Principal, entry pending) (connection.YNABConnection, error) {
	var zero connection.YNABConnection
	now := s.now().UTC()
	s.mu.Lock()
	validTime := s.observeTime(now)
	s.mu.Unlock()
	if !validTime || ctx.Err() != nil || now.Before(entry.created) || !now.Before(entry.expires) || !validPrincipal(principal, now) {
		return zero, ErrInvalidCallback
	}
	grant, current, err := s.repository.ReadAuthorizationState(ctx)
	if err != nil || !authorized(grant, current, principal) || expectation(grant, current) != entry.expected {
		return zero, ErrUnauthorized
	}
	return current, nil
}

func authorized(grant access.OwnerAccessGrant, current connection.YNABConnection, principal access.Principal) bool {
	state := current.State()
	if !grant.Enabled() || len(grant.BudgetIDs()) == 0 || grant.PrincipalKey() != principal.Key || grant.OwnerID() != state.OwnerID || grant.ConnectionID() != state.ID || state.Mode != connection.OAuth || state.RequestedScope != "read-only" {
		return false
	}
	if _, err := connection.Restore(state); err != nil {
		return false
	}
	return state.Status == connection.Unconnected || state.Status == connection.Active || state.Status == connection.ReconnectRequired
}

func expectation(grant access.OwnerAccessGrant, current connection.YNABConnection) ports.AuthorizationExpectation {
	state := current.State()
	return ports.AuthorizationExpectation{OwnerID: grant.OwnerID(), ConnectionID: state.ID, PrincipalKey: grant.PrincipalKey(), PolicyVersion: grant.PolicyVersion(), ConnectionVersion: state.Version, ConnectionStatus: state.Status}
}

func (s *Service) observeTime(now time.Time) bool {
	if now.IsZero() || now.Before(s.lastNow) {
		return false
	}
	s.lastNow = now
	return true
}
func (s *Service) prune(now time.Time) {
	for key, entry := range s.states {
		if !now.Before(entry.expires) {
			delete(s.states, key)
		}
	}
}
func randomID() (string, error) {
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data[:]), nil
}
func validPrincipal(p access.Principal, now time.Time) bool {
	return !now.IsZero() && p.Key.Validate() == nil && p.HasScope(access.ReadScopeName) && now.Before(p.ExpiresAt)
}
func validSession(session string) bool { return len(session) >= 32 && visibleASCII(session, 512) }
func visibleASCII(value string, maximum int) bool {
	if value == "" || len(value) > maximum {
		return false
	}
	for i := range value {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}
func unreserved(value string) bool {
	for i := range value {
		c := value[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("-._~", rune(c))) {
			return false
		}
	}
	return true
}
func validCallback(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && len(raw) <= 2048 && u.Scheme == "https" && u.Hostname() != "" && u.User == nil && u.Opaque == "" && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" && u.RawFragment == "" && u.Path != "" && u.String() == raw
}
func validAuthorizationURL(raw, callback, state, verifier string) bool {
	u, err := url.Parse(raw)
	if err != nil || len(raw) > 8192 || u.Scheme != "https" || u.Host != "app.ynab.com" || u.User != nil || u.Path != "/oauth/authorize" || u.RawPath != "" || u.Fragment != "" || u.Opaque != "" {
		return false
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil || len(q) != 7 {
		return false
	}
	expected := map[string]string{"response_type": "code", "redirect_uri": callback, "scope": "read-only", "state": state, "code_challenge_method": "S256", "code_challenge": oauth2.S256ChallengeFromVerifier(verifier)}
	for key, value := range expected {
		if len(q[key]) != 1 || q.Get(key) != value {
			return false
		}
	}
	return len(q["client_id"]) == 1 && visibleASCII(q.Get("client_id"), 1024)
}

func candidateReference(provider string, state connection.State, lineage string) (connection.CredentialRef, error) {
	if state.Generation.Number == math.MaxUint64 {
		return connection.CredentialRef{}, ErrUnavailable
	}
	hash := sha256.New()
	for _, value := range []string{string(state.OwnerID), string(state.ID), lineage} {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = hash.Write(size[:])
		_, _ = hash.Write([]byte(value))
	}
	var generation [8]byte
	binary.BigEndian.PutUint64(generation[:], state.Generation.Number+1)
	_, _ = hash.Write(generation[:])
	ref := connection.CredentialRef{Provider: provider, Location: "oauth-authorization/" + hex.EncodeToString(hash.Sum(nil)), ImmutableVersion: lineage}
	return ref, ref.Validate()
}
