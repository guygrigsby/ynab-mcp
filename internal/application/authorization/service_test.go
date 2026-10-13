package authorization

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/application/credentials"
	"github.com/guygrigsby/ynab-mcp/internal/application/ports"
	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/budget"
	"github.com/guygrigsby/ynab-mcp/internal/domain/connection"
	"golang.org/x/oauth2"
)

const callback = "https://owner.example/ynab/callback"
const session = "synthetic-authenticated-session-1234567890"

// These adapters are deliberately test-only. No callback persistence or secret
// store implementation here selects a production backend.
type testRepository struct {
	mu        sync.Mutex
	grant     access.OwnerAccessGrant
	current   connection.YNABConnection
	readError error
	beforeCAS func()
	casError  error
	commits   int
}

func (r *testRepository) ReadAuthorizationState(context.Context) (access.OwnerAccessGrant, connection.YNABConnection, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.grant, r.current, r.readError
}
func (r *testRepository) CompareAndSwapAuthorized(_ context.Context, expected ports.AuthorizationExpectation, next connection.YNABConnection) error {
	if r.beforeCAS != nil {
		r.beforeCAS()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.casError != nil {
		return r.casError
	}
	if expectation(r.grant, r.current) != expected || !r.grant.Enabled() || r.current.State().Status == connection.Disabled || r.current.State().Status == connection.Refreshing {
		return connection.ErrConflict
	}
	r.current = next
	r.commits++
	return nil
}
func (r *testRepository) disable() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.current, _ = r.current.Disable(r.current.State().Version)
}
func (r *testRepository) changePolicy() {
	r.mu.Lock()
	defer r.mu.Unlock()
	g := r.grant
	r.grant, _ = g.Replace(g.PolicyVersion(), access.GrantConfig{OwnerID: g.OwnerID(), PrincipalKey: g.PrincipalKey(), ConnectionID: g.ConnectionID(), ConnectionOwnerID: g.OwnerID(), BudgetIDs: []budget.BudgetID{"budget-other"}, Enabled: true})
}

type testOAuth struct {
	mu                     sync.Mutex
	bundle                 credentials.CompleteBundle
	exchangeError          error
	nilBundle              bool
	urlError               error
	alterURL               func(string) string
	onExchange             func()
	calls                  int
	states                 []string
	verifiers              map[string]string
	lastCode, lastVerifier string
}

func (o *testOAuth) AuthorizationURL(state, verifier string) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.states = append(o.states, state)
	o.verifiers[state] = verifier
	c := oauth2.Config{ClientID: "synthetic-client", RedirectURL: callback, Scopes: []string{"read-only"}, Endpoint: oauth2.Endpoint{AuthURL: "https://app.ynab.com/oauth/authorize"}}
	result := c.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier))
	if o.alterURL != nil {
		result = o.alterURL(result)
	}
	return result, o.urlError
}
func (o *testOAuth) Exchange(_ context.Context, code, verifier string) (*credentials.CompleteBundle, error) {
	o.mu.Lock()
	o.calls++
	o.lastCode = code
	o.lastVerifier = verifier
	o.mu.Unlock()
	if o.onExchange != nil {
		o.onExchange()
	}
	if o.nilBundle {
		return nil, o.exchangeError
	}
	return &o.bundle, o.exchangeError
}
func (o *testOAuth) callCount() int { o.mu.Lock(); defer o.mu.Unlock(); return o.calls }

type testSecrets struct {
	mu                  sync.Mutex
	items               map[connection.CredentialRef]credentials.CompleteBundle
	putError, readError error
	readOverride        *credentials.CompleteBundle
	onPut               func()
	puts, reads         int
}

func (s *testSecrets) PutImmutable(_ context.Context, ref connection.CredentialRef, b credentials.CompleteBundle) error {
	if s.onPut != nil {
		s.onPut()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.puts++
	if s.putError != nil {
		return s.putError
	}
	if old, ok := s.items[ref]; ok && !old.Equal(b) {
		return credentials.ErrConflict
	}
	s.items[ref] = b
	return nil
}
func (s *testSecrets) Read(_ context.Context, ref connection.CredentialRef) (credentials.CompleteBundle, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	if s.readError != nil {
		return credentials.CompleteBundle{}, s.readError
	}
	if s.readOverride != nil {
		return *s.readOverride, nil
	}
	b, ok := s.items[ref]
	if !ok {
		return credentials.CompleteBundle{}, credentials.ErrNotFound
	}
	return b, nil
}

type fixture struct {
	service   *Service
	repo      *testRepository
	oauth     *testOAuth
	secrets   *testSecrets
	principal access.Principal
	clock     atomic.Int64
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	p := access.Principal{Key: access.PrincipalKey{Issuer: "https://issuer.example", Subject: "owner-subject", Tenant: "tenant-a"}, Scopes: []string{access.ReadScopeName}, ExpiresAt: now.Add(time.Hour)}
	g, err := access.NewOwnerAccessGrant(access.GrantConfig{OwnerID: "owner-1", PrincipalKey: p.Key, ConnectionID: "connection-1", ConnectionOwnerID: "owner-1", BudgetIDs: []budget.BudgetID{"budget-1"}, Enabled: true, PolicyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	c, err := connection.New("connection-1", "owner-1", connection.OAuth)
	if err != nil {
		t.Fatal(err)
	}
	b, err := credentials.NewOAuthBundle("synthetic-access-marker", "synthetic-refresh-marker", now.Add(time.Hour), "read-only")
	if err != nil {
		t.Fatal(err)
	}
	f := &fixture{repo: &testRepository{grant: g, current: c}, oauth: &testOAuth{bundle: b, verifiers: map[string]string{}}, secrets: &testSecrets{items: map[connection.CredentialRef]credentials.CompleteBundle{}}, principal: p}
	f.clock.Store(now.UnixNano())
	f.service, err = NewService(Config{CallbackURL: callback, SecretProvider: "protected"}, f.repo, f.oauth, f.secrets)
	if err != nil {
		t.Fatal(err)
	}
	f.service.now = func() time.Time { return time.Unix(0, f.clock.Load()).UTC() }
	return f
}
func (f *fixture) start(t *testing.T) CallbackRequest {
	t.Helper()
	result, err := f.service.Begin(context.Background(), BeginRequest{Principal: f.principal, SessionID: session})
	if err != nil {
		t.Fatal(err)
	}
	u, err := url.Parse(result.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	return CallbackRequest{Principal: f.principal, SessionID: session, State: u.Query().Get("state"), Code: "synthetic-code-marker", CallbackURL: callback}
}

func TestConsentPersistsExactBundleBeforeActivation(t *testing.T) {
	f := newFixture(t)
	request := f.start(t)
	if err := f.service.Callback(context.Background(), request); err != nil {
		t.Fatal(err)
	}
	s := f.repo.current.State()
	if s.Status != connection.Active || s.Generation.Number != 1 || s.Version != 2 || s.AuthorizationLineage == "" || s.Generation.Reference.ImmutableVersion != s.AuthorizationLineage || s.Generation.Reference.Provider != "protected" || !strings.HasPrefix(s.Generation.Reference.Location, "oauth-authorization/") {
		t.Fatalf("bad activation: %#v", s)
	}
	stored := f.secrets.items[s.Generation.Reference]
	if !stored.Equal(f.oauth.bundle) || f.secrets.puts != 1 || f.secrets.reads != 1 || f.repo.commits != 1 || f.oauth.callCount() != 1 {
		t.Fatal("activation omitted exact bundle persistence/readback")
	}
	if f.oauth.lastVerifier != f.oauth.verifiers[request.State] || f.oauth.lastCode != request.Code {
		t.Fatal("exchange did not use bound code and verifier")
	}
	if len(f.service.states) != 0 || len(f.service.active) != 0 {
		t.Fatal("state retained after consumption")
	}
	if err := f.service.Callback(context.Background(), request); !errors.Is(err, ErrInvalidCallback) || f.oauth.callCount() != 1 {
		t.Fatal("callback replay reached exchange")
	}
}

func TestStatePKCEAndLineageAreIndependentAndRandom(t *testing.T) {
	f := newFixture(t)
	seen := map[string]bool{}
	for i := 0; i < 40; i++ {
		f.service.config.MaxPendingPerSession = 64
		result, err := f.service.Begin(context.Background(), BeginRequest{Principal: f.principal, SessionID: session})
		if err != nil {
			t.Fatal(err)
		}
		u, _ := url.Parse(result.AuthorizationURL)
		state := u.Query().Get("state")
		verifier := f.oauth.verifiers[state]
		entry := f.service.states[sha256.Sum256([]byte(state))]
		for _, value := range []string{state, verifier, entry.lineage} {
			if len(value) != 43 || seen[value] {
				t.Fatal("state, PKCE or lineage not independently random")
			}
			seen[value] = true
		}
		if u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("code_challenge") != oauth2.S256ChallengeFromVerifier(verifier) || strings.Contains(result.AuthorizationURL, verifier) || result.ExpiresAt.Sub(entry.created) != maxTTL {
			t.Fatal("invalid PKCE or expiry")
		}
	}
}

func TestBeginRequiresExactAuthenticatedOwnerGrant(t *testing.T) {
	cases := map[string]func(*fixture, *BeginRequest){
		"wrong issuer":        func(_ *fixture, r *BeginRequest) { r.Principal.Key.Issuer = "https://other.example" },
		"wrong subject":       func(_ *fixture, r *BeginRequest) { r.Principal.Key.Subject = "another" },
		"wrong tenant":        func(_ *fixture, r *BeginRequest) { r.Principal.Key.Tenant = "" },
		"missing scope":       func(_ *fixture, r *BeginRequest) { r.Principal.Scopes = nil },
		"expired":             func(f *fixture, r *BeginRequest) { r.Principal.ExpiresAt = f.service.now() },
		"zero expiry":         func(_ *fixture, r *BeginRequest) { r.Principal.ExpiresAt = time.Time{} },
		"no session":          func(_ *fixture, r *BeginRequest) { r.SessionID = "" },
		"short session":       func(_ *fixture, r *BeginRequest) { r.SessionID = "client-session" },
		"bad session":         func(_ *fixture, r *BeginRequest) { r.SessionID = session + "\n" },
		"disabled connection": func(f *fixture, _ *BeginRequest) { f.repo.disable() },
		"foreign connection": func(f *fixture, _ *BeginRequest) {
			f.repo.current, _ = connection.New("connection-1", "other-owner", connection.OAuth)
		},
		"foreign connection id": func(f *fixture, _ *BeginRequest) {
			f.repo.current, _ = connection.New("other-connection", "owner-1", connection.OAuth)
		},
		"personal token": func(f *fixture, _ *BeginRequest) {
			f.repo.current, _ = connection.New("connection-1", "owner-1", connection.PersonalToken)
		},
		"unavailable": func(f *fixture, _ *BeginRequest) { f.repo.readError = errors.New("sensitive database error") },
		"disabled grant": func(f *fixture, _ *BeginRequest) {
			g := f.repo.grant
			f.repo.grant, _ = g.Replace(g.PolicyVersion(), access.GrantConfig{OwnerID: g.OwnerID(), PrincipalKey: g.PrincipalKey(), ConnectionID: g.ConnectionID(), ConnectionOwnerID: g.OwnerID(), BudgetIDs: g.BudgetIDs(), Enabled: false})
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			r := BeginRequest{Principal: f.principal, SessionID: session}
			mutate(f, &r)
			if _, err := f.service.Begin(context.Background(), r); !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("error = %v", err)
			}
			if len(f.service.states) != 0 || f.oauth.callCount() != 0 {
				t.Fatal("unauthorized flow allocated state or exchanged")
			}
		})
	}
}

func TestCallbackRejectsBindingAndOriginMismatch(t *testing.T) {
	cases := map[string]func(*CallbackRequest){
		"state":           func(r *CallbackRequest) { r.State = strings.Repeat("z", 43) },
		"missing state":   func(r *CallbackRequest) { r.State = "" },
		"malformed state": func(r *CallbackRequest) { r.State = "/" + r.State[1:] },
		"session":         func(r *CallbackRequest) { r.SessionID = "another-authenticated-session-1234567890" },
		"owner":           func(r *CallbackRequest) { r.Principal.Key.Subject = "other" },
		"tenant":          func(r *CallbackRequest) { r.Principal.Key.Tenant = "other" },
		"scope":           func(r *CallbackRequest) { r.Principal.Scopes = nil },
		"http":            func(r *CallbackRequest) { r.CallbackURL = "http://owner.example/ynab/callback" },
		"host":            func(r *CallbackRequest) { r.CallbackURL = "https://evil.example/ynab/callback" },
		"subdomain":       func(r *CallbackRequest) { r.CallbackURL = "https://owner.example.evil.example/ynab/callback" },
		"port":            func(r *CallbackRequest) { r.CallbackURL = "https://owner.example:443/ynab/callback" },
		"case":            func(r *CallbackRequest) { r.CallbackURL = "https://OWNER.example/ynab/callback" },
		"slash":           func(r *CallbackRequest) { r.CallbackURL = callback + "/" },
		"query":           func(r *CallbackRequest) { r.CallbackURL = callback + "?code=synthetic" },
		"fragment":        func(r *CallbackRequest) { r.CallbackURL = callback + "#x" },
		"escaped path":    func(r *CallbackRequest) { r.CallbackURL = "https://owner.example/ynab/%63allback" },
		"missing code":    func(r *CallbackRequest) { r.Code = "" },
		"oversize code":   func(r *CallbackRequest) { r.Code = strings.Repeat("x", 4097) },
		"code control":    func(r *CallbackRequest) { r.Code = "code\n" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			r := f.start(t)
			mutate(&r)
			if err := f.service.Callback(context.Background(), r); !errors.Is(err, ErrInvalidCallback) {
				t.Fatalf("error = %v", err)
			}
			if f.oauth.callCount() != 0 || f.secrets.puts != 0 || f.repo.commits != 0 {
				t.Fatal("invalid callback performed I/O")
			}
		})
	}
}

func TestStateExpiresAbsolutelyAndRestartLosesPendingFlow(t *testing.T) {
	for _, duration := range []time.Duration{maxTTL, maxTTL + time.Second, -time.Second} {
		t.Run(duration.String(), func(t *testing.T) {
			f := newFixture(t)
			r := f.start(t)
			f.clock.Add(int64(duration))
			if err := f.service.Callback(context.Background(), r); err == nil || f.oauth.callCount() != 0 {
				t.Fatal("expired/rollback state accepted")
			}
		})
	}
	f := newFixture(t)
	r := f.start(t)
	restarted, err := NewService(f.service.config, f.repo, f.oauth, f.secrets)
	if err != nil {
		t.Fatal(err)
	}
	restarted.now = f.service.now
	if err := restarted.Callback(context.Background(), r); !errors.Is(err, ErrInvalidCallback) || f.oauth.callCount() != 0 {
		t.Fatal("restart recovered ephemeral state")
	}
}

func TestCallbackFailuresConsumeBeforeExchangeAndNeverActivate(t *testing.T) {
	cases := map[string]func(*fixture){
		"exchange failure": func(f *fixture) { f.oauth.exchangeError = errors.New("synthetic-access-marker synthetic-code-marker") },
		"nil bundle":       func(f *fixture) { f.oauth.nilBundle = true },
		"invalid bundle":   func(f *fixture) { f.oauth.bundle = credentials.CompleteBundle{} },
		"expired bundle": func(f *fixture) {
			f.oauth.bundle, _ = credentials.NewOAuthBundle("synthetic-access-marker", "synthetic-refresh-marker", f.service.now(), "read-only")
		},
		"failed write":     func(f *fixture) { f.secrets.putError = errors.New("synthetic-access-marker") },
		"missing readback": func(f *fixture) { f.secrets.readError = credentials.ErrNotFound },
		"failed readback":  func(f *fixture) { f.secrets.readError = errors.New("synthetic-refresh-marker") },
		"mismatched readback": func(f *fixture) {
			b, _ := credentials.NewOAuthBundle("other-access", "synthetic-refresh-marker", f.oauth.bundle.ExpiresAt(), "read-only")
			f.secrets.readOverride = &b
		},
		"invalid readback": func(f *fixture) { f.secrets.readOverride = &credentials.CompleteBundle{} },
		"failed commit":    func(f *fixture) { f.repo.casError = errors.New("synthetic-access-marker") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			r := f.start(t)
			mutate(f)
			err := f.service.Callback(context.Background(), r)
			if !errors.Is(err, ErrUnavailable) {
				t.Fatalf("error = %v", err)
			}
			if strings.Contains(err.Error(), "marker") || f.repo.commits != 0 || f.repo.current.State().Status != connection.Unconnected {
				t.Fatal("failed callback leaked or activated")
			}
			if err := f.service.Callback(context.Background(), r); !errors.Is(err, ErrInvalidCallback) || f.oauth.callCount() != 1 {
				t.Fatal("failed exchange replayed")
			}
		})
	}
}

func TestCallbackRevalidatesPolicyAndDisableAtEveryBoundary(t *testing.T) {
	for _, boundary := range []string{"before callback", "during exchange", "during persistence", "at commit"} {
		for _, change := range []string{"disable", "policy"} {
			t.Run(boundary+"/"+change, func(t *testing.T) {
				f := newFixture(t)
				r := f.start(t)
				mutate := f.repo.disable
				if change == "policy" {
					mutate = f.repo.changePolicy
				}
				switch boundary {
				case "before callback":
					mutate()
				case "during exchange":
					f.oauth.onExchange = mutate
				case "during persistence":
					f.secrets.onPut = mutate
				case "at commit":
					f.repo.beforeCAS = mutate
				}
				if err := f.service.Callback(context.Background(), r); err == nil || f.repo.commits != 0 {
					t.Fatal("late authorization defeated policy/disable")
				}
				if err := f.service.Callback(context.Background(), r); !errors.Is(err, ErrInvalidCallback) {
					t.Fatal("rejected state was reusable")
				}
				if boundary == "before callback" && f.oauth.callCount() != 0 {
					t.Fatal("changed baseline reached exchange")
				}
				if boundary == "during exchange" && f.secrets.puts != 0 {
					t.Fatal("revoked exchange was persisted")
				}
			})
		}
	}
}

func TestSessionExpiryAndFlowExpiryDuringExchange(t *testing.T) {
	for _, kind := range []string{"flow", "principal", "clock rollback"} {
		t.Run(kind, func(t *testing.T) {
			f := newFixture(t)
			if kind == "principal" {
				f.principal.ExpiresAt = f.service.now().Add(time.Second)
			}
			r := f.start(t)
			f.oauth.onExchange = func() {
				if kind == "flow" {
					f.clock.Add(int64(maxTTL))
				} else if kind == "principal" {
					f.clock.Add(int64(time.Second))
				} else {
					f.clock.Add(-int64(time.Second))
				}
			}
			if err := f.service.Callback(context.Background(), r); err == nil || f.secrets.puts != 0 || f.repo.commits != 0 {
				t.Fatal("expired or clock-rollback flow activated")
			}
		})
	}
}

func TestOneStateConcurrentCallbacksExchangeExactlyOnce(t *testing.T) {
	f := newFixture(t)
	r := f.start(t)
	entered, release := make(chan struct{}), make(chan struct{})
	f.oauth.onExchange = func() { close(entered); <-release }
	first := make(chan error, 1)
	go func() { first <- f.service.Callback(context.Background(), r) }()
	<-entered
	var wg sync.WaitGroup
	for i := 0; i < 25; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := f.service.Callback(context.Background(), r); !errors.Is(err, ErrInvalidCallback) {
				t.Errorf("concurrent replay error = %v", err)
			}
		}()
	}
	wg.Wait()
	close(release)
	if err := <-first; err != nil {
		t.Fatal(err)
	}
	if f.oauth.callCount() != 1 || f.repo.commits != 1 {
		t.Fatal("state concurrency was not single-use")
	}
}

func TestConcurrentFlowsCannotRaceConnectionExchanges(t *testing.T) {
	f := newFixture(t)
	first, second := f.start(t), f.start(t)
	entered, release := make(chan struct{}), make(chan struct{})
	f.oauth.onExchange = func() { close(entered); <-release }
	done := make(chan error, 1)
	go func() { done <- f.service.Callback(context.Background(), first) }()
	<-entered
	if err := f.service.Callback(context.Background(), second); !errors.Is(err, ErrBusy) {
		t.Fatalf("second callback = %v", err)
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if err := f.service.Callback(context.Background(), second); !errors.Is(err, ErrUnauthorized) || f.oauth.callCount() != 1 {
		t.Fatal("stale second flow reached token endpoint")
	}
}

func TestBoundedStatesAttemptsAndExpiryCleanup(t *testing.T) {
	f := newFixture(t)
	f.service.config.MaxPending = 2
	f.service.config.MaxPendingPerSession = 1
	first := f.start(t)
	if _, err := f.service.Begin(context.Background(), BeginRequest{Principal: f.principal, SessionID: session}); !errors.Is(err, ErrBusy) {
		t.Fatal("session bound exceeded")
	}
	if _, err := f.service.Begin(context.Background(), BeginRequest{Principal: f.principal, SessionID: session + "2"}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.service.Begin(context.Background(), BeginRequest{Principal: f.principal, SessionID: session + "3"}); !errors.Is(err, ErrBusy) {
		t.Fatal("global bound exceeded")
	}
	bad := first
	bad.SessionID = session + "wrong"
	for i := 0; i < f.service.config.MaxAttempts; i++ {
		if err := f.service.Callback(context.Background(), bad); !errors.Is(err, ErrInvalidCallback) {
			t.Fatal(err)
		}
	}
	if err := f.service.Callback(context.Background(), first); !errors.Is(err, ErrInvalidCallback) {
		t.Fatal("exhausted state accepted")
	}
	if len(f.service.states) != 1 {
		t.Fatal("attempt limit did not evict pending state")
	}
	f.clock.Add(int64(maxTTL))
	if _, err := f.service.Begin(context.Background(), BeginRequest{Principal: f.principal, SessionID: session}); err != nil {
		t.Fatal(err)
	}
	if len(f.service.states) != 1 {
		t.Fatal("expired states not pruned")
	}
}

func TestInFlightFlowCountsAgainstCapacity(t *testing.T) {
	f := newFixture(t)
	f.service.config.MaxPending = 1
	f.service.config.MaxPendingPerSession = 1
	r := f.start(t)
	entered, release := make(chan struct{}), make(chan struct{})
	f.oauth.onExchange = func() { close(entered); <-release }
	done := make(chan error, 1)
	go func() { done <- f.service.Callback(context.Background(), r) }()
	<-entered
	if _, err := f.service.Begin(context.Background(), BeginRequest{Principal: f.principal, SessionID: session + "other"}); !errors.Is(err, ErrBusy) {
		t.Fatal("in-flight flow escaped capacity bound")
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestReconnectUsesNewLineageAndImmutableGeneration(t *testing.T) {
	f := newFixture(t)
	r := f.start(t)
	if err := f.service.Callback(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	prior := f.repo.current.State()
	r = f.start(t)
	if err := f.service.Callback(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	current := f.repo.current.State()
	if current.AuthorizationLineage == prior.AuthorizationLineage || current.Generation.Reference == prior.Generation.Reference || current.Generation.Number != 2 || len(f.secrets.items) != 2 {
		t.Fatal("reconnect reused lineage, generation or reference")
	}
}

func TestConfigurationAndAuthorizationURLAreStrict(t *testing.T) {
	for _, invalid := range []string{"http://owner.example/callback", "https://owner.example/callback?x=y", "https://owner.example/callback#frag", "https://user@owner.example/callback", "https://owner.example"} {
		t.Run(invalid, func(t *testing.T) {
			f := newFixture(t)
			cfg := f.service.config
			cfg.CallbackURL = invalid
			if _, err := NewService(cfg, f.repo, f.oauth, f.secrets); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatal("bad callback configured")
			}
		})
	}
	for name, mutate := range map[string]func(*Config){"ttl": func(c *Config) { c.TTL = maxTTL + time.Second }, "pending": func(c *Config) { c.MaxPending = 1025 }, "session": func(c *Config) { c.MaxPendingPerSession = 129 }, "attempts": func(c *Config) { c.MaxAttempts = 6 }, "provider": func(c *Config) { c.SecretProvider = "" }, "negative": func(c *Config) { c.TTL = -time.Second }} {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t)
			cfg := f.service.config
			mutate(&cfg)
			if _, err := NewService(cfg, f.repo, f.oauth, f.secrets); !errors.Is(err, ErrInvalidConfiguration) {
				t.Fatal("bad limit configured")
			}
		})
	}
	for _, field := range []string{"scope", "redirect_uri", "state", "code_challenge", "code_challenge_method", "response_type", "host", "duplicate", "extra"} {
		t.Run("url "+field, func(t *testing.T) {
			f := newFixture(t)
			f.oauth.alterURL = func(raw string) string {
				u, _ := url.Parse(raw)
				q := u.Query()
				switch field {
				case "host":
					u.Host = "evil.example"
				case "duplicate":
					q.Add("state", "another")
				case "extra":
					q.Set("prompt", "malicious")
				default:
					q.Set(field, "wrong")
				}
				u.RawQuery = q.Encode()
				return u.String()
			}
			if _, err := f.service.Begin(context.Background(), BeginRequest{Principal: f.principal, SessionID: session}); !errors.Is(err, ErrUnavailable) || len(f.service.states) != 0 {
				t.Fatal("unbound or broad authorization URL accepted")
			}
		})
	}
}

func TestFormattingCannotDiscloseOAuthMaterial(t *testing.T) {
	f := newFixture(t)
	r := f.start(t)
	begin := BeginRequest{Principal: f.principal, SessionID: session}
	result := BeginResult{AuthorizationURL: "https://app.ynab.com?state=" + r.State, ExpiresAt: f.service.now()}
	values := []any{begin, r, result, f.service, *f.service}
	for _, value := range values {
		for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
			out := fmt.Sprintf(format, value)
			for _, marker := range []string{session, r.Code, r.State, f.oauth.verifiers[r.State], "synthetic-access-marker", "synthetic-refresh-marker"} {
				if strings.Contains(out, marker) {
					t.Fatalf("format disclosed marker for %T", value)
				}
			}
		}
		out, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), r.State) || strings.Contains(string(out), session) {
			t.Fatalf("JSON disclosed %T", value)
		}
	}
	var logs strings.Builder
	logger := slog.New(slog.NewJSONHandler(&logs, nil))
	logger.Info("synthetic", "callback", r, "service", f.service, "begin", begin, "result", result)
	for _, marker := range []string{session, r.Code, r.State, f.oauth.verifiers[r.State]} {
		if strings.Contains(logs.String(), marker) {
			t.Fatal("slog disclosed authorization material")
		}
	}
}

func TestCancelledContextDoesNotConsumePendingStateOrExchange(t *testing.T) {
	f := newFixture(t)
	r := f.start(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := f.service.Callback(ctx, r); !errors.Is(err, ErrUnavailable) || f.oauth.callCount() != 0 || len(f.service.states) != 1 {
		t.Fatal("pre-cancelled callback changed state")
	}
	if _, err := f.service.Begin(ctx, BeginRequest{Principal: f.principal, SessionID: session}); !errors.Is(err, ErrUnavailable) {
		t.Fatal("cancelled begin accepted")
	}
}

func TestCandidateReferencesBindOwnerConnectionLineageAndGeneration(t *testing.T) {
	f := newFixture(t)
	state := f.repo.current.State()
	base, err := candidateReference("protected", state, "lineage-one")
	if err != nil {
		t.Fatal(err)
	}
	again, err := candidateReference("protected", state, "lineage-one")
	if err != nil || again != base {
		t.Fatal("candidate is not deterministic for a single attempt")
	}
	for name, change := range map[string]func(*connection.State){
		"owner":      func(s *connection.State) { s.OwnerID = "different-owner" },
		"connection": func(s *connection.State) { s.ID = "different-connection" },
		"generation": func(s *connection.State) { s.Generation.Number++ },
	} {
		t.Run(name, func(t *testing.T) {
			changed := state
			change(&changed)
			ref, err := candidateReference("protected", changed, "lineage-one")
			if err != nil || ref == base {
				t.Fatal("candidate omitted binding")
			}
		})
	}
	ref, err := candidateReference("protected", state, "lineage-two")
	if err != nil || ref == base {
		t.Fatal("candidate omitted lineage")
	}
}

func TestBeginFailureDoesNotAllocateState(t *testing.T) {
	f := newFixture(t)
	f.oauth.urlError = errors.New("synthetic-sensitive-error")
	_, err := f.service.Begin(context.Background(), BeginRequest{Principal: f.principal, SessionID: session})
	if !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "synthetic") || len(f.service.states) != 0 {
		t.Fatal("failed authorization URL allocated state or exposed error")
	}
	f.oauth.urlError = nil
	f.oauth.alterURL = func(raw string) string { f.clock.Add(int64(maxTTL)); return raw }
	_, err = f.service.Begin(context.Background(), BeginRequest{Principal: f.principal, SessionID: session})
	if !errors.Is(err, ErrUnavailable) || len(f.service.states) != 0 {
		t.Fatal("begin returned an already-expired flow")
	}
}

func TestCallbackCancellationDuringExchangeCannotPersist(t *testing.T) {
	f := newFixture(t)
	request := f.start(t)
	ctx, cancel := context.WithCancel(context.Background())
	f.oauth.onExchange = cancel
	if err := f.service.Callback(ctx, request); err == nil || f.secrets.puts != 0 || f.repo.commits != 0 {
		t.Fatal("cancelled exchange published credentials")
	}
	if err := f.service.Callback(context.Background(), request); !errors.Is(err, ErrInvalidCallback) {
		t.Fatal("cancelled exchange state was reusable")
	}
}

func TestUninitializedServiceFailsClosed(t *testing.T) {
	for _, s := range []*Service{nil, {}} {
		if _, err := s.Begin(context.Background(), BeginRequest{}); !errors.Is(err, ErrUnavailable) {
			t.Fatal("uninitialized begin accepted")
		}
		if err := s.Callback(context.Background(), CallbackRequest{}); !errors.Is(err, ErrUnavailable) {
			t.Fatal("uninitialized callback accepted")
		}
	}
}
