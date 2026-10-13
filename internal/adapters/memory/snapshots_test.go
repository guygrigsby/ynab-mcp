package memory

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/budget"
	"github.com/guygrigsby/ynab-mcp/internal/domain/inquiry"
)

type testClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *testClock) now() time.Time          { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *testClock) advance(d time.Duration) { c.mu.Lock(); defer c.mu.Unlock(); c.t = c.t.Add(d) }
func fixture(t *testing.T, options Options) (*SnapshotStore, *testClock, access.ReadScope, inquiry.Query, inquiry.ReadResult) {
	t.Helper()
	clock := &testClock{t: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)}
	options.Now = clock.now
	store, err := NewSnapshotStore(options)
	if err != nil {
		t.Fatal(err)
	}
	scope := access.ReadScope{OwnerID: "owner-a", ConnectionID: "connection-a", AuthorizationLineage: "lineage-a", PolicyVersion: 1, BudgetID: "budget-a"}
	query := inquiry.Query{Tool: inquiry.ListTransactions, BudgetID: "budget-a", SinceDate: "2026-10-01", UntilDate: "2026-10-13", Limit: 2}
	result := inquiry.ReadResult{ObservedFrom: clock.now().Add(-time.Second), ObservedAt: clock.now(), Coverage: inquiry.Coverage{CollectionComplete: true, Warnings: []string{"upstream observations are not atomic"}}}
	for i := 0; i < 5; i++ {
		result.Items = append(result.Items, json.RawMessage(fmt.Sprintf(`{"id":"tx-%d","memo":"example"}`, i)))
	}
	return store, clock, scope, query, result
}
func publish(t *testing.T, s *SnapshotStore, scope access.ReadScope, q inquiry.Query, r inquiry.ReadResult) inquiry.Page {
	t.Helper()
	p, err := s.Publish(context.Background(), scope, q, r)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func read(t *testing.T, s *SnapshotStore, scope access.ReadScope, q inquiry.Query, c string) inquiry.Page {
	t.Helper()
	q.Cursor = c
	p, err := s.Read(context.Background(), scope, q)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestImmutableReplayAndDefensiveCopies(t *testing.T) {
	s, _, scope, q, r := fixture(t, Options{})
	first := publish(t, s, scope, q, r)
	if len(first.Items) != 2 || first.Metadata.PageComplete || first.Metadata.NextCursor == "" {
		t.Fatalf("invalid first page: %+v", first.Metadata)
	}
	cursor := first.Metadata.NextCursor
	second := read(t, s, scope, q, cursor)
	want, _ := json.Marshal(second)
	// Mutations of both the original result and a prior returned page cannot alter snapshots.
	r.Items[2][7] = 'z'
	r.Coverage.Warnings[0] = "mutated source"
	first.Items[0][7] = 'z'
	first.Metadata.Warnings[0] = "mutated page"
	second.Items[0][7] = 'z'
	second.Metadata.Warnings[0] = "mutated page"
	replay := read(t, s, scope, q, cursor)
	got, _ := json.Marshal(replay)
	if !bytes.Equal(want, got) {
		t.Fatalf("replay changed: %s != %s", got, want)
	}
	third := read(t, s, scope, q, replay.Metadata.NextCursor)
	if len(third.Items) != 1 || !third.Metadata.PageComplete || third.Metadata.NextCursor != "" {
		t.Fatalf("invalid last page: %+v", third)
	}
	if s.Stats().Cursors != 2 {
		t.Fatal("replay allocated additional cursors")
	}
	if first.Metadata.SnapshotID != third.Metadata.SnapshotID || first.Metadata.ExpiresAt != third.Metadata.ExpiresAt {
		t.Fatal("snapshot metadata changed across pages")
	}
}

func TestEveryScopeAndQueryDimensionIsBound(t *testing.T) {
	s, _, scope, q, r := fixture(t, Options{})
	p := publish(t, s, scope, q, r)
	cases := []struct {
		name  string
		scope func(*access.ReadScope)
		query func(*inquiry.Query)
	}{
		{name: "owner", scope: func(s *access.ReadScope) { s.OwnerID = "owner-b" }},
		{name: "connection", scope: func(s *access.ReadScope) { s.ConnectionID = "connection-b" }},
		{name: "lineage", scope: func(s *access.ReadScope) { s.AuthorizationLineage = "lineage-b" }},
		{name: "policy", scope: func(s *access.ReadScope) { s.PolicyVersion++ }},
		{name: "budget", scope: func(s *access.ReadScope) { s.BudgetID = "budget-b" }, query: func(q *inquiry.Query) { q.BudgetID = "budget-b" }},
		{name: "limit", query: func(q *inquiry.Query) { q.Limit = 1 }},
		{name: "notes", query: func(q *inquiry.Query) { q.IncludeNotes = true }},
		{name: "date-from", query: func(q *inquiry.Query) { q.SinceDate = "2026-10-02" }},
		{name: "date-until", query: func(q *inquiry.Query) { q.UntilDate = "2026-10-12" }},
		{name: "account", query: func(q *inquiry.Query) { q.AccountID = "account-b" }},
		{name: "category", query: func(q *inquiry.Query) { q.CategoryID = "category-b" }},
		{name: "status", query: func(q *inquiry.Query) { q.Status = "cleared" }},
		{name: "tool", query: func(q *inquiry.Query) { q.Tool = inquiry.ListScheduledTransactions }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sc, query := scope, q
			query.Cursor = p.Metadata.NextCursor
			if tc.scope != nil {
				tc.scope(&sc)
			}
			if tc.query != nil {
				tc.query(&query)
			}
			if _, err := s.Read(context.Background(), sc, query); !errors.Is(err, inquiry.ErrCursorMismatch) {
				t.Fatalf("expected mismatch, got %v", err)
			}
		})
	}
	// The public scope encoding intentionally omits all administrative identities.
	b, _ := json.Marshal(scope)
	if strings.Contains(string(b), "owner-a") || strings.Contains(string(b), "lineage-a") {
		t.Fatal("internal identity leaked")
	}
}

func TestMonthAndClosedFlagsAreBound(t *testing.T) {
	for _, tool := range []string{inquiry.ListCategories, inquiry.ListAccounts} {
		t.Run(tool, func(t *testing.T) {
			s, _, scope, _, r := fixture(t, Options{})
			q := inquiry.Query{Tool: tool, BudgetID: scope.BudgetID, Limit: 2}
			if tool == inquiry.ListCategories {
				q.Month = "2026-10-01"
			}
			p := publish(t, s, scope, q, r)
			q.Cursor = p.Metadata.NextCursor
			if tool == inquiry.ListCategories {
				q.Month = "2026-11-01"
			} else {
				q.IncludeClosed = true
			}
			if _, err := s.Read(context.Background(), scope, q); !errors.Is(err, inquiry.ErrCursorMismatch) {
				t.Fatal(err)
			}
		})
	}
}

func TestAbsoluteTTLNeverExtendsOnRead(t *testing.T) {
	s, clock, scope, q, r := fixture(t, Options{})
	p := publish(t, s, scope, q, r)
	clock.advance(MaxTTL - time.Nanosecond)
	replay := read(t, s, scope, q, p.Metadata.NextCursor)
	if replay.Metadata.ExpiresAt != p.Metadata.ExpiresAt {
		t.Fatal("read extended expiry")
	}
	clock.advance(time.Nanosecond)
	q.Cursor = p.Metadata.NextCursor
	if _, err := s.Read(context.Background(), scope, q); !errors.Is(err, inquiry.ErrCursorExpired) {
		t.Fatalf("expected expiry at deadline: %v", err)
	}
	if got := s.Stats(); got != (Stats{}) {
		t.Fatalf("expired data retained: %+v", got)
	}
}

func TestEvictionInvalidatesAllCursors(t *testing.T) {
	for _, mode := range []string{"explicit", "owner", "connection", "count", "restart"} {
		t.Run(mode, func(t *testing.T) {
			s, _, scope, q, r := fixture(t, Options{MaxSnapshots: 1})
			p := publish(t, s, scope, q, r)
			p2 := read(t, s, scope, q, p.Metadata.NextCursor)
			switch mode {
			case "explicit":
				s.Evict(p.Metadata.SnapshotID)
			case "owner":
				s.InvalidateOwner(scope.OwnerID)
			case "connection":
				s.InvalidateConnection(scope.ConnectionID)
			case "count":
				publish(t, s, scope, q, r)
			case "restart":
				s, _, _, _, _ = fixture(t, Options{})
			}
			for _, c := range []string{p.Metadata.NextCursor, p2.Metadata.NextCursor} {
				query := q
				query.Cursor = c
				if _, err := s.Read(context.Background(), scope, query); !errors.Is(err, inquiry.ErrCursorExpired) {
					t.Fatalf("cursor survived %s: %v", mode, err)
				}
			}
		})
	}
}

func TestPageByteCeilingIncludesMetadataAndEscapes(t *testing.T) {
	s, _, scope, q, r := fixture(t, Options{MaxPageBytes: 2048})
	q.Limit = 200
	r.Items = nil
	for i := 0; i < 15; i++ {
		r.Items = append(r.Items, json.RawMessage(`{"text":"`+strings.Repeat("<", 50)+`"}`))
	}
	p := publish(t, s, scope, q, r)
	count := 0
	pages := 0
	for {
		encoded, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(encoded) > 2048 {
			t.Fatalf("serialized page exceeded cap: %d", len(encoded))
		}
		if len(p.Items) > 200 || len(p.Items) == 0 {
			t.Fatal("invalid item count")
		}
		count += len(p.Items)
		pages++
		if p.Metadata.PageComplete {
			break
		}
		p = read(t, s, scope, q, p.Metadata.NextCursor)
	}
	if count != 15 || pages < 2 {
		t.Fatalf("unexpected pagination: %d items in %d pages", count, pages)
	}
}

func TestProductionCeilings(t *testing.T) {
	s, _, scope, q, r := fixture(t, Options{})
	q.Limit = 200
	r.Items = make([]json.RawMessage, 450)
	for i := range r.Items {
		r.Items[i] = json.RawMessage(`{"text":"` + strings.Repeat("x", 2000) + `"}`)
	}
	p := publish(t, s, scope, q, r)
	count := 0
	for {
		b, err := json.Marshal(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(b) > MaxPageBytes || len(p.Items) > MaxPageItems {
			t.Fatalf("production page ceiling violated: %d bytes, %d items", len(b), len(p.Items))
		}
		count += len(p.Items)
		if p.Metadata.PageComplete {
			break
		}
		p = read(t, s, scope, q, p.Metadata.NextCursor)
	}
	if count != 450 {
		t.Fatal("truncated result")
	}
	if stats := s.Stats(); stats.Bytes > MaxBytes || stats.Cursors > MaxCursors || stats.Snapshots > MaxSnapshots {
		t.Fatal(stats)
	}
}

func TestOversizedAndIncompleteResultsNeverPublish(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*inquiry.ReadResult)
		want error
	}{
		{"incomplete", func(r *inquiry.ReadResult) { r.Coverage.CollectionComplete = false }, inquiry.ErrDataInvalid},
		{"pending", func(r *inquiry.ReadResult) { r.Coverage.PendingTransactionsIncluded = true }, inquiry.ErrDataInvalid},
		{"notes", func(r *inquiry.ReadResult) { r.Coverage.NotesIncluded = true }, inquiry.ErrDataInvalid},
		{"observation", func(r *inquiry.ReadResult) { r.ObservedAt = r.ObservedFrom.Add(-time.Second) }, inquiry.ErrDataInvalid},
		{"future", func(r *inquiry.ReadResult) { r.ObservedAt = r.ObservedAt.Add(time.Second) }, inquiry.ErrDataInvalid},
		{"invalid-json", func(r *inquiry.ReadResult) { r.Items[4] = json.RawMessage(`{"broken"`) }, inquiry.ErrDataInvalid},
		{"large-item", func(r *inquiry.ReadResult) {
			r.Items[4] = json.RawMessage(`"` + strings.Repeat("x", MaxPageBytes) + `"`)
		}, inquiry.ErrNarrowQueryRequired},
		{"large-warning", func(r *inquiry.ReadResult) { r.Coverage.Warnings = []string{strings.Repeat("x", MaxPageBytes)} }, inquiry.ErrNarrowQueryRequired},
		{"many-warnings", func(r *inquiry.ReadResult) { r.Coverage.Warnings = make([]string, MaxPageBytes) }, inquiry.ErrNarrowQueryRequired},
	} {
		t.Run(test.name, func(t *testing.T) {
			s, _, scope, q, r := fixture(t, Options{})
			test.edit(&r)
			if _, err := s.Publish(context.Background(), scope, q, r); !errors.Is(err, test.want) {
				t.Fatalf("got %v; want %v", err, test.want)
			}
			if got := s.Stats(); got != (Stats{}) {
				t.Fatalf("partial result published: %+v", got)
			}
		})
	}
}

func TestEmptyResultIsCompleteArray(t *testing.T) {
	s, _, scope, q, r := fixture(t, Options{})
	r.Items = nil
	p := publish(t, s, scope, q, r)
	if p.Items == nil || len(p.Items) != 0 || !p.Metadata.PageComplete || p.Metadata.NextCursor != "" {
		t.Fatal(p)
	}
	b, _ := json.Marshal(p)
	if !bytes.Contains(b, []byte(`"data":[]`)) {
		t.Fatalf("empty result must be array: %s", b)
	}
	if s.Stats().Cursors != 0 {
		t.Fatal("empty result created cursors")
	}
}

func TestAllResourceLimits(t *testing.T) {
	t.Run("cursor-eviction", func(t *testing.T) {
		s, _, scope, q, r := fixture(t, Options{MaxCursors: 2})
		old := publish(t, s, scope, q, r)
		publish(t, s, scope, q, r)
		q.Cursor = old.Metadata.NextCursor
		if _, err := s.Read(context.Background(), scope, q); !errors.Is(err, inquiry.ErrCursorExpired) {
			t.Fatal(err)
		}
		if got := s.Stats(); got.Cursors != 2 || got.Snapshots != 1 {
			t.Fatal(got)
		}
	})
	t.Run("cursor-reject", func(t *testing.T) {
		s, _, scope, q, r := fixture(t, Options{MaxCursors: 1})
		if _, err := s.Publish(context.Background(), scope, q, r); !errors.Is(err, inquiry.ErrNarrowQueryRequired) {
			t.Fatal(err)
		}
		if s.Stats() != (Stats{}) {
			t.Fatal("partial snapshot")
		}
	})
	t.Run("bytes-eviction", func(t *testing.T) {
		s, _, scope, q, r := fixture(t, Options{MaxBytes: 4500})
		p := publish(t, s, scope, q, r)
		publish(t, s, scope, q, r)
		q.Cursor = p.Metadata.NextCursor
		if _, err := s.Read(context.Background(), scope, q); !errors.Is(err, inquiry.ErrCursorExpired) {
			t.Fatal(err)
		}
		if st := s.Stats(); st.Bytes > 4500 || st.Snapshots != 1 {
			t.Fatal(st)
		}
	})
	t.Run("bytes-reject", func(t *testing.T) {
		s, _, scope, q, r := fixture(t, Options{MaxBytes: 2048})
		if _, err := s.Publish(context.Background(), scope, q, r); !errors.Is(err, inquiry.ErrNarrowQueryRequired) {
			t.Fatal(err)
		}
	})
}

func TestBadOptionsCannotRaiseCeilings(t *testing.T) {
	for _, options := range []Options{{TTL: MaxTTL + time.Nanosecond}, {TTL: -1}, {MaxBytes: MaxBytes + 1}, {MaxBytes: -1}, {MaxPageBytes: MaxPageBytes + 1}, {MaxPageItems: 201}, {MaxSnapshots: MaxSnapshots + 1}, {MaxCursors: MaxCursors + 1}} {
		if _, err := NewSnapshotStore(options); !errors.Is(err, ErrOptions) {
			t.Fatalf("accepted invalid options: %+v", options)
		}
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func TestEntropyFailureAndDuplicateSeedFailClosed(t *testing.T) {
	for _, reader := range []io.Reader{errorReader{}, bytes.NewReader(nil)} {
		s, _, scope, q, r := fixture(t, Options{Random: reader})
		if _, err := s.Publish(context.Background(), scope, q, r); !errors.Is(err, inquiry.ErrDataInvalid) {
			t.Fatal(err)
		}
		if s.Stats() != (Stats{}) {
			t.Fatal("failed entropy published")
		}
	}
	s, _, scope, q, r := fixture(t, Options{Random: bytes.NewReader(make([]byte, 64))})
	p := publish(t, s, scope, q, r)
	if _, err := s.Publish(context.Background(), scope, q, r); !errors.Is(err, inquiry.ErrDataInvalid) {
		t.Fatalf("duplicate seed accepted: %v", err)
	}
	read(t, s, scope, q, p.Metadata.NextCursor)
}

func TestCursorLookupStoresHashes(t *testing.T) {
	s, _, scope, q, r := fixture(t, Options{})
	p := publish(t, s, scope, q, r)
	raw, err := base64.RawURLEncoding.DecodeString(p.Metadata.NextCursor)
	if err != nil || len(raw) != 32 {
		t.Fatal("cursor lacks 256-bit entropy format")
	}
	hash := sha256.Sum256([]byte(p.Metadata.NextCursor))
	if _, found := s.cursors[hash]; !found {
		t.Fatal("cursor not stored by hash")
	}
	if _, found := s.snapshots[p.Metadata.NextCursor]; found {
		t.Fatal("cursor misused as snapshot ID")
	}
	for _, cursor := range []string{"", strings.Repeat("a", 42), strings.Repeat("!", 43), strings.Repeat("a", 256), base64.RawURLEncoding.EncodeToString(make([]byte, 32))} {
		q.Cursor = cursor
		if _, err := s.Read(context.Background(), scope, q); !errors.Is(err, inquiry.ErrCursorExpired) {
			t.Fatalf("accepted unknown cursor %q: %v", cursor, err)
		}
	}
}

func TestContextCancellationDoesNotPublish(t *testing.T) {
	s, _, scope, q, r := fixture(t, Options{})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := s.Publish(ctx, scope, q, r); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := s.Read(ctx, scope, q); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(s.Stats(), Stats{}) {
		t.Fatal("canceled operation changed store")
	}
}

func TestConcurrentReadAndPublish(t *testing.T) {
	s, _, scope, q, r := fixture(t, Options{})
	p := publish(t, s, scope, q, r)
	var workers sync.WaitGroup
	for i := 0; i < 20; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for j := 0; j < 20; j++ {
				query := q
				query.Cursor = p.Metadata.NextCursor
				page, err := s.Read(context.Background(), scope, query)
				if err != nil {
					t.Error(err)
					return
				}
				page.Items[0][7] = 'z'
				page.Metadata.Warnings[0] = "mutated"
				if _, err = s.Publish(context.Background(), scope, q, r); err != nil {
					t.Error(err)
					return
				}
			}
		}()
	}
	workers.Wait()
	replay := read(t, s, scope, q, p.Metadata.NextCursor)
	if !strings.Contains(string(replay.Items[0]), "tx-2") || replay.Metadata.Warnings[0] == "mutated" {
		t.Fatal("concurrent mutation leaked")
	}
}

func TestInvalidScopeAndPublishCursor(t *testing.T) {
	s, _, scope, q, r := fixture(t, Options{})
	for _, change := range []func(*access.ReadScope){func(s *access.ReadScope) { s.OwnerID = "" }, func(s *access.ReadScope) { s.PolicyVersion = 0 }, func(s *access.ReadScope) { s.BudgetID = budget.BudgetID("wrong") }} {
		sc := scope
		change(&sc)
		if _, err := s.Publish(context.Background(), sc, q, r); !errors.Is(err, inquiry.ErrUnauthorizedScope) {
			t.Fatal(err)
		}
	}
	q.Cursor = "anything"
	if _, err := s.Publish(context.Background(), scope, q, r); !errors.Is(err, inquiry.ErrCursorMismatch) {
		t.Fatal(err)
	}
}

func TestDefaultAggregateMemoryCapEvictsOldest(t *testing.T) {
	s, _, scope, q, r := fixture(t, Options{})
	q.Limit = 200
	r.Items = make([]json.RawMessage, 450)
	for i := range r.Items {
		r.Items[i] = json.RawMessage(`{"text":"` + strings.Repeat("x", 2000) + `"}`)
	}
	first := publish(t, s, scope, q, r)
	for i := 0; i < 39; i++ {
		publish(t, s, scope, q, r)
		stats := s.Stats()
		if stats.Bytes > 32<<20 || stats.Cursors > MaxCursors || stats.Snapshots > MaxSnapshots {
			t.Fatalf("aggregate cache cap exceeded: %+v", stats)
		}
	}
	q.Cursor = first.Metadata.NextCursor
	if _, err := s.Read(context.Background(), scope, q); !errors.Is(err, inquiry.ErrCursorExpired) {
		t.Fatalf("oldest cursor survived aggregate eviction: %v", err)
	}
	if s.Stats().Snapshots >= 40 {
		t.Fatal("aggregate cap did not evict")
	}
}

func TestDefaultAndExplicitLimitHaveSameMeaning(t *testing.T) {
	s, _, scope, q, r := fixture(t, Options{})
	q.Limit = 0
	r.Items = make([]json.RawMessage, 51)
	for i := range r.Items {
		r.Items[i] = json.RawMessage(`{"id":"same"}`)
	}
	p := publish(t, s, scope, q, r)
	q.Limit = inquiry.DefaultLimit
	next := read(t, s, scope, q, p.Metadata.NextCursor)
	if len(next.Items) != 1 || !next.Metadata.PageComplete {
		t.Fatal("default limit failed to normalize")
	}
}
