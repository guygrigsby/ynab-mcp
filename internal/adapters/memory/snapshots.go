// Package memory keeps financial read data only in bounded process memory. It
// never writes payloads, snapshot handles, or cursor handles to durable storage.
package memory

import (
	"container/list"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/budget"
	"github.com/guygrigsby/ynab-mcp/internal/domain/inquiry"
)

const (
	MaxTTL       = 5 * time.Minute
	MaxBytes     = 32 << 20
	MaxPageBytes = 256 << 10
	MaxPageItems = 200
	MaxSnapshots = 1024
	MaxCursors   = 8192
	handleBytes  = 32
	handleLength = 43
	// Conservative charges bound small-record overhead as well as payload bytes.
	snapshotCharge = 1024
	itemCharge     = 64
	pageCharge     = 32
	cursorCharge   = 256
)

var ErrOptions = errors.New("invalid snapshot store limits")

// Options may lower the production ceilings but cannot raise them. Now and
// Random are injectable for tests; production should leave both unset.
type Options struct {
	TTL          time.Duration
	MaxBytes     int
	MaxPageBytes int
	MaxPageItems int
	MaxSnapshots int
	MaxCursors   int
	Now          func() time.Time
	Random       io.Reader
}

type pageRange struct{ from, to int }
type snapshot struct {
	id          string
	seed        [handleBytes]byte
	scope       access.ReadScope
	fingerprint string
	metadata    inquiry.ReadMetadata
	items       []json.RawMessage
	pages       []pageRange
	bytes       int
	expiresAt   time.Time
	order       *list.Element
}
type cursorRecord struct {
	snapshot *snapshot
	page     int
}

// SnapshotStore is concurrency-safe. Cursor possession never grants access: the
// application supplies a freshly authorized scope and reauthorizes disclosure.
// Only SHA-256 cursor hashes are indexed. Handles are pseudorandom HMAC outputs
// from a separate crypto/rand-generated 256-bit seed for each snapshot. This
// permits byte-identical next-cursor replay without retaining plaintext handles.
type SnapshotStore struct {
	mu        sync.Mutex
	options   Options
	snapshots map[string]*snapshot
	cursors   map[[sha256.Size]byte]cursorRecord
	order     *list.List
	bytes     int
}

func NewSnapshotStore(options Options) (*SnapshotStore, error) {
	if options.TTL == 0 {
		options.TTL = MaxTTL
	}
	if options.MaxBytes == 0 {
		options.MaxBytes = MaxBytes
	}
	if options.MaxPageBytes == 0 {
		options.MaxPageBytes = MaxPageBytes
	}
	if options.MaxPageItems == 0 {
		options.MaxPageItems = MaxPageItems
	}
	if options.MaxSnapshots == 0 {
		options.MaxSnapshots = MaxSnapshots
	}
	if options.MaxCursors == 0 {
		options.MaxCursors = MaxCursors
	}
	if options.TTL < 0 || options.TTL > MaxTTL || options.MaxBytes < 1 || options.MaxBytes > MaxBytes || options.MaxPageBytes < 1 || options.MaxPageBytes > MaxPageBytes || options.MaxPageItems < 1 || options.MaxPageItems > MaxPageItems || options.MaxSnapshots < 1 || options.MaxSnapshots > MaxSnapshots || options.MaxCursors < 1 || options.MaxCursors > MaxCursors {
		return nil, ErrOptions
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	return &SnapshotStore{options: options, snapshots: make(map[string]*snapshot), cursors: make(map[[sha256.Size]byte]cursorRecord), order: list.New()}, nil
}

// Publish validates and defensively copies a complete upstream result before
// atomically publishing any page. Input order is preserved; the upstream read
// service is responsible for applying the query's deterministic sort.
func (s *SnapshotStore) Publish(ctx context.Context, scope access.ReadScope, query inquiry.Query, result inquiry.ReadResult) (inquiry.Page, error) {
	if err := ctx.Err(); err != nil {
		return inquiry.Page{}, err
	}
	if query.Cursor != "" {
		return inquiry.Page{}, inquiry.ErrCursorMismatch
	}
	normalized, err := query.Normalize()
	if err != nil {
		return inquiry.Page{}, err
	}
	if err = validateScope(scope, normalized); err != nil {
		return inquiry.Page{}, err
	}
	if !result.Coverage.CollectionComplete || result.Coverage.PendingTransactionsIncluded || result.Coverage.UnresolvedReferenceCount < 0 || result.Coverage.NotesIncluded != normalized.IncludeNotes || result.ObservedFrom.IsZero() || result.ObservedAt.IsZero() || result.ObservedAt.Before(result.ObservedFrom) {
		return inquiry.Page{}, inquiry.ErrDataInvalid
	}
	// Bound metadata before copying or serializing it, including many empty warnings.
	if len(result.Coverage.Warnings) > s.options.MaxPageBytes/2 {
		return inquiry.Page{}, inquiry.ErrNarrowQueryRequired
	}
	warningBytes := 0
	for _, warning := range result.Coverage.Warnings {
		if len(warning) > s.options.MaxPageBytes-warningBytes {
			return inquiry.Page{}, inquiry.ErrNarrowQueryRequired
		}
		warningBytes += len(warning)
	}
	if normalized.Limit > s.options.MaxPageItems {
		return inquiry.Page{}, inquiry.ErrNarrowQueryRequired
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.options.Now()
	s.purgeExpired(now)
	if result.ObservedAt.After(now) {
		return inquiry.Page{}, inquiry.ErrDataInvalid
	}
	candidate := &snapshot{scope: cloneScope(scope), fingerprint: normalized.Fingerprint(), expiresAt: now.Add(s.options.TTL)}
	// A failing random source is an explicit failure, never a predictable fallback.
	if _, err = io.ReadFull(s.options.Random, candidate.seed[:]); err != nil {
		return inquiry.Page{}, inquiry.ErrDataInvalid
	}
	candidate.id = candidate.handle("snapshot", 0)
	if _, exists := s.snapshots[candidate.id]; exists {
		return inquiry.Page{}, inquiry.ErrDataInvalid
	}
	normalized.Cursor = ""
	normalized = cloneQuery(normalized)
	candidate.metadata = inquiry.ReadMetadata{
		BudgetID: normalized.BudgetID, SnapshotID: candidate.id,
		ObservedFrom: result.ObservedFrom.UTC(), ObservedAt: result.ObservedAt.UTC(), ExpiresAt: candidate.expiresAt.UTC(),
		Freshness: "fresh", RequestedScope: normalized, AppliedFilters: normalized,
		Sort: sortFor(normalized), Coverage: cloneCoverage(result.Coverage),
	}
	// Encode the empty envelope with a full-sized next cursor. All actual pages
	// fit this conservative envelope; even metadata is part of the byte ceiling.
	sizingMetadata := candidate.metadata
	sizingMetadata.NextCursor = strings.Repeat("x", handleLength)
	envelope, err := json.Marshal(inquiry.Page{Items: []json.RawMessage{}, Metadata: sizingMetadata})
	if err != nil {
		return inquiry.Page{}, inquiry.ErrDataInvalid
	}
	if len(envelope) > s.options.MaxPageBytes {
		return inquiry.Page{}, inquiry.ErrNarrowQueryRequired
	}
	candidate.bytes = snapshotCharge + len(envelope) + len(scope.OwnerID) + len(scope.ConnectionID) + len(scope.AuthorizationLineage) + len(scope.BudgetID) + len(result.Coverage.Warnings)*32
	if candidate.bytes > s.options.MaxBytes {
		return inquiry.Page{}, inquiry.ErrNarrowQueryRequired
	}
	// Never preallocate from the untrusted source length before enforcing limits.
	from, pageBytes := 0, len(envelope)
	for index, raw := range result.Items {
		if err = ctx.Err(); err != nil {
			return inquiry.Page{}, err
		}
		if len(raw) == 0 || len(raw) > s.options.MaxPageBytes {
			return inquiry.Page{}, inquiry.ErrNarrowQueryRequired
		}
		// json.Marshal validates, compacts, and accounts for HTML escaping exactly as
		// the eventual page serialization will. The returned slice owns its bytes.
		encoded, encodeErr := json.Marshal(raw)
		if encodeErr != nil {
			return inquiry.Page{}, inquiry.ErrDataInvalid
		}
		if len(envelope)+len(encoded) > s.options.MaxPageBytes {
			return inquiry.Page{}, inquiry.ErrNarrowQueryRequired
		}
		additional := len(encoded)
		if index > from {
			additional++
		}
		if index-from >= normalized.Limit || pageBytes+additional > s.options.MaxPageBytes {
			candidate.pages = append(candidate.pages, pageRange{from, index})
			if len(candidate.pages) > s.options.MaxCursors {
				return inquiry.Page{}, inquiry.ErrNarrowQueryRequired
			}
			candidate.bytes += pageCharge + cursorCharge
			from, pageBytes, additional = index, len(envelope), len(encoded)
		}
		candidate.bytes += len(encoded) + itemCharge
		if candidate.bytes+pageCharge > s.options.MaxBytes {
			return inquiry.Page{}, inquiry.ErrNarrowQueryRequired
		}
		owned := make(json.RawMessage, len(encoded))
		copy(owned, encoded)
		candidate.items = append(candidate.items, owned)
		pageBytes += additional
	}
	candidate.pages = append(candidate.pages, pageRange{from, len(candidate.items)})
	candidate.bytes += pageCharge
	if len(candidate.pages)-1 > s.options.MaxCursors || candidate.bytes > s.options.MaxBytes {
		return inquiry.Page{}, inquiry.ErrNarrowQueryRequired
	}
	// Guard even improbable entropy reuse/collisions; do not overwrite bindings.
	for index := 1; index < len(candidate.pages); index++ {
		hash := sha256.Sum256([]byte(candidate.handle("cursor", index)))
		if _, exists := s.cursors[hash]; exists {
			return inquiry.Page{}, inquiry.ErrDataInvalid
		}
	}
	if err = ctx.Err(); err != nil {
		return inquiry.Page{}, err
	}
	if !s.options.Now().Before(candidate.expiresAt) {
		return inquiry.Page{}, inquiry.ErrCursorExpired
	}
	// Admission is atomic: eviction removes every associated handle before insert.
	for s.bytes+candidate.bytes > s.options.MaxBytes || len(s.snapshots)+1 > s.options.MaxSnapshots || len(s.cursors)+len(candidate.pages)-1 > s.options.MaxCursors {
		oldest := s.order.Front()
		if oldest == nil {
			return inquiry.Page{}, inquiry.ErrNarrowQueryRequired
		}
		s.evict(oldest.Value.(*snapshot))
	}
	candidate.order = s.order.PushBack(candidate)
	s.snapshots[candidate.id] = candidate
	s.bytes += candidate.bytes
	for index := 1; index < len(candidate.pages); index++ {
		hash := sha256.Sum256([]byte(candidate.handle("cursor", index)))
		s.cursors[hash] = cursorRecord{snapshot: candidate, page: index}
	}
	return candidate.page(0), nil
}

// Read returns the same immutable page on repeated use, with the original
// absolute expiry. Unknown, expired, evicted, and restart-lost cursors fail.
func (s *SnapshotStore) Read(ctx context.Context, scope access.ReadScope, query inquiry.Query) (inquiry.Page, error) {
	if err := ctx.Err(); err != nil {
		return inquiry.Page{}, err
	}
	if len(query.Cursor) != handleLength {
		return inquiry.Page{}, inquiry.ErrCursorExpired
	}
	if decoded, err := base64.RawURLEncoding.Strict().DecodeString(query.Cursor); err != nil || len(decoded) != handleBytes {
		return inquiry.Page{}, inquiry.ErrCursorExpired
	}
	normalized, err := query.Normalize()
	if err != nil {
		return inquiry.Page{}, err
	}
	if err = validateScope(scope, normalized); err != nil {
		return inquiry.Page{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpired(s.options.Now())
	hash := sha256.Sum256([]byte(query.Cursor))
	cursor, found := s.cursors[hash]
	if !found {
		return inquiry.Page{}, inquiry.ErrCursorExpired
	}
	snapshot := cursor.snapshot
	if scope != snapshot.scope || normalized.Fingerprint() != snapshot.fingerprint {
		return inquiry.Page{}, inquiry.ErrCursorMismatch
	}
	if err = ctx.Err(); err != nil {
		return inquiry.Page{}, err
	}
	return snapshot.page(cursor.page), nil
}

// Evict explicitly invalidates a snapshot and every one of its cursors.
func (s *SnapshotStore) Evict(snapshotID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if snapshot, found := s.snapshots[snapshotID]; found {
		s.evict(snapshot)
	}
}

// InvalidateOwner drops all policy versions for an owner after policy changes.
func (s *SnapshotStore) InvalidateOwner(owner access.OwnerID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, snapshot := range s.snapshots {
		if snapshot.scope.OwnerID == owner {
			s.evict(snapshot)
		}
	}
}

// InvalidateConnection drops data for every authorization lineage of a connection.
func (s *SnapshotStore) InvalidateConnection(connection access.ConnectionID) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, snapshot := range s.snapshots {
		if snapshot.scope.ConnectionID == connection {
			s.evict(snapshot)
		}
	}
}

// PurgeExpired can be called by a process housekeeping tick. Expiry correctness
// never depends on that tick: every Publish and Read checks it synchronously.
func (s *SnapshotStore) PurgeExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpired(s.options.Now())
}

type Stats struct{ Snapshots, Cursors, Bytes int }

// Stats reports content-free accounting only.
func (s *SnapshotStore) Stats() Stats {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpired(s.options.Now())
	return Stats{Snapshots: len(s.snapshots), Cursors: len(s.cursors), Bytes: s.bytes}
}

func (s *SnapshotStore) purgeExpired(now time.Time) {
	for _, snapshot := range s.snapshots {
		if !now.Before(snapshot.expiresAt) {
			s.evict(snapshot)
		}
	}
}
func (s *SnapshotStore) evict(snapshot *snapshot) {
	delete(s.snapshots, snapshot.id)
	for index := 1; index < len(snapshot.pages); index++ {
		delete(s.cursors, sha256.Sum256([]byte(snapshot.handle("cursor", index))))
	}
	s.order.Remove(snapshot.order)
	s.bytes -= snapshot.bytes
}
func (s *snapshot) handle(purpose string, position int) string {
	mac := hmac.New(sha256.New, s.seed[:])
	mac.Write([]byte(purpose))
	var offset [8]byte
	binary.BigEndian.PutUint64(offset[:], uint64(position))
	mac.Write(offset[:])
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
func (s *snapshot) page(index int) inquiry.Page {
	bounds := s.pages[index]
	result := inquiry.Page{Items: make([]json.RawMessage, bounds.to-bounds.from), Metadata: s.metadata}
	for index, item := range s.items[bounds.from:bounds.to] {
		result.Items[index] = append(json.RawMessage(nil), item...)
	}
	result.Metadata.Coverage = cloneCoverage(s.metadata.Coverage)
	result.Metadata.PageComplete = index == len(s.pages)-1
	if !result.Metadata.PageComplete {
		result.Metadata.NextCursor = s.handle("cursor", index+1)
	}
	return result
}
func cloneCoverage(coverage inquiry.Coverage) inquiry.Coverage {
	if coverage.Warnings != nil {
		warnings := make([]string, len(coverage.Warnings))
		for index, warning := range coverage.Warnings {
			warnings[index] = strings.Clone(warning)
		}
		coverage.Warnings = warnings
	}
	return coverage
}
func cloneScope(scope access.ReadScope) access.ReadScope {
	scope.OwnerID = access.OwnerID(strings.Clone(string(scope.OwnerID)))
	scope.ConnectionID = access.ConnectionID(strings.Clone(string(scope.ConnectionID)))
	scope.AuthorizationLineage = strings.Clone(scope.AuthorizationLineage)
	scope.BudgetID = budget.BudgetID(strings.Clone(string(scope.BudgetID)))
	return scope
}

func cloneQuery(query inquiry.Query) inquiry.Query {
	query.Tool = strings.Clone(query.Tool)
	query.BudgetID = budget.BudgetID(strings.Clone(string(query.BudgetID)))
	query.AccountID = budget.AccountID(strings.Clone(string(query.AccountID)))
	query.CategoryID = budget.CategoryID(strings.Clone(string(query.CategoryID)))
	query.TransactionID = budget.TransactionID(strings.Clone(string(query.TransactionID)))
	query.Month = budget.BudgetMonth(strings.Clone(string(query.Month)))
	query.SinceDate = budget.LocalDate(strings.Clone(string(query.SinceDate)))
	query.UntilDate = budget.LocalDate(strings.Clone(string(query.UntilDate)))
	query.Status = strings.Clone(query.Status)
	query.Cursor = ""
	return query
}
func sortFor(query inquiry.Query) string {
	switch query.Tool {
	case inquiry.ListTransactions, inquiry.GetTransaction:
		return "date,id"
	case inquiry.ListScheduledTransactions:
		return "date_next,id"
	default:
		return "id"
	}
}
func validateScope(scope access.ReadScope, query inquiry.Query) error {
	if budget.ValidateID(string(scope.OwnerID)) != nil || budget.ValidateID(string(scope.ConnectionID)) != nil || budget.ValidateID(scope.AuthorizationLineage) != nil || scope.PolicyVersion == 0 || scope.BudgetID != query.BudgetID {
		return inquiry.ErrUnauthorizedScope
	}
	if query.Tool != inquiry.ListBudgets && budget.ValidateID(string(scope.BudgetID)) != nil {
		return inquiry.ErrUnauthorizedScope
	}
	return nil
}
