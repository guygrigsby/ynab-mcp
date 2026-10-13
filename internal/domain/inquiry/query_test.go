package inquiry

import (
	"encoding/json"
	"testing"
	"time"
)

func TestStrictQueries(t *testing.T) {
	valid := Query{Tool: ListTransactions, BudgetID: "budget-1", SinceDate: "2026-01-01", UntilDate: "2026-01-31"}
	q, err := valid.Normalize()
	if err != nil || q.Limit != 50 {
		t.Fatal(q, err)
	}
	for _, mutate := range []func(*Query){func(q *Query) { q.Tool = "delete_transaction" }, func(q *Query) { q.BudgetID = "default" }, func(q *Query) { q.SinceDate = "" }, func(q *Query) { q.UntilDate = "2027-02-01" }, func(q *Query) { q.Status = "pending" }, func(q *Query) { q.Limit = 201 }, func(q *Query) { q.Month = "2026-01-01" }, func(q *Query) { q.TransactionID = "unexpected" }} {
		bad := valid
		mutate(&bad)
		if bad.Validate() == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
}
func TestFingerprintBindsProjectionAndLimit(t *testing.T) {
	q := Query{Tool: ListTransactions, BudgetID: "budget-1", SinceDate: "2026-01-01", UntilDate: "2026-01-31"}
	fingerprint := q.Fingerprint()
	q.Cursor = "opaque"
	if q.Fingerprint() != fingerprint {
		t.Fatal("cursor changed query")
	}
	q.Limit = DefaultLimit
	if q.Fingerprint() != fingerprint {
		t.Fatal("implicit limit differs")
	}
	q.IncludeNotes = true
	if q.Fingerprint() == fingerprint {
		t.Fatal("projection not bound")
	}
	q.IncludeNotes = false
	q.Limit = 51
	if q.Fingerprint() == fingerprint {
		t.Fatal("limit not bound")
	}
}
func TestReadResultRejectsPartialAndInvalidIntervals(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	r := ReadResult{Items: []json.RawMessage{json.RawMessage(`{"id":"synthetic"}`)}, ObservedFrom: now, ObservedAt: now.Add(time.Second), Coverage: Coverage{CollectionComplete: true}}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	r.Coverage.CollectionComplete = false
	if r.Validate() == nil {
		t.Fatal("partial result published")
	}
	r.Coverage.CollectionComplete = true
	r.Coverage.PendingTransactionsIncluded = true
	if r.Validate() == nil {
		t.Fatal("invented pending coverage")
	}
	r.Coverage.PendingTransactionsIncluded = false
	r.ObservedAt = now.Add(-time.Second)
	if r.Validate() == nil {
		t.Fatal("invalid interval")
	}
}
