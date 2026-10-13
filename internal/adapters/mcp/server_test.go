package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/guygrigsby/ynab-mcp/internal/domain/inquiry"
)

func TestExactReadOnlyInventory(t *testing.T) {
	got := specs()
	want := []string{"list_budgets", "get_budget", "list_accounts", "list_categories", "get_month", "list_transactions", "get_transaction", "list_scheduled_transactions"}
	if len(got) != len(want) {
		t.Fatal("unexpected tool inventory")
	}
	for i, s := range got {
		if s.name != want[i] {
			t.Fatalf("tool %d: %s", i, s.name)
		}
	}
}
func TestStrictArguments(t *testing.T) {
	s := specs()[5]
	good := `{"budget_id":"b1","since_date":"2026-01-01","until_date":"2026-02-01"}`
	q, err := decodeArguments(s, json.RawMessage(good))
	if err != nil || q.Limit != 50 {
		t.Fatalf("valid query: %v", err)
	}
	for _, input := range []string{
		`null`, `[]`, `{} `, good + `{}`, `{"budget_id":"b1","budget_id":"b2","since_date":"2026-01-01","until_date":"2026-02-01"}`,
		strings.Replace(good, `"b1"`, `null`, 1), strings.Replace(good, `"b1"`, `"default"`, 1), strings.Replace(good, `"b1"`, `"../b2"`, 1),
		strings.TrimSuffix(good, "}") + `,"url":"https://evil.example"}`, strings.TrimSuffix(good, "}") + `,"limit":0}`, strings.TrimSuffix(good, "}") + `,"limit":201}`,
		strings.TrimSuffix(good, "}") + `,"status":""}`, strings.TrimSuffix(good, "}") + `,"include_closed":false}`, strings.TrimSuffix(good, "}") + `,"tool":"delete_transaction"}`,
		strings.Replace(good, "2026-02-01", "2028-02-01", 1),
	} {
		if _, err := decodeArguments(s, json.RawMessage(input)); !errors.Is(err, inquiry.ErrInvalidQuery) {
			t.Errorf("accepted %s: %v", input, err)
		}
	}
}
func TestSanitizedErrors(t *testing.T) {
	for _, err := range []error{errors.New("secret-token-and-private-memo"), context.Canceled, inquiry.ErrDataInvalid, inquiry.ErrUnauthorizedScope} {
		b, _ := json.Marshal(failure(err))
		if strings.Contains(string(b), "secret-token") || !failure(err).IsError {
			t.Fatal(string(b))
		}
	}
}
func FuzzArguments(f *testing.F) {
	f.Add(`{"budget_id":"b1","since_date":"2026-01-01","until_date":"2026-01-02"}`)
	f.Fuzz(func(t *testing.T, s string) {
		q, err := decodeArguments(specs()[5], json.RawMessage(s))
		if err == nil {
			if q.Validate() != nil || q.Tool != "list_transactions" {
				t.Fatal("invalid admitted query")
			}
		}
	})
}
