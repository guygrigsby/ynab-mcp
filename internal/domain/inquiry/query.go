// Package inquiry owns canonical queries and the coverage of disclosed reads.
package inquiry

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/budget"
)

const (
	ListBudgets               = "list_budgets"
	GetBudget                 = "get_budget"
	ListAccounts              = "list_accounts"
	ListCategories            = "list_categories"
	GetMonth                  = "get_month"
	ListTransactions          = "list_transactions"
	GetTransaction            = "get_transaction"
	ListScheduledTransactions = "list_scheduled_transactions"
	DefaultLimit              = 50
	MaximumLimit              = 200
	SchemaVersion             = 1
	SnapshotTTL               = 5 * time.Minute
)

var (
	ErrUnauthorizedScope   = access.ErrUnauthorized
	ErrReconnectRequired   = errors.New("upstream reconnect required")
	ErrRateLimited         = errors.New("upstream request rate limited")
	ErrUpstreamUnavailable = errors.New("upstream temporarily unavailable")
	ErrDataInvalid         = errors.New("invalid upstream data")
	ErrCurrencyMetadata    = errors.New("invalid or unresolved currency metadata")
	ErrNotFound            = errors.New("requested resource unavailable")
	ErrInvalidQuery        = errors.New("invalid or unsupported read query")
	ErrIncomplete          = errors.New("incomplete upstream collection")
	ErrCursorExpired       = errors.New("cursor expired or unavailable")
	ErrCursorMismatch      = errors.New("cursor does not match query or scope")
	ErrNarrowQueryRequired = errors.New("narrow query required")
)

type Query struct {
	Tool          string               `json:"tool"`
	BudgetID      budget.BudgetID      `json:"budget_id,omitempty"`
	AccountID     budget.AccountID     `json:"account_id,omitempty"`
	CategoryID    budget.CategoryID    `json:"category_id,omitempty"`
	TransactionID budget.TransactionID `json:"transaction_id,omitempty"`
	Month         budget.BudgetMonth   `json:"month,omitempty"`
	SinceDate     budget.LocalDate     `json:"since_date,omitempty"`
	UntilDate     budget.LocalDate     `json:"until_date,omitempty"`
	Status        string               `json:"status,omitempty"`
	IncludeClosed bool                 `json:"include_closed,omitempty"`
	IncludeNotes  bool                 `json:"include_notes,omitempty"`
	Limit         int                  `json:"limit,omitempty"`
	Cursor        string               `json:"cursor,omitempty"`
}

func (q Query) Normalize() (Query, error) {
	if q.Limit == 0 {
		q.Limit = DefaultLimit
	}
	return q, q.Validate()
}
func (q Query) Validate() error {
	if q.Limit < 0 || q.Limit > MaximumLimit || len(q.Cursor) > 256 {
		return ErrInvalidQuery
	}
	if q.Tool == ListBudgets {
		if q.BudgetID != "" || q.AccountID != "" || q.CategoryID != "" || q.TransactionID != "" || q.Month != "" || q.SinceDate != "" || q.UntilDate != "" || q.Status != "" || q.IncludeClosed || q.IncludeNotes {
			return ErrInvalidQuery
		}
		return nil
	}
	if budget.ValidateID(string(q.BudgetID)) != nil {
		return ErrInvalidQuery
	}
	for _, id := range []string{string(q.AccountID), string(q.CategoryID), string(q.TransactionID)} {
		if id != "" && budget.ValidateID(id) != nil {
			return ErrInvalidQuery
		}
	}
	if q.Month != "" && q.Month.Validate() != nil {
		return ErrInvalidQuery
	}
	if (q.SinceDate == "") != (q.UntilDate == "") {
		return ErrInvalidQuery
	}
	if q.SinceDate != "" {
		if (budget.DateRange{From: q.SinceDate, To: q.UntilDate}).Validate() != nil {
			return ErrInvalidQuery
		}
	}
	switch q.Tool {
	case GetBudget:
		if q.AccountID != "" || q.CategoryID != "" || q.TransactionID != "" || q.Month != "" || q.SinceDate != "" || q.Status != "" || q.IncludeClosed || q.IncludeNotes || q.Cursor != "" {
			return ErrInvalidQuery
		}
	case ListAccounts:
		if q.CategoryID != "" || q.TransactionID != "" || q.Month != "" || q.SinceDate != "" || q.Status != "" {
			return ErrInvalidQuery
		}
	case ListCategories:
		if q.AccountID != "" || q.TransactionID != "" || q.SinceDate != "" || q.Status != "" || q.IncludeClosed {
			return ErrInvalidQuery
		}
	case GetMonth:
		if q.Month == "" || q.AccountID != "" || q.CategoryID != "" || q.TransactionID != "" || q.SinceDate != "" || q.Status != "" || q.IncludeClosed || q.Cursor != "" {
			return ErrInvalidQuery
		}
	case ListTransactions:
		if q.SinceDate == "" || q.Month != "" || q.TransactionID != "" || q.IncludeClosed {
			return ErrInvalidQuery
		}
		switch q.Status {
		case "", "uncleared", "cleared", "reconciled", "approved", "unapproved":
		default:
			return ErrInvalidQuery
		}
	case GetTransaction:
		if q.TransactionID == "" || q.AccountID != "" || q.CategoryID != "" || q.Month != "" || q.SinceDate != "" || q.Status != "" || q.IncludeClosed || q.Cursor != "" {
			return ErrInvalidQuery
		}
	case ListScheduledTransactions:
		if q.TransactionID != "" || q.CategoryID != "" || q.Month != "" || q.Status != "" || q.IncludeClosed {
			return ErrInvalidQuery
		}
	default:
		return ErrInvalidQuery
	}
	return nil
}

// Fingerprint binds every output-affecting option, page size and schema version.
// Cursor is deliberately excluded because it denotes position in this same query.
func (q Query) Fingerprint() string {
	q.Cursor = ""
	if q.Limit == 0 {
		q.Limit = DefaultLimit
	}
	b, err := json.Marshal(struct {
		Schema int   `json:"schema"`
		Query  Query `json:"query"`
	}{SchemaVersion, q})
	if err != nil {
		return ""
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:])
}

type Coverage struct {
	CollectionComplete          bool     `json:"collection_complete"`
	PendingTransactionsIncluded bool     `json:"pending_transactions_included"`
	NotesIncluded               bool     `json:"notes_included"`
	UnresolvedReferenceCount    int      `json:"unresolved_reference_count"`
	Warnings                    []string `json:"warnings,omitempty"`
}

func (c Coverage) Validate() error {
	if !c.CollectionComplete || c.PendingTransactionsIncluded || c.UnresolvedReferenceCount < 0 {
		return ErrIncomplete
	}
	return nil
}

type ReadResult struct {
	Items        []json.RawMessage
	ObservedFrom time.Time
	ObservedAt   time.Time
	Coverage     Coverage
}

func (r ReadResult) Validate() error {
	if r.ObservedFrom.IsZero() || r.ObservedAt.Before(r.ObservedFrom) {
		return ErrIncomplete
	}
	if err := r.Coverage.Validate(); err != nil {
		return err
	}
	for _, item := range r.Items {
		if !json.Valid(item) {
			return ErrIncomplete
		}
	}
	return nil
}
