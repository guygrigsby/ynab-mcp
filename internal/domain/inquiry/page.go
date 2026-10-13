package inquiry

import (
	"encoding/json"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/domain/budget"
)

// Page is an immutable-snapshot page as disclosed to the caller. The application
// must reauthorize its internal ReadScope immediately before returning the page.
type Page struct {
	Items    []json.RawMessage `json:"data"`
	Metadata ReadMetadata      `json:"metadata"`
}

// ReadMetadata deliberately does not expose internal owner, connection, or
// authorization-lineage identifiers. An observation interval is not a claim of
// an atomic upstream financial snapshot.
type ReadMetadata struct {
	BudgetID       budget.BudgetID `json:"budget_id,omitempty"`
	SnapshotID     string          `json:"snapshot_id"`
	NextCursor     string          `json:"next_cursor,omitempty"`
	ObservedFrom   time.Time       `json:"observed_from"`
	ObservedAt     time.Time       `json:"observed_at"`
	ExpiresAt      time.Time       `json:"expires_at"`
	Freshness      string          `json:"freshness"`
	RequestedScope Query           `json:"requested_scope"`
	AppliedFilters Query           `json:"applied_filters"`
	Sort           string          `json:"sort"`
	Coverage
	PageComplete bool `json:"page_complete"`
}
