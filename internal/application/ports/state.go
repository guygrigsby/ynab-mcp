package ports

import (
	"context"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/admission"
	"github.com/guygrigsby/ynab-mcp/internal/domain/connection"
)

// AccessGrantRepository's implementation must replace the grant and validate
// owner/connection ownership in one transaction. A successful write increments
// policy version exactly once. No production adapter is selected yet.
type AccessGrantRepository interface {
	AccessStateRepository
	ReplaceGrant(context.Context, uint64, access.OwnerAccessGrant) error
}

// ConnectionRepository persists metadata only. Every transition is fenced by
// its expected version. No OAuth or secret-store I/O may occur in a retried
// database transaction callback.
type ConnectionRepository interface {
	Load(context.Context, access.ConnectionID) (connection.YNABConnection, error)
	CompareAndSwap(context.Context, access.ConnectionID, uint64, connection.YNABConnection) error
}

// QuotaRepository uses the connection's stable quota key across token rotation.
// Reserve atomically loads, applies QuotaWindow.Reserve, and commits before any
// GET is sent. Missing/corrupt state must fail closed or use Restart's full-window
// cooldown; the implementation may never initialize an empty usable window.
type QuotaRepository interface {
	Load(context.Context, admission.QuotaKey) (admission.QuotaWindow, error)
	Reserve(context.Context, admission.QuotaKey, string, time.Time) (admission.Reservation, error)
	RecordCooldown(context.Context, admission.QuotaKey, time.Time, time.Time) error
}
