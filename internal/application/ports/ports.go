// Package ports defines the application-owned consistency and I/O boundaries.
package ports

import (
	"context"
	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/inquiry"
)

// AccessStateRepository must atomically read the owner grant and its owned
// connection binding. Implementations must fail closed on unavailable state.
// No selected production persistence adapter exists in this foundation.
type AccessStateRepository interface {
	ReadAccessState(context.Context) (access.OwnerAccessGrant, access.ConnectionBinding, error)
}

type YNABReadGateway interface {
	Read(context.Context, access.ReadScope, inquiry.Query) (inquiry.ReadResult, error)
}

type SnapshotStore interface {
	Publish(context.Context, access.ReadScope, inquiry.Query, inquiry.ReadResult) (inquiry.Page, error)
	Read(context.Context, access.ReadScope, inquiry.Query) (inquiry.Page, error)
}
