package ports

import (
	"context"

	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/connection"
)

// AuthorizationExpectation fences initial consent/reconnect against both the
// access policy and connection metadata observed when consent began. It carries
// no code, state, session identifier, PKCE verifier or credential material.
type AuthorizationExpectation struct {
	OwnerID           access.OwnerID
	ConnectionID      access.ConnectionID
	PrincipalKey      access.PrincipalKey
	PolicyVersion     uint64
	ConnectionVersion uint64
	ConnectionStatus  connection.Status
}

// AuthorizationRepository makes access-policy and connection activation one
// atomic decision. An implementation must read the grant and full owned
// connection consistently, then validate all expectation fields, enabled grant,
// exact ownership, and an eligible prior connection status in the same short
// transaction as CompareAndSwapAuthorized. Disabled/refreshing connections and
// policy/version/identity changes must lose this comparison. Only Unconnected,
// Active and ReconnectRequired can be activated. The replacement must be the
// domain Activate transition of that prior state, with a new lineage and stored
// credential reference. No OAuth or secret-store I/O may occur in a retried
// transaction callback. Production implementations must be durable.
type AuthorizationRepository interface {
	ReadAuthorizationState(context.Context) (access.OwnerAccessGrant, connection.YNABConnection, error)
	CompareAndSwapAuthorized(context.Context, AuthorizationExpectation, connection.YNABConnection) error
}
