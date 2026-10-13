package bootstrap

import (
	"context"
	"net/http"

	"github.com/guygrigsby/ynab-mcp/internal/adapters/auth"
	"github.com/guygrigsby/ynab-mcp/internal/adapters/ynab"
	"github.com/guygrigsby/ynab-mcp/internal/application/credentials"
	"github.com/guygrigsby/ynab-mcp/internal/application/lifecycle"
	"github.com/guygrigsby/ynab-mcp/internal/application/ports"
	"github.com/guygrigsby/ynab-mcp/internal/application/upstream"
)

// NewCandidateReadHandler wires the durable ports to the fixed YNAB read adapter.
// It does not open a listener, initialize state, run an OAuth flow or silently
// recover a potentially restored database. The future production caller must
// establish trustworthy control state and external key/vault authority, reconcile
// unresolved attempts with real stopped-worker evidence, and obtain deployment
// approval before serving. No runnable command selects these dependencies.
func NewCandidateReadHandler(ctx context.Context, c Config, keys auth.KeyProvider,
	state ports.AccessStateRepository, connections ports.ScopedConnectionRepository,
	quotas ports.QuotaRepository, secrets credentials.Store, oauth lifecycle.OAuthGateway,
	snapshots ports.SnapshotStore, rotation lifecycle.Config) (http.Handler, error) {
	tokens, err := lifecycle.New(connections, state, secrets, oauth, rotation)
	if err != nil {
		return nil, err
	}
	admission, err := upstream.NewQuotaAdmission(state, quotas)
	if err != nil {
		return nil, err
	}
	gateway, err := ynab.New(tokens, admission)
	if err != nil {
		return nil, err
	}
	return NewHandler(ctx, c, keys, state, gateway, snapshots)
}
