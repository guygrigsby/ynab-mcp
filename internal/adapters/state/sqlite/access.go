package sqlite

import (
	"context"
	"database/sql"
	"math"
	"strings"

	"github.com/guygrigsby/ynab-mcp/internal/application/ports"
	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/budget"
	"github.com/guygrigsby/ynab-mcp/internal/domain/connection"
)

type querier interface {
	QueryContext(context.Context, string, ...any) (*sql.Rows, error)
	QueryRowContext(context.Context, string, ...any) *sql.Row
}

func grantConfig(g access.OwnerAccessGrant) access.GrantConfig {
	return access.GrantConfig{OwnerID: g.OwnerID(), PrincipalKey: g.PrincipalKey(), ConnectionID: g.ConnectionID(), ConnectionOwnerID: g.OwnerID(), BudgetIDs: g.BudgetIDs(), AllowNotes: g.AllowNotes(), Enabled: g.Enabled(), PolicyVersion: g.PolicyVersion()}
}

func validateGrant(g access.OwnerAccessGrant) error {
	if g.PolicyVersion() > math.MaxInt64 || len(g.BudgetIDs()) > maxAllowedBudgets {
		return access.ErrInvalidGrant
	}
	_, err := access.NewOwnerAccessGrant(grantConfig(g))
	return err
}

// Initialize atomically establishes one explicit owner, connection and grant.
// It is an administrative operation outside the MCP tool surface. No records are
// inferred from incoming identities and a second owner can never be inserted.
func (s *Store) Initialize(ctx context.Context, g access.OwnerAccessGrant, c connection.YNABConnection) error {
	if err := validateGrant(g); err != nil {
		return err
	}
	state := c.State()
	raw, err := encodeConnection(c)
	if err != nil {
		return err
	}
	if g.PolicyVersion() != 1 || g.OwnerID() != state.OwnerID || g.ConnectionID() != state.ID {
		return access.ErrInvalidGrant
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		var count int
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM owners").Scan(&count); err != nil {
			return dbError(ctx, err)
		}
		if count != 0 {
			return ErrAlreadyInitialized
		}
		p := g.PrincipalKey()
		if _, err := tx.ExecContext(ctx, "INSERT INTO owners(singleton,owner_id,issuer,subject,tenant_key,enabled,policy_version) VALUES(1,?,?,?,?,?,?)", g.OwnerID(), p.Issuer, p.Subject, p.TenantStorageKey(), g.Enabled(), g.PolicyVersion()); err != nil {
			return dbError(ctx, err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO connections(connection_id,owner_id,state_version,metadata) VALUES(?,?,?,?)", state.ID, state.OwnerID, state.Version, raw); err != nil {
			return dbError(ctx, err)
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO access_grants(owner_id,connection_id,notes_permitted) VALUES(?,?,?)", g.OwnerID(), g.ConnectionID(), g.AllowNotes()); err != nil {
			return dbError(ctx, err)
		}
		return insertBudgets(ctx, tx, g)
	})
}

func insertBudgets(ctx context.Context, tx *sql.Tx, g access.OwnerAccessGrant) error {
	for _, id := range g.BudgetIDs() {
		if _, err := tx.ExecContext(ctx, "INSERT INTO allowed_budgets(owner_id,budget_id) VALUES(?,?)", g.OwnerID(), id); err != nil {
			return dbError(ctx, err)
		}
	}
	return nil
}

func (s *Store) ReadAccessState(ctx context.Context) (access.OwnerAccessGrant, access.ConnectionBinding, error) {
	g, c, err := s.ReadAuthorizationState(ctx)
	if err != nil {
		return access.OwnerAccessGrant{}, access.ConnectionBinding{}, err
	}
	return g, c.Binding(), nil
}

func (s *Store) ReadAuthorizationState(ctx context.Context) (access.OwnerAccessGrant, connection.YNABConnection, error) {
	return readAuthorization(ctx, s.db)
}

// One SELECT supplies one SQLite snapshot, including the allowlist. Reads never
// observe a connection from a different revision than its joined owner grant.
func readAuthorization(ctx context.Context, q querier) (access.OwnerAccessGrant, connection.YNABConnection, error) {
	rows, err := q.QueryContext(ctx, `SELECT o.owner_id,o.issuer,o.subject,o.tenant_key,o.enabled,o.policy_version,
 g.connection_id,g.notes_permitted,c.owner_id,c.state_version,substr(c.metadata,1,65537),b.budget_id
 FROM owners o LEFT JOIN access_grants g ON g.owner_id=o.owner_id
 LEFT JOIN connections c ON c.connection_id=g.connection_id AND c.owner_id=o.owner_id
 LEFT JOIN allowed_budgets b ON b.owner_id=o.owner_id ORDER BY b.budget_id`)
	if err != nil {
		return access.OwnerAccessGrant{}, connection.YNABConnection{}, dbError(ctx, err)
	}
	defer rows.Close()
	var config access.GrantConfig
	var restored connection.YNABConnection
	count := 0
	for rows.Next() {
		var owner, issuer, subject, tenant, id, connOwner, raw string
		var enabled, notes int
		var version, connVersion int64
		var bid sql.NullString
		if err := rows.Scan(&owner, &issuer, &subject, &tenant, &enabled, &version, &id, &notes, &connOwner, &connVersion, &raw, &bid); err != nil {
			return access.OwnerAccessGrant{}, connection.YNABConnection{}, ErrCorrupt
		}
		if count == 0 {
			if version <= 0 || enabled < 0 || enabled > 1 || notes < 0 || notes > 1 || owner != connOwner {
				return access.OwnerAccessGrant{}, connection.YNABConnection{}, ErrCorrupt
			}
			key := access.PrincipalKey{Issuer: issuer, Subject: subject}
			if tenant == "n:" {
			} else if strings.HasPrefix(tenant, "v:") && len(tenant) > 2 {
				key.Tenant = strings.TrimPrefix(tenant, "v:")
			} else {
				return access.OwnerAccessGrant{}, connection.YNABConnection{}, ErrCorrupt
			}
			config = access.GrantConfig{OwnerID: access.OwnerID(owner), PrincipalKey: key, ConnectionID: access.ConnectionID(id), ConnectionOwnerID: access.OwnerID(connOwner), Enabled: enabled == 1, AllowNotes: notes == 1, PolicyVersion: uint64(version)}
			restored, err = decodeConnection(raw, access.ConnectionID(id), access.OwnerID(connOwner), connVersion)
			if err != nil {
				return access.OwnerAccessGrant{}, connection.YNABConnection{}, err
			}
		}
		if bid.Valid {
			config.BudgetIDs = append(config.BudgetIDs, budget.BudgetID(bid.String))
		}
		count++
		if count > maxAllowedBudgets {
			return access.OwnerAccessGrant{}, connection.YNABConnection{}, ErrCorrupt
		}
	}
	if err := rows.Err(); err != nil {
		return access.OwnerAccessGrant{}, connection.YNABConnection{}, dbError(ctx, err)
	}
	if count == 0 {
		return access.OwnerAccessGrant{}, connection.YNABConnection{}, ErrUninitialized
	}
	g, err := access.NewOwnerAccessGrant(config)
	if err != nil {
		return access.OwnerAccessGrant{}, connection.YNABConnection{}, ErrCorrupt
	}
	return g, restored, nil
}

// ReplaceGrant requires the already constructed successor (expected+1); it does
// not silently repair caller versions, change ownership or create connections.
func (s *Store) ReplaceGrant(ctx context.Context, expected uint64, next access.OwnerAccessGrant) error {
	if err := validateGrant(next); err != nil {
		return err
	}
	if expected == 0 || expected >= math.MaxInt64 || next.PolicyVersion() != expected+1 {
		return access.ErrVersionConflict
	}
	return s.write(ctx, func(tx *sql.Tx) error {
		current, c, err := readAuthorization(ctx, tx)
		if err != nil {
			return err
		}
		if current.PolicyVersion() != expected {
			return access.ErrVersionConflict
		}
		if next.OwnerID() != current.OwnerID() || next.ConnectionID() != c.State().ID || c.State().OwnerID != next.OwnerID() {
			return access.ErrInvalidGrant
		}
		p := next.PrincipalKey()
		r, err := tx.ExecContext(ctx, "UPDATE owners SET issuer=?,subject=?,tenant_key=?,enabled=?,policy_version=? WHERE owner_id=? AND policy_version=?", p.Issuer, p.Subject, p.TenantStorageKey(), next.Enabled(), next.PolicyVersion(), next.OwnerID(), expected)
		if err != nil {
			return dbError(ctx, err)
		}
		if n, err := r.RowsAffected(); err != nil || n != 1 {
			return access.ErrVersionConflict
		}
		if _, err := tx.ExecContext(ctx, "UPDATE access_grants SET notes_permitted=? WHERE owner_id=?", next.AllowNotes(), next.OwnerID()); err != nil {
			return dbError(ctx, err)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM allowed_budgets WHERE owner_id=?", next.OwnerID()); err != nil {
			return dbError(ctx, err)
		}
		return insertBudgets(ctx, tx, next)
	})
}

var _ ports.AuthorizationRepository = (*Store)(nil)

func (s *Store) CompareAndSwapAuthorized(ctx context.Context, expected ports.AuthorizationExpectation, next connection.YNABConnection) error {
	return s.write(ctx, func(tx *sql.Tx) error {
		g, current, err := readAuthorization(ctx, tx)
		if err != nil {
			return err
		}
		state := current.State()
		if !g.Enabled() || g.OwnerID() != expected.OwnerID || g.ConnectionID() != expected.ConnectionID || g.PrincipalKey() != expected.PrincipalKey || g.PolicyVersion() != expected.PolicyVersion {
			return access.ErrUnauthorized
		}
		if state.Version != expected.ConnectionVersion || state.Status != expected.ConnectionStatus {
			return connection.ErrConflict
		}
		if state.Status != connection.Unconnected && state.Status != connection.Active && state.Status != connection.ReconnectRequired {
			return connection.ErrNotActive
		}
		if next.State().AuthorizationLineage == state.AuthorizationLineage || next.State().Status != connection.Active || next.State().Attempt != nil {
			return connection.ErrInvalidState
		}
		return swapConnection(ctx, tx, expected.ConnectionID, expected.ConnectionVersion, current, next)
	})
}
