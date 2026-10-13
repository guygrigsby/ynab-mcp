// Package access owns exact owner identity and bounded financial disclosure policy.
package access

import (
	"errors"
	"math"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/domain/budget"
)

var (
	ErrUnauthorized    = errors.New("unauthorized scope")
	ErrInvalidGrant    = errors.New("invalid owner access grant")
	ErrVersionConflict = errors.New("policy version conflict")
)

const ReadScopeName = "budget:read"

type OwnerID string
type ConnectionID string

type PrincipalKey struct {
	Issuer  string
	Subject string
	Tenant  string
}

func (k PrincipalKey) Validate() error {
	u, err := url.Parse(k.Issuer)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || len(k.Issuer) > 2048 || len(k.Subject) == 0 || len(k.Subject) > 512 || len(k.Tenant) > 512 || strings.ContainsAny(k.Subject+k.Tenant, "\x00\r\n") {
		return ErrInvalidGrant
	}
	return nil
}

// TenantStorageKey distinguishes no tenant from every possible present tenant.
func (k PrincipalKey) TenantStorageKey() string {
	if k.Tenant == "" {
		return "n:"
	}
	return "v:" + k.Tenant
}

type Principal struct {
	Key       PrincipalKey
	Scopes    []string
	ExpiresAt time.Time
}

func (p Principal) HasScope(scope string) bool {
	for _, s := range p.Scopes {
		if s == scope {
			return true
		}
	}
	return false
}

type ReadScope struct {
	OwnerID              OwnerID         `json:"-"`
	ConnectionID         ConnectionID    `json:"-"`
	AuthorizationLineage string          `json:"-"`
	PolicyVersion        uint64          `json:"-"`
	BudgetID             budget.BudgetID `json:"budget_id,omitempty"`
}
type ConnectionBinding struct {
	OwnerID              OwnerID
	ConnectionID         ConnectionID
	AuthorizationLineage string
	Active               bool
}
type GrantConfig struct {
	OwnerID           OwnerID
	PrincipalKey      PrincipalKey
	ConnectionID      ConnectionID
	ConnectionOwnerID OwnerID
	BudgetIDs         []budget.BudgetID
	AllowNotes        bool
	Enabled           bool
	PolicyVersion     uint64
}

// OwnerAccessGrant is immutable; exposed slices and replacement configs are copied.
type OwnerAccessGrant struct{ config GrantConfig }

func NewOwnerAccessGrant(c GrantConfig) (OwnerAccessGrant, error) {
	if budget.ValidateID(string(c.OwnerID)) != nil || budget.ValidateID(string(c.ConnectionID)) != nil || c.ConnectionOwnerID != c.OwnerID || c.PolicyVersion == 0 || c.PrincipalKey.Validate() != nil || c.Enabled && len(c.BudgetIDs) == 0 {
		return OwnerAccessGrant{}, ErrInvalidGrant
	}
	seen := make(map[budget.BudgetID]struct{}, len(c.BudgetIDs))
	ids := make([]budget.BudgetID, 0, len(c.BudgetIDs))
	for _, id := range c.BudgetIDs {
		if budget.ValidateID(string(id)) != nil {
			return OwnerAccessGrant{}, ErrInvalidGrant
		}
		if _, ok := seen[id]; !ok {
			ids = append(ids, id)
			seen[id] = struct{}{}
		}
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	c.BudgetIDs = ids
	return OwnerAccessGrant{config: c}, nil
}
func (g OwnerAccessGrant) OwnerID() OwnerID           { return g.config.OwnerID }
func (g OwnerAccessGrant) ConnectionID() ConnectionID { return g.config.ConnectionID }
func (g OwnerAccessGrant) PrincipalKey() PrincipalKey { return g.config.PrincipalKey }
func (g OwnerAccessGrant) BudgetIDs() []budget.BudgetID {
	return append([]budget.BudgetID(nil), g.config.BudgetIDs...)
}
func (g OwnerAccessGrant) PolicyVersion() uint64 { return g.config.PolicyVersion }
func (g OwnerAccessGrant) Enabled() bool         { return g.config.Enabled }
func (g OwnerAccessGrant) AllowNotes() bool      { return g.config.AllowNotes }
func (g OwnerAccessGrant) AllowsBudget(id budget.BudgetID) bool {
	i := sort.Search(len(g.config.BudgetIDs), func(i int) bool { return g.config.BudgetIDs[i] >= id })
	return g.config.Enabled && i < len(g.config.BudgetIDs) && g.config.BudgetIDs[i] == id
}
func (g OwnerAccessGrant) Replace(expectedVersion uint64, c GrantConfig) (OwnerAccessGrant, error) {
	if expectedVersion != g.config.PolicyVersion || expectedVersion == math.MaxUint64 {
		return OwnerAccessGrant{}, ErrVersionConflict
	}
	if c.OwnerID != g.config.OwnerID {
		return OwnerAccessGrant{}, ErrInvalidGrant
	}
	c.PolicyVersion = expectedVersion + 1
	return NewOwnerAccessGrant(c)
}
func (g OwnerAccessGrant) authorize(p Principal, b ConnectionBinding) (ReadScope, error) {
	if !g.config.Enabled || !p.HasScope(ReadScopeName) || p.Key != g.config.PrincipalKey || !b.Active || b.OwnerID != g.config.OwnerID || b.ConnectionID != g.config.ConnectionID || budget.ValidateID(b.AuthorizationLineage) != nil {
		return ReadScope{}, ErrUnauthorized
	}
	return ReadScope{OwnerID: g.config.OwnerID, ConnectionID: g.config.ConnectionID, AuthorizationLineage: b.AuthorizationLineage, PolicyVersion: g.config.PolicyVersion}, nil
}
func (g OwnerAccessGrant) Authorize(p Principal, id budget.BudgetID, b ConnectionBinding) (ReadScope, error) {
	if !g.AllowsBudget(id) {
		return ReadScope{}, ErrUnauthorized
	}
	s, err := g.authorize(p, b)
	if err != nil {
		return ReadScope{}, err
	}
	s.BudgetID = id
	return s, nil
}

// AuthorizeList creates an empty-budget scope exclusively for filtered list_budgets.
func (g OwnerAccessGrant) AuthorizeList(p Principal, b ConnectionBinding) (ReadScope, error) {
	return g.authorize(p, b)
}

// Revalidate checks current policy again after external work and on every page.
func (g OwnerAccessGrant) Revalidate(p Principal, scope ReadScope, b ConnectionBinding) error {
	var current ReadScope
	var err error
	if scope.BudgetID == "" {
		current, err = g.AuthorizeList(p, b)
	} else {
		current, err = g.Authorize(p, scope.BudgetID, b)
	}
	if err != nil || current != scope {
		return ErrUnauthorized
	}
	return nil
}
