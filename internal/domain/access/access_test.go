package access

import (
	"errors"
	"testing"

	"github.com/guygrigsby/ynab-mcp/internal/domain/budget"
)

func fixture(t *testing.T) (OwnerAccessGrant, Principal, ConnectionBinding, GrantConfig) {
	t.Helper()
	key := PrincipalKey{Issuer: "https://issuer.example", Subject: "owner-subject"}
	c := GrantConfig{OwnerID: "owner-1", PrincipalKey: key, ConnectionID: "connection-1", ConnectionOwnerID: "owner-1", BudgetIDs: []budget.BudgetID{"budget-2", "budget-1"}, Enabled: true, PolicyVersion: 1}
	g, err := NewOwnerAccessGrant(c)
	if err != nil {
		t.Fatal(err)
	}
	return g, Principal{Key: key, Scopes: []string{ReadScopeName}}, ConnectionBinding{OwnerID: c.OwnerID, ConnectionID: c.ConnectionID, AuthorizationLineage: "lineage-1", Active: true}, c
}
func TestGrantRejectsInvalidConfiguration(t *testing.T) {
	_, _, _, base := fixture(t)
	for _, mutate := range []func(*GrantConfig){func(c *GrantConfig) { c.BudgetIDs = nil }, func(c *GrantConfig) { c.ConnectionOwnerID = "foreign" }, func(c *GrantConfig) { c.BudgetIDs = []budget.BudgetID{"default"} }, func(c *GrantConfig) { c.PolicyVersion = 0 }, func(c *GrantConfig) { c.PrincipalKey.Subject = "" }} {
		c := base
		mutate(&c)
		if _, err := NewOwnerAccessGrant(c); !errors.Is(err, ErrInvalidGrant) {
			t.Fatalf("accepted invalid grant: %+v", c)
		}
	}
}
func TestExactPrincipalScopeAndConnection(t *testing.T) {
	g, p, b, _ := fixture(t)
	s, err := g.Authorize(p, "budget-1", b)
	if err != nil || s.BudgetID != "budget-1" {
		t.Fatal(s, err)
	}
	for _, mutate := range []func(*Principal, *ConnectionBinding){func(p *Principal, b *ConnectionBinding) { p.Key.Subject = "other" }, func(p *Principal, b *ConnectionBinding) { p.Key.Issuer = "https://issuer.example/" }, func(p *Principal, b *ConnectionBinding) { p.Key.Tenant = "unexpected" }, func(p *Principal, b *ConnectionBinding) { p.Scopes = []string{"budget:write"} }, func(p *Principal, b *ConnectionBinding) { b.OwnerID = "other" }, func(p *Principal, b *ConnectionBinding) { b.Active = false }, func(p *Principal, b *ConnectionBinding) { b.AuthorizationLineage = "" }} {
		pp, bb := p, b
		mutate(&pp, &bb)
		if _, err := g.Authorize(pp, "budget-1", bb); err != ErrUnauthorized {
			t.Fatal(err)
		}
	}
	if _, err := g.Authorize(p, "budget-3", b); err != ErrUnauthorized {
		t.Fatal(err)
	}
	if (PrincipalKey{}).TenantStorageKey() == (PrincipalKey{Tenant: "n:"}).TenantStorageKey() {
		t.Fatal("tenant sentinel collision")
	}
}
func TestGrantImmutableAndRevocationRechecked(t *testing.T) {
	g, p, b, c := fixture(t)
	c.BudgetIDs[0] = "evil"
	if g.AllowsBudget("evil") {
		t.Fatal("constructor retained slice")
	}
	ids := g.BudgetIDs()
	ids[0] = "evil"
	if g.AllowsBudget("evil") {
		t.Fatal("getter exposes slice")
	}
	scope, err := g.Authorize(p, "budget-1", b)
	if err != nil {
		t.Fatal(err)
	}
	c.BudgetIDs = []budget.BudgetID{"budget-2"}
	next, err := g.Replace(1, c)
	if err != nil || next.PolicyVersion() != 2 {
		t.Fatal(err)
	}
	if next.Revalidate(p, scope, b) != ErrUnauthorized {
		t.Fatal("in-flight revoked result disclosed")
	}
	if _, err := next.Replace(1, c); err != ErrVersionConflict {
		t.Fatal(err)
	}
	c.Enabled = false
	c.BudgetIDs = nil
	disabled, err := g.Replace(1, c)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := disabled.AuthorizeList(p, b); err != ErrUnauthorized {
		t.Fatal("disabled grant disclosed list")
	}
	b.AuthorizationLineage = "lineage-2"
	if g.Revalidate(p, scope, b) != ErrUnauthorized {
		t.Fatal("reconnect did not invalidate")
	}
}
