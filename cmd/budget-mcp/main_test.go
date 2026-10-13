package main

import (
	"bytes"
	"context"
	state "github.com/guygrigsby/ynab-mcp/internal/adapters/state/sqlite"
	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/budget"
	"github.com/guygrigsby/ynab-mcp/internal/domain/connection"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestHelpStartsNothing(t *testing.T) {
	var out bytes.Buffer
	if err := run(context.Background(), []string{"--help"}, &out); err != nil || !strings.Contains(out.String(), "Production serving is not enabled") {
		t.Fatal(err)
	}
}
func TestNoImplicitServingOrInitialization(t *testing.T) {
	for _, args := range [][]string{nil, {"serve"}, {"run"}, {"init"}, {"check-state"}} {
		if run(context.Background(), args, &bytes.Buffer{}) == nil {
			t.Fatal("unsupported action accepted", args)
		}
	}
	path := filepath.Join(t.TempDir(), "must-not-create.db")
	if run(context.Background(), []string{"check-state", path}, &bytes.Buffer{}) == nil {
		t.Fatal("missing database accepted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("check created database")
	}
}

func TestCheckStateDoesNotMutateExistingMetadata(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "metadata.db")
	store, err := state.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := access.NewOwnerAccessGrant(access.GrantConfig{OwnerID: "owner", ConnectionID: "connection", ConnectionOwnerID: "owner", PrincipalKey: access.PrincipalKey{Issuer: "https://issuer.example", Subject: "synthetic-owner"}, BudgetIDs: []budget.BudgetID{"budget"}, Enabled: true, PolicyVersion: 1})
	if err != nil {
		t.Fatal(err)
	}
	c, err := connection.New("connection", "owner", connection.OAuth)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Initialize(ctx, grant, c); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err = run(ctx, []string{"check-state", path}, &out); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("read-only check mutated metadata")
	}
	if !strings.Contains(out.String(), "does not authorize reads") {
		t.Fatal("missing safety boundary")
	}
}
