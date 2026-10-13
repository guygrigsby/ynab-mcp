// Command budget-mcp provides offline, read-only development checks. It does not
// start a listener, provision accounts, initialize state, or load credentials.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	state "github.com/guygrigsby/ynab-mcp/internal/adapters/state/sqlite"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
func run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 1 && (args[0] == "help" || args[0] == "--help") {
		_, err := fmt.Fprintln(out, "Budget MCP for YNAB development checks\nUsage: budget-mcp check-state PATH\nOpens existing SQLite metadata read-only. No network, migrations, account setup or credential loading.\nProduction serving is not enabled.")
		return err
	}
	if len(args) != 2 || args[0] != "check-state" {
		return errors.New("usage: budget-mcp check-state PATH (or --help); no server command is enabled")
	}
	db, err := state.OpenReadOnly(args[1])
	if err != nil {
		return errors.New("metadata check failed: existing readable candidate database required")
	}
	defer db.Close()
	if _, _, err := db.ReadAccessState(ctx); err != nil {
		return errors.New("metadata check failed: valid owner and connection state required")
	}
	_, err = fmt.Fprintln(out, "Metadata structure validated. This does not authorize reads or verify credential freshness. Trusted startup reconciliation, protected secret storage and approved deployment are still required.")
	return err
}
