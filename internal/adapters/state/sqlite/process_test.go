package sqlite

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/domain/admission"
	"github.com/guygrigsby/ynab-mcp/internal/domain/connection"
)

// These helpers are separate OS processes with independent SQLite connections.
// Abrupt os.Exit deliberately skips Store.Close and transaction defers. No
// network call, real credential or user account is involved.
func TestSQLiteProcessHelper(t *testing.T) {
	action := os.Getenv("YNAB_SQLITE_TEST_ACTION")
	if action == "" {
		return
	}
	s, err := Open(os.Getenv("YNAB_SQLITE_TEST_PATH"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	now := testTime.Add(time.Hour + time.Second)
	switch action {
	case "crash-before-send":
		if _, err := s.Quotas().Reserve(ctx, "conn", "crash-reserved", now); err != nil {
			t.Fatal(err)
		}
		os.Exit(0)
	case "crash-policy":
		tx, err := s.db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, "UPDATE owners SET policy_version=2"); err != nil {
			t.Fatal(err)
		}
		if _, err := tx.ExecContext(ctx, "DELETE FROM allowed_budgets"); err != nil {
			t.Fatal(err)
		}
		os.Exit(0)
	case "quota":
		accepted := 0
		for i := 0; i < 40; i++ {
			id := fmt.Sprintf("p%s-attempt-%d", os.Getenv("YNAB_SQLITE_TEST_ID"), i)
			if _, err := s.Quotas().Reserve(ctx, "conn", id, now); err == nil {
				accepted++
			} else if !errors.Is(err, admission.ErrRateLimited) {
				t.Fatal(err)
			}
		}
		fmt.Printf("accepted=%d\n", accepted)
	case "cas":
		c, err := s.Connections().Load(ctx, "conn")
		if err != nil {
			t.Fatal(err)
		}
		next, err := c.Disable(c.State().Version)
		if err != nil {
			t.Fatal(err)
		}
		err = s.Connections().CompareAndSwap(ctx, "conn", 2, next)
		if err == nil {
			fmt.Println("accepted=1")
		} else if errors.Is(err, connection.ErrConflict) {
			fmt.Println("accepted=0")
		} else {
			t.Fatal(err)
		}
	default:
		t.Fatal("unknown helper action")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func runHelper(t *testing.T, path, action, id string) string {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestSQLiteProcessHelper$")
	cmd.Env = append(os.Environ(), "YNAB_SQLITE_TEST_ACTION="+action, "YNAB_SQLITE_TEST_PATH="+path, "YNAB_SQLITE_TEST_ID="+id)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("helper failed: %v %s", err, out)
	}
	return string(out)
}

func TestCommittedReservationSurvivesProcessCrashBeforeSend(t *testing.T) {
	s, path, _, _ := openFixture(t, true)
	now := warmQuota(t, s)
	s.Close()
	runHelper(t, path, "crash-before-send", "")
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	w, err := reopened.Quotas().Load(testContext, "conn")
	if err != nil {
		t.Fatal(err)
	}
	if len(w.State().Reservations) != 1 || w.State().Reservations[0].AttemptID != "crash-reserved" {
		t.Fatal("committed reservation lost on crash")
	}
	if _, err := reopened.Quotas().Reserve(testContext, "conn", "crash-reserved", now); !errors.Is(err, admission.ErrDuplicateReservation) {
		t.Fatal(err)
	}
}

func TestInterruptedGrantTransactionRollsBackAfterProcessCrash(t *testing.T) {
	s, path, g, _ := openFixture(t, true)
	s.Close()
	runHelper(t, path, "crash-policy", "")
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	got, _, err := reopened.ReadAccessState(testContext)
	if err != nil {
		t.Fatal(err)
	}
	if got.PolicyVersion() != g.PolicyVersion() || len(got.BudgetIDs()) != len(g.BudgetIDs()) {
		t.Fatal("interrupted grant transaction was partially visible")
	}
}

func TestCrossProcessQuotaAndCAS(t *testing.T) {
	for _, action := range []string{"quota", "cas"} {
		t.Run(action, func(t *testing.T) {
			s, path, _, _ := openFixture(t, true)
			if action == "quota" {
				warmQuota(t, s)
			}
			var accepted atomic.Int64
			var wg sync.WaitGroup
			for i := 0; i < 6; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					out := runHelper(t, path, action, strconv.Itoa(i))
					for _, line := range strings.Split(out, "\n") {
						if strings.HasPrefix(line, "accepted=") {
							n, err := strconv.Atoi(strings.TrimPrefix(line, "accepted="))
							if err != nil {
								t.Error(err)
							}
							accepted.Add(int64(n))
						}
					}
				}(i)
			}
			wg.Wait()
			want := int64(1)
			if action == "quota" {
				want = 180
			}
			if accepted.Load() != want {
				t.Fatalf("cross-process accepted=%d, want %d", accepted.Load(), want)
			}
		})
	}
}

func TestConcurrentOpenMigratesExactlyOnce(t *testing.T) {
	path := filepath.Join(t.TempDir(), "metadata.db")
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s, err := Open(path)
			if err != nil {
				t.Error(err)
				return
			}
			defer s.Close()
			if _, _, err := s.ReadAccessState(testContext); !errors.Is(err, ErrUninitialized) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
}
