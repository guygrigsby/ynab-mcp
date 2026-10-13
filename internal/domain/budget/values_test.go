package budget

import (
	"encoding/json"
	"errors"
	"math"
	"strconv"
	"strings"
	"testing"
)

func TestMoneyExactBoundaryValues(t *testing.T) {
	for _, tt := range []struct {
		n    int64
		want string
	}{{-12345, "-12.345"}, {0, "0.000"}, {1, "0.001"}, {-1, "-0.001"}, {math.MinInt64, "-9223372036854775.808"}, {math.MaxInt64, "9223372036854775.807"}} {
		m, err := NewMoney(tt.n, "USD")
		if err != nil || m.Decimal() != tt.want {
			t.Errorf("%d: %q %v", tt.n, m.Decimal(), err)
		}
		b, err := json.Marshal(m)
		if err != nil || !strings.Contains(string(b), `"milliunits":"`) {
			t.Fatalf("unsafe amount JSON %s: %v", b, err)
		}
	}
}
func TestMoneyCheckedArithmetic(t *testing.T) {
	tests := []struct {
		name     string
		a, b     int64
		subtract bool
		want     int64
		overflow bool
	}{{"positive addition", math.MaxInt64, 1, false, 0, true}, {"negative addition", math.MinInt64, -1, false, 0, true}, {"subtract min safely", math.MinInt64, math.MinInt64, true, 0, false}, {"subtract min overflow", 0, math.MinInt64, true, 0, true}, {"subtract max overflow", math.MinInt64, 1, true, 0, true}, {"normal sum", -60000, -40000, false, -100000, false}, {"normal difference", -100000, -40000, true, -60000, false}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := Money{tt.a, "USD"}
			b := Money{tt.b, "USD"}
			var got Money
			var err error
			if tt.subtract {
				got, err = a.Sub(b)
			} else {
				got, err = a.Add(b)
			}
			if tt.overflow {
				if !errors.Is(err, ErrOverflow) {
					t.Fatalf("expected overflow, got %v", err)
				}
			} else if err != nil || got.Milliunits != tt.want {
				t.Fatalf("got %+v %v", got, err)
			}
		})
	}
	if _, err := (Money{math.MinInt64, "USD"}).Negate(); err != ErrOverflow {
		t.Fatal(err)
	}
	if _, err := (Money{1, "USD"}).Add(Money{1, "EUR"}); err != ErrCurrencyMismatch {
		t.Fatal(err)
	}
	if _, err := NewMoney(1, ""); err != ErrCurrency {
		t.Fatal("unresolved currency accepted")
	}
	if _, err := json.Marshal(Money{}); err == nil {
		t.Fatal("unresolved currency serialized")
	}
}
func TestDatesAndInclusiveBounds(t *testing.T) {
	for _, s := range []string{"2026-2-03", "2025-02-29", "2026-02-30", "2026-01-01T00:00:00Z", "0000-01-01"} {
		if _, err := ParseLocalDate(s); err == nil {
			t.Errorf("accepted %s", s)
		}
	}
	for _, s := range []string{"2024-02-29", "2026-10-13"} {
		if _, err := ParseLocalDate(s); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := ParseBudgetMonth("2026-10-13"); err == nil {
		t.Fatal("noncanonical month accepted")
	}
	for _, tt := range []struct {
		from, to string
		ok       bool
	}{{"2024-01-01", "2024-12-31", true}, {"2024-01-01", "2025-01-01", false}, {"2026-10-13", "2026-10-12", false}, {"2026-10-13", "2026-10-13", true}} {
		r := DateRange{LocalDate(tt.from), LocalDate(tt.to)}
		if (r.Validate() == nil) != tt.ok {
			t.Errorf("range %+v", r)
		}
	}
}
func TestIDsOpaqueNotUUIDOrAliases(t *testing.T) {
	for _, s := range []string{"account-123", "category_internal_7", "A0"} {
		if err := ValidateID(s); err != nil {
			t.Fatal(err)
		}
	}
	for _, s := range []string{"", "default", "last-used", "../bad", "a/b", "a?b", "a%2fb", " a", "a\n", strings.Repeat("x", 129)} {
		if ValidateID(s) == nil {
			t.Errorf("accepted %q", s)
		}
	}
}
func TestTextPresenceAndUnknownEnums(t *testing.T) {
	for _, v := range []OptionalText{{TextAbsent, ""}, {TextNull, ""}, {TextPresent, ""}, {TextRedacted, ""}} {
		if err := v.Validate(); err != nil {
			t.Fatal(err)
		}
	}
	if (OptionalText{TextRedacted, "private"}).Validate() == nil {
		t.Fatal("redacted value leaked")
	}
	e := NewEnumValue("future-enum", "known")
	if e.Recognized || e.Value != "future-enum" {
		t.Fatal(e)
	}
}
func TestSplitParentNotDoubleCounted(t *testing.T) {
	cat := CategoryID("category-1")
	tx := TransactionView{Amount: Money{-100000, "USD"}, Splits: []SplitView{{ID: "split-1", Amount: Money{-60000, "USD"}, Category: CategoryRef{ID: &cat}}, {ID: "split-2", Amount: Money{-40000, "USD"}, Category: CategoryRef{ID: &cat}}}}
	if tx.AccountMovement().Milliunits != -100000 {
		t.Fatal("split double counted")
	}
	ok, ids := tx.MatchingCategory(cat)
	if !ok || len(ids) != 2 {
		t.Fatal(ok, ids)
	}
}
func TestNullGoalIsDistinctFromZeroAndCurrentMonth(t *testing.T) {
	zero := Money{0, "USD"}
	v := CategoryMonthView{CurrentView: true, Assigned: zero, Activity: zero, Available: zero}
	a, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	v.GoalAmount = &zero
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	if string(a) == string(b) || !strings.Contains(string(a), `"goal_amount":null`) || !strings.Contains(string(a), `"month":null`) {
		t.Fatal(string(a), string(b))
	}
}
func FuzzMoneyDecimal(f *testing.F) {
	f.Add(int64(-12345))
	f.Add(int64(math.MinInt64))
	f.Fuzz(func(t *testing.T, n int64) {
		m := Money{n, "USD"}
		roundTrip, err := strconv.ParseInt(strings.Replace(m.Decimal(), ".", "", 1), 10, 64)
		if err != nil || roundTrip != n {
			t.Fatalf("exact decimal round trip failed: %d -> %s -> %d, %v", n, m.Decimal(), roundTrip, err)
		}
		if _, err := json.Marshal(m); err != nil {
			t.Fatal(err)
		}
	})
}
