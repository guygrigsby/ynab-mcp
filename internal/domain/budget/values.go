// Package budget defines upstream financial read values. It is not a local ledger.
package budget

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

var (
	ErrInvalidID        = errors.New("invalid concrete resource ID")
	ErrCurrency         = errors.New("invalid or unresolved currency metadata")
	ErrCurrencyMismatch = errors.New("currency mismatch")
	ErrOverflow         = errors.New("money arithmetic overflow")
	ErrInvalidDate      = errors.New("invalid calendar date")
	ErrDateRange        = errors.New("invalid or excessive date range")
)

type BudgetID string
type AccountID string
type CategoryGroupID string
type CategoryID string
type TransactionID string
type SubTransactionID string
type ScheduledTransactionID string
type ScheduledSplitID string
type PayeeID string

// ValidateID accepts bounded opaque path-safe IDs, not only UUIDs. Aliases cannot
// authorize a resource. Upstream adapters must still validate required references.
func ValidateID(id string) error {
	if len(id) == 0 || len(id) > 128 || id == "default" || id == "last-used" {
		return ErrInvalidID
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
			return ErrInvalidID
		}
	}
	return nil
}

type CurrencyCode string

func ParseCurrencyCode(v string) (CurrencyCode, error) {
	if len(v) != 3 {
		return "", ErrCurrency
	}
	for _, c := range v {
		if c < 'A' || c > 'Z' {
			return "", ErrCurrency
		}
	}
	return CurrencyCode(v), nil
}

type CurrencyFormat struct {
	ISOCode          CurrencyCode `json:"iso_code"`
	DecimalDigits    int          `json:"decimal_digits"`
	DecimalSeparator string       `json:"decimal_separator"`
	GroupSeparator   string       `json:"group_separator"`
	Symbol           string       `json:"symbol"`
	SymbolFirst      bool         `json:"symbol_first"`
	DisplaySymbol    bool         `json:"display_symbol"`
}

func (f CurrencyFormat) Validate() error {
	if _, err := ParseCurrencyCode(string(f.ISOCode)); err != nil {
		return err
	}
	if f.DecimalDigits < 0 || f.DecimalDigits > 3 || len(f.DecimalSeparator) > 8 || len(f.GroupSeparator) > 8 || len(f.Symbol) > 32 {
		return ErrCurrency
	}
	return nil
}

type Money struct {
	Milliunits int64
	Currency   CurrencyCode
}

func NewMoney(n int64, c CurrencyCode) (Money, error) {
	if _, err := ParseCurrencyCode(string(c)); err != nil {
		return Money{}, err
	}
	return Money{n, c}, nil
}
func (m Money) Validate() error { _, err := ParseCurrencyCode(string(m.Currency)); return err }
func (m Money) Add(n Money) (Money, error) {
	if err := m.Validate(); err != nil {
		return Money{}, err
	}
	if err := n.Validate(); err != nil {
		return Money{}, err
	}
	if m.Currency != n.Currency {
		return Money{}, ErrCurrencyMismatch
	}
	if n.Milliunits > 0 && m.Milliunits > math.MaxInt64-n.Milliunits || n.Milliunits < 0 && m.Milliunits < math.MinInt64-n.Milliunits {
		return Money{}, ErrOverflow
	}
	return Money{m.Milliunits + n.Milliunits, m.Currency}, nil
}
func (m Money) Sub(n Money) (Money, error) {
	if err := m.Validate(); err != nil {
		return Money{}, err
	}
	if err := n.Validate(); err != nil {
		return Money{}, err
	}
	if m.Currency != n.Currency {
		return Money{}, ErrCurrencyMismatch
	}
	if n.Milliunits > 0 && m.Milliunits < math.MinInt64+n.Milliunits || n.Milliunits < 0 && m.Milliunits > math.MaxInt64+n.Milliunits {
		return Money{}, ErrOverflow
	}
	return Money{m.Milliunits - n.Milliunits, m.Currency}, nil
}
func (m Money) Negate() (Money, error) {
	if err := m.Validate(); err != nil {
		return Money{}, err
	}
	if m.Milliunits == math.MinInt64 {
		return Money{}, ErrOverflow
	}
	return Money{-m.Milliunits, m.Currency}, nil
}

// Decimal does not round to the currency's display precision. It also handles MinInt64.
func (m Money) Decimal() string {
	s := strconv.FormatInt(m.Milliunits, 10)
	sign := ""
	if strings.HasPrefix(s, "-") {
		sign = "-"
		s = s[1:]
	}
	for len(s) < 4 {
		s = "0" + s
	}
	return sign + s[:len(s)-3] + "." + s[len(s)-3:]
}
func (m Money) MarshalJSON() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Milliunits string       `json:"milliunits"`
		Decimal    string       `json:"decimal"`
		Currency   CurrencyCode `json:"currency"`
	}{strconv.FormatInt(m.Milliunits, 10), m.Decimal(), m.Currency})
}

type LocalDate string

func ParseLocalDate(s string) (LocalDate, error) {
	if len(s) != 10 {
		return "", ErrInvalidDate
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil || t.Year() < 1 || t.Format("2006-01-02") != s {
		return "", ErrInvalidDate
	}
	return LocalDate(s), nil
}
func (d LocalDate) Validate() error             { _, err := ParseLocalDate(string(d)); return err }
func (d LocalDate) String() string              { return string(d) }
func (d LocalDate) Before(other LocalDate) bool { return d < other }
func (d LocalDate) MarshalJSON() ([]byte, error) {
	if err := d.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(string(d))
}
func (d *LocalDate) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return ErrInvalidDate
	}
	v, err := ParseLocalDate(s)
	if err == nil {
		*d = v
	}
	return err
}

type BudgetMonth string

func ParseBudgetMonth(s string) (BudgetMonth, error) {
	d, err := ParseLocalDate(s)
	if err != nil || string(d)[8:] != "01" {
		return "", ErrInvalidDate
	}
	return BudgetMonth(s), nil
}
func (m BudgetMonth) Validate() error { _, err := ParseBudgetMonth(string(m)); return err }
func (m BudgetMonth) String() string  { return string(m) }
func (m BudgetMonth) MarshalJSON() ([]byte, error) {
	if err := m.Validate(); err != nil {
		return nil, err
	}
	return json.Marshal(string(m))
}
func (m *BudgetMonth) UnmarshalJSON(b []byte) error {
	var s string
	if err := json.Unmarshal(b, &s); err != nil {
		return ErrInvalidDate
	}
	v, err := ParseBudgetMonth(s)
	if err == nil {
		*m = v
	}
	return err
}

type DateRange struct {
	From LocalDate `json:"from"`
	To   LocalDate `json:"to"`
}

func NewDateRange(from, to LocalDate) (DateRange, error) {
	r := DateRange{from, to}
	return r, r.Validate()
}
func (r DateRange) Validate() error {
	if r.From.Validate() != nil || r.To.Validate() != nil || r.From > r.To {
		return ErrDateRange
	}
	a, _ := time.Parse("2006-01-02", string(r.From))
	b, _ := time.Parse("2006-01-02", string(r.To))
	if b.Sub(a) > 365*24*time.Hour {
		return ErrDateRange
	}
	return nil
}
func (r DateRange) Contains(d LocalDate) bool { return d.Validate() == nil && d >= r.From && d <= r.To }

// OptionalText separates absent, source-null, empty text and policy-redacted values.
// The state is explicit; no fake source null is emitted for policy redaction.
type TextState string

const (
	TextAbsent   TextState = "absent"
	TextNull     TextState = "null"
	TextPresent  TextState = "present"
	TextRedacted TextState = "redacted"
)

type OptionalText struct {
	State TextState `json:"state"`
	Value string    `json:"value,omitempty"`
}

func (t OptionalText) Validate() error {
	switch t.State {
	case TextPresent:
		return nil
	case TextAbsent, TextNull, TextRedacted:
		if t.Value == "" {
			return nil
		}
	}
	return fmt.Errorf("invalid optional text state")
}

// EnumValue preserves an unknown safe upstream value without inventing its meaning.
type EnumValue struct {
	Value      string `json:"value"`
	Recognized bool   `json:"recognized"`
}

func NewEnumValue(value string, known ...string) EnumValue {
	e := EnumValue{Value: value}
	for _, k := range known {
		if value == k {
			e.Recognized = true
			break
		}
	}
	return e
}
