package ynab

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/guygrigsby/ynab-mcp/internal/domain/budget"
	"github.com/guygrigsby/ynab-mcp/internal/domain/inquiry"
)

// mapper accumulates the first validation failure without exposing input values.
// A caller never publishes any mapped item unless the whole projection validates.
type mapper struct {
	budgetID budget.BudgetID
	currency budget.CurrencyCode
	notes    bool
	err      error
}

func (m *mapper) invalid() {
	if m.err == nil {
		m.err = dataInvalid()
	}
}
func (m *mapper) id(v string) string {
	if budget.ValidateID(v) != nil {
		m.invalid()
	}
	return v
}
func (m *mapper) text(v *string) string {
	if v == nil {
		m.invalid()
		return ""
	}
	return *v
}
func (m *mapper) boolean(v *bool) bool {
	if v == nil {
		m.invalid()
		return false
	}
	return *v
}
func (m *mapper) enum(v string, known ...string) budget.EnumValue {
	if v == "" || len(v) > 128 || strings.IndexFunc(v, func(r rune) bool { return r < 32 || r == 127 }) >= 0 {
		m.invalid()
	}
	return budget.NewEnumValue(v, known...)
}
func (m *mapper) money(v *int64) budget.Money {
	if v == nil {
		m.invalid()
		return budget.Money{Currency: m.currency}
	}
	n, err := budget.NewMoney(*v, m.currency)
	if err != nil {
		m.err = inquiry.ErrCurrencyMetadata
	}
	return n
}
func (m *mapper) optionalMoney(v *int64) *budget.Money {
	if v == nil {
		return nil
	}
	n := m.money(v)
	return &n
}
func (m *mapper) date(v string) budget.LocalDate {
	d, err := budget.ParseLocalDate(v)
	if err != nil {
		m.invalid()
	}
	return d
}
func (m *mapper) optionalDate(v *string) *budget.LocalDate {
	if v == nil {
		return nil
	}
	d := m.date(*v)
	return &d
}
func (m *mapper) note(v json.RawMessage) budget.OptionalText {
	if !m.notes {
		return budget.OptionalText{State: budget.TextRedacted}
	}
	if len(v) == 0 {
		return budget.OptionalText{State: budget.TextAbsent}
	}
	if string(v) == "null" {
		return budget.OptionalText{State: budget.TextNull}
	}
	var s string
	if json.Unmarshal(v, &s) != nil {
		m.invalid()
		return budget.OptionalText{State: budget.TextAbsent}
	}
	return budget.OptionalText{State: budget.TextPresent, Value: s}
}
func optionalID[T ~string](m *mapper, v *string) *T {
	if v == nil {
		return nil
	}
	s := T(m.id(*v))
	return &s
}
func (m *mapper) payee(id *string, name *string) budget.PayeeRef {
	return budget.PayeeRef{BudgetID: m.budgetID, ID: optionalID[budget.PayeeID](m, id), Name: name}
}
func (m *mapper) categoryRef(id *string, name *string) budget.CategoryRef {
	return budget.CategoryRef{BudgetID: m.budgetID, ID: optionalID[budget.CategoryID](m, id), Name: name}
}
func currency(d *currencyDTO) (budget.CurrencyFormat, error) {
	if d == nil || d.DecimalDigits == nil || d.DecimalSeparator == nil || d.GroupSeparator == nil || d.CurrencySymbol == nil || d.SymbolFirst == nil || d.DisplaySymbol == nil {
		return budget.CurrencyFormat{}, inquiry.ErrCurrencyMetadata
	}
	f := budget.CurrencyFormat{ISOCode: budget.CurrencyCode(d.ISOCode), DecimalDigits: *d.DecimalDigits, DecimalSeparator: *d.DecimalSeparator, GroupSeparator: *d.GroupSeparator, Symbol: *d.CurrencySymbol, SymbolFirst: *d.SymbolFirst, DisplaySymbol: *d.DisplaySymbol}
	if f.Validate() != nil {
		return budget.CurrencyFormat{}, inquiry.ErrCurrencyMetadata
	}
	return f, nil
}
func plan(d planDTO) (budget.BudgetView, error) {
	if budget.ValidateID(d.ID) != nil || d.Name == nil || d.DateFormat == nil || d.DateFormat.Format == "" {
		return budget.BudgetView{}, dataInvalid()
	}
	f, err := currency(d.Currency)
	if err != nil {
		return budget.BudgetView{}, err
	}
	out := budget.BudgetView{ID: budget.BudgetID(d.ID), Name: *d.Name, CurrencyFormat: f, DateFormat: d.DateFormat.Format}
	if d.LastModified != nil {
		v, err := time.Parse(time.RFC3339Nano, *d.LastModified)
		if err != nil {
			return budget.BudgetView{}, dataInvalid()
		}
		v = v.UTC()
		out.LastModified = &v
	}
	return out, nil
}
func (m *mapper) account(d accountDTO) budget.AccountView {
	return budget.AccountView{
		BudgetID: m.budgetID, ID: budget.AccountID(m.id(d.ID)), Name: m.text(d.Name), Type: m.enum(d.Type, "checking", "savings", "cash", "creditCard", "lineOfCredit", "otherAsset", "otherLiability", "mortgage", "autoLoan", "studentLoan", "personalLoan", "medicalDebt", "otherDebt"), OnBudget: m.boolean(d.OnBudget), Closed: m.boolean(d.Closed), Balance: m.money(d.Balance), ClearedBalance: m.money(d.Cleared), UnclearedBalance: m.money(d.Uncleared), Note: m.note(d.Note),
	}
}

type categoryItem struct {
	Category  budget.CategoryView       `json:"category"`
	Financial budget.CategoryMonthView  `json:"financial"`
	Group     *budget.CategoryGroupView `json:"group,omitempty"`
}

func (m *mapper) category(d categoryDTO, month budget.BudgetMonth) categoryItem {
	var monthPtr *budget.BudgetMonth
	if month != "" {
		v := month
		monthPtr = &v
	}
	out := categoryItem{Category: budget.CategoryView{BudgetID: m.budgetID, ID: budget.CategoryID(m.id(d.ID)), GroupID: budget.CategoryGroupID(m.id(d.GroupID)), Name: m.text(d.Name), Hidden: d.Hidden, Internal: d.Internal, Deleted: d.Deleted, Note: m.note(d.Note)}, Financial: budget.CategoryMonthView{
		BudgetID: m.budgetID, Month: monthPtr, CurrentView: month == "", CategoryID: budget.CategoryID(d.ID), Assigned: m.money(d.Assigned), Activity: m.money(d.Activity), Available: m.money(d.Available), GoalAmount: m.optionalMoney(d.GoalAmount), GoalTargetDate: m.optionalDate(d.GoalTargetDate), GoalCadence: d.GoalCadence, GoalPercentageComplete: d.GoalPercentageComplete,
	}}
	if d.GoalType != nil {
		g := m.enum(*d.GoalType, "TB", "TBD", "MF", "NEED", "DEBT")
		out.Financial.GoalType = &g
	}
	return out
}
func (m *mapper) month(d monthDTO) budget.MonthView {
	month, err := budget.ParseBudgetMonth(d.Month)
	if err != nil {
		m.invalid()
	}
	out := budget.MonthView{BudgetID: m.budgetID, Month: month, Income: m.money(d.Income), Assigned: m.money(d.Assigned), Activity: m.money(d.Activity), ReadyToAssign: m.money(d.ReadyToAssign), AgeOfMoney: d.AgeOfMoney, Note: m.note(d.Note), Categories: []budget.CategoryMonthView{}}
	if d.Categories == nil {
		m.invalid()
		return out
	}
	seen := map[string]bool{}
	for _, c := range *d.Categories {
		m.id(c.ID)
		if seen[c.ID] {
			m.invalid()
		}
		seen[c.ID] = true
		if !c.Deleted {
			out.Categories = append(out.Categories, m.category(c, month).Financial)
		}
	}
	return out
}
func (m *mapper) transaction(d transactionDTO) budget.TransactionView {
	out := budget.TransactionView{BudgetID: m.budgetID, ID: budget.TransactionID(m.id(d.ID)), AccountID: budget.AccountID(m.id(d.AccountID)), Date: m.date(d.Date), Amount: m.money(d.Amount), Payee: m.payee(d.PayeeID, d.PayeeName), Category: m.categoryRef(d.CategoryID, d.CategoryName), Cleared: m.enum(d.Cleared, "uncleared", "cleared", "reconciled"), Approved: m.boolean(d.Approved), TransferAccountID: optionalID[budget.AccountID](m, d.TransferAccountID), TransferTransactionID: optionalID[budget.TransactionID](m, d.TransferTransactionID), MatchedTransactionID: optionalID[budget.TransactionID](m, d.MatchedTransactionID), Memo: m.note(d.Memo), Splits: []budget.SplitView{}}
	if d.Subtransactions == nil {
		m.invalid()
		return out
	}
	seen := map[string]bool{}
	for _, s := range *d.Subtransactions {
		m.id(s.ID)
		if seen[s.ID] {
			m.invalid()
		}
		seen[s.ID] = true
		if s.Deleted {
			continue
		}
		if s.ParentID != d.ID {
			m.invalid()
		}
		out.Splits = append(out.Splits, budget.SplitView{BudgetID: m.budgetID, ParentID: out.ID, ID: budget.SubTransactionID(s.ID), Amount: m.money(s.Amount), Payee: m.payee(s.PayeeID, s.PayeeName), Category: m.categoryRef(s.CategoryID, s.CategoryName), TransferAccountID: optionalID[budget.AccountID](m, s.TransferAccountID), TransferTransactionID: optionalID[budget.TransactionID](m, s.TransferTransactionID), Memo: m.note(s.Memo)})
	}
	return out
}
func (m *mapper) scheduled(d scheduledDTO) budget.ScheduledTransactionView {
	out := budget.ScheduledTransactionView{BudgetID: m.budgetID, ID: budget.ScheduledTransactionID(m.id(d.ID)), AccountID: budget.AccountID(m.id(d.AccountID)), DateFirst: m.date(d.DateFirst), DateNext: m.date(d.DateNext), Frequency: m.enum(d.Frequency, "never", "daily", "weekly", "everyOtherWeek", "twiceAMonth", "every4Weeks", "monthly", "everyOtherMonth", "every3Months", "every4Months", "twiceAYear", "yearly", "everyOtherYear"), Amount: m.money(d.Amount), Payee: m.payee(d.PayeeID, d.PayeeName), Category: m.categoryRef(d.CategoryID, d.CategoryName), TransferAccountID: optionalID[budget.AccountID](m, d.TransferAccountID), Memo: m.note(d.Memo), Splits: []budget.ScheduledSplitView{}}
	if d.Subtransactions == nil {
		m.invalid()
		return out
	}
	seen := map[string]bool{}
	for _, s := range *d.Subtransactions {
		m.id(s.ID)
		if seen[s.ID] {
			m.invalid()
		}
		seen[s.ID] = true
		if s.Deleted {
			continue
		}
		if s.ParentID != d.ID {
			m.invalid()
		}
		out.Splits = append(out.Splits, budget.ScheduledSplitView{BudgetID: m.budgetID, ParentID: out.ID, ID: budget.ScheduledSplitID(s.ID), Amount: m.money(s.Amount), Payee: m.payee(s.PayeeID, s.PayeeName), Category: m.categoryRef(s.CategoryID, s.CategoryName), TransferAccountID: optionalID[budget.AccountID](m, s.TransferAccountID), Memo: m.note(s.Memo)})
	}
	return out
}
