package ynab

import (
	"context"
	"encoding/json"
	"net/url"
	"sort"

	"github.com/guygrigsby/ynab-mcp/internal/domain/access"
	"github.com/guygrigsby/ynab-mcp/internal/domain/budget"
	"github.com/guygrigsby/ynab-mcp/internal/domain/inquiry"
)

// Read implements the eight fixed full-read use cases. Cursors and disclosure
// authorization belong to the application. No delta mode is accepted implicitly.
func (c *Client) Read(ctx context.Context, scope access.ReadScope, q inquiry.Query) (inquiry.ReadResult, error) {
	var zero inquiry.ReadResult
	var err error
	if q, err = q.Normalize(); err != nil {
		return zero, err
	}
	if q.Cursor != "" {
		return zero, inquiry.ErrInvalidQuery
	}
	if budget.ValidateID(string(scope.OwnerID)) != nil || budget.ValidateID(string(scope.ConnectionID)) != nil || budget.ValidateID(scope.AuthorizationLineage) != nil || scope.PolicyVersion == 0 || scope.BudgetID != q.BudgetID {
		return zero, unauthorized()
	}
	ctx, cancel := context.WithTimeout(ctx, requestTimeout)
	defer cancel()
	result := inquiry.ReadResult{Items: []json.RawMessage{}, ObservedFrom: c.now().UTC(), Coverage: inquiry.Coverage{CollectionComplete: true, NotesIncluded: q.IncludeNotes}}
	var items []any
	switch q.Tool {
	case inquiry.ListBudgets, inquiry.GetBudget:
		items, err = c.readPlans(ctx, scope, q)
	default:
		var cf budget.CurrencyFormat
		cf, err = c.readCurrency(ctx, scope)
		if err == nil {
			m := mapper{budgetID: scope.BudgetID, currency: cf.ISOCode, notes: q.IncludeNotes}
			items, err = c.readFinancial(ctx, scope, q, &m, &result.Coverage)
			if err == nil {
				err = m.err
			}
		}
		result.Coverage.Warnings = append(result.Coverage.Warnings, "Currency settings and financial data were observed in separate upstream reads.")
	}
	if err != nil {
		return zero, err
	}
	total := 0
	for _, item := range items {
		b, e := json.Marshal(item)
		if e != nil {
			return zero, dataInvalid()
		}
		total += len(b)
		if total > maxResponseBytes {
			return zero, narrowQuery()
		}
		result.Items = append(result.Items, b)
	}
	if ctx.Err() != nil {
		return zero, unavailable()
	}
	result.ObservedAt = c.now().UTC()
	if result.Validate() != nil {
		return zero, dataInvalid()
	}
	return result, nil
}

func (c *Client) fetch(ctx context.Context, s access.ReadScope, route string, values url.Values) (*responseData, error) {
	var envelope responseDTO
	if err := c.get(ctx, s, route, values, &envelope); err != nil {
		return nil, err
	}
	if envelope.Data == nil {
		return nil, dataInvalid()
	}
	return envelope.Data, nil
}

// The discovery projection is intentionally narrower than get_budget.
type budgetSummary struct {
	ID             budget.BudgetID       `json:"id"`
	Name           string                `json:"name"`
	CurrencyFormat budget.CurrencyFormat `json:"currency_format"`
}

func (c *Client) readPlans(ctx context.Context, s access.ReadScope, q inquiry.Query) ([]any, error) {
	// Listing summaries deliberately avoids GET /plans/{id}, which returns the
	// whole nested plan graph. The application filters list output to the grant.
	data, err := c.fetch(ctx, s, plansPath, nil)
	if err != nil {
		return nil, err
	}
	if data.Plans == nil {
		return nil, dataInvalid()
	}
	list := append([]planDTO(nil), (*data.Plans)...)
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	items := []any{}
	seen := map[string]bool{}
	for _, d := range list {
		if budget.ValidateID(d.ID) != nil || seen[d.ID] {
			return nil, dataInvalid()
		}
		seen[d.ID] = true
		if q.Tool == inquiry.GetBudget && d.ID != string(q.BudgetID) {
			continue
		}
		if q.Tool == inquiry.GetBudget && (d.Currency == nil || d.DateFormat == nil) {
			extra, err := c.fetch(ctx, s, plansPath+"/"+string(s.BudgetID)+"/settings", nil)
			if err != nil {
				return nil, err
			}
			if extra.Settings == nil {
				return nil, dataInvalid()
			}
			d.Currency = extra.Settings.Currency
			d.DateFormat = extra.Settings.DateFormat
		}
		if q.Tool == inquiry.ListBudgets {
			if d.Name == nil {
				return nil, dataInvalid()
			}
			cf, err := currency(d.Currency)
			if err != nil {
				return nil, err
			}
			items = append(items, budgetSummary{ID: budget.BudgetID(d.ID), Name: *d.Name, CurrencyFormat: cf})
			continue
		}
		v, err := plan(d)
		if err != nil {
			return nil, err
		}
		items = append(items, v)
	}
	if q.Tool == inquiry.GetBudget && len(items) != 1 {
		return nil, notFound()
	}
	return items, nil
}
func (c *Client) readCurrency(ctx context.Context, s access.ReadScope) (budget.CurrencyFormat, error) {
	data, err := c.fetch(ctx, s, plansPath+"/"+string(s.BudgetID)+"/settings", nil)
	if err != nil {
		return budget.CurrencyFormat{}, err
	}
	if data.Settings == nil {
		return budget.CurrencyFormat{}, inquiry.ErrCurrencyMetadata
	}
	return currency(data.Settings.Currency)
}
func (c *Client) readFinancial(ctx context.Context, s access.ReadScope, q inquiry.Query, m *mapper, coverage *inquiry.Coverage) ([]any, error) {
	root := plansPath + "/" + string(s.BudgetID)
	switch q.Tool {
	case inquiry.ListAccounts:
		return c.accounts(ctx, s, q, m, root)
	case inquiry.ListCategories:
		return c.categories(ctx, s, q, m, root, coverage)
	case inquiry.GetMonth:
		d, err := c.fetch(ctx, s, root+"/months/"+string(q.Month), nil)
		if err != nil {
			return nil, err
		}
		if d.Month == nil || d.Month.Month != string(q.Month) {
			return nil, dataInvalid()
		}
		return []any{m.month(*d.Month)}, nil
	case inquiry.ListTransactions, inquiry.GetTransaction:
		return c.transactions(ctx, s, q, m, root, coverage)
	case inquiry.ListScheduledTransactions:
		return c.scheduled(ctx, s, q, m, root, coverage)
	}
	return nil, inquiry.ErrInvalidQuery
}
func (c *Client) accounts(ctx context.Context, s access.ReadScope, q inquiry.Query, m *mapper, root string) ([]any, error) {
	route := root + "/accounts"
	if q.AccountID != "" {
		route += "/" + string(q.AccountID)
	}
	d, err := c.fetch(ctx, s, route, nil)
	if err != nil {
		return nil, err
	}
	var list []accountDTO
	if q.AccountID != "" {
		if d.Account == nil || d.Account.ID != string(q.AccountID) {
			return nil, dataInvalid()
		}
		list = []accountDTO{*d.Account}
	} else {
		if d.Accounts == nil {
			return nil, dataInvalid()
		}
		list = *d.Accounts
	}
	sort.Slice(list, func(i, j int) bool { return list[i].ID < list[j].ID })
	out := []any{}
	seen := map[string]bool{}
	for _, a := range list {
		m.id(a.ID)
		if seen[a.ID] {
			m.invalid()
		}
		seen[a.ID] = true
		if a.Deleted {
			continue
		}
		v := m.account(a)
		if q.IncludeClosed || !v.Closed {
			out = append(out, v)
		}
	}
	return out, nil
}
func (c *Client) categories(ctx context.Context, s access.ReadScope, q inquiry.Query, m *mapper, root string, coverage *inquiry.Coverage) ([]any, error) {
	route := root
	if q.Month != "" {
		route += "/months/" + string(q.Month)
		if q.CategoryID != "" {
			route += "/categories/" + string(q.CategoryID)
		}
	} else {
		route += "/categories"
		if q.CategoryID != "" {
			route += "/" + string(q.CategoryID)
		}
	}
	d, err := c.fetch(ctx, s, route, nil)
	if err != nil {
		return nil, err
	}
	var items []categoryItem
	seen := map[string]bool{}
	add := func(c categoryDTO, g *budget.CategoryGroupView) {
		m.id(c.ID)
		if seen[c.ID] {
			m.invalid()
		}
		seen[c.ID] = true
		if c.Deleted {
			return
		}
		v := m.category(c, q.Month)
		v.Group = g
		items = append(items, v)
	}
	switch {
	case q.CategoryID != "":
		if d.Category == nil || d.Category.ID != string(q.CategoryID) {
			return nil, dataInvalid()
		}
		add(*d.Category, nil)
	case q.Month != "":
		if d.Month == nil || d.Month.Month != string(q.Month) || d.Month.Categories == nil {
			return nil, dataInvalid()
		}
		for _, c := range *d.Month.Categories {
			add(c, nil)
		}
	default:
		if d.CategoryGroups == nil {
			return nil, dataInvalid()
		}
		groups := map[string]bool{}
		for _, g := range *d.CategoryGroups {
			m.id(g.ID)
			if groups[g.ID] {
				m.invalid()
			}
			groups[g.ID] = true
			if g.Deleted {
				continue
			}
			if g.Categories == nil {
				return nil, dataInvalid()
			}
			group := budget.CategoryGroupView{BudgetID: s.BudgetID, ID: budget.CategoryGroupID(g.ID), Name: m.text(g.Name), Hidden: g.Hidden, Deleted: g.Deleted}
			for _, c := range *g.Categories {
				if c.GroupID != g.ID {
					m.invalid()
				}
				add(c, &group)
			}
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Category.ID < items[j].Category.ID })
	out := make([]any, 0, len(items))
	for _, v := range items {
		out = append(out, v)
	}
	if q.Month == "" {
		coverage.Warnings = append(coverage.Warnings, "Categories are the upstream-current view, not a historical month.")
	}
	return out, nil
}

type transactionItem struct {
	budget.TransactionView
	MatchingSplitIDs []budget.SubTransactionID `json:"matching_split_ids,omitempty"`
}

func (c *Client) transactions(ctx context.Context, s access.ReadScope, q inquiry.Query, m *mapper, root string, coverage *inquiry.Coverage) ([]any, error) {
	route := root + "/transactions"
	values := url.Values{}
	if q.Tool == inquiry.GetTransaction {
		route += "/" + string(q.TransactionID)
	} else {
		// Category endpoints can return hybrid split records. Fetch full parent
		// details from plan/account scope and apply category matching locally.
		if q.AccountID != "" {
			route = root + "/accounts/" + string(q.AccountID) + "/transactions"
		}
		values.Set("since_date", string(q.SinceDate))
		values.Set("until_date", string(q.UntilDate))
	}
	d, err := c.fetch(ctx, s, route, values)
	if err != nil {
		return nil, err
	}
	var list []transactionDTO
	if q.Tool == inquiry.GetTransaction {
		if d.Transaction == nil || d.Transaction.ID != string(q.TransactionID) {
			return nil, dataInvalid()
		}
		if d.Transaction.Deleted {
			return nil, notFound()
		}
		list = []transactionDTO{*d.Transaction}
	} else {
		if d.Transactions == nil {
			return nil, dataInvalid()
		}
		list = *d.Transactions
	}
	items := []transactionItem{}
	seen := map[string]bool{}
	for _, t := range list {
		m.id(t.ID)
		if seen[t.ID] {
			m.invalid()
		}
		seen[t.ID] = true
		if t.Deleted {
			continue
		}
		v := m.transaction(t)
		if q.Tool == inquiry.ListTransactions {
			if v.Date < q.SinceDate || v.Date > q.UntilDate {
				continue
			}
			if q.AccountID != "" && v.AccountID != q.AccountID {
				continue
			}
			switch q.Status {
			case "":
			case "approved":
				if !v.Approved {
					continue
				}
			case "unapproved":
				if v.Approved {
					continue
				}
			default:
				if v.Cleared.Value != q.Status {
					continue
				}
			}
		}
		item := transactionItem{TransactionView: v}
		if q.CategoryID != "" {
			matched, ids := v.MatchingCategory(q.CategoryID)
			if !matched {
				continue
			}
			item.MatchingSplitIDs = ids
		}
		items = append(items, item)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].Date != items[j].Date {
			return items[i].Date < items[j].Date
		}
		return items[i].ID < items[j].ID
	})
	disclosed := map[budget.TransactionID]bool{}
	for _, v := range items {
		disclosed[v.ID] = true
	}
	for _, v := range items {
		for _, id := range []*budget.TransactionID{v.TransferTransactionID, v.MatchedTransactionID} {
			if id != nil && !disclosed[*id] {
				coverage.UnresolvedReferenceCount++
			}
		}
		for _, split := range v.Splits {
			if split.TransferTransactionID != nil && !disclosed[*split.TransferTransactionID] {
				coverage.UnresolvedReferenceCount++
			}
		}
	}
	coverage.Warnings = append(coverage.Warnings, "Recorded transactions exclude pending transactions and do not prove bank settlement.")
	out := make([]any, 0, len(items))
	for _, v := range items {
		out = append(out, v)
	}
	return out, nil
}
func (c *Client) scheduled(ctx context.Context, s access.ReadScope, q inquiry.Query, m *mapper, root string, coverage *inquiry.Coverage) ([]any, error) {
	d, err := c.fetch(ctx, s, root+"/scheduled_transactions", nil)
	if err != nil {
		return nil, err
	}
	if d.ScheduledTransactions == nil {
		return nil, dataInvalid()
	}
	items := []budget.ScheduledTransactionView{}
	seen := map[string]bool{}
	for _, t := range *d.ScheduledTransactions {
		m.id(t.ID)
		if seen[t.ID] {
			m.invalid()
		}
		seen[t.ID] = true
		if t.Deleted {
			continue
		}
		v := m.scheduled(t)
		if q.AccountID != "" && v.AccountID != q.AccountID {
			continue
		}
		if q.SinceDate != "" && (v.DateNext < q.SinceDate || v.DateNext > q.UntilDate) {
			continue
		}
		items = append(items, v)
	}
	sort.Slice(items, func(i, j int) bool {
		if items[i].DateNext != items[j].DateNext {
			return items[i].DateNext < items[j].DateNext
		}
		return items[i].ID < items[j].ID
	})
	coverage.Warnings = append(coverage.Warnings, "Scheduled dates filter date_next only; recurrence is not expanded into a forecast.")
	out := make([]any, 0, len(items))
	for _, v := range items {
		out = append(out, v)
	}
	return out, nil
}
