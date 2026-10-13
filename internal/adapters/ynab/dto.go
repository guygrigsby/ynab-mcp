package ynab

import "encoding/json"

// Private upstream DTOs intentionally omit formatted-money fields, bank import
// identifiers, original payee text, URLs, and other non-contract fields.
type responseDTO struct {
	Data *responseData `json:"data"`
}
type responseData struct {
	Plans                 *[]planDTO          `json:"plans"`
	Plan                  *planDTO            `json:"plan"`
	Settings              *settingsDTO        `json:"settings"`
	Accounts              *[]accountDTO       `json:"accounts"`
	Account               *accountDTO         `json:"account"`
	CategoryGroups        *[]categoryGroupDTO `json:"category_groups"`
	Category              *categoryDTO        `json:"category"`
	Month                 *monthDTO           `json:"month"`
	Transactions          *[]transactionDTO   `json:"transactions"`
	Transaction           *transactionDTO     `json:"transaction"`
	ScheduledTransactions *[]scheduledDTO     `json:"scheduled_transactions"`
}
type currencyDTO struct {
	ISOCode          string  `json:"iso_code"`
	DecimalDigits    *int    `json:"decimal_digits"`
	DecimalSeparator *string `json:"decimal_separator"`
	GroupSeparator   *string `json:"group_separator"`
	CurrencySymbol   *string `json:"currency_symbol"`
	SymbolFirst      *bool   `json:"symbol_first"`
	DisplaySymbol    *bool   `json:"display_symbol"`
}
type dateFormatDTO struct {
	Format string `json:"format"`
}
type settingsDTO struct {
	Currency   *currencyDTO   `json:"currency_format"`
	DateFormat *dateFormatDTO `json:"date_format"`
}
type planDTO struct {
	ID           string         `json:"id"`
	Name         *string        `json:"name"`
	Currency     *currencyDTO   `json:"currency_format"`
	DateFormat   *dateFormatDTO `json:"date_format"`
	LastModified *string        `json:"last_modified_on"`
}
type accountDTO struct {
	ID        string          `json:"id"`
	Name      *string         `json:"name"`
	Type      string          `json:"type"`
	OnBudget  *bool           `json:"on_budget"`
	Closed    *bool           `json:"closed"`
	Deleted   bool            `json:"deleted"`
	Balance   *int64          `json:"balance"`
	Cleared   *int64          `json:"cleared_balance"`
	Uncleared *int64          `json:"uncleared_balance"`
	Note      json.RawMessage `json:"note"`
}
type categoryGroupDTO struct {
	ID         string         `json:"id"`
	Name       *string        `json:"name"`
	Hidden     bool           `json:"hidden"`
	Deleted    bool           `json:"deleted"`
	Categories *[]categoryDTO `json:"categories"`
}
type categoryDTO struct {
	ID                     string          `json:"id"`
	GroupID                string          `json:"category_group_id"`
	Name                   *string         `json:"name"`
	Hidden                 bool            `json:"hidden"`
	Deleted                bool            `json:"deleted"`
	Internal               bool            `json:"internal"`
	Note                   json.RawMessage `json:"note"`
	Assigned               *int64          `json:"budgeted"`
	Activity               *int64          `json:"activity"`
	Available              *int64          `json:"balance"`
	GoalType               *string         `json:"goal_type"`
	GoalAmount             *int64          `json:"goal_target"`
	GoalTargetDate         *string         `json:"goal_target_date"`
	GoalCadence            *int            `json:"goal_cadence"`
	GoalPercentageComplete *int            `json:"goal_percentage_complete"`
}
type monthDTO struct {
	Month         string          `json:"month"`
	Income        *int64          `json:"income"`
	Assigned      *int64          `json:"budgeted"`
	Activity      *int64          `json:"activity"`
	ReadyToAssign *int64          `json:"to_be_budgeted"`
	AgeOfMoney    *int            `json:"age_of_money"`
	Note          json.RawMessage `json:"note"`
	Categories    *[]categoryDTO  `json:"categories"`
}
type transactionDTO struct {
	ID                    string          `json:"id"`
	AccountID             string          `json:"account_id"`
	Date                  string          `json:"date"`
	Amount                *int64          `json:"amount"`
	PayeeID               *string         `json:"payee_id"`
	PayeeName             *string         `json:"payee_name"`
	CategoryID            *string         `json:"category_id"`
	CategoryName          *string         `json:"category_name"`
	Cleared               string          `json:"cleared"`
	Approved              *bool           `json:"approved"`
	TransferAccountID     *string         `json:"transfer_account_id"`
	TransferTransactionID *string         `json:"transfer_transaction_id"`
	MatchedTransactionID  *string         `json:"matched_transaction_id"`
	Subtransactions       *[]splitDTO     `json:"subtransactions"`
	Memo                  json.RawMessage `json:"memo"`
	Deleted               bool            `json:"deleted"`
}
type splitDTO struct {
	ID                    string          `json:"id"`
	ParentID              string          `json:"transaction_id"`
	Amount                *int64          `json:"amount"`
	PayeeID               *string         `json:"payee_id"`
	PayeeName             *string         `json:"payee_name"`
	CategoryID            *string         `json:"category_id"`
	CategoryName          *string         `json:"category_name"`
	TransferAccountID     *string         `json:"transfer_account_id"`
	TransferTransactionID *string         `json:"transfer_transaction_id"`
	Memo                  json.RawMessage `json:"memo"`
	Deleted               bool            `json:"deleted"`
}
type scheduledDTO struct {
	ID                string               `json:"id"`
	AccountID         string               `json:"account_id"`
	DateFirst         string               `json:"date_first"`
	DateNext          string               `json:"date_next"`
	Frequency         string               `json:"frequency"`
	Amount            *int64               `json:"amount"`
	PayeeID           *string              `json:"payee_id"`
	PayeeName         *string              `json:"payee_name"`
	CategoryID        *string              `json:"category_id"`
	CategoryName      *string              `json:"category_name"`
	TransferAccountID *string              `json:"transfer_account_id"`
	Subtransactions   *[]scheduledSplitDTO `json:"subtransactions"`
	Memo              json.RawMessage      `json:"memo"`
	Deleted           bool                 `json:"deleted"`
}
type scheduledSplitDTO struct {
	ID                string          `json:"id"`
	ParentID          string          `json:"scheduled_transaction_id"`
	Amount            *int64          `json:"amount"`
	PayeeID           *string         `json:"payee_id"`
	PayeeName         *string         `json:"payee_name"`
	CategoryID        *string         `json:"category_id"`
	CategoryName      *string         `json:"category_name"`
	TransferAccountID *string         `json:"transfer_account_id"`
	Memo              json.RawMessage `json:"memo"`
	Deleted           bool            `json:"deleted"`
}
