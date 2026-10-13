package budget

import "time"

type BudgetView struct {
	ID             BudgetID       `json:"id"`
	Name           string         `json:"name"`
	CurrencyFormat CurrencyFormat `json:"currency_format"`
	DateFormat     string         `json:"date_format"`
	LastModified   *time.Time     `json:"last_modified,omitempty"`
}
type AccountView struct {
	BudgetID         BudgetID     `json:"budget_id"`
	ID               AccountID    `json:"id"`
	Name             string       `json:"name"`
	Type             EnumValue    `json:"type"`
	OnBudget         bool         `json:"on_budget"`
	Closed           bool         `json:"closed"`
	Balance          Money        `json:"balance"`
	ClearedBalance   Money        `json:"cleared_balance"`
	UnclearedBalance Money        `json:"uncleared_balance"`
	Note             OptionalText `json:"note"`
}
type CategoryGroupView struct {
	BudgetID BudgetID        `json:"budget_id"`
	ID       CategoryGroupID `json:"id"`
	Name     string          `json:"name"`
	Hidden   bool            `json:"hidden"`
	Deleted  bool            `json:"deleted"`
}
type CategoryView struct {
	BudgetID BudgetID        `json:"budget_id"`
	ID       CategoryID      `json:"id"`
	GroupID  CategoryGroupID `json:"group_id"`
	Name     string          `json:"name"`
	Hidden   bool            `json:"hidden"`
	Internal bool            `json:"internal"`
	Deleted  bool            `json:"deleted"`
	Note     OptionalText    `json:"note"`
}
type CategoryMonthView struct {
	BudgetID               BudgetID     `json:"budget_id"`
	Month                  *BudgetMonth `json:"month"`
	CurrentView            bool         `json:"upstream_current"`
	CategoryID             CategoryID   `json:"category_id"`
	Assigned               Money        `json:"assigned"`
	Activity               Money        `json:"activity"`
	Available              Money        `json:"available"`
	GoalType               *EnumValue   `json:"goal_type"`
	GoalAmount             *Money       `json:"goal_amount"`
	GoalTargetDate         *LocalDate   `json:"goal_target_date"`
	GoalCadence            *int         `json:"goal_cadence"`
	GoalPercentageComplete *int         `json:"goal_percentage_complete"`
}
type MonthView struct {
	BudgetID      BudgetID            `json:"budget_id"`
	Month         BudgetMonth         `json:"month"`
	Income        Money               `json:"income"`
	Assigned      Money               `json:"assigned"`
	Activity      Money               `json:"activity"`
	ReadyToAssign Money               `json:"ready_to_assign"`
	AgeOfMoney    *int                `json:"age_of_money"`
	Note          OptionalText        `json:"note"`
	Categories    []CategoryMonthView `json:"categories"`
}
type PayeeRef struct {
	BudgetID BudgetID `json:"budget_id"`
	ID       *PayeeID `json:"id"`
	Name     *string  `json:"name"`
}
type CategoryRef struct {
	BudgetID BudgetID    `json:"budget_id"`
	ID       *CategoryID `json:"id"`
	Name     *string     `json:"name"`
}
type TransactionView struct {
	BudgetID              BudgetID       `json:"budget_id"`
	ID                    TransactionID  `json:"id"`
	AccountID             AccountID      `json:"account_id"`
	Date                  LocalDate      `json:"date"`
	Amount                Money          `json:"amount"`
	Payee                 PayeeRef       `json:"payee"`
	Category              CategoryRef    `json:"category"`
	Cleared               EnumValue      `json:"cleared"`
	Approved              bool           `json:"approved"`
	TransferAccountID     *AccountID     `json:"transfer_account_id"`
	TransferTransactionID *TransactionID `json:"transfer_transaction_id"`
	MatchedTransactionID  *TransactionID `json:"matched_transaction_id"`
	Splits                []SplitView    `json:"splits"`
	Memo                  OptionalText   `json:"memo"`
}
type SplitView struct {
	BudgetID              BudgetID         `json:"budget_id"`
	ParentID              TransactionID    `json:"parent_id"`
	ID                    SubTransactionID `json:"id"`
	Amount                Money            `json:"amount"`
	Payee                 PayeeRef         `json:"payee"`
	Category              CategoryRef      `json:"category"`
	TransferAccountID     *AccountID       `json:"transfer_account_id"`
	TransferTransactionID *TransactionID   `json:"transfer_transaction_id"`
	Memo                  OptionalText     `json:"memo"`
}
type ScheduledTransactionView struct {
	BudgetID          BudgetID               `json:"budget_id"`
	ID                ScheduledTransactionID `json:"id"`
	AccountID         AccountID              `json:"account_id"`
	DateFirst         LocalDate              `json:"date_first"`
	DateNext          LocalDate              `json:"date_next"`
	Frequency         EnumValue              `json:"frequency"`
	Amount            Money                  `json:"amount"`
	Payee             PayeeRef               `json:"payee"`
	Category          CategoryRef            `json:"category"`
	TransferAccountID *AccountID             `json:"transfer_account_id"`
	Splits            []ScheduledSplitView   `json:"splits"`
	Memo              OptionalText           `json:"memo"`
}
type ScheduledSplitView struct {
	BudgetID          BudgetID               `json:"budget_id"`
	ParentID          ScheduledTransactionID `json:"parent_id"`
	ID                ScheduledSplitID       `json:"id"`
	Amount            Money                  `json:"amount"`
	Payee             PayeeRef               `json:"payee"`
	Category          CategoryRef            `json:"category"`
	TransferAccountID *AccountID             `json:"transfer_account_id"`
	Memo              OptionalText           `json:"memo"`
}

// AccountMovement returns the parent's signed movement. Split children allocate
// that movement and must never be added to it a second time. This is not spending.
func (t TransactionView) AccountMovement() Money { return t.Amount }

// MatchingCategory returns a parent once and identifies relevant allocations.
func (t TransactionView) MatchingCategory(id CategoryID) (bool, []SubTransactionID) {
	var matches []SubTransactionID
	for _, s := range t.Splits {
		if s.Category.ID != nil && *s.Category.ID == id {
			matches = append(matches, s.ID)
		}
	}
	return t.Category.ID != nil && *t.Category.ID == id || len(matches) > 0, matches
}
