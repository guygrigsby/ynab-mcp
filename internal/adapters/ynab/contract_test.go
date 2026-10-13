package ynab

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"reflect"
	"strings"
	"testing"
)

// The projection manifest pins the reviewed upstream spec and a small original
// inventory of source facts, not generated SDK code or an entire upstream spec.
// To review drift: fetch the source, compare SHA-256, review these read paths and
// schema fields, and update the manifest plus synthetic fixtures together.
func TestProjectionFieldsMatchPinnedReadContract(t *testing.T) {
	b, err := os.ReadFile("testdata/read-contract.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract struct {
		Source     string              `json:"source"`
		SHA        string              `json:"source_sha256"`
		Origin     string              `json:"origin"`
		Base       string              `json:"base_path"`
		ReadPaths  []string            `json:"read_paths"`
		Properties map[string][]string `json:"schema_properties"`
	}
	if err = json.Unmarshal(b, &contract); err != nil {
		t.Fatal(err)
	}
	hash, err := hex.DecodeString(contract.SHA)
	if err != nil || len(hash) != 32 {
		t.Fatal("missing reviewed spec hash")
	}
	if contract.Source != "https://api.ynab.com/papi/open_api_spec.yaml" || contract.Origin != apiOrigin || contract.Base+"/plans" != plansPath {
		t.Fatal("upstream origin drift")
	}
	for _, p := range contract.ReadPaths {
		if p != "/plans" && !strings.HasPrefix(p, "/plans/") {
			t.Fatalf("unexpected path %s", p)
		}
	}
	for _, tt := range []struct {
		schema string
		dto    any
	}{{"PlanSummary", planDTO{}}, {"PlanSettings", settingsDTO{}}, {"CurrencyFormat", currencyDTO{}}, {"DateFormat", dateFormatDTO{}}, {"Account", accountDTO{}}, {"CategoryGroupWithCategories", categoryGroupDTO{}}, {"Category", categoryDTO{}}, {"MonthDetail", monthDTO{}}, {"TransactionDetail", transactionDTO{}}, {"SubTransaction", splitDTO{}}, {"ScheduledTransactionDetail", scheduledDTO{}}, {"ScheduledSubTransaction", scheduledSplitDTO{}}} {
		t.Run(tt.schema, func(t *testing.T) {
			allowed := map[string]bool{}
			for _, v := range contract.Properties[tt.schema] {
				allowed[v] = true
			}
			typ := reflect.TypeOf(tt.dto)
			for i := 0; i < typ.NumField(); i++ {
				name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
				if !allowed[name] {
					t.Errorf("DTO field %s not in pinned %s schema", name, tt.schema)
				}
			}
		})
	}
}
