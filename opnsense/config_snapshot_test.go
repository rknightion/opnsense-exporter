package opnsense

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestFetchFirewallConfigSnapshotsProjectsStableUpstreamRows(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/firewall/filter/search_rule":
			if r.Method != http.MethodPost {
				t.Errorf("filter search method = %s, want POST", r.Method)
			}
			_, _ = w.Write([]byte(`{"rows":[{"uuid":"filter-a","description":"allow","password":"not-exported"}]}`))
		case "/api/firewall/source_nat/search_rule":
			_, _ = w.Write([]byte(`{"rows":[{"uuid":"nat-source-a","enabled":"1"}]}`))
		case "/api/firewall/d_nat/search_rule":
			_, _ = w.Write([]byte(`{"rows":[{"uuid":"nat-dest-a","disabled":"0"}]}`))
		case "/api/firewall/one_to_one/search_rule":
			_, _ = w.Write([]byte(`{"rows":[{"uuid":"nat-one-a","enabled":"1"}]}`))
		case "/api/firewall/npt/search_rule":
			_, _ = w.Write([]byte(`{"rows":[{"uuid":"nat-npt-a","enabled":"1"}]}`))
		default:
			// t.FailNow (and so t.Fatalf) is only defined on the goroutine
			// running the test. This handler runs on an httptest server
			// goroutine, so it records the failure and answers the request
			// instead, letting the client return a normal error.
			t.Errorf("unexpected path %s", r.URL.Path)
			http.Error(w, "unexpected path", http.StatusNotFound)
		}
	})
	defer server.Close()

	entities, err := client.FetchFirewallConfigSnapshots()
	if err != nil {
		t.Fatalf("FetchFirewallConfigSnapshots: %v", err)
	}
	if len(entities) != 5 {
		t.Fatalf("entity count = %d, want 5", len(entities))
	}
	for _, entity := range entities {
		if entity.ID == "" || entity.Kind == "" {
			t.Errorf("entity has no stable kind/id: %+v", entity)
		}
		if _, found := entity.Config["password"]; found {
			t.Errorf("entity %s leaked a sensitive password field", entity.ID)
		}
	}
}

func TestFetchFirewallConfigSnapshotsPreservesRepeatedGeneratedFilterRows(t *testing.T) {
	// FilterController::searchRuleAction merges the non-MVC rows emitted by
	// scripts/filter/list_non_mvc_rules.php into the MVC rows. That producer
	// maps a generated PF label to uuid, while emitting every rule with its own
	// sort_order. The producer maps its source descr field to response
	// description. Util::calcRuleHash, called by Plugin, excludes descr, so
	// these two generated rows are a source-valid repeated-uuid shape on
	// stable/26.7 and stable/26.1.
	const filterRowsForward = `[
		{"uuid":"generated-rule","legacy":true,"is_automatic":true,"enabled":"1","description":"generated first","sort_order":"000100.1000001"},
		{"uuid":"generated-rule","legacy":true,"is_automatic":true,"enabled":"1","description":"generated second","sort_order":"000100.1000002"}
	]`
	const filterRowsReverse = `[
		{"uuid":"generated-rule","legacy":true,"is_automatic":true,"enabled":"1","description":"generated second","sort_order":"000100.1000002"},
		{"uuid":"generated-rule","legacy":true,"is_automatic":true,"enabled":"1","description":"generated first","sort_order":"000100.1000001"}
	]`

	fetch := func(filterRows string) []ConfigSnapshotEntity {
		t.Helper()
		server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/firewall/filter/search_rule":
				_, _ = w.Write([]byte(`{"rows":` + filterRows + `}`))
			case "/api/firewall/source_nat/search_rule":
				_, _ = w.Write([]byte(`{"rows":[{"uuid":"nat-source-a","enabled":"1"}]}`))
			case "/api/firewall/d_nat/search_rule":
				_, _ = w.Write([]byte(`{"rows":[{"uuid":"nat-dest-a","disabled":"0"}]}`))
			case "/api/firewall/one_to_one/search_rule":
				_, _ = w.Write([]byte(`{"rows":[{"uuid":"nat-one-a","enabled":"1"}]}`))
			case "/api/firewall/npt/search_rule":
				_, _ = w.Write([]byte(`{"rows":[{"uuid":"nat-npt-a","enabled":"1"}]}`))
			default:
				t.Errorf("unexpected path %s", r.URL.Path)
				http.Error(w, "unexpected path", http.StatusNotFound)
			}
		})
		defer server.Close()

		entities, err := client.FetchFirewallConfigSnapshots()
		if err != nil {
			t.Fatalf("FetchFirewallConfigSnapshots: %v", err)
		}
		return entities
	}

	first := fetch(filterRowsForward)
	second := fetch(filterRowsReverse)

	if len(first) != 6 || len(second) != 6 {
		t.Fatalf("entity counts = %d and %d, want 6 in both snapshots", len(first), len(second))
	}

	firstByDescription := make(map[string]ConfigSnapshotEntity)
	secondByDescription := make(map[string]ConfigSnapshotEntity)
	for _, entity := range first {
		if entity.Kind == "filter_rule" {
			description, ok := entity.Config["description"].(string)
			if !ok {
				t.Fatalf("filter entity %q has no response description", entity.ID)
			}
			firstByDescription[description] = entity
		}
	}
	for _, entity := range second {
		if entity.Kind == "filter_rule" {
			description, ok := entity.Config["description"].(string)
			if !ok {
				t.Fatalf("reversed filter entity %q has no response description", entity.ID)
			}
			secondByDescription[description] = entity
		}
	}
	if len(firstByDescription) != 2 || len(secondByDescription) != 2 {
		t.Fatalf("filter rows by description = %d and %d, want 2 in both snapshots", len(firstByDescription), len(secondByDescription))
	}
	firstRow, firstOK := firstByDescription["generated first"]
	secondRow, secondOK := firstByDescription["generated second"]
	if !firstOK || !secondOK {
		t.Fatalf("filter descriptions = %v, want both generated rows", firstByDescription)
	}
	if firstRow.ID == secondRow.ID {
		t.Fatalf("repeated filter rows share ID %q", firstRow.ID)
	}
	for description, entity := range firstByDescription {
		reversed, ok := secondByDescription[description]
		if !ok {
			t.Fatalf("reversed snapshot lost filter row %q", description)
		}
		if entity.ID == "generated-rule" {
			t.Fatalf("repeated filter row %q kept the colliding raw UUID", description)
		}
		sortOrder, ok := entity.Config["sort_order"].(string)
		if !ok || !strings.HasSuffix(entity.ID, configSnapshotDuplicateIDDelimiter+sortOrder) {
			t.Errorf("filter row %q ID = %q, want sort_order discriminator %q", description, entity.ID, sortOrder)
		}
		if reversed.ID != entity.ID {
			t.Errorf("filter row %q ID after response reversal = %q, want %q", description, reversed.ID, entity.ID)
		}
		if got := entity.Config["uuid"]; got != "generated-rule" {
			t.Errorf("filter row %q retained uuid = %v, want generated-rule", description, got)
		}
		if got := entity.Config["legacy"]; got != true {
			t.Errorf("filter row %q retained legacy = %v, want true", description, got)
		}
		if got := entity.Config["is_automatic"]; got != true {
			t.Errorf("filter row %q retained is_automatic = %v, want true", description, got)
		}
		if got, ok := entity.Config["sort_order"].(string); !ok || strings.TrimSpace(got) == "" {
			t.Errorf("filter row %q retained sort_order = %v, want nonempty string", description, entity.Config["sort_order"])
		}
	}

	natPresent := false
	for _, entity := range first {
		if entity.Kind == "source_nat" && entity.ID == "nat-source-a" {
			natPresent = true
			break
		}
	}
	if !natPresent {
		t.Fatal("source NAT entity was lost while preserving repeated filter rows")
	}
}

func TestConfigSnapshotRowsRejectsRepeatedFilterUUIDWithoutSortOrder(t *testing.T) {
	// The upstream non-MVC producer always supplies sort_order; this malformed
	// row is synthetic to pin fail-closed handling if that discriminator is lost.
	rows := []json.RawMessage{
		json.RawMessage(`{"uuid":"generated-rule","legacy":true,"is_automatic":true,"enabled":"1","description":"generated first","sort_order":"000100.1000001"}`),
		json.RawMessage(`{"uuid":"generated-rule","legacy":true,"is_automatic":true,"enabled":"1","description":"generated second"}`),
	}

	_, err := configSnapshotRows("filter_rule", rows)
	if err == nil {
		t.Fatal("configSnapshotRows accepted a repeated filter UUID without sort_order")
	}
	if !strings.Contains(err.Error(), "sort_order") {
		t.Fatalf("configSnapshotRows error = %v, want sort_order diagnostic", err)
	}
}

func TestRedactConfigSnapshotFieldsRemovesNestedCamelCaseSecrets(t *testing.T) {
	config := map[string]any{
		"privateKey": "top-private",
		"apiKey":     "top-api",
		"safe":       "keep",
		"nested": map[string]any{
			"clientSecret": "nested-secret",
			"publicKey":    "keep-public",
		},
		"items": []any{
			map[string]any{"accessToken": "nested-token", "name": "keep-name"},
		},
	}

	redactConfigSnapshotFields(config)

	if _, found := config["privateKey"]; found {
		t.Error("top-level privateKey was not redacted")
	}
	if _, found := config["apiKey"]; found {
		t.Error("top-level apiKey was not redacted")
	}
	nested := config["nested"].(map[string]any)
	if _, found := nested["clientSecret"]; found {
		t.Error("nested clientSecret was not redacted")
	}
	if got := nested["publicKey"]; got != "keep-public" {
		t.Errorf("non-sensitive publicKey = %v, want keep-public", got)
	}
	item := config["items"].([]any)[0].(map[string]any)
	if _, found := item["accessToken"]; found {
		t.Error("slice-nested accessToken was not redacted")
	}
	if got := item["name"]; got != "keep-name" {
		t.Errorf("non-sensitive name = %v, want keep-name", got)
	}
}

func TestSensitiveConfigKey(t *testing.T) {
	cases := []struct {
		key  string
		want bool
	}{
		{key: "password", want: true},
		{key: "key", want: true},
		{key: "dns_cf_key", want: true},
		{key: "keyexpiry", want: false},
		{key: "monkey", want: false},
		{key: "apiKey", want: true},
		{key: "otp_seed", want: true},
		{key: "ldap_bindpw", want: true},
		{key: "enckey", want: true},
		{key: "community", want: true},
		{key: "prvPayload", want: true},
		{key: "community_id", want: false},
		{key: "community_name", want: false},
		{key: "remoteCommunity", want: false},
	}

	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			if got := SensitiveConfigKey(tc.key); got != tc.want {
				t.Errorf("SensitiveConfigKey(%q) = %t, want %t", tc.key, got, tc.want)
			}
		})
	}
}
