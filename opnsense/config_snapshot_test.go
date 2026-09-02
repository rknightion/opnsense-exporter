package opnsense

import (
	"net/http"
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
