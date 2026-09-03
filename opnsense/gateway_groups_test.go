package opnsense

import (
	"net/http"
	"testing"
)

const gatewayGroupsFixture = `{
  "total": 2,
  "rowCount": 2,
  "current": 1,
  "rows": [
    {
      "uuid": "group-uuid-a",
      "name": "WAN_FAILOVER",
      "item": "WAN_GW",
      "%item": "WAN Gateway",
      "item2": "LTE_GW, BACKUP_GW",
      "%item2": "LTE Gateway, Backup Gateway",
      "item3": "",
      "item4": "",
      "item5": "",
      "trigger": "downloss",
      "poolopts": "round-robin",
      "descr": "WAN failover",
      "gateways": {
        "1": [
          {"name":"WAN_GW","address":"10.0.0.1","status":"none","loss":"0.0 %","delay":"1.0 ms","stddev":"0.1 ms","monitor":"10.0.0.2","status_translated":"Online","label":"success"}
        ],
        "2": [
          {"name":"LTE_GW","address":"10.0.0.3","status":"loss","loss":"12.0 %","delay":"2.0 ms","stddev":"0.2 ms","monitor":"10.0.0.4","status_translated":"Packetloss","label":"warning"},
          {"name":"BACKUP_GW","status_translated":"Disabled or inactive","label":"danger"},
          {"name":"BACKUP_GW","status_translated":"Disabled or inactive","label":"danger"}
        ],
        "3": [], "4": [], "5": []
      }
    },
    {
      "uuid": "group-uuid-b",
      "name": "VPN_POLICY",
      "item": "VPN_GW",
      "item2": "",
      "item3": "",
      "item4": "",
      "item5": "",
      "trigger": "down",
      "poolopts": "",
      "descr": "VPN policy route",
      "gateways": {"1": [{"name":"VPN_GW","address":"10.0.0.5","status":"none","loss":"~","delay":"~","stddev":"~","monitor":"~","status_translated":"Online","label":"default"}]}
    }
  ]
}`

func TestFetchGatewayGroups_Populated(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	client.endpoints["gatewayGroups"] = "api/routing/group_settings/search"

	mux.HandleFunc("/api/routing/group_settings/search", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("method = %s, want GET", r.Method)
		}
		if r.URL.RawQuery != "" {
			t.Errorf("query = %q, want empty", r.URL.RawQuery)
		}
		_, _ = w.Write([]byte(gatewayGroupsFixture))
	})

	data, err := client.FetchGatewayGroups()
	if err != nil {
		t.Fatalf("FetchGatewayGroups: %v", err)
	}
	if !data.Present {
		t.Fatal("Present = false, want true")
	}
	if data.Total != 2 || data.RowCount != 2 || data.Current != 1 {
		t.Errorf("envelope = total %d rowCount %d current %d, want 2/2/1", data.Total, data.RowCount, data.Current)
	}
	if len(data.Groups) != 2 {
		t.Fatalf("groups = %d, want 2", len(data.Groups))
	}

	group := data.Groups[0]
	if group.Name != "WAN_FAILOVER" || group.Description != "WAN failover" || group.Trigger != "downloss" || group.PoolOpts != "round-robin" {
		t.Errorf("group metadata = %+v", group)
	}
	if got := group.ConfiguredTiers[2]; len(got) != 2 || got[0] != "LTE_GW" || got[1] != "BACKUP_GW" {
		t.Errorf("configured tier 2 = %#v, want [LTE_GW BACKUP_GW]", got)
	}
	if group.ConfiguredTierDescriptions[1] != "WAN Gateway" || group.ConfiguredTierDescriptions[2] != "LTE Gateway, Backup Gateway" {
		t.Errorf("tier descriptions = %#v", group.ConfiguredTierDescriptions)
	}

	// The duplicate BACKUP_GW row is removed at the API normalization boundary,
	// while the member with no address remains (the source uses that shape for
	// disabled/inactive gateways).
	if len(group.Members) != 3 {
		t.Fatalf("members = %d, want 3, got %#v", len(group.Members), group.Members)
	}
	if got := group.Members[0]; got.Tier != 1 || got.Name != "WAN_GW" || got.Address != "10.0.0.1" || got.Status != "none" {
		t.Errorf("tier 1 member = %+v", got)
	}
	if got := group.Members[1]; got.Tier != 2 || got.Name != "LTE_GW" || got.Status != "loss" || got.Label != "warning" {
		t.Errorf("tier 2 member 1 = %+v", got)
	}
	if got := group.Members[2]; got.Tier != 2 || got.Name != "BACKUP_GW" || got.Address != "" || got.StatusTranslated != "Disabled or inactive" {
		t.Errorf("tier 2 member 2 = %+v", got)
	}
}

func TestFetchGatewayGroups_Empty(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	client.endpoints["gatewayGroups"] = "api/routing/group_settings/search"
	mux.HandleFunc("/api/routing/group_settings/search", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})

	data, err := client.FetchGatewayGroups()
	if err != nil {
		t.Fatalf("FetchGatewayGroups: %v", err)
	}
	if !data.Present {
		t.Fatal("Present = false, want true for successful empty response")
	}
	if len(data.Groups) != 0 {
		t.Errorf("groups = %#v, want empty", data.Groups)
	}
}

func TestFetchGatewayGroups_NotFoundIsFeatureAbsent(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	client.endpoints["gatewayGroups"] = "api/routing/group_settings/search"
	mux.HandleFunc("/api/routing/group_settings/search", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errorMessage":"Endpoint not found"}`))
	})

	data, err := client.FetchGatewayGroups()
	if err != nil {
		t.Fatalf("expected nil error on feature-absent 404, got %v", err)
	}
	if data.Present || len(data.Groups) != 0 {
		t.Errorf("feature-absent result = %+v, want zero value", data)
	}
}

func TestFetchGatewayGroups_ServerErrorPropagates(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	client.endpoints["gatewayGroups"] = "api/routing/group_settings/search"
	mux.HandleFunc("/api/routing/group_settings/search", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})

	_, err := client.FetchGatewayGroups()
	if err == nil || err.StatusCode != http.StatusInternalServerError {
		t.Fatalf("FetchGatewayGroups error = %v, want HTTP 500", err)
	}
}
