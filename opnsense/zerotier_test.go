package opnsense

import (
	"net/http"
	"testing"
)

// zeroTierSearchFixture is source-derived from the plugin's Zerotier.xml
// model and NetworkController::searchAction UIModelGrid fields. The second
// row uses the PHP empty-array representation of an unset TextField.
const zeroTierSearchFixture = `{
	"total": 2,
	"rowCount": 2,
	"current": 1,
	"rows": [
		{"uuid":"network-uuid-1","enabled":"1","networkId":"8056c2e21c000001","description":"primary mesh"},
		{"uuid":"network-uuid-2","enabled":"0","networkId":"8056c2e21c000002","description":[]}
	]
}`

func TestFetchZeroTierNetworks_Populated(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	client.endpoints["zerotierNetworks"] = "api/zerotier/network/search"
	client.endpoints["zerotierNetworkInfo"] = "api/zerotier/network/info"

	mux.HandleFunc("/api/zerotier/network/search", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("search method = %s, want GET", r.Method)
		}
		_, _ = w.Write([]byte(zeroTierSearchFixture))
	})
	// The message is source-derived from ZeroTierOne's one.cpp
	// listnetworks formatter: nwid, name, MAC, status, type, device and the
	// comma-joined assignedAddresses field.
	mux.HandleFunc("/api/zerotier/network/info/network-uuid-1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("info method = %s, want GET", r.Method)
		}
		_, _ = w.Write([]byte(`{"title":"Information on network 8056c2e21c000001","message":" 8056c2e21c000001 primary-mesh 12:34:56:78:9a:bc OK PRIVATE ztmesh0 10.0.0.1/24,fd00::1/64\n    AUTH OK, expires in: 3600 seconds"}`))
	})
	mux.HandleFunc("/api/zerotier/network/info/network-uuid-2", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"title":"Information on network 8056c2e21c000002","message":"200 listnetworks 8056c2e21c000002 a-network-with-spaces 12:34:56:78:9a:bd NOT_FOUND PRIVATE - -"}`))
	})

	data, err := client.FetchZeroTierNetworks()
	if err != nil {
		t.Fatalf("FetchZeroTierNetworks returned error: %v", err)
	}
	if !data.Present || data.Total != 2 {
		t.Fatalf("unexpected envelope: %+v", data)
	}
	if len(data.Networks) != 2 {
		t.Fatalf("got %d networks, want 2: %+v", len(data.Networks), data.Networks)
	}

	first := data.Networks[0]
	if first.UUID != "network-uuid-1" || first.NetworkID != "8056c2e21c000001" || !first.Enabled {
		t.Errorf("unexpected first configured network: %+v", first)
	}
	if !first.HasStatus || first.Status != "OK" {
		t.Errorf("first network status = (%q, %v), want (OK, true)", first.Status, first.HasStatus)
	}
	if !first.HasAssignedAddresses || first.AssignedAddresses != 2 {
		t.Errorf("first assigned addresses = (%d, %v), want (2, true)", first.AssignedAddresses, first.HasAssignedAddresses)
	}

	second := data.Networks[1]
	if second.Description != "" || second.Enabled {
		t.Errorf("expected empty description and disabled second network: %+v", second)
	}
	if !second.HasStatus || second.Status != "NOT_FOUND" {
		t.Errorf("second network status = (%q, %v), want (NOT_FOUND, true)", second.Status, second.HasStatus)
	}
	if !second.HasAssignedAddresses || second.AssignedAddresses != 0 {
		t.Errorf("second assigned addresses = (%d, %v), want (0, true)", second.AssignedAddresses, second.HasAssignedAddresses)
	}
}

func TestFetchZeroTierNetworks_PluginAbsent(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	client.endpoints["zerotierNetworks"] = "api/zerotier/network/search"
	client.endpoints["zerotierNetworkInfo"] = "api/zerotier/network/info"
	infoCalls := 0

	mux.HandleFunc("/api/zerotier/network/search", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/api/zerotier/network/info/network-uuid-1", func(w http.ResponseWriter, r *http.Request) {
		infoCalls++
		w.WriteHeader(http.StatusInternalServerError)
	})

	data, err := client.FetchZeroTierNetworks()
	if err != nil {
		t.Fatalf("expected nil error for absent plugin, got %v", err)
	}
	if data.Present || data.Total != 0 || len(data.Networks) != 0 {
		t.Errorf("expected empty absent-plugin result, got %+v", data)
	}
	if infoCalls != 0 {
		t.Errorf("info endpoint called %d times after search 404, want 0", infoCalls)
	}
}

func TestFetchZeroTierNetworks_EmptyButPresent(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	client.endpoints["zerotierNetworks"] = "api/zerotier/network/search"
	client.endpoints["zerotierNetworkInfo"] = "api/zerotier/network/info"
	mux.HandleFunc("/api/zerotier/network/search", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})

	data, err := client.FetchZeroTierNetworks()
	if err != nil {
		t.Fatalf("FetchZeroTierNetworks returned error: %v", err)
	}
	if !data.Present || data.Total != 0 || len(data.Networks) != 0 {
		t.Errorf("expected present empty result, got %+v", data)
	}
}

func TestFetchZeroTierNetworks_DeduplicatesNetworkID(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	client.endpoints["zerotierNetworks"] = "api/zerotier/network/search"
	client.endpoints["zerotierNetworkInfo"] = "api/zerotier/network/info"
	mux.HandleFunc("/api/zerotier/network/search", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"total":2,"rowCount":2,"current":1,"rows":[{"uuid":"u1","enabled":"1","networkId":"8056c2e21c000001","description":"first"},{"uuid":"u2","enabled":"0","networkId":"8056C2E21C000001","description":"duplicate"}]}`))
	})
	mux.HandleFunc("/api/zerotier/network/info/u1", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"message":"8056c2e21c000001 net 12:34:56:78:9a:bc OK PRIVATE zt0 -"}`))
	})

	data, err := client.FetchZeroTierNetworks()
	if err != nil {
		t.Fatalf("FetchZeroTierNetworks returned error: %v", err)
	}
	if len(data.Networks) != 1 {
		t.Fatalf("got %d networks after duplicate suppression, want 1: %+v", len(data.Networks), data.Networks)
	}
}

func TestParseZeroTierNetworkInfo(t *testing.T) {
	tests := []struct {
		name       string
		message    string
		networkID  string
		wantFound  bool
		wantStatus string
		wantHasSt  bool
		wantAddrs  int
		wantHasAdr bool
	}{
		{
			name:       "controller segment",
			message:    " 8056c2e21c000001 primary-mesh 12:34:56:78:9a:bc OK PRIVATE zt0 10.0.0.2/24,fd00::2/64",
			networkID:  "8056c2e21c000001",
			wantFound:  true,
			wantStatus: "OK",
			wantHasSt:  true,
			wantAddrs:  2,
			wantHasAdr: true,
		},
		{
			name:       "complete line and spaced name",
			message:    "200 listnetworks 8056c2e21c000002 primary mesh 12:34:56:78:9a:bd AUTHENTICATION_REQUIRED PRIVATE zt1 -",
			networkID:  "8056c2e21c000002",
			wantFound:  true,
			wantStatus: "AUTHENTICATION_REQUIRED",
			wantHasSt:  true,
			wantAddrs:  0,
			wantHasAdr: true,
		},
		{
			name:      "unrelated network",
			message:   "8056c2e21c000099 other 12:34:56:78:9a:bf OK PRIVATE zt2 10.0.0.9/24",
			networkID: "8056c2e21c000001",
			wantFound: false,
		},
		{
			name:      "daemon failure text",
			message:   "Unable to obtain Zerotier information for 8056c2e21c000001! Is the network enabled?",
			networkID: "8056c2e21c000001",
			wantFound: false,
		},
		{
			name:       "unknown status",
			message:    "8056c2e21c000003 future network name 12:34:56:78:9a:c0 FUTURE_STATE PRIVATE zt3 10.0.0.3/24",
			networkID:  "8056c2e21c000003",
			wantFound:  true,
			wantStatus: "unknown",
			wantHasSt:  true,
			wantAddrs:  1,
			wantHasAdr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, found := parseZeroTierNetworkInfo(tt.message, tt.networkID)
			if found != tt.wantFound {
				t.Fatalf("found = %v, want %v; got %+v", found, tt.wantFound, got)
			}
			if !tt.wantFound {
				return
			}
			if got.Status != tt.wantStatus || got.HasStatus != tt.wantHasSt {
				t.Errorf("status = (%q, %v), want (%q, %v)", got.Status, got.HasStatus, tt.wantStatus, tt.wantHasSt)
			}
			if got.AssignedAddresses != tt.wantAddrs || got.HasAssignedAddresses != tt.wantHasAdr {
				t.Errorf("addresses = (%d, %v), want (%d, %v)", got.AssignedAddresses, got.HasAssignedAddresses, tt.wantAddrs, tt.wantHasAdr)
			}
		})
	}
}

func TestCanonicalizeZeroTierNetworkStatus(t *testing.T) {
	for raw, want := range map[string]string{
		"REQUESTING_CONFIGURATION": "REQUESTING_CONFIGURATION",
		"ok":                       "OK",
		"ACCESS_DENIED":            "ACCESS_DENIED",
		"NOT_FOUND":                "NOT_FOUND",
		"PORT_ERROR":               "PORT_ERROR",
		"CLIENT_TOO_OLD":           "CLIENT_TOO_OLD",
		"AUTHENTICATION_REQUIRED":  "AUTHENTICATION_REQUIRED",
		"future":                   "unknown",
	} {
		got, ok := canonicalizeZeroTierNetworkStatus(raw)
		if !ok || got != want {
			t.Errorf("canonicalizeZeroTierNetworkStatus(%q) = (%q, %v), want (%q, true)", raw, got, ok, want)
		}
	}
	for _, raw := range []string{"", "   ", "-"} {
		if got, ok := canonicalizeZeroTierNetworkStatus(raw); ok || got != "" {
			t.Errorf("canonicalizeZeroTierNetworkStatus(%q) = (%q, %v), want (\"\", false)", raw, got, ok)
		}
	}
}
