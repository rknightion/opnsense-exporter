package opnsense

import (
	"net/http"
	"os"
	"path/filepath"
	"testing"
)

func readKeaReservationFixture(t *testing.T, name string) []byte {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", "kea_reservations", name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return body
}

func TestFetchKeaReservations_Empty(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	client.endpoints["keaReservations4"] = "api/kea/dhcpv4/searchReservation"
	client.endpoints["keaReservations6"] = "api/kea/dhcpv6/searchReservation"

	mux.HandleFunc("/api/kea/dhcpv4/searchReservation", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("DHCPv4 request method = %s, want GET", r.Method)
		}
		if r.URL.RawQuery != "" {
			t.Errorf("DHCPv4 request query = %q, want none so UIModelGrid returns all rows", r.URL.RawQuery)
		}
		_, _ = w.Write(readKeaReservationFixture(t, "search_reservation4_empty.json"))
	})
	mux.HandleFunc("/api/kea/dhcpv6/searchReservation", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("DHCPv6 request method = %s, want GET", r.Method)
		}
		if r.URL.RawQuery != "" {
			t.Errorf("DHCPv6 request query = %q, want none so UIModelGrid returns all rows", r.URL.RawQuery)
		}
		_, _ = w.Write(readKeaReservationFixture(t, "search_reservation6_empty.json"))
	})

	for _, fetch := range []struct {
		name string
		fn   func() ([]KeaReservation, *APICallError)
	}{
		{"dhcpv4", client.FetchKeaReservations4},
		{"dhcpv6", client.FetchKeaReservations6},
	} {
		t.Run(fetch.name, func(t *testing.T) {
			reservations, err := fetch.fn()
			if err != nil {
				t.Fatalf("FetchKeaReservations: %v", err)
			}
			if len(reservations) != 0 {
				t.Fatalf("reservations = %#v, want empty", reservations)
			}
		})
	}
}

func TestFetchKeaReservations_CompleteConfiguredInventory(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	client.endpoints["keaReservations4"] = "api/kea/dhcpv4/searchReservation"
	client.endpoints["keaReservations6"] = "api/kea/dhcpv6/searchReservation"

	mux.HandleFunc("/api/kea/dhcpv4/searchReservation", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(readKeaReservationFixture(t, "search_reservation4_populated.json"))
	})
	mux.HandleFunc("/api/kea/dhcpv6/searchReservation", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(readKeaReservationFixture(t, "search_reservation6_populated.json"))
	})

	cases := []struct {
		name       string
		fetch      func() ([]KeaReservation, *APICallError)
		subnets    []KeaSubnet
		wantCounts map[string]int
	}{
		{
			name:  "dhcpv4",
			fetch: client.FetchKeaReservations4,
			subnets: []KeaSubnet{
				{UUID: "v4-subnet-a", Subnet: "10.23.0.0/24"},
				{UUID: "v4-subnet-b", Subnet: "10.24.0.0/24"},
			},
			wantCounts: map[string]int{"10.23.0.0/24": 1, "10.24.0.0/24": 1},
		},
		{
			name:  "dhcpv6",
			fetch: client.FetchKeaReservations6,
			subnets: []KeaSubnet{
				{UUID: "v6-subnet-a", Subnet: "fd23::/64"},
				{UUID: "v6-subnet-b", Subnet: "fd24::/64"},
			},
			wantCounts: map[string]int{"fd23::/64": 1, "fd24::/64": 1},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			reservations, err := tc.fetch()
			if err != nil {
				t.Fatalf("FetchKeaReservations: %v", err)
			}
			if len(reservations) != 2 {
				t.Fatalf("got %d reservations, want complete two-row inventory", len(reservations))
			}
			gotCounts := KeaReservationCountsBySubnet(reservations, tc.subnets)
			if len(gotCounts) != len(tc.wantCounts) {
				t.Fatalf("counts = %#v, want %#v", gotCounts, tc.wantCounts)
			}
			for subnet, want := range tc.wantCounts {
				if got := gotCounts[subnet]; got != want {
					t.Errorf("count[%q] = %d, want %d", subnet, got, want)
				}
			}
		})
	}
}

func TestKeaReservationCountsBySubnet_UsesOnlyCIDRRelations(t *testing.T) {
	reservations := []KeaReservation{
		{SubnetUUID: "known-v4", SubnetDisplay: "10.25.0.0/24"},
		{SubnetUUID: "missing-v6", SubnetDisplay: "LAN fd25::/64"},
		{SubnetUUID: "missing-no-cidr", SubnetDisplay: "not a configured subnet"},
	}
	counts := KeaReservationCountsBySubnet(reservations, []KeaSubnet{
		{UUID: "known-v4", Subnet: "10.25.0.0/24"},
	})
	if counts["10.25.0.0/24"] != 1 || counts["fd25::/64"] != 1 || len(counts) != 2 {
		t.Errorf("counts = %#v, want only resolved CIDRs", counts)
	}
}
