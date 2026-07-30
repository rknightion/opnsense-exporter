package opnsense

import (
	"fmt"
	"net/http"
	"testing"
	"time"
)

// hostDiscoveryFixture is shaped after a live OPNsense 26.7 devel-box capture
// (#223): hostwatch enabled, three interfaces, one IPv6 row, one row with a
// null organization_name (randomized-MAC device).
const hostDiscoveryFixtureTemplate = `{"total":5,"rowCount":5,"current":1,"rows":[
  {"source":"discovery","interface_name":"LAN","ether_address":"bc:24:11:c1:d5:12","ip_address":"10.0.0.114","organization_name":"Proxmox Server Solutions GmbH","first_seen":"2026-07-12T15:23:06Z","last_seen":%q},
  {"source":"discovery","interface_name":"LAN","ether_address":"3e:13:8f:ef:ae:26","ip_address":"10.0.0.113","organization_name":null,"first_seen":"2026-07-12T16:16:49Z","last_seen":%q},
  {"source":"discovery","interface_name":"LAN","ether_address":"8c:1f:64:f4:92:1b","ip_address":"2001:db8::1007","organization_name":"IEEE Registration Authority","first_seen":"2026-07-12T15:21:09Z","last_seen":%q},
  {"source":"discovery","interface_name":"WAN","ether_address":"bc:24:11:25:6f:8f","ip_address":"10.0.0.11","organization_name":"Proxmox Server Solutions GmbH","first_seen":"2026-07-12T18:38:29Z","last_seen":%q},
  {"source":"discovery","interface_name":"TESTLAN","ether_address":"00:00:5e:00:01:09","ip_address":"172.16.9.254","organization_name":"ICANN, IANA Department","first_seen":"2026-07-12T16:06:47Z","last_seen":%q}
]}`

// hostDiscoveryArpNdpFallbackFixture mirrors the shape captured after
// temporarily disabling hostwatch (general.enabled=0 + service/reconfigure)
// on the same box: source flips to "arp-ndp" and first_seen/last_seen become
// empty strings, not null/omitted (#223).
const hostDiscoveryArpNdpFallbackFixture = `{"total":2,"rowCount":2,"current":1,"rows":[
  {"source":"arp-ndp","interface_name":"LAN","ether_address":"8c:1f:64:f4:92:1b","ip_address":"10.0.0.2","organization_name":"IEEE Registration Authority","first_seen":"","last_seen":""},
  {"source":"arp-ndp","interface_name":"WAN","ether_address":"7c:10:c9:5e:84:86","ip_address":"10.0.0.6","organization_name":"ASUSTek COMPUTER INC.","first_seen":"","last_seen":""}
]}`

func TestFetchHostDiscovery_AggregatesByInterfaceAndRecency(t *testing.T) {
	now := time.Now().UTC()
	recent := now.Add(-2 * time.Minute).Format(time.RFC3339)
	stale := now.Add(-2 * time.Hour).Format(time.RFC3339)

	body := fmt.Sprintf(hostDiscoveryFixtureTemplate, recent, stale, recent, stale, recent)

	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("expected GET, got %s", r.Method)
		}
		_, _ = w.Write([]byte(body))
	})
	defer server.Close()

	data, err := client.FetchHostDiscovery()
	if err != nil {
		t.Fatalf("FetchHostDiscovery: %v", err)
	}

	// LAN now splits into 3 groups because organization_name (manufacturer) is
	// part of the grouping key: "Proxmox Server Solutions GmbH" (IPv4 row),
	// "unknown" (the null-organization_name row), and "IEEE Registration
	// Authority" (the IPv6 row) are three distinct manufacturers on LAN.
	if len(data.Groups) != 5 {
		t.Fatalf("expected 5 groups (LAN x3 manufacturers, WAN, TESTLAN), got %d: %+v", len(data.Groups), data.Groups)
	}

	byKey := map[string]HostDiscoveryGroup{}
	for _, g := range data.Groups {
		byKey[g.Interface+"|"+g.Manufacturer] = g
	}

	lanProxmox, ok := byKey["LAN|Proxmox Server Solutions GmbH"]
	if !ok {
		t.Fatalf("no LAN/Proxmox group in %+v", data.Groups)
	}
	if lanProxmox.Source != "discovery" {
		t.Errorf("LAN/Proxmox.Source = %q, want discovery", lanProxmox.Source)
	}
	if lanProxmox.Hosts != 1 || lanProxmox.RecentHosts != 1 {
		t.Errorf("LAN/Proxmox = %+v, want Hosts=1 RecentHosts=1", lanProxmox)
	}

	lanUnknown, ok := byKey["LAN|unknown"]
	if !ok {
		t.Fatalf("no LAN/unknown group in %+v", data.Groups)
	}
	if lanUnknown.Hosts != 1 || lanUnknown.RecentHosts != 0 {
		t.Errorf("LAN/unknown = %+v, want Hosts=1 RecentHosts=0 (stale, null organization_name)", lanUnknown)
	}

	lanIEEE, ok := byKey["LAN|IEEE Registration Authority"]
	if !ok {
		t.Fatalf("no LAN/IEEE group in %+v", data.Groups)
	}
	if lanIEEE.Hosts != 1 || lanIEEE.RecentHosts != 1 {
		t.Errorf("LAN/IEEE = %+v, want Hosts=1 RecentHosts=1", lanIEEE)
	}

	wan, ok := byKey["WAN|Proxmox Server Solutions GmbH"]
	if !ok {
		t.Fatalf("no WAN group in %+v", data.Groups)
	}
	if wan.Hosts != 1 || wan.RecentHosts != 0 {
		t.Errorf("WAN = %+v, want Hosts=1 RecentHosts=0 (stale)", wan)
	}

	testlan, ok := byKey["TESTLAN|ICANN, IANA Department"]
	if !ok {
		t.Fatalf("no TESTLAN group in %+v", data.Groups)
	}
	if testlan.Hosts != 1 || testlan.RecentHosts != 1 {
		t.Errorf("TESTLAN = %+v, want Hosts=1 RecentHosts=1 (recent)", testlan)
	}
}

// TestFetchHostDiscovery_OrganizationNameSentinel proves a null
// organization_name (a randomized-MAC device the OUI lookup cannot resolve)
// becomes the "unknown" sentinel rather than an empty label, and a present
// value passes through unchanged.
func TestFetchHostDiscovery_OrganizationNameSentinel(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"total":2,"rowCount":2,"current":1,"rows":[
			{"source":"discovery","interface_name":"LAN","ether_address":"aa:bb:cc:dd:ee:01","ip_address":"10.0.0.1","organization_name":null,"first_seen":"","last_seen":""},
			{"source":"discovery","interface_name":"LAN","ether_address":"aa:bb:cc:dd:ee:02","ip_address":"10.0.0.2","organization_name":"Vendor A","first_seen":"","last_seen":""}
		]}`))
	})
	defer server.Close()

	data, err := client.FetchHostDiscovery()
	if err != nil {
		t.Fatalf("FetchHostDiscovery: %v", err)
	}

	byManufacturer := map[string]HostDiscoveryGroup{}
	for _, g := range data.Groups {
		byManufacturer[g.Manufacturer] = g
	}

	if g, ok := byManufacturer["unknown"]; !ok || g.Hosts != 1 {
		t.Errorf("expected a manufacturer=unknown group with 1 host, got %+v", data.Groups)
	}
	if g, ok := byManufacturer["Vendor A"]; !ok || g.Hosts != 1 {
		t.Errorf("expected a manufacturer=Vendor A group with 1 host, got %+v", data.Groups)
	}
}

// TestFetchHostDiscovery_ArpNdpFallback proves the disabled-hostwatch shape
// (source="arp-ndp", empty first_seen/last_seen strings) is aggregated into
// its own group -- distinguishable from "discovery" rows via Source -- and
// never counted as recent, since there is no timestamp to judge recency from.
func TestFetchHostDiscovery_ArpNdpFallback(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(hostDiscoveryArpNdpFallbackFixture))
	})
	defer server.Close()

	data, err := client.FetchHostDiscovery()
	if err != nil {
		t.Fatalf("FetchHostDiscovery: %v", err)
	}

	if len(data.Groups) != 2 {
		t.Fatalf("expected 2 groups, got %d: %+v", len(data.Groups), data.Groups)
	}
	for _, g := range data.Groups {
		if g.Source != "arp-ndp" {
			t.Errorf("group %+v: Source = %q, want arp-ndp", g, g.Source)
		}
		if g.Hosts != 1 {
			t.Errorf("group %+v: Hosts = %d, want 1", g, g.Hosts)
		}
		if g.RecentHosts != 0 {
			t.Errorf("group %+v: RecentHosts = %d, want 0 (empty last_seen never counts as recent)", g, g.RecentHosts)
		}
	}
}

// TestFetchHostDiscovery_Empty proves an empty inventory (no hosts ever seen,
// e.g. right after hostwatch is first enabled) yields a nil/empty Groups
// slice with no error, not a synthetic zero-value group.
func TestFetchHostDiscovery_Empty(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	defer server.Close()

	data, err := client.FetchHostDiscovery()
	if err != nil {
		t.Fatalf("FetchHostDiscovery: %v", err)
	}
	if len(data.Groups) != 0 {
		t.Errorf("expected 0 groups, got %d: %+v", len(data.Groups), data.Groups)
	}
}

// TestFetchHostDiscovery_NotFoundIsFeatureAbsent proves a 404 (an OPNsense
// release older than the exporter's support window, which predates the
// hostdiscovery module) is treated as "feature absent" -- empty data, nil
// error -- mirroring FetchACMECertificates, and deliberately NOT plugin-gated
// (this is a core endpoint; see CLAUDE.md's PluginGatedEndpoints rule).
func TestFetchHostDiscovery_NotFoundIsFeatureAbsent(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"errorMessage":"Endpoint not found"}`))
	})
	defer server.Close()

	data, err := client.FetchHostDiscovery()
	if err != nil {
		t.Fatalf("expected nil error on 404, got: %v", err)
	}
	if len(data.Groups) != 0 {
		t.Errorf("expected empty data on 404, got: %+v", data.Groups)
	}
}

// TestFetchHostDiscovery_ServerErrorPropagates proves a genuine server error
// (as opposed to a 404) is NOT swallowed as feature-absent.
func TestFetchHostDiscovery_ServerErrorPropagates(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	defer server.Close()

	_, err := client.FetchHostDiscovery()
	if err == nil {
		t.Fatal("expected an error on 500, got nil")
	}
}

func TestHostDiscoveryEndpoint_Registered(t *testing.T) {
	endpoints := defaultEndpoints()
	path, ok := endpoints["hostdiscoverySearch"]
	if !ok {
		t.Fatal("hostdiscoverySearch endpoint not registered in defaultEndpoints()")
	}
	if path != "api/hostdiscovery/service/search" {
		t.Errorf("hostdiscoverySearch path = %q, want api/hostdiscovery/service/search", path)
	}
}
