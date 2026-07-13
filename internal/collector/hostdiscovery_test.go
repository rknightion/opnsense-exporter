package collector

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/prometheus/common/promslog"
)

func TestHostDiscoveryCollector_Update(t *testing.T) {
	now := time.Now().UTC()
	recent := now.Add(-2 * time.Minute).Format(time.RFC3339)
	stale := now.Add(-2 * time.Hour).Format(time.RFC3339)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/hostdiscovery/service/search", func(w http.ResponseWriter, _ *http.Request) {
		body := fmt.Sprintf(`{"total":3,"rowCount":3,"current":1,"rows":[
			{"source":"discovery","interface_name":"LAN","ether_address":"aa:bb:cc:dd:ee:01","ip_address":"10.0.0.1","organization_name":"Vendor A","first_seen":"2026-07-12T15:00:00Z","last_seen":%q},
			{"source":"discovery","interface_name":"LAN","ether_address":"aa:bb:cc:dd:ee:02","ip_address":"10.0.0.2","organization_name":null,"first_seen":"2026-07-12T15:00:00Z","last_seen":%q},
			{"source":"discovery","interface_name":"WAN","ether_address":"aa:bb:cc:dd:ee:03","ip_address":"10.0.0.3","organization_name":"Vendor B","first_seen":"2026-07-12T15:00:00Z","last_seen":%q}
		]}`, recent, stale, recent)
		_, _ = w.Write([]byte(body))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &hostDiscoveryCollector{subsystem: HostDiscoverySubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	// 2 interfaces (LAN, WAN) x 2 metrics (hosts, hosts_recent) = 4 series.
	if len(metrics) != 4 {
		t.Fatalf("expected 4 metrics, got %d", len(metrics))
	}

	foundLANHosts, foundLANRecent, foundWANHosts := false, false, false
	for _, m := range metrics {
		labels := getMetricLabels(m)
		value := getMetricValue(m)
		switch {
		case hasFqName(m, "opnsense_hostdiscovery_hosts") && labels["interface"] == "LAN":
			foundLANHosts = true
			if value != 2 {
				t.Errorf("LAN hosts = %v, want 2", value)
			}
		case hasFqName(m, "opnsense_hostdiscovery_hosts_recent") && labels["interface"] == "LAN":
			foundLANRecent = true
			if value != 1 {
				t.Errorf("LAN hosts_recent = %v, want 1 (one row is decades stale)", value)
			}
		case hasFqName(m, "opnsense_hostdiscovery_hosts") && labels["interface"] == "WAN":
			foundWANHosts = true
			if value != 1 {
				t.Errorf("WAN hosts = %v, want 1", value)
			}
		}
		if labels["source"] != "discovery" {
			t.Errorf("expected source label = discovery, got %q", labels["source"])
		}
		if labels["opnsense_instance"] != "test" {
			t.Errorf("expected instance label = test, got %q", labels["opnsense_instance"])
		}
	}

	if !foundLANHosts || !foundLANRecent || !foundWANHosts {
		t.Errorf("missing expected series: LANHosts=%v LANRecent=%v WANHosts=%v", foundLANHosts, foundLANRecent, foundWANHosts)
	}
}

// TestHostDiscoveryCollector_EmptyInventory proves an empty inventory (no
// hosts ever seen) emits zero series rather than a synthetic zero-value one.
func TestHostDiscoveryCollector_EmptyInventory(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/hostdiscovery/service/search", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &hostDiscoveryCollector{subsystem: HostDiscoverySubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics for an empty inventory, got %d", len(metrics))
	}
}

// TestHostDiscoveryCollector_FeatureAbsent proves a 404 (OPNsense release
// older than the hostdiscovery module) is silent -- zero series, nil error --
// not a scrape failure.
func TestHostDiscoveryCollector_FeatureAbsent(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/hostdiscovery/service/search", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &hostDiscoveryCollector{subsystem: HostDiscoverySubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when feature absent, got %d", len(metrics))
	}
}

// TestHostDiscoveryCollector_ArpNdpFallbackSourceLabel proves the disabled
// -hostwatch fallback shape surfaces as its own source="arp-ndp" series
// rather than being silently merged into "discovery" or dropped.
func TestHostDiscoveryCollector_ArpNdpFallbackSourceLabel(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/hostdiscovery/service/search", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"total":1,"rowCount":1,"current":1,"rows":[
			{"source":"arp-ndp","interface_name":"LAN","ether_address":"aa:bb:cc:dd:ee:01","ip_address":"10.0.0.1","organization_name":"Vendor A","first_seen":"","last_seen":""}
		]}`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &hostDiscoveryCollector{subsystem: HostDiscoverySubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 2 {
		t.Fatalf("expected 2 metrics (hosts + hosts_recent for one group), got %d", len(metrics))
	}
	for _, m := range metrics {
		labels := getMetricLabels(m)
		if labels["source"] != "arp-ndp" {
			t.Errorf("expected source=arp-ndp, got %q", labels["source"])
		}
		if hasFqName(m, "opnsense_hostdiscovery_hosts_recent") && getMetricValue(m) != 0 {
			t.Errorf("hosts_recent should be 0 for arp-ndp rows (no timestamp), got %v", getMetricValue(m))
		}
	}
}
