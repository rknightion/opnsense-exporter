package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

func TestZeroTierCollector_Update(t *testing.T) {
	server, mux, client := newZeroTierCollectorTestClient(t)
	defer server.Close()
	clientEndpoints := client.Endpoints()
	clientEndpoints["zerotierNetworks"] = "api/zerotier/network/search"
	clientEndpoints["zerotierNetworkInfo"] = "api/zerotier/network/info"

	mux.HandleFunc("/api/zerotier/network/search", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"total":2,"rowCount":2,"current":1,"rows":[{"uuid":"network-uuid-1","enabled":"1","networkId":"8056c2e21c000001","description":"primary"},{"uuid":"network-uuid-2","enabled":"0","networkId":"8056c2e21c000002","description":"secondary"}]}`))
	})
	mux.HandleFunc("/api/zerotier/network/info/network-uuid-1", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"message":"8056c2e21c000001 primary 12:34:56:78:9a:bc OK PRIVATE zt0 10.0.0.1/24,fd00::1/64"}`))
	})
	mux.HandleFunc("/api/zerotier/network/info/network-uuid-2", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"message":"8056c2e21c000002 secondary 12:34:56:78:9a:bd ACCESS_DENIED PRIVATE zt1 -"}`))
	})

	c := &zeroTierCollector{subsystem: ZeroTierSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	if got := len(metrics); got != 7 {
		t.Fatalf("got %d metrics, want 7 (total + 2 enabled + 2 status + 2 address counts)", got)
	}
	byName := metricsByName(t, metrics)
	if got := getMetricValue(byName["opnsense_zerotier_networks_configured"][0]); got != 2 {
		t.Errorf("networks_configured = %v, want 2", got)
	}

	for _, metric := range byName["opnsense_zerotier_network_enabled"] {
		labels := getMetricLabels(metric)
		want := 0.0
		if labels["network_id"] == "8056c2e21c000001" {
			want = 1
		}
		if got := getMetricValue(metric); got != want {
			t.Errorf("network_enabled{%v} = %v, want %v", labels, got, want)
		}
	}

	status := byName["opnsense_zerotier_network_status"]
	if len(status) != 2 {
		t.Fatalf("got %d status metrics, want 2", len(status))
	}
	seenStatuses := map[string]bool{}
	for _, metric := range status {
		labels := getMetricLabels(metric)
		seenStatuses[labels["network_id"]+"/"+labels["status"]] = true
		if got := getMetricValue(metric); got != 1 {
			t.Errorf("network_status{%v} = %v, want 1", labels, got)
		}
	}
	if !seenStatuses["8056c2e21c000001/OK"] || !seenStatuses["8056c2e21c000002/ACCESS_DENIED"] {
		t.Errorf("unexpected network statuses: %v", seenStatuses)
	}

	addresses := byName["opnsense_zerotier_network_assigned_addresses"]
	if len(addresses) != 2 {
		t.Fatalf("got %d assigned-address metrics, want 2", len(addresses))
	}
	for _, metric := range addresses {
		labels := getMetricLabels(metric)
		want := 0.0
		if labels["network_id"] == "8056c2e21c000001" {
			want = 2
		}
		if got := getMetricValue(metric); got != want {
			t.Errorf("assigned addresses{%v} = %v, want %v", labels, got, want)
		}
	}
}

func TestZeroTierCollector_Update_PluginAbsentIsSilent(t *testing.T) {
	server, mux, client := newZeroTierCollectorTestClient(t)
	defer server.Close()
	client.Endpoints()["zerotierNetworks"] = "api/zerotier/network/search"
	client.Endpoints()["zerotierNetworkInfo"] = "api/zerotier/network/info"
	mux.HandleFunc("/api/zerotier/network/search", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	c := &zeroTierCollector{subsystem: ZeroTierSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Fatalf("got %d metrics for absent plugin, want silence", len(metrics))
	}
}

func TestZeroTierCollector_Update_MalformedInfoDoesNotFabricateRuntimeMetrics(t *testing.T) {
	server, mux, client := newZeroTierCollectorTestClient(t)
	defer server.Close()
	client.Endpoints()["zerotierNetworks"] = "api/zerotier/network/search"
	client.Endpoints()["zerotierNetworkInfo"] = "api/zerotier/network/info"
	mux.HandleFunc("/api/zerotier/network/search", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"total":1,"rowCount":1,"current":1,"rows":[{"uuid":"network-uuid-1","enabled":"1","networkId":"8056c2e21c000001","description":"primary"}]}`))
	})
	mux.HandleFunc("/api/zerotier/network/info/network-uuid-1", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"title":"Information on network 8056c2e21c000001","message":"Unable to obtain Zerotier information for 8056c2e21c000001! Is the network enabled?"}`))
	})

	c := &zeroTierCollector{subsystem: ZeroTierSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())
	metrics := collectMetrics(t, c, client)
	if got := len(metrics); got != 2 {
		t.Fatalf("got %d metrics for malformed info, want networks_total + enabled only", got)
	}
	for _, metric := range metrics {
		if strings.Contains(metric.Desc().String(), "network_status") || strings.Contains(metric.Desc().String(), "network_assigned_addresses") {
			t.Errorf("malformed info emitted runtime metric: %s", metric.Desc())
		}
	}
}

// newZeroTierCollectorTestClient is a local variant of newCollectorTestClient
// that exposes the mux so a test can serve both the search and dynamic info
// routes without changing the shared collector test helper.
func newZeroTierCollectorTestClient(t *testing.T) (*httptest.Server, *http.ServeMux, *opnsense.Client) {
	t.Helper()
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	client := newCollectorTestClientForURL(t, server.URL)
	return server, mux, client
}
