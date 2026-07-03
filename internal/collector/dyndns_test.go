package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

func dyndnsTestMux(t *testing.T, accountsResponse, serviceResponse string) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/api/dyndns/accounts/searchItem", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(accountsResponse))
	})
	mux.HandleFunc("/api/dyndns/service/status", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(serviceResponse))
	})
	return mux
}

// TestDynDNSCollector_LastUpdateUniquePerInterface reproduces the #81 dyndns
// collision: two accounts sharing description/service/hostnames but bound to
// different interfaces (a dual-WAN failover setup). The last_update metric
// previously omitted the interface label, so the two rows collided and 500'd the
// whole scrape.
func TestDynDNSCollector_LastUpdateUniquePerInterface(t *testing.T) {
	accountsResponse := `{
		"total": 2, "rowCount": 2, "current": 1,
		"rows": [
			{"uuid":"a","enabled":"1","service":"cloudflare","%service":"Cloudflare","hostnames":"dyn.example.com","zone":"example.com","interface":"wan","%interface":"WAN","description":"dual","current_ip":"1.1.1.1","current_mtime":"2026-05-29T21:37:38+01:00"},
			{"uuid":"b","enabled":"1","service":"cloudflare","%service":"Cloudflare","hostnames":"dyn.example.com","zone":"example.com","interface":"wan2","%interface":"WAN2","description":"dual","current_ip":"2.2.2.2","current_mtime":"2026-05-29T22:37:38+01:00"}
		]
	}`
	mux := dyndnsTestMux(t, accountsResponse, `{"status": "running"}`)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &dyndnsCollector{subsystem: DynDNSSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)

	var lastUpdate []map[string]string
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "account_last_update_timestamp_seconds") {
			lastUpdate = append(lastUpdate, getMetricLabels(m))
		}
	}
	if len(lastUpdate) != 2 {
		t.Fatalf("expected 2 last_update metrics, got %d", len(lastUpdate))
	}
	if lastUpdate[0]["interface"] == lastUpdate[1]["interface"] {
		t.Errorf("expected distinct interface labels on last_update metrics, got %q twice", lastUpdate[0]["interface"])
	}
}

func TestDynDNSCollector_Update_Normal(t *testing.T) {
	accountsResponse := `{
		"total": 2,
		"rowCount": 2,
		"current": 1,
		"rows": [
			{
				"uuid": "aaaa-1111",
				"enabled": "1",
				"service": "cloudflare",
				"%service": "Cloudflare",
				"hostnames": "dyn.example.com",
				"zone": "example.com",
				"interface": "opt7",
				"%interface": "AAISP",
				"description": "Home IP",
				"current_ip": "81.187.237.31",
				"current_mtime": "2026-05-29T21:37:38+01:00"
			},
			{
				"uuid": "bbbb-2222",
				"enabled": "0",
				"service": "dyndns",
				"%service": "DynDNS",
				"hostnames": "other.example.org",
				"zone": "",
				"interface": "wan",
				"%interface": "WAN",
				"description": "Office",
				"current_ip": "",
				"current_mtime": ""
			}
		]
	}`
	serviceResponse := `{"status": "running"}`

	mux := dyndnsTestMux(t, accountsResponse, serviceResponse)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &dyndnsCollector{subsystem: DynDNSSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Expected metrics:
	//   1 accounts_total
	//   Per account (2): account_enabled + account_info = 2 each → 4
	//   account with current_mtime: +1 last_update_timestamp → 1
	//   never-updated account: no timestamp metric → 0
	//   1 service_running
	//   Total = 1 + 4 + 1 + 1 = 7
	expectedCount := 7
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
		for _, m := range metrics {
			t.Logf("  metric: %s", m.Desc().String())
		}
	}

	// Verify accounts_total = 2
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "accounts_total") {
			if val := getMetricValue(m); val != 2 {
				t.Errorf("expected accounts_total=2, got %v", val)
			}
		}
	}

	// Verify account_enabled values
	foundEnabled := 0
	for _, m := range metrics {
		if !strings.Contains(m.Desc().String(), "account_enabled") {
			continue
		}
		labels := getMetricLabels(m)
		val := getMetricValue(m)
		if labels["description"] == "Home IP" {
			if val != 1 {
				t.Errorf("expected account_enabled=1 for 'Home IP', got %v", val)
			}
			foundEnabled++
		}
		if labels["description"] == "Office" {
			if val != 0 {
				t.Errorf("expected account_enabled=0 for 'Office', got %v", val)
			}
			foundEnabled++
		}
	}
	if foundEnabled != 2 {
		t.Errorf("expected 2 account_enabled metrics, found %d", foundEnabled)
	}

	// Verify last_update_timestamp_seconds is emitted only for the account with current_mtime
	foundTimestamp := 0
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "last_update_timestamp_seconds") {
			foundTimestamp++
			labels := getMetricLabels(m)
			if labels["hostnames"] != "dyn.example.com" {
				t.Errorf("expected timestamp metric for 'dyn.example.com', got hostnames=%q", labels["hostnames"])
			}
			val := getMetricValue(m)
			if val <= 0 {
				t.Errorf("expected positive timestamp, got %v", val)
			}
		}
	}
	if foundTimestamp != 1 {
		t.Errorf("expected exactly 1 last_update_timestamp metric, found %d", foundTimestamp)
	}

	// Verify account_info labels include current_ip
	for _, m := range metrics {
		if !strings.Contains(m.Desc().String(), "account_info") {
			continue
		}
		labels := getMetricLabels(m)
		val := getMetricValue(m)
		if val != 1 {
			t.Errorf("expected account_info=1, got %v", val)
		}
		if labels["description"] == "Home IP" {
			if labels["current_ip"] != "81.187.237.31" {
				t.Errorf("expected current_ip='81.187.237.31', got %q", labels["current_ip"])
			}
			if labels["service"] != "cloudflare" {
				t.Errorf("expected service='cloudflare', got %q", labels["service"])
			}
			if labels["zone"] != "example.com" {
				t.Errorf("expected zone='example.com', got %q", labels["zone"])
			}
		}
	}

	// Verify service_running = 1
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "service_running") {
			if val := getMetricValue(m); val != 1 {
				t.Errorf("expected service_running=1, got %v", val)
			}
		}
	}
}

func TestDynDNSCollector_Update_TimestampSkippedWhenEmpty(t *testing.T) {
	// Both accounts have empty current_mtime — no timestamp metrics should be emitted.
	accountsResponse := `{
		"total": 1,
		"rowCount": 1,
		"current": 1,
		"rows": [
			{
				"uuid": "cccc-3333",
				"enabled": "1",
				"service": "cloudflare",
				"hostnames": "new.example.com",
				"zone": "",
				"interface": "wan",
				"description": "New account",
				"current_ip": "",
				"current_mtime": ""
			}
		]
	}`
	serviceResponse := `{"status": "stopped"}`

	mux := dyndnsTestMux(t, accountsResponse, serviceResponse)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &dyndnsCollector{subsystem: DynDNSSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Expected: 1 accounts_total + 1 account_enabled + 1 account_info + 1 service_running = 4
	// No timestamp metric.
	expectedCount := 4
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics (no timestamp), got %d", expectedCount, len(metrics))
	}

	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "last_update_timestamp") {
			t.Errorf("expected no timestamp metric for never-updated account, but got: %s", m.Desc().String())
		}
	}

	// service_running should be 0 (stopped)
	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "service_running") {
			if val := getMetricValue(m); val != 0 {
				t.Errorf("expected service_running=0 for stopped service, got %v", val)
			}
		}
	}
}

func TestDynDNSCollector_Update_Empty(t *testing.T) {
	accountsResponse := `{
		"total": 0,
		"rowCount": 0,
		"current": 1,
		"rows": []
	}`
	serviceResponse := `{"status": "running"}`

	mux := dyndnsTestMux(t, accountsResponse, serviceResponse)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &dyndnsCollector{subsystem: DynDNSSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// Expected: 1 accounts_total (=0) + 1 service_running = 2
	expectedCount := 2
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	for _, m := range metrics {
		if strings.Contains(m.Desc().String(), "accounts_total") {
			if val := getMetricValue(m); val != 0 {
				t.Errorf("expected accounts_total=0, got %v", val)
			}
		}
	}
}

func TestDynDNSCollector_Name(t *testing.T) {
	c := &dyndnsCollector{subsystem: DynDNSSubsystem}
	if c.Name() != DynDNSSubsystem {
		t.Errorf("expected %s, got %s", DynDNSSubsystem, c.Name())
	}
}
