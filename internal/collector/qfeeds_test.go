package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestQFeedsCollector_Update(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/qfeeds/settings/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"feeds": [{"name":"malware_ip","total_entries":437283,"packets_blocked":18646,"bytes_blocked":949357,"addresses_blocked":3815,"updated_at":"2026-06-09T22:40:00Z","next_update":"2026-06-09T23:00:58Z","licensed":true}],
			"totals": {"entries":437283,"addresses_blocked":3815,"packets_blocked":18646,"bytes_blocked":949357},
			"license": {"name":"Premium","expiry_date":"2027-02-08T13:53:37Z"}
		}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &qfeedsCollector{subsystem: QFeedsSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// feeds_total + 6 per-feed + 4 aggregate + license_info + license_expiry = 13
	if len(metrics) != 13 {
		t.Fatalf("expected 13 metrics, got %d", len(metrics))
	}
	var sawFeedEntries, sawLicense bool
	for _, m := range metrics {
		desc := m.Desc().String()
		labels := getMetricLabels(m)
		if strings.Contains(desc, "qfeeds_feed_entries") {
			sawFeedEntries = true
			if labels["feed"] != "malware_ip" || getMetricValue(m) != 437283 {
				t.Errorf("bad feed_entries: value=%v labels=%v", getMetricValue(m), labels)
			}
		}
		if strings.Contains(desc, "qfeeds_license_info") {
			sawLicense = true
			if labels["license"] != "Premium" {
				t.Errorf("bad license_info labels: %v", labels)
			}
		}
	}
	if !sawFeedEntries || !sawLicense {
		t.Errorf("missing metrics: feed_entries=%v license_info=%v", sawFeedEntries, sawLicense)
	}
}

func TestQFeedsCollector_PluginAbsent(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &qfeedsCollector{subsystem: QFeedsSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected 0 metrics when plugin absent, got %d", len(metrics))
	}
}
