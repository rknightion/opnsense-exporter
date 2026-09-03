package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/common/promslog"
)

func TestFirewallMigrationCollector_Update(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/firewall/migration/countRules", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","count":7}`))
	})
	mux.HandleFunc("/api/firewall/migration/countOutbound", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","count":3}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &firewallMigrationCollector{subsystem: FirewallMigrationSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	assertNoDuplicateSeries(t, metrics)
	if len(metrics) != 2 {
		t.Fatalf("metrics = %d, want 2 debt gauges", len(metrics))
	}
	for _, metric := range metrics {
		switch {
		case hasFqName(metric, "opnsense_firewall_migration_legacy_rules"):
			if got := getMetricValue(metric); got != 7 {
				t.Errorf("legacy_rules = %v, want 7", got)
			}
		case hasFqName(metric, "opnsense_firewall_migration_legacy_outbound_nat_rules"):
			if got := getMetricValue(metric); got != 3 {
				t.Errorf("legacy_outbound_nat_rules = %v, want 3", got)
			}
		default:
			t.Errorf("unexpected metric descriptor: %s", metric.Desc())
		}
	}
}

func TestFirewallMigrationCollector_FeatureAbsent(t *testing.T) {
	server := httptest.NewServer(http.NewServeMux())
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &firewallMigrationCollector{subsystem: FirewallMigrationSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	if metrics := collectMetrics(t, c, client); len(metrics) != 0 {
		t.Fatalf("metrics = %d, want 0 when migration endpoints are absent", len(metrics))
	}
}

func TestFirewallMigrationCollector_PartialFeatureAbsent(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/firewall/migration/countRules", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/api/firewall/migration/countOutbound", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","count":2}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &firewallMigrationCollector{subsystem: FirewallMigrationSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 1 || !hasFqName(metrics[0], "opnsense_firewall_migration_legacy_outbound_nat_rules") || getMetricValue(metrics[0]) != 2 {
		t.Fatalf("partial metrics = %#v, want outbound gauge=2", metrics)
	}
}
