package collector

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
)

// TestFirewallCollector_InterfaceLogEntriesIsGauge guards #74: the per-interface
// firewall log-entry count is a sliding-window value (rises and falls as log
// lines age out of the fixed ~5000-record window), so it must be a Gauge — never
// a Counter that rate()/increase() would misread as a reset. It also asserts the
// synthetic "other" aggregate bucket is emitted.
func TestFirewallCollector_InterfaceLogEntriesIsGauge(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/diagnostics/firewall/pf_statistics/interfaces", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"statistics":{"interfaces":{}}}`))
	})
	mux.HandleFunc("/api/diagnostics/firewall/pf_states/1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"current":"1","limit":"2"}`))
	})
	mux.HandleFunc("/api/diagnostics/firewall/stats", func(w http.ResponseWriter, r *http.Request) {
		// A value that would look like a counter reset if typed as a counter.
		w.Write([]byte(`[{"label":"LAN","value":42},{"label":"other","value":7}]`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &firewallCollector{subsystem: FirewallSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	foundLAN, foundOther := false, false
	for _, m := range metrics {
		if !strings.Contains(m.Desc().String(), "interface_log_entries_recent") {
			continue
		}
		d := &dto.Metric{}
		_ = m.Write(d)
		if d.Gauge == nil {
			t.Errorf("interface_log_entries_recent must be a Gauge (not Counter) so rate() can't misread window churn; got %v", d)
		}
		switch getMetricLabels(m)["interface"] {
		case "LAN":
			foundLAN = true
		case "other":
			foundOther = true
		}
	}
	if !foundLAN {
		t.Error("expected an interface_log_entries_recent series for LAN")
	}
	if !foundOther {
		t.Error("expected the synthetic 'other' aggregate bucket to be emitted")
	}
}

func TestFirewallCollector_Update(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/diagnostics/firewall/pf_statistics/interfaces", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"interfaces": {
				"igb0": {
					"references": 1,
					"in4_pass_packets": 1000,
					"in4_block_packets": 50,
					"out4_pass_packets": 900,
					"out4_block_packets": 10,
					"in6_pass_packets": 200,
					"in6_block_packets": 5,
					"out6_pass_packets": 180,
					"out6_block_packets": 2,
					"in4_pass_bytes": 1048576,
					"in4_block_bytes": 5120,
					"out4_pass_bytes": 921600,
					"out4_block_bytes": 1024,
					"in6_pass_bytes": 204800,
					"in6_block_bytes": 512,
					"out6_pass_bytes": 184320,
					"out6_block_bytes": 256
				}
			}
		}`))
	})

	mux.HandleFunc("/api/diagnostics/firewall/pf_states/1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"current": "12345",
			"limit": "200000"
		}`))
	})

	mux.HandleFunc("/api/diagnostics/firewall/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[
			{"label": "igb0", "value": 5000},
			{"label": "lo0", "value": 100}
		]`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &firewallCollector{subsystem: FirewallSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 17 metrics per interface (8 packet types + 8 byte types + pf_interface_references, #542)
	// + 2 pfStates (current + limit) + 2 firewallStats = 21
	expectedCount := 21
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

func TestFirewallCollector_Update_MultipleInterfaces(t *testing.T) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/diagnostics/firewall/pf_statistics/interfaces", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"interfaces": {
				"igb0": {
					"references": 1,
					"in4_pass_packets": 100,
					"in4_block_packets": 10,
					"out4_pass_packets": 90,
					"out4_block_packets": 5,
					"in6_pass_packets": 20,
					"in6_block_packets": 1,
					"out6_pass_packets": 18,
					"out6_block_packets": 0,
					"in4_pass_bytes": 10000,
					"in4_block_bytes": 1000,
					"out4_pass_bytes": 9000,
					"out4_block_bytes": 500,
					"in6_pass_bytes": 2000,
					"in6_block_bytes": 100,
					"out6_pass_bytes": 1800,
					"out6_block_bytes": 0
				},
				"igb1": {
					"references": 1,
					"in4_pass_packets": 50,
					"in4_block_packets": 5,
					"out4_pass_packets": 45,
					"out4_block_packets": 2,
					"in6_pass_packets": 10,
					"in6_block_packets": 0,
					"out6_pass_packets": 9,
					"out6_block_packets": 0,
					"in4_pass_bytes": 5000,
					"in4_block_bytes": 500,
					"out4_pass_bytes": 4500,
					"out4_block_bytes": 200,
					"in6_pass_bytes": 1000,
					"in6_block_bytes": 0,
					"out6_pass_bytes": 900,
					"out6_block_bytes": 0
				}
			}
		}`))
	})

	mux.HandleFunc("/api/diagnostics/firewall/pf_states/1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"current": "500",
			"limit": "100000"
		}`))
	})

	mux.HandleFunc("/api/diagnostics/firewall/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[
			{"label": "igb0", "value": 1000},
			{"label": "igb1", "value": 2000}
		]`))
	})

	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &firewallCollector{subsystem: FirewallSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 17 metrics per interface (16 + pf_interface_references, #542) * 2 interfaces
	// + 2 pfStates + 2 firewallStats = 38
	expectedCount := 38
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}
}

// TestFirewallCollector_PFCountersAreCounters guards #106: the pf per-interface
// pass/block byte and packet totals are cumulative counters and must be emitted
// with CounterValue, not GaugeValue.
func TestFirewallCollector_PFCountersAreCounters(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/diagnostics/firewall/pf_statistics/interfaces", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"interfaces":{"igb0":{"in4_pass_bytes":100,"in4_pass_packets":10,"out6_block_bytes":5,"out6_block_packets":1}}}`))
	})
	mux.HandleFunc("/api/diagnostics/firewall/pf_states/1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"current":"1","limit":"2"}`))
	})
	mux.HandleFunc("/api/diagnostics/firewall/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &firewallCollector{subsystem: FirewallSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	assertMetricsAreCounters(t, metrics,
		"opnsense_firewall_in_ipv4_pass_bytes_total",
		"opnsense_firewall_in_ipv4_pass_packets_total",
		"opnsense_firewall_out_ipv6_block_bytes_total",
		"opnsense_firewall_out_ipv6_block_packets_total",
	)
}

// TestFirewallCollector_CounterMetricsEndInTotal guards #418: Prometheus/OTLP
// convention is that a monotonic sum (COUNTER instrument type) exports with a
// `_total` suffix. The live-supported backend is OTLP-fed, and OTLP->Prometheus
// canonicalization appends `_total` to every counter regardless of what name the
// Go code declared, so a counter declared WITHOUT `_total` produces two different
// names depending on backend (direct /metrics vs OTLP-bridged Prometheus) and any
// consumer written against the unsuffixed name returns no data on the supported
// live backend. This asserts, for every metric this collector emits: emitted as
// CounterValue implies the descriptor name ends in `_total`.
func TestFirewallCollector_CounterMetricsEndInTotal(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/diagnostics/firewall/pf_statistics/interfaces", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"interfaces":{"igb0":{"in4_pass_bytes":100,"in4_pass_packets":10,"out6_block_bytes":5,"out6_block_packets":1}}}`))
	})
	mux.HandleFunc("/api/diagnostics/firewall/pf_states/1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"current":"1","limit":"2"}`))
	})
	mux.HandleFunc("/api/diagnostics/firewall/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &firewallCollector{subsystem: FirewallSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	checked := 0
	for _, m := range metrics {
		d := &dto.Metric{}
		_ = m.Write(d)
		if d.Counter == nil {
			continue
		}
		checked++
		name := descFQName(m.Desc().String())
		if name == "" {
			t.Fatalf("could not parse fqName from descriptor: %s", m.Desc().String())
		}
		if !strings.HasSuffix(name, "_total") {
			t.Errorf("counter metric %q is emitted with CounterValue but its name does not end in _total", name)
		}
	}
	if checked == 0 {
		t.Fatal("expected at least one CounterValue metric from the firewall collector")
	}
}

func TestFirewallCollector_Name(t *testing.T) {
	c := &firewallCollector{subsystem: FirewallSubsystem}
	if c.Name() != FirewallSubsystem {
		t.Errorf("expected %s, got %s", FirewallSubsystem, c.Name())
	}
}

// TestFirewallCollector_PFInterfaceReferences covers #542: the per-interface PF
// state-table reference count is parsed on every scrape and, until this metric,
// was read by nothing. It is the only per-interface breakdown of PF state usage
// obtainable anywhere — the exporter otherwise has just one global
// pf_states_current.
//
// The fixture reproduces the real prod key set and shape captured from
// api/diagnostics/firewall/pf_statistics/interfaces on 10.0.0.254 (OPNsense 26.1):
// a heavily-referenced device, an all-zero device, two " (skip)"-suffixed devices,
// and the "all" aggregate row.
func TestFirewallCollector_PFInterfaceReferences(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/diagnostics/firewall/pf_statistics/interfaces", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{
			"interfaces": {
				"pppoe0":         {"references": 486},
				"igb0":           {"references": 0},
				"lo0 (skip)":     {"references": 28},
				"pfsync0 (skip)": {"references": 0},
				"all":            {"references": 42}
			}
		}`))
	})
	mux.HandleFunc("/api/diagnostics/firewall/pf_states/1", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"current":"1","limit":"2"}`))
	})
	mux.HandleFunc("/api/diagnostics/firewall/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)
	c := &firewallCollector{subsystem: FirewallSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	type series struct {
		value   float64
		skipped string
	}
	got := make(map[string]series)
	for _, m := range collectMetrics(t, c, client) {
		if !strings.Contains(m.Desc().String(), "pf_interface_references") {
			continue
		}
		d := &dto.Metric{}
		_ = m.Write(d)
		if d.Gauge == nil {
			t.Fatalf("pf_interface_references must be a Gauge (a live state-table depth, not a cumulative counter); got %v", d)
		}
		labels := getMetricLabels(m)
		got[labels["interface"]] = series{value: d.Gauge.GetValue(), skipped: labels["skipped"]}
	}

	if _, ok := got["all"]; ok {
		t.Error(`the "all" aggregate row must not be emitted: it is a sum of the other rows, so a panel that aggregates this family would double every total`)
	}

	tests := []struct {
		iface       string
		wantValue   float64
		wantSkipped string
	}{
		{iface: "pppoe0", wantValue: 486, wantSkipped: "false"},
		{iface: "igb0", wantValue: 0, wantSkipped: "false"},
		{iface: "lo0", wantValue: 28, wantSkipped: "true"},
		{iface: "pfsync0", wantValue: 0, wantSkipped: "true"},
	}
	for _, tt := range tests {
		t.Run(tt.iface, func(t *testing.T) {
			s, ok := got[tt.iface]
			if !ok {
				t.Fatalf("expected a pf_interface_references series for %q, got %v", tt.iface, got)
			}
			if s.value != tt.wantValue {
				t.Errorf("value = %v, want %v", s.value, tt.wantValue)
			}
			if s.skipped != tt.wantSkipped {
				t.Errorf("skipped label = %q, want %q", s.skipped, tt.wantSkipped)
			}
		})
	}
}
