package collector

import (
	"net/http"
	"net/http/httptest"
	"testing"

	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
)

func vnstatTestMux(t *testing.T) *http.ServeMux {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/api/vnstat/service/interface_list", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"interfaces":["vtnet1","vtnet2"]}`))
	})

	mux.HandleFunc("/api/vnstat/service/get_json_data", func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("iface") {
		case "vtnet1":
			_, _ = w.Write([]byte(`{
				"interfaces":[{
					"name":"vtnet1",
					"updated":{"date":{"year":2026,"month":7,"day":13}},
					"traffic":{
						"total":{"rx":4820720,"tx":5762},
						"day":[{"date":{"year":2026,"month":7,"day":13},"rx":4820720,"tx":5762}],
						"month":[{"date":{"year":2026,"month":7},"rx":4820720,"tx":5762}]
					}
				}]
			}`))
		case "vtnet2":
			_, _ = w.Write([]byte(`{
				"interfaces":[{
					"name":"vtnet2",
					"updated":{"date":{"year":2026,"month":7,"day":13}},
					"traffic":{
						"total":{"rx":41070,"tx":130480},
						"day":[{"date":{"year":2026,"month":7,"day":13},"rx":41070,"tx":130480}],
						"month":[{"date":{"year":2026,"month":7},"rx":41070,"tx":130480}]
					}
				}]
			}`))
		default:
			http.Error(w, "unexpected iface", http.StatusBadRequest)
		}
	})

	return mux
}

func TestVnstatCollector_Update_Normal(t *testing.T) {
	mux := vnstatTestMux(t)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &vnstatCollector{subsystem: VnstatSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	// 2 interfaces * 3 metric families * 2 directions (rx/tx) = 12 series.
	expectedCount := 12
	if len(metrics) != expectedCount {
		t.Errorf("expected %d metrics, got %d", expectedCount, len(metrics))
	}

	var sawTotalRX, sawDayRX, sawMonthRX bool
	for _, m := range metrics {
		val := getMetricValue(m)
		desc := m.Desc().String()
		switch {
		case hasFqName(m, "opnsense_vnstat_total_bytes") && val == 4820720:
			sawTotalRX = true
		case hasFqName(m, "opnsense_vnstat_current_day_bytes") && val == 4820720:
			sawDayRX = true
		case hasFqName(m, "opnsense_vnstat_current_month_bytes") && val == 4820720:
			sawMonthRX = true
		}
		_ = desc
	}
	if !sawTotalRX {
		t.Error("expected a total_bytes series with vtnet1's rx total (4820720)")
	}
	if !sawDayRX {
		t.Error("expected a current_day_bytes series with vtnet1's rx day figure (4820720)")
	}
	if !sawMonthRX {
		t.Error("expected a current_month_bytes series with vtnet1's rx month figure (4820720)")
	}
}

// Every metric must be a counter for total_bytes and a gauge for the current
// day/month figures — the day/month buckets are not monotonic (they reset
// daily/monthly in vnstat's own bookkeeping), so miscategorizing them as
// counters would corrupt rate()/increase() at the reset boundary.
func TestVnstatCollector_MetricTypes(t *testing.T) {
	mux := vnstatTestMux(t)
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &vnstatCollector{subsystem: VnstatSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)

	for _, m := range metrics {
		d := &dto.Metric{}
		_ = m.Write(d)
		switch {
		case hasFqName(m, "opnsense_vnstat_total_bytes"):
			if d.Counter == nil {
				t.Errorf("expected total_bytes to be a counter: %s", m.Desc().String())
			}
		case hasFqName(m, "opnsense_vnstat_current_day_bytes"), hasFqName(m, "opnsense_vnstat_current_month_bytes"):
			if d.Gauge == nil {
				t.Errorf("expected current day/month bytes to be a gauge: %s", m.Desc().String())
			}
		}
	}
}

// os-vnstat plugin absent: interface_list 404s, FetchVnstat reports
// Present=false, and the collector must emit no metrics at all rather than
// erroring.
func TestVnstatCollector_Update_PluginAbsent(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/vnstat/service/interface_list", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &vnstatCollector{subsystem: VnstatSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 0 {
		t.Errorf("expected no metrics when the plugin is absent, got %d", len(metrics))
	}
}

// An interface with an empty vnstat DB (no traffic recorded yet) must still
// emit explicit zero-valued series, not be skipped.
func TestVnstatCollector_Update_EmptyDB(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/vnstat/service/interface_list", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"interfaces":["vtnet3"]}`))
	})
	mux.HandleFunc("/api/vnstat/service/get_json_data", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"interfaces":[{
				"name":"vtnet3",
				"updated":{"date":{"year":2026,"month":7,"day":13}},
				"traffic":{"total":{"rx":0,"tx":0},"day":[],"month":[]}
			}]
		}`))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newCollectorTestClient(t, server)

	c := &vnstatCollector{subsystem: VnstatSubsystem}
	c.Register(namespace, "test", promslog.NewNopLogger())

	metrics := collectMetrics(t, c, client)
	if len(metrics) != 6 {
		t.Fatalf("expected 6 metrics (3 families * rx/tx) for one interface, got %d", len(metrics))
	}
	for _, m := range metrics {
		if getMetricValue(m) != 0 {
			t.Errorf("expected all-zero values for an empty DB interface, got %v on %s", getMetricValue(m), m.Desc().String())
		}
	}
}
