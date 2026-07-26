package zenarmor

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestNewMetrics_ReusedExcludedCollectorSeedsNewRules(t *testing.T) {
	reg := prometheus.NewRegistry()
	first := mustRules(t, `query=~^first\.example$`)
	second := mustRules(t, `query=~^second\.example$`)

	newMetrics(reg, first)
	newMetrics(reg, second)

	const name = "opnsense_exporter_logs_zenarmor_excluded_total"
	if value, ok := seriesValue(t, reg, name, "rule", second[0].Raw); !ok {
		t.Fatalf("rebuild rule %q was not pre-initialised on the reused collector", second[0].Raw)
	} else if value != 0 {
		t.Errorf("rebuild rule %q = %v, want 0 before its first match", second[0].Raw, value)
	}
}

func TestNewMetrics_IncompatibleCollectorCollisionPanics(t *testing.T) {
	reg := prometheus.NewRegistry()
	reg.MustRegister(prometheus.NewGauge(prometheus.GaugeOpts{
		Namespace: "opnsense_exporter",
		Name:      "logs_zenarmor_bulk_requests_total",
		Help:      "Total Elasticsearch _bulk requests accepted from Zenarmor.",
	}))

	defer func() {
		if recover() == nil {
			t.Fatal("incompatible collector collision did not panic")
		}
	}()
	newMetrics(reg, nil)
}
