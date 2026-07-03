package collector

import (
	"context"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense-exporter/internal/options"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

// assertNoDuplicateSeries fails if any two metrics share the same descriptor and
// label values — the exact condition that makes a checked registry's Gather()
// error and (before #81) 500 the whole scrape.
func assertNoDuplicateSeries(t *testing.T, metrics []prometheus.Metric) {
	t.Helper()
	seen := make(map[string]bool, len(metrics))
	for _, m := range metrics {
		d := &dto.Metric{}
		_ = m.Write(d)
		parts := make([]string, 0, len(d.GetLabel()))
		for _, lp := range d.GetLabel() {
			parts = append(parts, lp.GetName()+"="+lp.GetValue())
		}
		sort.Strings(parts)
		key := m.Desc().String() + "|" + strings.Join(parts, ",")
		if seen[key] {
			t.Fatalf("duplicate series (would fail Gather): %s", key)
		}
		seen[key] = true
	}
}

// assertMetricsAreCounters fails if any collected metric whose descriptor
// mentions one of nameSubstrings is not emitted with CounterValue. Guards against
// cumulative counters regressing to GaugeValue (#106).
func assertMetricsAreCounters(t *testing.T, metrics []prometheus.Metric, nameSubstrings ...string) {
	t.Helper()
	found := map[string]bool{}
	for _, m := range metrics {
		desc := m.Desc().String()
		for _, sub := range nameSubstrings {
			if !strings.Contains(desc, `fqName: "`+sub+`"`) {
				continue
			}
			found[sub] = true
			d := &dto.Metric{}
			_ = m.Write(d)
			if d.Counter == nil {
				t.Errorf("%s must be emitted as CounterValue (TYPE counter), got %v", sub, d)
			}
		}
	}
	for _, sub := range nameSubstrings {
		if !found[sub] {
			t.Errorf("expected a metric named %q to be emitted", sub)
		}
	}
}

func newCollectorTestClient(t *testing.T, server *httptest.Server) *opnsense.Client {
	t.Helper()
	u, _ := url.Parse(server.URL)
	cfg := options.OPNSenseConfig{
		Protocol:  "http",
		Host:      u.Host,
		APIKey:    "test",
		APISecret: "test",
	}
	client, err := opnsense.NewClient(cfg, "test", promslog.NewNopLogger())
	if err != nil {
		t.Fatalf("failed to create test client: %v", err)
	}
	return &client
}

func collectMetrics(t *testing.T, instance CollectorInstance, client *opnsense.Client) []prometheus.Metric {
	t.Helper()
	ch := make(chan prometheus.Metric, 500)
	err := instance.Update(context.Background(), client, ch)
	close(ch)
	if err != nil {
		t.Fatalf("Update returned error: %v", err)
	}
	var metrics []prometheus.Metric
	for m := range ch {
		metrics = append(metrics, m)
	}
	return metrics
}

// hasFqName reports whether a metric's descriptor has exactly the given fqName (matches
// the `fqName: "<name>"` token, so a prefix like ..._entries does not match ..._entries_total).
func hasFqName(m prometheus.Metric, name string) bool {
	return strings.Contains(m.Desc().String(), `fqName: "`+name+`"`)
}

func getMetricValue(m prometheus.Metric) float64 {
	d := &dto.Metric{}
	_ = m.Write(d)
	if d.Gauge != nil {
		return d.Gauge.GetValue()
	}
	if d.Counter != nil {
		return d.Counter.GetValue()
	}
	return 0
}

func getMetricLabels(m prometheus.Metric) map[string]string {
	d := &dto.Metric{}
	_ = m.Write(d)
	labels := make(map[string]string)
	for _, lp := range d.GetLabel() {
		labels[lp.GetName()] = lp.GetValue()
	}
	return labels
}
