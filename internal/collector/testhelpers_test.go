package collector

import (
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense-exporter/internal/options"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

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
	err := instance.Update(client, ch)
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
