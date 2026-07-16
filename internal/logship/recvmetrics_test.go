package logship

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// TestReceiverMetricsTwoSourcesShareOneRegistry is the regression this whole type
// exists for: before it, the syslog package owned logs_parse_errors_total and
// logs_rejected_total under source-neutral names with no source label, registered
// with MustRegister from its own factory. A second receiver registering the same
// names panicked the exporter at startup — and both are enabled from the same
// main.go block, so it was not a theoretical collision.
func TestReceiverMetricsTwoSourcesShareOneRegistry(t *testing.T) {
	reg := prometheus.NewRegistry()
	a := NewReceiverMetrics(reg, "syslog")
	b := NewReceiverMetrics(reg, "zenarmor") // must NOT panic

	a.ParseError("envelope")
	b.ParseError("bulk")
	b.ParseError("bulk")

	if got := counterValue(t, a.parseErrors.WithLabelValues("syslog", "envelope")); got != 1 {
		t.Errorf("syslog/envelope = %v, want 1", got)
	}
	if got := counterValue(t, b.parseErrors.WithLabelValues("zenarmor", "bulk")); got != 2 {
		t.Errorf("zenarmor/bulk = %v, want 2", got)
	}
}

// The second handle must SHARE the first's collector, not silently keep a private
// unregistered one whose values never reach /metrics.
func TestReceiverMetricsSecondHandleSharesTheCollector(t *testing.T) {
	reg := prometheus.NewRegistry()
	a := NewReceiverMetrics(reg, "syslog")
	b := NewReceiverMetrics(reg, "zenarmor")

	if a.parseErrors != b.parseErrors {
		t.Error("handles hold different parseErrors collectors; the second registration did not reuse the first")
	}
	if a.rejected != b.rejected {
		t.Error("handles hold different rejected collectors; the second registration did not reuse the first")
	}

	b.Reject("unhandled_endpoint")
	// Reading through the FIRST handle must see the second handle's write.
	if got := counterValue(t, a.rejected.WithLabelValues("zenarmor", "unhandled_endpoint")); got != 1 {
		t.Errorf("shared rejected counter = %v, want 1", got)
	}
}

func TestReceiverMetricsRejectIsSourceLabelled(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewReceiverMetrics(reg, "zenarmor")
	m.Reject("peer")
	m.Reject("peer")
	m.Reject("oversized")

	if got := counterValue(t, m.rejected.WithLabelValues("zenarmor", "peer")); got != 2 {
		t.Errorf("peer = %v, want 2", got)
	}
	if got := counterValue(t, m.rejected.WithLabelValues("zenarmor", "oversized")); got != 1 {
		t.Errorf("oversized = %v, want 1", got)
	}
}

func TestReceiverMetricsNilRegisterer(t *testing.T) {
	m := NewReceiverMetrics(nil, "syslog")
	m.ParseError("envelope") // must not panic
	m.Reject("peer")
}

// A nil handle is a no-op, so tests and any caller that opts out can pass nil.
// The syslog listener relies on this (listener_test.go:343).
func TestReceiverMetricsNilHandle(t *testing.T) {
	var m *ReceiverMetrics
	m.ParseError("envelope") // must not panic
	m.Reject("peer")
}
