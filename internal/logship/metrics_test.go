package logship

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// counterValue reads the current value of a prometheus.Counter without
// depending on the (unvendored) prometheus/testutil package — mirrors the
// dto.Metric.Write pattern already used in internal/collector/testhelpers_test.go.
func counterValue(t *testing.T, c prometheus.Counter) float64 {
	t.Helper()
	var d dto.Metric
	if err := c.Write(&d); err != nil {
		t.Fatalf("write metric: %v", err)
	}
	return d.GetCounter().GetValue()
}

func TestRecordPossibleGap_IncrementsCounterPerSource(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetrics(reg, 10, func() float64 { return 0 })

	recordPossibleGap("unbound")
	recordPossibleGap("unbound")
	recordPossibleGap("other")

	if got := counterValue(t, m.possibleGap.WithLabelValues("unbound")); got != 2 {
		t.Fatalf("possibleGap[unbound] = %v, want 2", got)
	}
	if got := counterValue(t, m.possibleGap.WithLabelValues("other")); got != 1 {
		t.Fatalf("possibleGap[other] = %v, want 1", got)
	}
}

func TestRecordPossibleGap_NoOpBeforeAnyPipelineMetrics(t *testing.T) {
	// Simulate "no pipeline has started in this process yet" and restore
	// afterwards so later tests in this package are unaffected.
	setActivePossibleGapVec(nil)
	t.Cleanup(func() {
		newMetrics(prometheus.NewRegistry(), 10, func() float64 { return 0 })
	})

	recordPossibleGap("unbound") // must not panic
}
