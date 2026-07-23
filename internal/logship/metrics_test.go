package logship

import (
	"fmt"
	"sort"
	"strings"
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

// gatherSeries returns every series reg would publish at /metrics, keyed
// `name{k="v",...}` with labels sorted.
//
// #280 is about a series being ABSENT, so a test for it must go through Gather:
// reading a vec child with WithLabelValues CREATES that child, which is the very
// act whose absence is the bug. Any assertion built on WithLabelValues would pass
// against the broken code.
func gatherSeries(t *testing.T, reg *prometheus.Registry) map[string]float64 {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	out := map[string]float64{}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			pairs := make([]string, 0, len(m.GetLabel()))
			for _, lp := range m.GetLabel() {
				pairs = append(pairs, fmt.Sprintf("%s=%q", lp.GetName(), lp.GetValue()))
			}
			sort.Strings(pairs)
			key := mf.GetName()
			if len(pairs) > 0 {
				key += "{" + strings.Join(pairs, ",") + "}"
			}
			switch {
			case m.GetCounter() != nil:
				out[key] = m.GetCounter().GetValue()
			case m.GetGauge() != nil:
				out[key] = m.GetGauge().GetValue()
			}
		}
	}
	return out
}

// mustBeZero asserts the series exists AND reads zero — "present at 0", the whole
// point of #280. A missing series fails with the message the issue describes.
func mustBeZero(t *testing.T, series map[string]float64, key string) {
	t.Helper()
	v, ok := series[key]
	if !ok {
		t.Errorf("%s is ABSENT on a healthy pipeline; rate() over it returns no-data instead of 0", key)
		return
	}
	if v != 0 {
		t.Errorf("%s = %v, want 0", key, v)
	}
}

// mustBeAbsent asserts a series was NOT pre-initialised. The counterpart rule to
// mustBeZero: pre-initialise exactly what the code can produce and nothing else,
// because a series that can never be non-zero claims we are watching something we
// are not.
func mustBeAbsent(t *testing.T, series map[string]float64, key string) {
	t.Helper()
	if _, ok := series[key]; ok {
		t.Errorf("%s was pre-initialised but nothing can ever increment it", key)
	}
}

// The pipeline's own CounterVecs must publish their known label combinations at 0
// from startup. Before #280 every one of these was absent until its first
// increment, so a healthy exporter published nothing and a restart reset them back
// to invisible.
func TestPipelineCountersPreInitialisedToZero(t *testing.T) {
	reg := prometheus.NewRegistry()
	newMetrics(reg, queueBounds{capacity: 10, length: func() float64 { return 0 }}, sourceNames{
		all:  []string{"syslog", "unbound"},
		poll: []string{"unbound"},
		gap:  []string{"unbound"},
	})

	s := gatherSeries(t, reg)

	// Every source ships and can overflow the shared queue.
	mustBeZero(t, s, `opnsense_exporter_logs_shipped_total{source="syslog"}`)
	mustBeZero(t, s, `opnsense_exporter_logs_shipped_total{source="unbound"}`)
	mustBeZero(t, s, `opnsense_exporter_logs_dropped_total{reason="overflow",source="syslog"}`)
	mustBeZero(t, s, `opnsense_exporter_logs_dropped_total{reason="overflow",source="unbound"}`)
	mustBeZero(t, s, `opnsense_exporter_logs_dropped_total{reason="ship_failed",source="syslog"}`)
	mustBeZero(t, s, `opnsense_exporter_logs_dropped_total{reason="ship_failed",source="unbound"}`)

	// The unlabelled counters already behaved; guard against a regression.
	mustBeZero(t, s, `opnsense_exporter_logs_ship_errors_total`)
	mustBeZero(t, s, `opnsense_exporter_logs_resource_capped_total`)

	// Only a POLL source can fail a Poll. A push receiver never polls.
	mustBeZero(t, s, `opnsense_exporter_logs_poll_errors_total{source="unbound"}`)
	mustBeAbsent(t, s, `opnsense_exporter_logs_poll_errors_total{source="syslog"}`)

	// Only a bounded-window source can gap. A cursor-based source never can.
	mustBeZero(t, s, `opnsense_exporter_logs_possible_gap_total{source="unbound"}`)
	mustBeAbsent(t, s, `opnsense_exporter_logs_possible_gap_total{source="syslog"}`)
}

// gapFakeSource is a poll source that declares itself bounded-window.
type gapFakeSource struct{ *fakeSource }

func (gapFakeSource) ReportsGaps() {}

// collectSourceNames decides the label sets the pipeline actually publishes in
// production, so the split has to be exercised on real Source values rather than
// only through the hand-built sourceNames literal above.
func TestCollectSourceNames_SplitsPollPushAndGap(t *testing.T) {
	poll := &fakeSource{name: "crowdsec"}
	gap := gapFakeSource{&fakeSource{name: "unbound"}}
	push := &fakePush{}

	got := collectSourceNames([]Source{poll, gap}, []PushSource{push})

	assertSameSet(t, "all", got.all, []string{"crowdsec", "unbound", "fake"})
	// A push receiver never calls Poll, so it must not get a poll-error zero.
	assertSameSet(t, "poll", got.poll, []string{"crowdsec", "unbound"})
	// Only the source that declares GapReportingSource can gap.
	assertSameSet(t, "gap", got.gap, []string{"unbound"})
}

func assertSameSet(t *testing.T, what string, got, want []string) {
	t.Helper()
	g := append([]string(nil), got...)
	w := append([]string(nil), want...)
	sort.Strings(g)
	sort.Strings(w)
	if strings.Join(g, ",") != strings.Join(w, ",") {
		t.Errorf("%s = %v, want %v", what, g, w)
	}
}

func TestRecordPossibleGap_IncrementsCounterPerSource(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetrics(reg, queueBounds{capacity: 10, length: func() float64 { return 0 }}, sourceNames{})

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
		newMetrics(prometheus.NewRegistry(), queueBounds{capacity: 10, length: func() float64 { return 0 }}, sourceNames{})
	})

	recordPossibleGap("unbound") // must not panic
}

// The sink degrades to the base resource once maxLogResources is hit, dropping the
// record's opnsense.* index labels. That is not data loss, but it IS silent label
// loss — label-scoped queries under-report and nothing says so. Before AttrAction
// the cap was genuinely unreachable; action multiplies the key count, so the
// degrade path must be counted.
func TestRecordResourceCapped_IncrementsCounter(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := newMetrics(reg, queueBounds{capacity: 10, length: func() float64 { return 0 }}, sourceNames{})

	recordResourceCapped()
	recordResourceCapped()

	if got := counterValue(t, m.resourceCapped); got != 2 {
		t.Errorf("logs_resource_capped_total = %v, want 2", got)
	}
}

// Safe to call before any pipeline exists (a sink unit test never starts one).
func TestRecordResourceCapped_NoPipelineIsNoOp(t *testing.T) {
	setActiveResourceCapped(nil)
	recordResourceCapped() // must not panic
}
