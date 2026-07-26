package logship

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"github.com/rknightion/opnsense-exporter/internal/logship/capture"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
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

// assertEveryLogsSeriesCarriesInstance is the #395 contract: EVERY series in the
// opnsense_exporter_logs_* family must carry opnsense_instance, with the expected
// value. It walks the raw Gather output rather than gatherSeries' flattened keys so
// the failure message can name the offending family, and so a family that publishes
// no series at all is reported as "watching nothing" instead of silently passing.
//
// The invariant is what makes the Log Shipping and Zenarmor dashboard tabs honest on
// a multi-box deployment: without it, two exporters' self-metrics are indistinguishable
// and $opnsense_instance cannot filter them, so one healthy box masks a stalled one.
func assertEveryLogsSeriesCarriesInstance(t *testing.T, reg *prometheus.Registry, want string) {
	t.Helper()
	mfs, err := reg.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	seen := 0
	for _, mf := range mfs {
		if !strings.HasPrefix(mf.GetName(), "opnsense_exporter_logs_") {
			continue
		}
		if len(mf.GetMetric()) == 0 {
			t.Errorf("%s publishes no series; this assertion is watching nothing", mf.GetName())
			continue
		}
		for _, m := range mf.GetMetric() {
			seen++
			got, ok := "", false
			for _, lp := range m.GetLabel() {
				if lp.GetName() == instanceLabelName {
					got, ok = lp.GetValue(), true
				}
			}
			if !ok {
				t.Errorf("%s series %v is missing the %s label; it cannot be attributed to an exporter instance",
					mf.GetName(), m.GetLabel(), instanceLabelName)
				continue
			}
			if got != want {
				t.Errorf("%s carries %s=%q, want %q", mf.GetName(), instanceLabelName, got, want)
			}
		}
	}
	if seen == 0 {
		t.Fatal("no opnsense_exporter_logs_* series were gathered; the test built nothing to assert on")
	}
}

// Every self-metric built through the two logship constructor seams carries the
// instance label when they are handed the registerer Start builds (#395). This
// covers the pipeline metrics AND the shared receiver metrics, including the two
// GaugeFuncs (which are wrapped collectors, not vec children, so they are the ones
// most likely to slip through a const-label scheme).
func TestLogshipSelfMetrics_CarryInstanceLabel(t *testing.T) {
	base := prometheus.NewRegistry()
	reg := SelfMetricsRegisterer(base, "box-a")

	m := newMetrics(reg, queueBounds{
		capacity: 10, maxBytes: 100,
		length: func() float64 { return 0 },
		bytes:  func() float64 { return 0 },
	}, sourceNames{
		all:  []string{"syslog", "unbound"},
		poll: []string{"unbound"},
		gap:  []string{"unbound"},
	})
	// The last-* gauges are deliberately not pre-initialised (a zero there would read
	// as 1970), so touch them explicitly or the family would not be gathered at all.
	m.lastReceived.WithLabelValues("syslog").Set(1)
	m.lastExported.WithLabelValues("syslog").Set(1)

	// Two receivers sharing the parse/reject vecs, exactly as production does.
	NewReceiverMetrics(reg, "syslog", ReceiverVocab{Reasons: []string{"peer"}, Stages: []string{"envelope"}})
	NewReceiverMetrics(reg, "zenarmor", ReceiverVocab{Reasons: []string{"auth"}, Stages: []string{"bulk"}})

	assertEveryLogsSeriesCarriesInstance(t, base, "box-a")
}

// capture.New and enrich.NewMetrics are the two log self-metric constructors built
// outside Start. Exercise the real constructors through the exported composition-root
// seam so a new or renamed series cannot silently escape instance attribution.
func TestOutOfStartSelfMetrics_CarryInstanceLabel(t *testing.T) {
	base := prometheus.NewRegistry()
	reg := SelfMetricsRegisterer(base, "box-outside-start")

	capturer, err := capture.New(capture.Config{
		Dir:      t.TempDir(),
		MaxBytes: 1 << 20,
	}, reg, nil)
	if err != nil {
		t.Fatalf("capture.New: %v", err)
	}
	t.Cleanup(func() {
		if err := capturer.Close(); err != nil {
			t.Errorf("close capturer: %v", err)
		}
	})

	enrichMetrics := enrich.NewMetrics(reg)
	// LastRefresh is deliberately not pre-initialised because zero would mean 1970.
	// Touch one child so the gauge family joins the counters in the gathered contract.
	enrichMetrics.LastRefresh.WithLabelValues("rules").Set(1)

	assertEveryLogsSeriesCarriesInstance(t, base, "box-outside-start")
	series := gatherSeries(t, base)
	for _, prefix := range []string{
		"opnsense_exporter_logs_debug_",
		"opnsense_exporter_logs_enrich_",
	} {
		found := false
		for key := range series {
			if strings.HasPrefix(key, prefix) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no %s* series gathered; one out-of-Start constructor registered nothing", prefix)
		}
	}
}

// Two receivers must still SHARE the parse/reject collectors under the wrapping
// registerer rather than tripping duplicate registration — the wrapping registerer
// hands back a wrapped collector on conflict, so registerOrExisting's unwrap has to
// survive it (#395 keeps #280's shared-vec contract intact).
func TestLogshipSelfMetrics_ReceiversStillShareVecsUnderInstanceLabel(t *testing.T) {
	base := prometheus.NewRegistry()
	reg := SelfMetricsRegisterer(base, "box-a")

	a := NewReceiverMetrics(reg, "syslog", ReceiverVocab{Reasons: []string{"peer"}})
	b := NewReceiverMetrics(reg, "zenarmor", ReceiverVocab{Reasons: []string{"auth"}})
	if a.rejected != b.rejected {
		t.Fatal("the two receivers registered separate logs_rejected_total collectors")
	}
	a.Reject("peer")
	b.Reject("auth")

	s := gatherSeries(t, base)
	mustHave(t, s, `opnsense_exporter_logs_rejected_total{opnsense_instance="box-a",reason="peer",source="syslog"}`, 1)
	mustHave(t, s, `opnsense_exporter_logs_rejected_total{opnsense_instance="box-a",reason="auth",source="zenarmor"}`, 1)
}

func mustHave(t *testing.T, series map[string]float64, key string, want float64) {
	t.Helper()
	got, ok := series[key]
	if !ok {
		t.Errorf("%s is absent", key)
		return
	}
	if got != want {
		t.Errorf("%s = %v, want %v", key, got, want)
	}
}

// The wiring test: the invariant has to hold for the registerer Start actually
// installs, not only for one a test constructs by hand. Start is what wraps both the
// pipeline registry AND deps.Registerer, and a receiver registering through an
// unwrapped deps.Registerer is exactly the regression this catches.
func TestStart_WrapsBothRegisterersWithInstanceLabel(t *testing.T) {
	base := prometheus.NewRegistry()
	withRegistry(t, func(Deps) (Source, error) { return &fakeSource{name: "unbound"}, nil })
	withPushRegistry(t, func(d Deps) (PushSource, error) {
		return &receiverRegisteringPush{reg: d.Registerer}, nil
	})

	deps := testDeps()
	deps.Registerer = base
	cfg := testCfg()
	cfg.Sink = "stdout" // no OTLP endpoint needed; the fake source emits nothing

	stop, err := Start(context.Background(), cfg, nil, deps, "v", "box-b", base)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = stop(context.Background()) })

	waitFor(t, func() bool {
		return len(gatherSeries(t, base)) > 0 &&
			gatherSeries(t, base)[`opnsense_exporter_logs_rejected_total{opnsense_instance="box-b",reason="peer",source="pushfake"}`] == 0
	})
	assertEveryLogsSeriesCarriesInstance(t, base, "box-b")
}

// receiverRegisteringPush is a push source that builds ReceiverMetrics off
// deps.Registerer, the way the real syslog and zenarmor receivers do.
type receiverRegisteringPush struct{ reg prometheus.Registerer }

func (p *receiverRegisteringPush) Name() string { return "pushfake" }

func (p *receiverRegisteringPush) Run(ctx context.Context, _ func(Record)) error {
	NewReceiverMetrics(p.reg, "pushfake", ReceiverVocab{Reasons: []string{"peer"}, Stages: []string{"envelope"}})
	<-ctx.Done()
	return nil
}

// withPushRegistry swaps the package push-source registry for one test, mirroring
// withRegistry.
func withPushRegistry(t *testing.T, factories ...PushSourceFactory) {
	t.Helper()
	saved := registeredPushFactories
	registeredPushFactories = append([]PushSourceFactory(nil), factories...)
	t.Cleanup(func() { registeredPushFactories = saved })
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
