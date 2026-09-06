package flowlog

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v5/internal/flow"
	"github.com/rknightion/opnsense2otel/v5/internal/logship"
	"github.com/rknightion/opnsense2otel/v5/internal/options"
)

func rec(source flow.Source) flow.Record {
	return flow.Record{
		Source:  source,
		Proto:   6,
		SrcAddr: netip.MustParseAddr("192.0.2.1"),
		DstAddr: netip.MustParseAddr("203.0.113.9"),
		SrcPort: 5000,
		DstPort: 443,
		NF:      flow.Counters{TxBytes: 100, Present: true},
	}
}

// runBridge starts a bridge's Run and returns a captured-record sink plus a stop func.
func runBridge(t *testing.T, b *Bridge) (*[]logship.Record, func()) {
	t.Helper()
	var got []logship.Record
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		_ = b.Run(ctx, func(r logship.Record) { got = append(got, r) })
		close(done)
	}()
	// Wait until Run has captured the emit callback.
	for i := 0; i < 1000 && b.emit.Load() == nil; i++ {
		time.Sleep(time.Millisecond)
	}
	return &got, func() { cancel(); <-done }
}

// Mode off ships nothing even with an active pipeline.
func TestBridge_OffEmitsNothing(t *testing.T) {
	b := New() // defaults to off
	got, stop := runBridge(t, b)
	defer stop()
	b.Emit(rec(flow.SourceMerged))
	if len(*got) != 0 {
		t.Fatalf("mode off emitted %d records, want 0", len(*got))
	}
}

// per_flow ships one record, stamped with the flow subsystem and the per-record source
// override, carrying the flow attributes.
func TestBridge_PerFlowShipsWithSubsystemAndSource(t *testing.T) {
	b := New()
	b.Configure(LogModePerFlow, 0)
	got, stop := runBridge(t, b)
	defer stop()

	b.Emit(rec(flow.SourceMerged))
	if len(*got) != 1 {
		t.Fatalf("want 1 emitted record, got %d", len(*got))
	}
	r := (*got)[0]
	if r.Source != "merged" {
		t.Errorf("source override = %q, want merged", r.Source)
	}
	if r.Attributes[logship.AttrSubsystem] != subsystem {
		t.Errorf("subsystem = %q, want %q", r.Attributes[logship.AttrSubsystem], subsystem)
	}
	if r.Attributes["dst.port"] != "443" {
		t.Errorf("flow attributes missing: %v", r.Attributes)
	}
	if st := b.Stats(); st.Emitted != 1 {
		t.Errorf("Emitted = %d, want 1", st.Emitted)
	}
}

// A blocked flow raises severity above Info.
func TestBridge_BlockedRaisesSeverity(t *testing.T) {
	b := New()
	b.Configure(LogModePerFlow, 0)
	got, stop := runBridge(t, b)
	defer stop()

	r := rec(flow.SourceNetflow)
	r.Verdict = flow.VerdictBlock
	b.Emit(r)
	if (*got)[0].Severity != logship.SeverityWarn {
		t.Errorf("severity = %v, want Warn for a blocked flow", (*got)[0].Severity)
	}
}

// The per-window budget truncates over the cap and counts every truncation; metrics
// (elsewhere) are untouched. Removing the budget check ships all five.
func TestBridge_BudgetTruncatesAndCounts(t *testing.T) {
	b := New()
	b.Configure(LogModePerFlow, 3)
	fixed := time.Unix(1_700_000_000, 0)
	b.clock = func() time.Time { return fixed } // one budget window
	got, stop := runBridge(t, b)
	defer stop()

	for range 5 {
		b.Emit(rec(flow.SourceNetflow))
	}
	if len(*got) != 3 {
		t.Fatalf("budget of 3 shipped %d records, want 3", len(*got))
	}
	if st := b.Stats(); st.Emitted != 3 || st.Truncated != 2 {
		t.Fatalf("stats emitted/truncated = %d/%d, want 3/2", st.Emitted, st.Truncated)
	}
}

// A new budget window resets the allowance.
func TestBridge_BudgetResetsNextWindow(t *testing.T) {
	b := New()
	b.Configure(LogModePerFlow, 1)
	now := time.Unix(1_700_000_000, 0)
	b.clock = func() time.Time { return now }
	got, stop := runBridge(t, b)
	defer stop()

	b.Emit(rec(flow.SourceNetflow)) // window 1: allowed
	b.Emit(rec(flow.SourceNetflow)) // window 1: truncated
	now = now.Add(budgetWindow)     // advance to window 2
	b.Emit(rec(flow.SourceNetflow)) // window 2: allowed again
	if len(*got) != 2 {
		t.Fatalf("want 2 shipped across two windows, got %d", len(*got))
	}
}

// With no active pipeline (Run not started), Emit drops and counts it rather than
// panicking on a nil callback.
func TestBridge_DropsWhenNoPipeline(t *testing.T) {
	b := New()
	b.Configure(LogModePerFlow, 0)
	b.Emit(rec(flow.SourceNetflow))
	if st := b.Stats(); st.Dropped != 1 || st.Emitted != 0 {
		t.Fatalf("dropped/emitted = %d/%d, want 1/0", st.Dropped, st.Emitted)
	}
}

// --- #391: preserve flow-close event time on per-flow log records ---

// TestFlowTimestampFallback pins the fallback order End -> Start -> Observed -> zero
// (#391). End is the correlator's authoritative flow-close time (internal/flow/
// correlate.go finalize(): earliest start, latest end across fragments); Start and
// Observed are defensive fallbacks only, for an incomplete/synthetic record that
// never reached the correlator with a close time.
func TestFlowTimestampFallback(t *testing.T) {
	end := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	start := end.Add(-5 * time.Minute)
	observed := end.Add(30 * time.Minute) // arrival lag, e.g. #346's 30m41s

	cases := []struct {
		name string
		r    flow.Record
		want time.Time
	}{
		{
			name: "all three set: End wins",
			r:    flow.Record{Start: start, End: end, Observed: observed},
			want: end,
		},
		{
			name: "no End: falls back to Start",
			r:    flow.Record{Start: start, Observed: observed},
			want: start,
		},
		{
			name: "no End or Start: falls back to Observed",
			r:    flow.Record{Observed: observed},
			want: observed,
		},
		{
			name: "nothing set: zero",
			r:    flow.Record{},
			want: time.Time{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := flowTimestamp(tc.r); !got.Equal(tc.want) {
				t.Errorf("flowTimestamp() = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestBridge_EmitStampsEndAsTimestamp is the acceptance test from #391: a flow with
// three DISTINCT Start/End/Observed values must ship with logship.Record.Timestamp
// equal to End, never bridge/emission time (b.clock, or wall-clock at Emit).
func TestBridge_EmitStampsEndAsTimestamp(t *testing.T) {
	b := New()
	b.Configure(LogModePerFlow, 0)
	// Pin the bridge's own clock to a THIRD, distinct time so a bug that used the
	// budget clock instead of the flow's own time is caught, not accidentally passed.
	budgetClockTime := time.Date(2099, 1, 1, 0, 0, 0, 0, time.UTC)
	b.clock = func() time.Time { return budgetClockTime }
	got, stop := runBridge(t, b)
	defer stop()

	r := rec(flow.SourceMerged)
	r.Start = time.Date(2026, 7, 20, 11, 55, 0, 0, time.UTC)
	r.End = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	r.Observed = time.Date(2026, 7, 20, 12, 30, 0, 0, time.UTC)
	b.Emit(r)

	if len(*got) != 1 {
		t.Fatalf("want 1 emitted record, got %d", len(*got))
	}
	ts := (*got)[0].Timestamp
	if !ts.Equal(r.End) {
		t.Errorf("Timestamp = %v, want flow End %v", ts, r.End)
	}
	if ts.Equal(r.Start) || ts.Equal(r.Observed) || ts.Equal(budgetClockTime) {
		t.Errorf("Timestamp %v must be End specifically, not Start/Observed/budget-clock", ts)
	}
}

// A record with no times at all (never legitimately produced by either lane, but
// defensively handled) stamps a zero Timestamp. The configured sink substitutes
// emit-time under record.go's documented zero-value contract; the bridge must not
// invent a time first.
func TestBridge_EmitZeroTimesStampsZeroTimestamp(t *testing.T) {
	b := New()
	b.Configure(LogModePerFlow, 0)
	got, stop := runBridge(t, b)
	defer stop()

	b.Emit(rec(flow.SourceNetflow)) // rec() sets no times
	if !(*got)[0].Timestamp.IsZero() {
		t.Errorf("Timestamp = %v, want zero (emit-time fallback is the sink's job)", (*got)[0].Timestamp)
	}
}

// --- #411: start, end and derived duration log attributes ---

// TestBridge_EmitAddsIntervalAttributes is #411's acceptance test: a correlated
// multi-fragment flow (distinct Start/End as the correlator's finalize() would
// produce them) exports the earliest start, latest end, and their exact
// non-negative duration as log attributes -- fields, never labels.
func TestBridge_EmitAddsIntervalAttributes(t *testing.T) {
	b := New()
	b.Configure(LogModePerFlow, 0)
	got, stop := runBridge(t, b)
	defer stop()

	r := rec(flow.SourceMerged)
	r.Start = time.Date(2026, 7, 20, 11, 55, 30, 250_000_000, time.UTC)
	r.End = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	b.Emit(r)

	attrs := (*got)[0].Attributes
	if attrs["flow.start_time"] != "2026-07-20T11:55:30.25Z" {
		t.Errorf("flow.start_time = %q, want RFC3339Nano UTC start", attrs["flow.start_time"])
	}
	if attrs["flow.end_time"] != "2026-07-20T12:00:00Z" {
		t.Errorf("flow.end_time = %q, want RFC3339Nano UTC end", attrs["flow.end_time"])
	}
	if attrs["flow.duration_ms"] != "269750" {
		t.Errorf("flow.duration_ms = %q, want exact 269750 (4m29.75s)", attrs["flow.duration_ms"])
	}
}

// An incomplete record (only one of Start/End known -- e.g. a synthetic or
// defensively-incomplete record) omits every interval field rather than fabricate
// the missing half or a meaningless duration against it.
func TestBridge_EmitOmitsIntervalAttributesWhenIncomplete(t *testing.T) {
	b := New()
	b.Configure(LogModePerFlow, 0)
	got, stop := runBridge(t, b)
	defer stop()

	r := rec(flow.SourceNetflow)
	r.End = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC) // Start left zero
	b.Emit(r)

	attrs := (*got)[0].Attributes
	if v, ok := attrs["flow.start_time"]; ok {
		t.Errorf("flow.start_time = %q present, want absent (Start is zero)", v)
	}
	if attrs["flow.end_time"] != "2026-07-20T12:00:00Z" {
		t.Errorf("flow.end_time = %q, want the known End", attrs["flow.end_time"])
	}
	if v, ok := attrs["flow.duration_ms"]; ok {
		t.Errorf("flow.duration_ms = %q present, want absent (Start unknown, nothing to derive against)", v)
	}
}

// A record with no times at all omits all three interval fields.
func TestBridge_EmitOmitsIntervalAttributesWhenNoTimes(t *testing.T) {
	b := New()
	b.Configure(LogModePerFlow, 0)
	got, stop := runBridge(t, b)
	defer stop()

	b.Emit(rec(flow.SourceNetflow))

	attrs := (*got)[0].Attributes
	for _, k := range []string{"flow.start_time", "flow.end_time", "flow.duration_ms"} {
		if v, ok := attrs[k]; ok {
			t.Errorf("%s = %q present, want absent on a record with no times at all", k, v)
		}
	}
}

// A negative interval (End before Start -- a malformed or synthetic record) omits
// ONLY the derived duration; Start and End are each independently real, directly
// observed timestamps and are still reported, since withholding a directly-observed
// field over a problem specific to the derived one would hide real data.
func TestBridge_EmitRejectsNegativeDuration(t *testing.T) {
	b := New()
	b.Configure(LogModePerFlow, 0)
	got, stop := runBridge(t, b)
	defer stop()

	r := rec(flow.SourceMerged)
	r.Start = time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	r.End = time.Date(2026, 7, 20, 11, 59, 0, 0, time.UTC) // before Start
	b.Emit(r)

	attrs := (*got)[0].Attributes
	if v, ok := attrs["flow.duration_ms"]; ok {
		t.Errorf("flow.duration_ms = %q present, want absent for a negative interval", v)
	}
	if attrs["flow.start_time"] == "" || attrs["flow.end_time"] == "" {
		t.Errorf("start/end = %q/%q, want both still reported despite the negative interval",
			attrs["flow.start_time"], attrs["flow.end_time"])
	}
}

// Zero duration (a single-instant flow) is non-negative and must be reported, not
// treated as "no duration".
func TestBridge_EmitReportsZeroDuration(t *testing.T) {
	b := New()
	b.Configure(LogModePerFlow, 0)
	got, stop := runBridge(t, b)
	defer stop()

	r := rec(flow.SourceNetflow)
	same := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	r.Start, r.End = same, same
	b.Emit(r)

	if v, ok := (*got)[0].Attributes["flow.duration_ms"]; !ok || v != "0" {
		t.Errorf("flow.duration_ms = %q, want \"0\" for a zero-length interval", v)
	}
}

// gatherSeries returns every series reg would publish at /metrics, keyed
// `name{k="v",...}` with labels sorted -- mirrors internal/logship/metrics_test.go's
// helper of the same name (unexported, package-local, so duplicated here rather than
// imported: flowlog must not reach into logship's test-only internals).
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
			case m.GetGauge() != nil:
				out[key] = m.GetGauge().GetValue()
			case m.GetCounter() != nil:
				out[key] = m.GetCounter().GetValue()
			}
		}
	}
	return out
}

// TestBridge_PushPathAdvancesLastReceivedGauge is the #391 acceptance test proving
// the push path advances the pipeline's per-source liveness gauge for
// source="netflow"/"merged" once the bridge emits a record -- before the #391 fix
// Emit built a Timestamp-less logship.Record, and prior to #394/#395 the single
// unified gauge was stamped from that record Timestamp directly, so it stayed flat
// for these two sources and (separately) was forgeable by a sender-controlled clock.
//
// #394/#395 replaced that single gauge with logs_last_received_timestamp_seconds /
// logs_last_exported_timestamp_seconds, BOTH stamped from the EXPORTER's own clock at
// admission/acknowledgement (internal/logship/push.go's enqueue call, internal/
// logship/pipeline.go's shipBatch) -- never from the record's own event time. That is
// deliberate: an admitted flow record's Timestamp is sender/derivation-controlled
// (flowlog.flowTimestamp resolves it from End/Start/Observed), so letting it drive a
// liveness gauge would let a spoofed or stale flow pin the gauge into the future (or
// the past) and mask a real stall -- exactly the defect #394 fixed for the syslog
// receiver. So the correct assertion here is the INVERSE of the pre-#394 test: the
// gauge must reflect wall-clock "now" at admission, NOT the flow's fabricated End
// time (deliberately set far from "now" in this fixture), proving the anti-forgery
// property holds for flow-sourced pushes too.
//
// logs_last_exported_timestamp_seconds is not asserted here: it only advances once
// the emitter goroutine ships and the sink acknowledges the batch (shipBatch), which
// is exercised by the pipeline/push_test.go suite already covering that gauge
// generically for every source -- this test's job is only the flowlog-specific
// wiring (the per-record source override reaching netflow/merged at all).
//
// This drives the REAL pipeline (logship.Start) rather than reimplementing its
// gauge logic, so it exercises the exact code path the fix depends on. It uses the
// process-wide Sink singleton because that is the only *logship.PushSource the
// registered factory (flowlog.go's init()) will ever hand back to logship.Start.
func TestBridge_PushPathAdvancesLastReceivedGauge(t *testing.T) {
	const gaugeName = "opnsense_exporter_logs_last_received_timestamp_seconds"

	Sink.Configure(LogModePerFlow, 0)
	t.Cleanup(func() { Sink.Configure(LogModeOff, 0) })

	reg := prometheus.NewRegistry()
	cfg := &options.LogsConfig{
		Sink:         "stdout",
		PollInterval: 5 * time.Second,
		BufferSize:   100,
		BatchMax:     10,
	}
	stop, err := logship.Start(context.Background(), cfg, nil, logship.Deps{}, "test", "test-instance", reg)
	if err != nil {
		t.Fatalf("logship.Start: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = stop(ctx)
	})

	// Wait for the pipeline's push-source goroutine to capture Sink's emit callback
	// (mirrors runBridge's own busy-wait for the identical race).
	for i := 0; i < 1000 && Sink.emit.Load() == nil; i++ {
		time.Sleep(time.Millisecond)
	}
	if Sink.emit.Load() == nil {
		t.Fatal("pipeline never captured the push-source emit callback")
	}

	r := rec(flow.SourceNetflow)
	// End (and Start/Observed) are deliberately set FAR from wall-clock "now" -- if the
	// gauge ever regressed to reading the record's own event time (the pre-#394
	// behaviour, and the exact forgery #394 closed), this value leaking through would
	// be unmistakable: it is nowhere near the [before, after] window asserted below.
	end := time.Date(2026, 7, 20, 12, 0, 0, 0, time.UTC)
	r.Start = end.Add(-time.Minute)
	r.End = end
	r.Observed = end.Add(30 * time.Minute)
	before := time.Now()
	Sink.Emit(r)
	after := time.Now()

	// logship.Start wraps the registerer with the constant "opnsense_instance" label
	// (its instance argument) on every series alongside "source"; gatherSeries sorts
	// labels alphabetically, so opnsense_instance sorts before source.
	wantKey := fmt.Sprintf(`%s{opnsense_instance="test-instance",source="netflow"}`, gaugeName)
	deadline := time.Now().Add(2 * time.Second)
	var got float64
	var ok bool
	for time.Now().Before(deadline) {
		series := gatherSeries(t, reg)
		if got, ok = series[wantKey]; ok && got != 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ok {
		t.Fatalf("series %s never appeared", wantKey)
	}
	// The gauge must land in the exporter's own admission window, not at the flow's
	// fabricated End time (#394's anti-forgery contract -- see the test doc comment).
	// unixSeconds mirrors internal/logship's own (unexported) gauge encoding: whole
	// Unix seconds plus sub-second precision, not truncated.
	unixSeconds := func(t time.Time) float64 { return float64(t.UnixNano()) / float64(time.Second) }
	if lo, hi := unixSeconds(before), unixSeconds(after); got < lo || got > hi {
		t.Errorf("%s = %v, want between %v and %v (exporter admission clock, not the flow's own End time %v)",
			gaugeName, got, lo, hi, float64(end.Unix()))
	}
}
