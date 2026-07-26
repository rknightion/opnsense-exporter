// Package flowlog bridges normalized flow records (internal/flow) into the logship
// OTLP pipeline as log records. It is the log-emission counterpart of the flow metric
// rollup: the correlator hands finished records here, and this ships them on exactly
// the same rails as every other log lane — the shared bounded queue and OTLP sink.
//
// It exists as its own package, not inside internal/flow, because emitting a
// logship.Record means importing logship, and logship imports flow (for FlowSink), so
// flow must not import logship back. The attribute SCHEMA stays in flow
// (Record.LogAttributes); this package only packages it.
//
// The Bridge is a logship.PushSource whose Run captures the pipeline's emit callback.
// A package-level Sink singleton, configured by main and read by the registered
// factory, wires the two together without a Deps change — the same seam pattern as
// collector.Flow.
package flowlog

import (
	"context"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/flow"
	"github.com/rknightion/opnsense-exporter/internal/logship"
)

// subsystem is the coarse, code-defined grouping every flow log record carries. It is
// hoisted onto the OTLP resource so a tenant can select the stream on it; the
// per-record source ("netflow" or "merged") is the finer axis.
const subsystem = "flow"

// LogModeOff and LogModePerFlow are the two --flow.log-mode values. Off keeps the
// correlator running (it still feeds metrics) but ships no log records.
const (
	LogModeOff     = "off"
	LogModePerFlow = "per_flow"
)

// budgetWindow is the fixed span the --flow.max-logs-per-window budget counts over. It
// is not a flag: the budget is a flood guard on an unauthenticated ingress, and a
// per-minute cap is a rate an operator can reason about directly.
const budgetWindow = time.Minute

// Sink is the process-wide bridge, configured by main and returned by the registered
// push-source factory. A singleton for the same reason as collector.Flow: the factory
// runs inside logship.Start while the correlator that feeds it is built separately, so
// a package-level value is the seam that joins them without either importing the other.
var Sink = New()

// Bridge turns flow.Records into logship.Records and feeds them to the pipeline.
type Bridge struct {
	// emit is the pipeline's callback, non-nil only while Run is executing. Stored
	// atomically because Emit reads it from correlator/ticker goroutines while Run
	// writes it once at startup.
	emit atomic.Pointer[func(logship.Record)]

	mode   atomic.Value // string; LogModeOff until configured
	budget *budget
	clock  func() time.Time

	emitted   atomic.Uint64
	truncated atomic.Uint64 // dropped by the per-window budget
	dropped   atomic.Uint64 // no active pipeline emit (pre-start / post-shutdown)
}

// New returns an unconfigured bridge (mode off, no budget). Tests build their own; main
// uses the Sink singleton.
func New() *Bridge {
	b := &Bridge{clock: time.Now}
	b.mode.Store(LogModeOff)
	return b
}

// Configure sets the emission mode and per-window budget. maxPerWindow <= 0 is
// unlimited. Call before logship.Start so the factory sees the configured mode.
func (b *Bridge) Configure(mode string, maxPerWindow int) {
	if mode != LogModePerFlow {
		mode = LogModeOff
	}
	b.mode.Store(mode)
	b.budget = &budget{max: maxPerWindow, window: budgetWindow}
}

// Enabled reports whether the bridge should be registered as a push source. Off means
// no log records ship, so there is nothing for the pipeline to run.
func (b *Bridge) Enabled() bool { return b.mode.Load() == LogModePerFlow }

// Name identifies the lane; the per-record source override ("netflow"/"merged") is what
// actually stamps each record, so this is only the default and the metric key.
func (b *Bridge) Name() string { return subsystem }

// ExtraSourceNames declares the source values Emit stamps via the record override, so
// the pipeline pre-initialises their per-source counters to zero (#280) — a lane that
// has shipped nothing yet still reads a flat 0 rather than absent.
func (b *Bridge) ExtraSourceNames() []string { return []string{"netflow", "merged"} }

// Run captures the pipeline's emit callback and blocks until ctx is cancelled. It must
// return promptly on cancellation — the pipeline waits on it during shutdown.
func (b *Bridge) Run(ctx context.Context, emit func(logship.Record)) error {
	fn := emit
	b.emit.Store(&fn)
	<-ctx.Done()
	// Clear the handle so a late Emit counts as dropped rather than racing a
	// torn-down pipeline.
	b.emit.Store(nil)
	return nil
}

// Emit ships one flow record as a log record. Safe for concurrent callers. It never
// blocks beyond the pipeline's own non-blocking enqueue, matching the Sink.Observe
// contract, because it runs on the correlator's and expiry ticker's goroutines.
func (b *Bridge) Emit(r flow.Record) {
	if b.mode.Load() != LogModePerFlow {
		return
	}
	fn := b.emit.Load()
	if fn == nil {
		b.dropped.Add(1)
		return
	}
	if b.budget != nil && !b.budget.allow(b.clock()) {
		// Truncate, never sample: the drop is counted so a flood is visible rather than
		// a silently thinned stream (spec §10).
		b.truncated.Add(1)
		return
	}
	attrs := r.LogAttributes()
	attrs[logship.AttrSubsystem] = subsystem
	addIntervalAttributes(attrs, r)
	lr := logship.Record{
		Body:       r.LogBody(),
		Attributes: attrs,
		Source:     r.Source.String(),
		Timestamp:  flowTimestamp(r),
	}
	if r.LogSeverityBlocked() {
		lr.Severity = logship.SeverityWarn
	}
	(*fn)(lr)
	b.emitted.Add(1)
}

// flowTimestamp resolves a flow record's own event time for the emitted log record
// (#391). End is the correlator's authoritative flow-close time — finalize()
// (internal/flow/correlate.go) writes the EARLIEST start and LATEST end across every
// fragment it folded together, so End is "when this conversation last had traffic",
// exactly matching the Zenarmor lane's own end_time-first rule
// (internal/logship/zenarmor/parse.go). Start and Observed are defensive fallbacks
// only, for an incomplete/synthetic record that never reached the correlator with a
// close time; a genuine NetFlow or merged record always has End set.
//
// This deliberately never reads b.clock: that clock exists only to key the
// per-window log-flood budget and stamping it here would preserve the #391 defect
// (every record placed at pipeline time) under a different name. A zero return
// means "no time is known at all" and is left for the sink's own zero-value
// emit-time fallback (logship/record.go) to handle — this function never invents a
// time either.
func flowTimestamp(r flow.Record) time.Time {
	switch {
	case !r.End.IsZero():
		return r.End
	case !r.Start.IsZero():
		return r.Start
	case !r.Observed.IsZero():
		return r.Observed
	default:
		return time.Time{}
	}
}

// addIntervalAttributes adds the flow's covered interval to attrs as stable OTLP log
// attributes (#411): the flow-close event time already stamps the record's own
// Timestamp (#391), but the interval's START and its DURATION are otherwise lost,
// which blocks filtering long-lived flows or joining on the covered window without
// reconstructing it elsewhere.
//
// Naming follows logemit.go's existing "flow."-namespaced, dotted convention
// (flow.direction, flow.vlan, flow.fragments, …) and the codebase's established
// time-attribute format — internal/logship/ids.go already ships gap_start/gap_end
// as RFC3339Nano strings, so flow.start_time/flow.end_time match that precedent
// rather than inventing a new representation. flow.duration_ms is milliseconds
// because Start/End are firewall-clock timestamps with sub-second precision
// (FIRST_SWITCHED/LAST_SWITCHED); seconds would truncate every short-lived flow to 0.
//
// Everything here is Loki structured metadata (map[string]string), NEVER a label —
// same rule as every other key LogAttributes sets, and reinforced by #411's own
// scope: no new metric family or resource label may result from this.
//
// Absence over fabrication, twice over: an unset Start or End omits its own key
// rather than inventing a value (an incomplete/synthetic record legitimately lacks
// one), and a negative interval (End before Start — a malformed or synthetic record)
// omits ONLY flow.duration_ms. Start/End themselves are each independently real
// firewall timestamps and are still reported: withholding a directly-observed field
// because a DERIVED one turned out nonsensical would hide real data over a problem
// that is specifically the derived field's to reject.
func addIntervalAttributes(attrs map[string]string, r flow.Record) {
	if !r.Start.IsZero() {
		attrs["flow.start_time"] = r.Start.UTC().Format(time.RFC3339Nano)
	}
	if !r.End.IsZero() {
		attrs["flow.end_time"] = r.End.UTC().Format(time.RFC3339Nano)
	}
	if r.Start.IsZero() || r.End.IsZero() {
		return
	}
	if d := r.End.Sub(r.Start); d >= 0 {
		attrs["flow.duration_ms"] = strconv.FormatInt(d.Milliseconds(), 10)
	}
}

// Stats is the bridge's own health, published as self-metrics.
type Stats struct {
	Emitted   uint64
	Truncated uint64
	Dropped   uint64
}

// Stats reports counters.
func (b *Bridge) Stats() Stats {
	return Stats{
		Emitted:   b.emitted.Load(),
		Truncated: b.truncated.Load(),
		Dropped:   b.dropped.Load(),
	}
}

// budget is a fixed-window rate cap. Over max records in one window, allow returns
// false. max <= 0 is unlimited.
type budget struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	curWin int64
	count  int
}

func (bu *budget) allow(now time.Time) bool {
	if bu.max <= 0 {
		return true
	}
	w := now.UnixNano() / int64(bu.window)
	bu.mu.Lock()
	defer bu.mu.Unlock()
	if w != bu.curWin {
		bu.curWin = w
		bu.count = 0
	}
	if bu.count >= bu.max {
		return false
	}
	bu.count++
	return true
}

func init() {
	logship.RegisterPushSource(func(_ logship.Deps) (logship.PushSource, error) {
		if !Sink.Enabled() {
			return nil, nil
		}
		return Sink, nil
	})
}

var _ logship.PushSource = (*Bridge)(nil)
