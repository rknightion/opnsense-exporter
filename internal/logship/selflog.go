package logship

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// SelfLogSource and SelfLogSubsystem are the fixed resource dimensions for
// the exporter's own slog records. They are intentionally closed values: the
// records are process diagnostics, not data received from a firewall or sender.
const (
	SelfLogSource    = "exporter"
	SelfLogSubsystem = "self"
	selfLogRedacted  = "[REDACTED]"

	// selfLogPendingLimit is the startup buffer for records emitted after the
	// handler is installed but before logship.Start binds it to the pipeline.
	// A process can log during configuration and client construction, so dropping
	// the oldest records at a fixed bound is preferable to allowing startup
	// logging to become an unbounded heap allocation.
	selfLogPendingLimit = 256
)

// SelfLogHandler keeps the normal slog handler (normally the configured stderr
// handler) and optionally submits the same records to the shared log pipeline.
// It is installed by the composition root before startup logging begins and is
// bound by logship.Start once the existing queue and OTLP sink are ready.
//
// The adapter never calls Sink.Emit directly. Binding to the pipeline queue is
// what preserves the existing record-size limits, queue overflow accounting,
// delivery retry policy and shipped/dropped counters.
type SelfLogHandler struct {
	next  slog.Handler
	state *selfLogState
	attrs []slog.Attr
	group []string
}

type selfLogState struct {
	mu sync.Mutex
	// drained is signaled when the last submission that acquired enqueue returns.
	// Unbind waits on it before allowing its caller to close the shared queue.
	drained *sync.Cond

	enqueue          func(Entry) bool
	pending          []Record
	closed           bool
	inFlight         int
	overflowReported bool
}

// NewSelfLogHandler wraps next with the opt-in self-log adapter. The adapter is
// active only after Bind is called; records emitted before then are retained up
// to selfLogPendingLimit. A nil next is replaced with a discard handler, which
// keeps tests and defensive callers from panicking while preserving the sink
// path's behaviour.
func NewSelfLogHandler(next slog.Handler) *SelfLogHandler {
	if next == nil {
		next = slog.NewTextHandler(io.Discard, nil)
	}
	state := &selfLogState{}
	state.drained = sync.NewCond(&state.mu)
	return &SelfLogHandler{
		next:  next,
		state: state,
	}
}

// DiagnosticLogger returns a logger using the wrapped stderr handler without
// the self-log forwarding layer. The log pipeline uses this logger for sink,
// retry and shutdown diagnostics: if those diagnostics were submitted to the
// same failing sink, each failed attempt could manufacture another self-log
// record. Keeping this one-way path is the recursion guard for asynchronous
// delivery failures.
func (h *SelfLogHandler) DiagnosticLogger() *slog.Logger {
	if h == nil {
		return slog.Default()
	}
	return slog.New(h.next)
}

// Bind attaches the handler to a pipeline enqueue function and drains records
// buffered during startup. The callback must be non-blocking and must not log
// through this handler; the shared pipeline's enqueue path satisfies that
// contract because logship builds the pipeline with DiagnosticLogger. That
// contract is the whole recursion guard — there is no runtime re-entrancy flag,
// because a shared one would drop records logged concurrently by unrelated
// goroutines.
func (h *SelfLogHandler) Bind(enqueue func(Entry) bool) {
	if h == nil {
		return
	}
	h.state.mu.Lock()
	if h.state.closed {
		h.state.mu.Unlock()
		return
	}
	h.state.enqueue = enqueue
	pending := append([]Record(nil), h.state.pending...)
	h.state.pending = nil
	h.state.mu.Unlock()

	for _, record := range pending {
		h.submit(record)
	}
}

// Unbind stops new records from entering a pipeline that is being shut down.
// Records already admitted remain owned by the pipeline and are drained there;
// records emitted after this point still reach stderr through next.
func (h *SelfLogHandler) Unbind() {
	if h == nil {
		return
	}
	h.state.mu.Lock()
	h.state.enqueue = nil
	h.state.pending = nil
	h.state.closed = true
	for h.state.inFlight > 0 {
		h.state.drained.Wait()
	}
	h.state.mu.Unlock()
}

// Enabled preserves the wrapped handler's level filtering. A record that would
// not reach stderr is not copied into the OTLP stream either.
func (h *SelfLogHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.next.Enabled(ctx, level)
}

// Handle writes to stderr first, then submits a converted logship record. The
// stderr write remains authoritative when the optional remote path is absent
// or unavailable.
func (h *SelfLogHandler) Handle(ctx context.Context, record slog.Record) error {
	err := h.next.Handle(ctx, record)
	h.submit(selfLogRecord(record, h.attrs, h.group))
	return err
}

// WithAttrs preserves attributes for stderr through the wrapped handler and
// separately retains them for the converted Record. slog's Handler contract
// permits implementations to pre-bind attributes, so omitting them here would
// make logger.With("component", ...) disappear from OTLP self-logs.
func (h *SelfLogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	c := &SelfLogHandler{
		next:  h.next.WithAttrs(attrs),
		state: h.state,
		attrs: append([]slog.Attr(nil), h.attrs...),
		group: append([]string(nil), h.group...),
	}
	c.attrs = append(c.attrs, groupedSelfLogAttrs(h.group, attrs)...)
	return c
}

// WithGroup mirrors the wrapped handler and records the group path for the
// flattened string attributes carried by logship.Record.
func (h *SelfLogHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	return &SelfLogHandler{
		next:  h.next.WithGroup(name),
		state: h.state,
		attrs: append([]slog.Attr(nil), h.attrs...),
		group: append(append([]string(nil), h.group...), name),
	}
}

// submit is deliberately the only route into the shared queue. Recursion is
// prevented structurally rather than by a runtime flag: the pipeline is
// constructed with DiagnosticLogger, so its own ingest and sink diagnostics
// never re-enter this handler. A process-wide re-entrancy flag cannot tell
// re-entry from concurrency, so it would silently drop a record logged by an
// unrelated goroutine while another goroutine was inside enqueue.
func (h *SelfLogHandler) submit(record Record) {
	if h == nil {
		return
	}
	h.state.mu.Lock()
	if h.state.closed {
		h.state.mu.Unlock()
		return
	}
	enqueue := h.state.enqueue
	if enqueue == nil {
		reportOverflow := false
		if len(h.state.pending) >= selfLogPendingLimit {
			copy(h.state.pending, h.state.pending[1:])
			h.state.pending = h.state.pending[:selfLogPendingLimit-1]
			if !h.state.overflowReported {
				h.state.overflowReported = true
				reportOverflow = true
			}
		}
		h.state.pending = append(h.state.pending, record)
		h.state.mu.Unlock()
		if reportOverflow {
			h.reportStartupOverflow()
		}
		return
	}
	h.state.inFlight++
	h.state.mu.Unlock()

	defer h.finishSubmit()
	_ = enqueue(Entry{Source: SelfLogSource, Record: record})
}

// reportStartupOverflow writes directly to the wrapped non-forwarding handler.
// It deliberately does not use slog.New(h): the loss diagnostic must not enter
// the full startup buffer and evict another record while reporting the eviction.
func (h *SelfLogHandler) reportStartupOverflow() {
	record := slog.NewRecord(time.Now(), slog.LevelWarn, "self-log startup buffer overflow: oldest record discarded", 0)
	_ = h.next.Handle(context.Background(), record)
}

func (h *SelfLogHandler) finishSubmit() {
	h.state.mu.Lock()
	h.state.inFlight--
	if h.state.inFlight == 0 {
		h.state.drained.Broadcast()
	}
	h.state.mu.Unlock()
}

func selfLogRecord(record slog.Record, bound []slog.Attr, group []string) Record {
	attrs := make(map[string]string, record.NumAttrs()+len(bound)+1)
	// Handler.WithAttrs semantics put bound attributes before attributes on the
	// record. Iterating in that order means a record-level duplicate wins, as it
	// does for the wrapped slog handler. Bound attributes already carry their
	// group wrapper (see groupedSelfLogAttrs); record attributes need the active
	// WithGroup path applied here.
	for _, attr := range bound {
		flattenSelfLogAttr(attrs, "", attr)
	}
	recordPrefix := strings.Join(group, ".")
	record.Attrs(func(attr slog.Attr) bool {
		flattenSelfLogAttr(attrs, recordPrefix, attr)
		return true
	})

	// Resource identity is controlled by Entry.Source and the OTLP sink. A
	// process logger must not be able to accidentally override it through a
	// structured attribute, and all other hoisted dimensions are irrelevant for
	// the fixed self stream.
	delete(attrs, attrSource)
	delete(attrs, attrServiceName)
	delete(attrs, attrServiceInstanceID)
	delete(attrs, AttrAction)
	delete(attrs, AttrDeviceCategory)
	delete(attrs, AttrInterface)
	attrs[AttrSubsystem] = SelfLogSubsystem

	return Record{
		Timestamp:  record.Time,
		Body:       record.Message,
		Attributes: attrs,
		Severity:   selfLogSeverity(record.Level),
	}
}

func selfLogSeverity(level slog.Level) Severity {
	switch {
	case level < slog.LevelDebug:
		return SeverityTrace
	case level < slog.LevelInfo:
		return SeverityDebug
	case level < slog.LevelWarn:
		return SeverityInfo
	case level < slog.LevelError:
		return SeverityWarn
	default:
		return SeverityError
	}
}

func groupedSelfLogAttrs(group []string, attrs []slog.Attr) []slog.Attr {
	if len(group) == 0 {
		return append([]slog.Attr(nil), attrs...)
	}
	return []slog.Attr{{Key: strings.Join(group, "."), Value: slog.GroupValue(attrs...)}}
}

func flattenSelfLogAttr(dst map[string]string, prefix string, attr slog.Attr) {
	value := attr.Value.Resolve()
	key := joinSelfLogAttrKey(prefix, attr.Key)
	if value.Kind() == slog.KindGroup {
		for _, child := range value.Group() {
			flattenSelfLogAttr(dst, key, child)
		}
		return
	}
	if key == "" {
		return
	}
	dst[key] = sanitizeSelfLogValue(formatSelfLogValue(value))
}

// sanitizeSelfLogValue removes credentials from absolute URLs before a
// converted record can reach either the startup buffer or the live pipeline.
// Only URL components with credential semantics are changed; ordinary strings
// and the URL's scheme, host, path and non-sensitive query parameters survive.
func sanitizeSelfLogValue(value string) string {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return value
	}

	changed := false
	if parsed.User != nil {
		parsed.User = url.User(selfLogRedacted)
		changed = true
	}
	if rawQuery, redacted := redactSelfLogURLQuery(parsed.RawQuery); redacted {
		parsed.RawQuery = rawQuery
		changed = true
	}
	if !changed {
		return value
	}
	return parsed.String()
}

func redactSelfLogURLQuery(rawQuery string) (string, bool) {
	parts := strings.Split(rawQuery, "&")
	changed := false
	for i, part := range parts {
		rawKey, _, hasValue := strings.Cut(part, "=")
		if !hasValue {
			continue
		}
		key, err := url.QueryUnescape(rawKey)
		if err != nil || !opnsense.SensitiveConfigKey(key) {
			continue
		}
		parts[i] = rawKey + "=" + url.QueryEscape(selfLogRedacted)
		changed = true
	}
	return strings.Join(parts, "&"), changed
}

func joinSelfLogAttrKey(prefix, key string) string {
	switch {
	case prefix == "":
		return key
	case key == "":
		return prefix
	default:
		return prefix + "." + key
	}
}

func formatSelfLogValue(value slog.Value) string {
	switch value.Kind() {
	case slog.KindString:
		return value.String()
	case slog.KindBool:
		return strconv.FormatBool(value.Bool())
	case slog.KindInt64:
		return strconv.FormatInt(value.Int64(), 10)
	case slog.KindUint64:
		return strconv.FormatUint(value.Uint64(), 10)
	case slog.KindFloat64:
		return strconv.FormatFloat(value.Float64(), 'g', -1, 64)
	case slog.KindDuration:
		return value.Duration().String()
	case slog.KindTime:
		return value.Time().UTC().Format(time.RFC3339Nano)
	default:
		return fmt.Sprint(value.Any())
	}
}
