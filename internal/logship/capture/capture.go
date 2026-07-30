// Package capture implements the logship debug-capture sink: an opt-in,
// disk-backed dump of the receiver signals the exporter does NOT yet model, so an
// operator can inspect real payloads and decide to model or drop them without a
// packet capture on a multi-GB/day stream (#330).
//
// Two things shape the whole package:
//
//   - It sits on the receivers' hot paths — a Zenarmor request goroutine, a syslog
//     read goroutine — where "nothing may block" is a hard rule (a synchronous disk
//     write there would stall the socket loop and drop datagrams). So Capture never
//     touches the disk itself: it copies what it needs, hands a finished entry to a
//     bounded channel, and a single writer goroutine owns every file. A full channel
//     DROPS (counted), it never blocks.
//   - It is a debug tool pointed at a bind mount, so it must never fill the disk. A
//     global byte cap governs the whole capture dir; once reached the writer STOPS
//     and keeps what is there (the first samples are the ones worth modelling), it
//     does not rotate the oldest away.
package capture

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"maps"
	"net/textproto"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// Receiver and Kind are the CLOSED label vocabulary the capture metrics are
// pre-initialised against (#280): a healthy capturer reports a flat 0 for a
// {receiver,kind} that has never fired rather than no series at all. Anything
// captured with a receiver/kind outside these sets still writes to disk — the
// vocabulary only bounds the metric labels, never what reaches the file.
const (
	ReceiverZenarmor = "zenarmor"
	ReceiverSyslog   = "syslog"
	ReceiverNetflow  = "netflow"

	// Zenarmor kinds.
	KindUnhandledEndpoint = "unhandled_endpoint"
	KindUnknownFamily     = "unknown_family"
	KindParseError        = "parse_error"

	// Syslog kind: a line no parser matched (unknown program, parser miss, or an
	// envelope that would not parse).
	KindUnparsed = "unparsed"

	// NetFlow kinds (#360). These MUST match the notice-kind constants in
	// internal/flow/netflow — capture_netflow_test.go pins that, since the two
	// packages cannot import each other's vocabulary without inverting the layering.
	// They are all code-defined: nothing a sender supplies ever becomes a kind.
	KindUnknownField       = "unknown_field"
	KindOptionsTemplate    = "options_template"
	KindUnknownFlowset     = "unknown_flowset"
	KindMalformed          = "malformed"
	KindUnsupportedVersion = "unsupported_version"
	KindVarLenRejected     = "var_len_rejected"
	KindDecodeError        = "decode_error"
	KindDatagram           = "datagram"
)

// capturedKinds is the {receiver -> kinds} matrix used only to pre-initialise the
// captured counter to zero. It is code-defined and closed.
var capturedKinds = map[string][]string{
	ReceiverZenarmor: {KindUnhandledEndpoint, KindUnknownFamily, KindParseError},
	ReceiverSyslog:   {KindUnparsed},
	ReceiverNetflow: {
		KindUnknownField, KindOptionsTemplate, KindUnknownFlowset,
		KindMalformed, KindUnsupportedVersion, KindVarLenRejected,
		KindDecodeError, KindDatagram,
	},
}

// dropReasons is the closed reason set for the dropped counter.
var dropReasons = []string{"buffer_full", "cap_reached", "write_error", "duplicate_shape"}

// receivers is the closed set the dropped counter is pre-initialised across.
var receivers = []string{ReceiverZenarmor, ReceiverSyslog, ReceiverNetflow}

// Defaults for the tunables a caller does not set.
const (
	defaultPerFileBytes int64 = 32 << 20 // 32 MiB: files stay small enough to copy off a box
	defaultChanBuf            = 1024     // deep enough to ride out a disk stall, bounded so a runaway peer cannot grow it
)

// Config configures a Capturer.
type Config struct {
	// Dir is the capture root. Per-receiver subdirectories are created beneath it.
	Dir string
	// MaxBytes caps the TOTAL bytes across the whole capture dir, counting bytes left
	// by previous runs. At or above it the writer stops (keep-oldest).
	MaxBytes int64
	// PerFileBytes rotates a receiver's current file once it reaches this size. Zero
	// uses defaultPerFileBytes.
	PerFileBytes int64
	// ChanBuf is the hand-off channel depth. Zero uses defaultChanBuf.
	ChanBuf int
}

// entry is one finished capture record, already detached from any caller-owned
// memory, on its way to the writer goroutine.
type entry struct {
	receiver string
	kind     string
	fields   map[string]any
}

// Capturer is the disk sink. A nil *Capturer is a no-op throughout, so a receiver
// with capture disabled calls the same methods unconditionally.
type Capturer struct {
	dir          string
	maxBytes     int64
	perFileBytes int64
	log          *slog.Logger

	ch   chan entry
	done chan struct{}

	m *metrics

	// shapes dedupes the CaptureShape path (#362). It lives here, on the process-wide
	// Capturer, rather than on ReceiverSink: For() mints a sink on demand (the NetFlow
	// lane calls it inline), so per-sink state would reset the window on every call and
	// silently dedupe nothing. Keys are (receiver, kind, shape), so two receivers
	// reporting the same text never suppress each other.
	shapes *ShapeLimiter

	// closeOnce guards Close so a double Close (defer + explicit) cannot double-close
	// the channel.
	closeOnce sync.Once
}

type metrics struct {
	captured *prometheus.CounterVec
	dropped  *prometheus.CounterVec
}

func newMetrics(reg prometheus.Registerer) *metrics {
	const ns = "opnsense_exporter"
	m := &metrics{
		captured: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_debug_captured_total",
			Help: "Total receiver signals written to the debug-capture dir, by receiver and kind. " +
				"Only signals the exporter does not model are captured (unhandled endpoints, unknown " +
				"families, parse errors, unparsed syslog lines); enabled with --logs.debug-capture.dir " +
				"plus a per-receiver --logs.<recv>.debug-capture.",
		}, []string{"receiver", "kind"}),
		dropped: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: ns, Name: "logs_debug_capture_dropped_total",
			Help: "Total debug-capture entries dropped rather than written, by receiver and reason: " +
				"buffer_full (disk could not keep up), cap_reached (--logs.debug-capture.max-bytes hit; " +
				"capture stops keeping the oldest samples), write_error (the file write failed), " +
				"duplicate_shape (a repeat of a message shape already captured this window; one example " +
				"is on disk, so this rate — not the file size — is what says how busy the lane is).",
		}, []string{"receiver", "reason"}),
	}
	if reg != nil {
		reg.MustRegister(m.captured, m.dropped)
	}
	for recv, kinds := range capturedKinds {
		for _, k := range kinds {
			m.captured.WithLabelValues(recv, k)
		}
	}
	for _, recv := range receivers {
		for _, r := range dropReasons {
			m.dropped.WithLabelValues(recv, r)
		}
	}
	return m
}

// New builds a Capturer and starts its writer goroutine. It fails only if the
// capture dir cannot be created — a caller that gets an error should treat capture
// as unavailable, never abort ingest for it.
func New(cfg Config, reg prometheus.Registerer, log *slog.Logger) (*Capturer, error) {
	if log == nil {
		log = slog.Default()
	}
	if strings.TrimSpace(cfg.Dir) == "" {
		return nil, fmt.Errorf("capture: dir is required")
	}
	if err := os.MkdirAll(cfg.Dir, 0o750); err != nil {
		return nil, fmt.Errorf("capture: create dir %s: %w", cfg.Dir, err)
	}
	perFile := cfg.PerFileBytes
	if perFile <= 0 {
		perFile = defaultPerFileBytes
	}
	buf := cfg.ChanBuf
	if buf <= 0 {
		buf = defaultChanBuf
	}
	c := &Capturer{
		dir:          cfg.Dir,
		maxBytes:     cfg.MaxBytes,
		perFileBytes: perFile,
		log:          log,
		ch:           make(chan entry, buf),
		done:         make(chan struct{}),
		m:            newMetrics(reg),
		shapes:       NewShapeLimiter(DefaultShapeWindow, DefaultMaxShapeKeys),
	}
	go c.run()
	return c, nil
}

// Capture enqueues one captured signal. It is safe to call from any goroutine and
// NEVER blocks: a full channel drops the entry and counts it. fields may carry
// []byte or json.RawMessage values (a raw document or line) — they are COPIED here,
// on the caller's goroutine, so the caller may reuse its buffer the instant Capture
// returns (the Zenarmor onBulk contract forbids retaining doc). A nil Capturer is a
// no-op.
func (c *Capturer) Capture(receiver, kind string, fields map[string]any) {
	if c == nil {
		return
	}
	e := entry{receiver: receiver, kind: kind, fields: copyFields(fields)}
	select {
	case c.ch <- e:
	default:
		// Disk cannot keep up. Dropping here, on the hot path, is the whole point of the
		// bounded channel: a debug tool must never be able to stall ingest.
		c.m.dropped.WithLabelValues(receiver, "buffer_full").Inc()
	}
}

// CaptureShape enqueues one captured signal only if this shape has not been captured
// in the current window; a suppressed repeat is counted as duplicate_shape and is
// NOT written (#362). Same contract as Capture otherwise: never blocks, copies what
// it needs, nil-safe.
//
// It is for a lane whose "unmodelled" is a CLASS of line rather than an event — the
// syslog unparsed capture, where most of a firewall's traffic is a program with no
// parser. One example of a shape is what an operator needs to decide whether to
// model it; the 11,484 repeats behind it only fill the shared byte cap and starve
// every other lane. Lanes that are already bounded must keep using Capture.
//
// Suppression happens HERE, on the caller's goroutine and before the channel, so the
// duplicate_shape counter is exact even when the writer is behind or has stopped at
// the cap.
func (c *Capturer) CaptureShape(receiver, kind, shape string, fields map[string]any) {
	if c == nil {
		return
	}
	if !c.shapes.Allow(receiver+"\x00"+kind+"\x00"+shape, time.Now()) {
		c.m.dropped.WithLabelValues(receiver, "duplicate_shape").Inc()
		return
	}
	c.Capture(receiver, kind, fields)
}

// ReceiverSink binds one receiver's name to a Capturer, so a receiver that captures
// need not know — or be able to get wrong — which name its entries are filed under.
// A nil *ReceiverSink is a no-op, exactly like a nil *Capturer.
type ReceiverSink struct {
	c        *Capturer
	receiver string
}

// For returns this Capturer as one receiver's sink. A nil Capturer yields a sink
// whose Capture does nothing, so a caller never has to branch on capture being off.
func (c *Capturer) For(receiver string) *ReceiverSink {
	return &ReceiverSink{c: c, receiver: receiver}
}

// Capture enqueues one entry under this sink's receiver. Same contract as
// Capturer.Capture: never blocks, copies what it needs, nil-safe.
func (s *ReceiverSink) Capture(kind string, fields map[string]any) {
	if s == nil {
		return
	}
	s.c.Capture(s.receiver, kind, fields)
}

// CaptureShape captures like Capture, but writes only the first occurrence of each
// shape per window; suppressed repeats are counted as duplicate_shape. See
// Capturer.CaptureShape for when a lane should want this and when it must not.
func (s *ReceiverSink) CaptureShape(kind, shape string, fields map[string]any) {
	if s == nil {
		return
	}
	s.c.CaptureShape(s.receiver, kind, shape, fields)
}

// redactedPlaceholder replaces every sensitive header value. It is a fixed constant
// rather than any function of the original value (a length, a truncated prefix, a
// hash) — #561's bar is IRREVERSIBLE, and a hash with no salt is a rainbow-table
// lookup away from reversible for anything low-entropy (a short Basic password), so
// the only value that carries no information about the secret is one that does not
// depend on it at all.
const redactedPlaceholder = "[REDACTED]"

// sensitiveHeaderNames is the closed, code-defined set of header names redacted from
// any captured "headers" field before it reaches the enqueue channel (#561). This is
// deliberately a single named table rather than scattered string comparisons at each
// capture call site, and it covers every receiver, not just Zenarmor's Basic auth:
//
//   - Authorization, Proxy-Authorization: reusable Basic/Bearer/Digest credentials —
//     the #561 finding.
//   - Cookie, Set-Cookie: session identifiers that are just as reusable as a bearer
//     token; Set-Cookie is a response header and would only appear here if some future
//     caller ever captures a response, but the cost of including it now is zero.
//   - X-Api-Key, X-Auth-Token: the two other conventional bearer-style header names —
//     no current receiver accepts either, but the whole point of fixing this at the
//     capture chokepoint (rather than in Zenarmor's unhandled-request path alone) is
//     that a future receiver's auth headers are covered without having to remember to
//     add a redaction call at its own capture site.
var sensitiveHeaderNames = map[string]bool{
	textproto.CanonicalMIMEHeaderKey("Authorization"):       true,
	textproto.CanonicalMIMEHeaderKey("Proxy-Authorization"): true,
	textproto.CanonicalMIMEHeaderKey("Cookie"):              true,
	textproto.CanonicalMIMEHeaderKey("Set-Cookie"):          true,
	textproto.CanonicalMIMEHeaderKey("X-Api-Key"):           true,
	textproto.CanonicalMIMEHeaderKey("X-Auth-Token"):        true,
}

// redactSensitiveHeaders returns a copy of a captured "headers" value with every
// sensitive header's values replaced by redactedPlaceholder. Header names are matched
// via textproto.CanonicalMIMEHeaderKey rather than assumed pre-canonicalised: net/http
// canonicalises http.Header for us today, but this is the shared chokepoint for every
// receiver's capture call, and nothing guarantees a future caller hands it a
// http.Header rather than some other case a wire sender chose. Non-map values are
// returned unchanged so a caller's malformed "headers" field is not itself an error
// here — capture must never fail a request over its own diagnostics.
func redactSensitiveHeaders(v any) any {
	src, ok := v.(map[string][]string)
	if !ok {
		return v
	}
	out := make(map[string][]string, len(src))
	for k, vals := range src {
		if sensitiveHeaderNames[textproto.CanonicalMIMEHeaderKey(k)] {
			out[k] = []string{redactedPlaceholder}
			continue
		}
		out[k] = vals
	}
	return out
}

// copyFields returns a shallow copy of fields with every []byte / json.RawMessage
// value duplicated, so the returned map shares no backing array with caller memory,
// and with any "headers" field redacted per redactSensitiveHeaders. This is the
// chokepoint every Capture/CaptureShape call passes through before the entry reaches
// the enqueue channel (#561): fixing it here, rather than at each receiver's own
// capture call site, means a raw credential can never reach the sink through any
// call path — present or future — that builds a "headers" field.
func copyFields(fields map[string]any) map[string]any {
	if len(fields) == 0 {
		return nil
	}
	out := make(map[string]any, len(fields))
	for k, v := range fields {
		switch b := v.(type) {
		case []byte:
			out[k] = embedBytes(b)
		case json.RawMessage:
			out[k] = embedBytes(b)
		default:
			out[k] = v
		}
		if k == "headers" {
			out[k] = redactSensitiveHeaders(out[k])
		}
	}
	return out
}

// embedBytes returns a detached copy of b for the capture record: valid JSON is
// embedded as a raw object/array (so a captured document reads as structured data),
// anything else — including a document that would not parse, which is exactly what a
// parse_error captures — is embedded as a JSON string so json.Marshal can never fail
// on it and the record is never silently lost.
func embedBytes(b []byte) any {
	cp := append([]byte(nil), b...)
	if json.Valid(cp) {
		return json.RawMessage(cp)
	}
	return string(cp)
}

// run is the single writer goroutine: it owns every file handle and the byte
// counter, so no locking is needed around either.
func (c *Capturer) run() {
	defer close(c.done)

	files := map[string]*rotatingFile{}
	total := c.existingBytes()
	stopped := total >= c.maxBytes && c.maxBytes > 0
	if stopped {
		c.log.Warn("debug capture starting already at its size cap; nothing will be captured until the dir is cleared",
			"dir", c.dir, "bytes", total, "max_bytes", c.maxBytes)
	}

	flushAll := func() {
		for _, f := range files {
			f.close()
		}
	}
	defer flushAll()

	for e := range c.ch {
		line, err := encode(e)
		if err != nil {
			c.m.dropped.WithLabelValues(e.receiver, "write_error").Inc()
			continue
		}
		if c.maxBytes > 0 && total+int64(len(line)) > c.maxBytes {
			if !stopped {
				stopped = true
				c.log.Warn("debug capture reached its size cap; capture paused, oldest samples kept",
					"dir", c.dir, "bytes", total, "max_bytes", c.maxBytes)
			}
			c.m.dropped.WithLabelValues(e.receiver, "cap_reached").Inc()
			continue
		}
		f := files[e.receiver]
		if f == nil {
			nf, ferr := newRotatingFile(c.dir, e.receiver, c.perFileBytes, c.log)
			if ferr != nil {
				c.m.dropped.WithLabelValues(e.receiver, "write_error").Inc()
				continue
			}
			files[e.receiver] = nf
			f = nf
		}
		n, werr := f.write(line)
		if werr != nil {
			c.m.dropped.WithLabelValues(e.receiver, "write_error").Inc()
			continue
		}
		total += int64(n)
		c.m.captured.WithLabelValues(e.receiver, e.kind).Inc()
	}
}

// existingBytes sums the sizes of every capture file already under the dir, so a
// restart resumes counting toward the cap rather than blowing past it.
func (c *Capturer) existingBytes() int64 {
	var total int64
	_ = filepath.WalkDir(c.dir, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil //nolint:nilerr // a walk error on one entry must not abort the sum
		}
		if !strings.HasSuffix(path, ".ndjson") {
			return nil
		}
		if info, ierr := d.Info(); ierr == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

// encode renders one entry as a single NDJSON line (trailing newline included). The
// top-level keys ts/receiver/kind are merged with the entry's fields; a field named
// ts/receiver/kind would be shadowed, so callers must not use those names.
func encode(e entry) ([]byte, error) {
	obj := make(map[string]any, len(e.fields)+3)
	maps.Copy(obj, e.fields)
	obj["ts"] = time.Now().UTC().Format(time.RFC3339Nano)
	obj["receiver"] = e.receiver
	obj["kind"] = e.kind
	b, err := json.Marshal(obj)
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// Close stops the writer and flushes. It is idempotent and safe to call from a
// defer even if the process is also closing explicitly. A nil Capturer is a no-op.
func (c *Capturer) Close() error {
	if c == nil {
		return nil
	}
	c.closeOnce.Do(func() {
		close(c.ch)
		<-c.done
	})
	return nil
}

// rotatingFile owns one receiver's current capture file and rolls to the next
// numbered file once perFileBytes is reached.
type rotatingFile struct {
	dir     string
	perFile int64
	log     *slog.Logger

	f   *os.File
	w   *bufio.Writer
	n   int64 // bytes in the current file
	idx int   // current file index
}

// newRotatingFile prepares a receiver's subdir and opens a fresh file whose index
// is one past the highest already present, so a new run never appends to (and risks
// corrupting) a file left by a crashed one.
func newRotatingFile(root, receiver string, perFile int64, log *slog.Logger) (*rotatingFile, error) {
	dir := filepath.Join(root, receiver)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	rf := &rotatingFile{dir: dir, perFile: perFile, log: log, idx: nextIndex(dir)}
	if err := rf.open(); err != nil {
		return nil, err
	}
	return rf, nil
}

func nextIndex(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	sort.Strings(names)
	max := -1
	for _, n := range names {
		var i int
		if _, err := fmt.Sscanf(n, "capture-%d.ndjson", &i); err == nil && i > max {
			max = i
		}
	}
	return max + 1
}

func (rf *rotatingFile) open() error {
	path := filepath.Join(rf.dir, fmt.Sprintf("capture-%03d.ndjson", rf.idx))
	// 0600: captures carry real network data (addresses, DNS queries, TLS SNI, HTTP
	// hosts). O_EXCL is deliberate — nextIndex guarantees a fresh name, and if the name
	// somehow exists we want the error, not to append to another run's file.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	rf.f = f
	rf.w = bufio.NewWriter(f)
	rf.n = 0
	return nil
}

// write appends one line, rotating first if the current file is full. It returns
// the bytes written so the caller can advance the global total.
func (rf *rotatingFile) write(line []byte) (int, error) {
	if rf.n > 0 && rf.n+int64(len(line)) > rf.perFile {
		rf.close()
		rf.idx++
		if err := rf.open(); err != nil {
			return 0, err
		}
	}
	n, err := rf.w.Write(line)
	rf.n += int64(n)
	if err != nil {
		return n, err
	}
	// Flush every line: a debug capture the operator is about to `tail -f` is worth the
	// syscall, and the volume (unknowns only) is low by construction.
	return n, rf.w.Flush()
}

func (rf *rotatingFile) close() {
	if rf.w != nil {
		_ = rf.w.Flush()
	}
	if rf.f != nil {
		_ = rf.f.Close()
	}
	rf.w = nil
	rf.f = nil
}
