package netflow

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"
)

// Debug capture for the NetFlow lane (#360).
//
// Two separate obligations live here, and only one of them is opt-in:
//
//   - ALWAYS ON: whatever the decoder could not interpret is counted (in Stats) and
//     logged, rate-limited. Before this, unknown template elements, options
//     templates and unknown control flowsets were stepped over in total silence, so
//     a box that started exporting something new said nothing anywhere.
//   - OPT-IN: --flow.netflow.debug-capture writes the raw datagram to the shared
//     debug-capture dir, so a real payload can be inspected and replayed. The
//     listener holds the only copy of those bytes — by the time anything downstream
//     sees a record, the wire form is gone.
//
// The capture path is deliberately on the listener rather than the decoder: the
// decoder is handed a payload it does not own and returns records, while the
// listener owns the datagram, the peer and the receive instant, which is exactly the
// frame flowanon needs to rebuild a fixture.

// CaptureMode selects what the listener writes to the debug-capture sink.
type CaptureMode int

const (
	// CaptureOff is the default and costs one integer comparison per datagram.
	CaptureOff CaptureMode = iota
	// CaptureUnidentified writes only datagrams carrying something the decoder could
	// not interpret. Bounded by how often the export surprises us — on a healthy box
	// that is a couple of datagrams at startup and nothing after — which is what
	// makes it the mode worth leaving on.
	CaptureUnidentified
	// CaptureAll writes every datagram. The fixture-generation and measurement mode:
	// deliberately heavy, turned on for a window, and bounded only by the capture
	// dir's byte cap.
	CaptureAll
)

// ParseCaptureMode resolves the flag value. An unrecognised mode is an error rather
// than a silent "off": a debug capture that quietly never happens is worse than one
// that refuses to start, because the operator only finds out when they go looking
// for the samples.
func ParseCaptureMode(s string) (CaptureMode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "off":
		return CaptureOff, nil
	case "unidentified":
		return CaptureUnidentified, nil
	case "all":
		return CaptureAll, nil
	default:
		return CaptureOff, fmt.Errorf("netflow: unknown debug-capture mode %q (want off, unidentified or all)", s)
	}
}

func (m CaptureMode) String() string {
	switch m {
	case CaptureUnidentified:
		return "unidentified"
	case CaptureAll:
		return "all"
	default:
		return "off"
	}
}

// CaptureSink is the slice of the debug-capture writer the listener needs. Taking an
// interface here keeps this package independent of internal/logship/capture and
// keeps the receiver name — which the sink owns — out of the listener entirely.
type CaptureSink interface {
	Capture(kind string, fields map[string]any)
}

// Capture entry field names. flowanon reads the first three back to rebuild a
// datagram frame, so they are a format, not a debug convenience.
//
// ts/receiver/kind are set by the capture writer at the top level and MUST NOT be
// used here — a field of the same name would be shadowed.
const (
	captureFieldPayload  = "payload_b64"
	captureFieldExporter = "exporter"
	captureFieldReceived = "received"
	captureFieldBytes    = "bytes"
	captureFieldNotices  = "unidentified"
	captureFieldError    = "error"
	captureFieldVersion  = "version"
	captureFieldSequence = "sequence"
	captureFieldSourceID = "source_id"
	captureFieldRecords  = "records"
)

// Listener-level notice kinds. These name a whole DATAGRAM that did not decode,
// where the decoder's own kinds (types.go) name something inside one that did.
const (
	UnidentifiedMalformed   = "malformed"
	UnidentifiedVersion     = "unsupported_version"
	UnidentifiedVarLen      = "var_len_rejected"
	UnidentifiedDecodeError = "decode_error"

	// CapturedDatagram is the kind written for an ordinary, fully understood
	// datagram — which only "all" mode ever writes.
	CapturedDatagram = "datagram"
)

// noticePriority orders the kinds from "this datagram is structurally broken" down
// to "this datagram is fine but declares something we skip". The capture entry
// carries every notice; its KIND label is the highest-priority one, so a file
// grepped by kind surfaces the worst thing about each entry.
var noticePriority = map[string]int{
	UnidentifiedMalformed:   0,
	UnidentifiedVersion:     1,
	UnidentifiedVarLen:      2,
	UnidentifiedDecodeError: 3,
	UnidentifiedField:       4,
	UnidentifiedOptions:     5,
	UnidentifiedFlowset:     6,
}

func primaryNoticeKind(notices []Unidentified) string {
	best, bestRank := CapturedDatagram, len(noticePriority)+1
	for _, n := range notices {
		rank, ok := noticePriority[n.Kind]
		if !ok {
			rank = len(noticePriority)
		}
		if rank < bestRank {
			best, bestRank = n.Kind, rank
		}
	}
	return best
}

// errorNoticeKind maps a decode error to its notice kind. ErrShortPacket folds into
// "malformed" because that is where the decoder counts it (Stats.Malformed) — the
// notice vocabulary and the counters must not disagree about the same datagram.
func errorNoticeKind(err error) string {
	switch {
	case errors.Is(err, ErrShortPacket), errors.Is(err, ErrMalformed):
		return UnidentifiedMalformed
	case errors.Is(err, ErrUnsupportedVersion):
		return UnidentifiedVersion
	case errors.Is(err, ErrVariableLength):
		return UnidentifiedVarLen
	default:
		return UnidentifiedDecodeError
	}
}

// --- rate-limited logging --------------------------------------------------

const (
	// unidentifiedLogInterval is how long the same notice stays quiet after it has
	// been logged. The FIRST occurrence always logs; a repeat is the same fact.
	unidentifiedLogInterval = 15 * time.Minute
	// maxNoticeKeys bounds the limiter's map. NetFlow is unauthenticated, so a sender
	// can mint arbitrary field and flowset ids; without a bound, "one key per
	// distinct notice" is one map entry per id the attacker chooses. Past the bound
	// every further notice shares one folded key, so the log still says something is
	// happening and memory stays flat.
	maxNoticeKeys = 64
)

// noticeLimiter suppresses repeats of the same notice. It is shared by the decode
// workers, so every method takes the mutex.
type noticeLimiter struct {
	mu   sync.Mutex
	max  int
	seen map[string]time.Time
}

func newNoticeLimiter(max int) *noticeLimiter {
	if max <= 0 {
		max = maxNoticeKeys
	}
	return &noticeLimiter{max: max, seen: make(map[string]time.Time)}
}

// allow reports whether this notice should be logged now, and records that it was.
func (n *noticeLimiter) allow(u Unidentified, now time.Time) bool {
	key := fmt.Sprintf("%s/%d", u.Kind, u.Detail)
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, known := n.seen[key]; !known && len(n.seen) >= n.max {
		// Folded: everything past the bound shares one key. The log line still names
		// the real kind and detail — only the SUPPRESSION is shared.
		key = "other"
	}
	last, known := n.seen[key]
	if known && now.Sub(last) < unidentifiedLogInterval {
		return false
	}
	n.seen[key] = now
	return true
}

func (n *noticeLimiter) size() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.seen)
}

// --- the listener's hook ---------------------------------------------------

// note is called once per datagram with whatever the decoder could not interpret.
// It is the whole of the #360 behaviour: log (always, rate-limited) and capture
// (only when a mode is configured).
//
// With capture off and nothing unidentified — the overwhelmingly common case — this
// is a length check and a mode comparison.
func (l *Listener) note(payload []byte, peer netip.Addr, recv time.Time,
	notices []Unidentified, dg *Datagram, decErr error,
) {
	if len(notices) == 0 && l.cfg.CaptureMode != CaptureAll {
		return
	}
	l.logUnidentified(peer, recv, notices)
	// Reaching here means either something was unidentified or the mode is "all", so
	// the mode/sink check is all that is left to decide.
	if l.cfg.CaptureMode == CaptureOff || l.cfg.Capture == nil {
		return
	}
	l.cfg.Capture.Capture(primaryNoticeKind(notices),
		captureFields(payload, peer, recv, notices, dg, decErr))
}

func (l *Listener) logUnidentified(peer netip.Addr, recv time.Time, notices []Unidentified) {
	if len(notices) == 0 {
		return
	}
	var loggable []Unidentified
	for _, u := range notices {
		if l.notices.allow(u, recv) {
			loggable = append(loggable, u)
		}
	}
	if len(loggable) == 0 {
		return
	}
	attrs := []any{
		"exporter", peer.String(),
		"unidentified", formatNotices(loggable),
	}
	// Only suggest the capture when there ISN'T one. Telling an operator who is
	// already capturing to turn on capture reads as the message not knowing what the
	// exporter is doing, which is the fastest way to make a diagnostic line ignored.
	if l.cfg.CaptureMode == CaptureOff {
		attrs = append(attrs,
			"capture", "enable --flow.netflow.debug-capture=unidentified to keep the datagrams")
	} else {
		attrs = append(attrs, "capture", l.cfg.CaptureMode.String())
	}
	l.log.Warn("netflow export carried something this decoder does not model; "+
		"the records behind it still decoded, the unmodelled part was stepped over",
		attrs...)
}

// formatNotices renders notices for the log line as "kind:detail" pairs. The detail
// is a sender-supplied number and appears HERE and in the capture file only — never
// as a metric label, because the socket is unauthenticated and a label value from an
// unauthenticated sender is unbounded cardinality.
func formatNotices(notices []Unidentified) string {
	parts := make([]string, 0, len(notices))
	for _, u := range notices {
		if u.Detail == 0 {
			parts = append(parts, u.Kind)
			continue
		}
		parts = append(parts, fmt.Sprintf("%s:%d", u.Kind, u.Detail))
	}
	return strings.Join(parts, ",")
}

// captureFields builds one capture entry.
//
// The payload is base64, NOT raw bytes: the capture writer embeds a []byte as a Go
// string when it is not valid JSON, and json.Marshal replaces invalid UTF-8 with
// U+FFFD — which would silently destroy the very datagram the capture exists to
// preserve. base64 also makes the entry a plain JSON string, so a capture file is
// still one-line-per-datagram greppable.
func captureFields(payload []byte, peer netip.Addr, recv time.Time,
	notices []Unidentified, dg *Datagram, decErr error,
) map[string]any {
	f := map[string]any{
		captureFieldPayload:  base64.StdEncoding.EncodeToString(payload),
		captureFieldExporter: peer.String(),
		captureFieldReceived: recv.UTC().Format(time.RFC3339Nano),
		captureFieldBytes:    len(payload),
	}
	if len(notices) > 0 {
		f[captureFieldNotices] = formatNotices(notices)
	}
	if decErr != nil {
		f[captureFieldError] = decErr.Error()
	}
	if dg != nil {
		f[captureFieldVersion] = int(dg.Version)
		f[captureFieldSequence] = dg.Sequence
		f[captureFieldSourceID] = dg.SourceID
		f[captureFieldRecords] = len(dg.Records)
	}
	return f
}
