package netflow

import (
	"context"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- test doubles ----------------------------------------------------------

type recordedCapture struct {
	kind   string
	fields map[string]any
}

type fakeSink struct {
	mu   sync.Mutex
	seen []recordedCapture
}

func (f *fakeSink) Capture(kind string, fields map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen = append(f.seen, recordedCapture{kind: kind, fields: fields})
}

func (f *fakeSink) all() []recordedCapture {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedCapture(nil), f.seen...)
}

// countingHandler records how many WARN-or-above lines were emitted and the last
// message, so the always-on logging path can be asserted without a live logger.
type countingHandler struct {
	mu   sync.Mutex
	msgs []string
	attr []map[string]string
}

func (h *countingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *countingHandler) Handle(_ context.Context, r slog.Record) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	attrs := map[string]string{}
	r.Attrs(func(a slog.Attr) bool {
		attrs[a.Key] = a.Value.String()
		return true
	})
	h.msgs = append(h.msgs, r.Message)
	h.attr = append(h.attr, attrs)
	return nil
}

func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *countingHandler) WithGroup(string) slog.Handler      { return h }

func (h *countingHandler) count() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.msgs)
}

func (h *countingHandler) lastAttrs() map[string]string {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.attr) == 0 {
		return nil
	}
	return h.attr[len(h.attr)-1]
}

// noticingDecoder returns a datagram carrying whatever notices the test wants, or an
// error. The listener's capture decisions are about what the decoder REPORTED, not
// about wire bytes, so a fake keeps the two concerns apart. The decode workers read
// its fields while a test may be changing them mid-run, so both sit behind a mutex.
type noticingDecoder struct {
	mu      sync.Mutex
	notices []Unidentified
	err     error
}

func (n *noticingDecoder) setNotices(u []Unidentified) {
	n.mu.Lock()
	defer n.mu.Unlock()
	n.notices = u
}

func (n *noticingDecoder) Decode([]byte, netip.Addr, time.Time) (*Datagram, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.err != nil {
		return nil, n.err
	}
	return &Datagram{Version: V9, Sequence: 7, SourceID: 3, Unidentified: n.notices,
		Records: []Record{{Proto: 6}}}, nil
}

// --- capture modes ---------------------------------------------------------

func TestListener_CaptureOffWritesNothing(t *testing.T) {
	sink := &fakeSink{}
	dec := &noticingDecoder{notices: []Unidentified{{Kind: UnidentifiedField, Detail: 61}}}
	l := newTestListener(t, ListenerConfig{Capture: sink}, dec, nil)

	send(t, l.Addr(), []byte{0, 9, 1, 2})
	waitFor(t, "the datagram to be decoded", func() bool { return l.Stats().Datagrams == 1 })
	time.Sleep(20 * time.Millisecond)

	if got := len(sink.all()); got != 0 {
		t.Fatalf("capture mode off wrote %d entries, want 0", got)
	}
}

func TestListener_UnidentifiedModeWritesOnlySurprisingDatagrams(t *testing.T) {
	sink := &fakeSink{}
	clean := &noticingDecoder{}
	l := newTestListener(t, ListenerConfig{Capture: sink, CaptureMode: CaptureUnidentified}, clean, nil)

	send(t, l.Addr(), []byte{0, 9, 1, 2})
	waitFor(t, "the clean datagram", func() bool { return l.Stats().Datagrams == 1 })
	time.Sleep(20 * time.Millisecond)
	if got := len(sink.all()); got != 0 {
		t.Fatalf("a fully understood datagram was captured in unidentified mode (%d entries)", got)
	}

	clean.setNotices([]Unidentified{{Kind: UnidentifiedOptions, Detail: 1}})
	send(t, l.Addr(), []byte{0, 9, 3, 4})
	waitFor(t, "the surprising datagram to be captured", func() bool { return len(sink.all()) == 1 })

	got := sink.all()[0]
	if got.kind != UnidentifiedOptions {
		t.Fatalf("kind = %q, want %q", got.kind, UnidentifiedOptions)
	}
}

func TestListener_AllModeWritesEveryDatagram(t *testing.T) {
	sink := &fakeSink{}
	l := newTestListener(t, ListenerConfig{Capture: sink, CaptureMode: CaptureAll}, &noticingDecoder{}, nil)

	send(t, l.Addr(), []byte{0, 9, 1, 2})
	send(t, l.Addr(), []byte{0, 9, 3, 4})
	waitFor(t, "both datagrams to be captured", func() bool { return len(sink.all()) == 2 })

	if k := sink.all()[0].kind; k != CapturedDatagram {
		t.Fatalf("kind = %q, want %q for an ordinary datagram", k, CapturedDatagram)
	}
}

// The capture must carry enough to rebuild the datagram: flowanon reads exactly
// these three fields back.
func TestListener_CaptureCarriesTheReplayableFrame(t *testing.T) {
	sink := &fakeSink{}
	l := newTestListener(t, ListenerConfig{Capture: sink, CaptureMode: CaptureAll}, &noticingDecoder{}, nil)

	payload := []byte{0x00, 0x09, 0xff, 0xfe, 0x80, 0x01}
	send(t, l.Addr(), payload)
	waitFor(t, "the capture", func() bool { return len(sink.all()) == 1 })

	f := sink.all()[0].fields
	b64, ok := f[captureFieldPayload].(string)
	if !ok {
		t.Fatalf("%s is %T, want a base64 string", captureFieldPayload, f[captureFieldPayload])
	}
	// Base64, NOT the raw bytes: capture.embedBytes would render a non-UTF-8 payload
	// as a Go string, and json.Marshal replaces invalid bytes with U+FFFD — silently
	// destroying exactly the datagram we captured it to inspect.
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("payload is not base64: %v", err)
	}
	if string(raw) != string(payload) {
		t.Fatalf("payload round-trip = % x, want % x", raw, payload)
	}
	if _, ok := f[captureFieldExporter].(string); !ok {
		t.Fatalf("%s missing", captureFieldExporter)
	}
	if ts, ok := f[captureFieldReceived].(string); !ok {
		t.Fatalf("%s missing", captureFieldReceived)
	} else if _, perr := time.Parse(time.RFC3339Nano, ts); perr != nil {
		t.Fatalf("%s = %q is not RFC3339Nano: %v", captureFieldReceived, ts, perr)
	}
}

// A datagram that would not decode at all is the most interesting thing the socket
// ever sees, and the listener holds the only copy of its bytes.
func TestListener_DecodeErrorIsCapturedInUnidentifiedMode(t *testing.T) {
	sink := &fakeSink{}
	dec := &noticingDecoder{err: ErrMalformed}
	l := newTestListener(t, ListenerConfig{Capture: sink, CaptureMode: CaptureUnidentified}, dec, nil)

	send(t, l.Addr(), []byte{0, 9, 1, 2})
	waitFor(t, "the malformed datagram to be captured", func() bool { return len(sink.all()) == 1 })

	got := sink.all()[0]
	if got.kind != UnidentifiedMalformed {
		t.Fatalf("kind = %q, want %q", got.kind, UnidentifiedMalformed)
	}
	if got.fields[captureFieldError] == nil {
		t.Fatalf("capture did not record the decode error: %+v", got.fields)
	}
}

func TestErrorNotice_MapsEveryDecoderError(t *testing.T) {
	cases := []struct {
		err  error
		want string
	}{
		{ErrShortPacket, UnidentifiedMalformed},
		{ErrMalformed, UnidentifiedMalformed},
		{ErrUnsupportedVersion, UnidentifiedVersion},
		{ErrVariableLength, UnidentifiedVarLen},
		{errors.New("something else entirely"), UnidentifiedDecodeError},
	}
	for _, c := range cases {
		if got := errorNoticeKind(c.err); got != c.want {
			t.Errorf("errorNoticeKind(%v) = %q, want %q", c.err, got, c.want)
		}
	}
}

// --- always-on logging (capture OFF) ---------------------------------------

func TestListener_UnidentifiedIsLoggedWithCaptureOff(t *testing.T) {
	h := &countingHandler{}
	dec := &noticingDecoder{notices: []Unidentified{{Kind: UnidentifiedField, Detail: 61}}}
	l := NewListener(ListenerConfig{Addr: "127.0.0.1:0"}, dec, nil, slog.New(h))
	if err := l.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go l.Serve()

	send(t, l.Addr(), []byte{0, 9, 1, 2})
	waitFor(t, "the log line", func() bool { return h.count() == 1 })

	attrs := h.lastAttrs()
	if got := attrs["unidentified"]; !strings.Contains(got, "unknown_field") || !strings.Contains(got, "61") {
		t.Fatalf("log line did not name what was not understood: %v", attrs)
	}
	if attrs["exporter"] == "" {
		t.Fatalf("log line did not name the exporter: %v", attrs)
	}
}

// The socket is unauthenticated: a sender that repeats a surprise must not be able
// to turn the log into its own throughput.
func TestListener_RepeatedNoticeIsRateLimited(t *testing.T) {
	h := &countingHandler{}
	dec := &noticingDecoder{notices: []Unidentified{{Kind: UnidentifiedField, Detail: 61}}}
	l := NewListener(ListenerConfig{Addr: "127.0.0.1:0"}, dec, nil, slog.New(h))
	if err := l.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	go l.Serve()

	for range 20 {
		send(t, l.Addr(), []byte{0, 9, 1, 2})
	}
	waitFor(t, "the datagrams to be decoded", func() bool { return l.Stats().Datagrams == 20 })
	time.Sleep(30 * time.Millisecond)

	if got := h.count(); got != 1 {
		t.Fatalf("%d log lines for 20 identical notices, want 1", got)
	}
}

// A distinct surprise is a distinct fact and logs on its own.
func TestNoticeLimiter_LogsEachDistinctNoticeOnceThenFolds(t *testing.T) {
	lim := newNoticeLimiter(3)
	now := time.Now()

	for i := range 3 {
		if !lim.allow(Unidentified{Kind: UnidentifiedField, Detail: uint16(i)}, now) {
			t.Fatalf("distinct notice %d was suppressed", i)
		}
	}
	if lim.allow(Unidentified{Kind: UnidentifiedField, Detail: 0}, now) {
		t.Fatal("a repeat inside the interval was allowed")
	}
	// Past the bound the limiter must not keep growing: the fold key is shared, so the
	// 4th and 5th distinct notices log once between them, not once each.
	if !lim.allow(Unidentified{Kind: UnidentifiedField, Detail: 100}, now) {
		t.Fatal("the first folded notice was suppressed")
	}
	if lim.allow(Unidentified{Kind: UnidentifiedField, Detail: 101}, now) {
		t.Fatal("a second folded notice logged again inside the interval")
	}
	if got := lim.size(); got > 4 {
		t.Fatalf("limiter holds %d keys, want at most 4 (bound + the fold key)", got)
	}

	// The interval having elapsed, the same notice is news again.
	if !lim.allow(Unidentified{Kind: UnidentifiedField, Detail: 0}, now.Add(unidentifiedLogInterval+time.Second)) {
		t.Fatal("the notice was still suppressed after its interval elapsed")
	}
}

func TestPrimaryNoticeKind_PrefersTheMostStructuralFailure(t *testing.T) {
	notices := []Unidentified{
		{Kind: UnidentifiedFlowset, Detail: 7},
		{Kind: UnidentifiedMalformed},
		{Kind: UnidentifiedField, Detail: 61},
	}
	if got := primaryNoticeKind(notices); got != UnidentifiedMalformed {
		t.Fatalf("primaryNoticeKind = %q, want %q", got, UnidentifiedMalformed)
	}
	if got := primaryNoticeKind(nil); got != CapturedDatagram {
		t.Fatalf("primaryNoticeKind(nil) = %q, want %q", got, CapturedDatagram)
	}
}

func TestParseCaptureMode(t *testing.T) {
	for in, want := range map[string]CaptureMode{
		"off": CaptureOff, "": CaptureOff,
		"unidentified": CaptureUnidentified,
		"all":          CaptureAll,
	} {
		got, err := ParseCaptureMode(in)
		if err != nil {
			t.Fatalf("ParseCaptureMode(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("ParseCaptureMode(%q) = %v, want %v", in, got, want)
		}
	}
	if _, err := ParseCaptureMode("everything"); err == nil {
		t.Fatal("an unknown mode must be a configuration error, not a silent off")
	}
}
