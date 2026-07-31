package capture

import (
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rknightion/opnsense2otel/v4/internal/flow/netflow"
)

// The NetFlow lane's notice kinds live in internal/flow/netflow (which must not
// import this package — the listener takes a small interface precisely so the
// layering stays one-way), while the metric's closed label vocabulary lives here.
// Two copies of the same strings drift silently: a renamed kind would keep writing
// to disk under the new name while the counter stayed pre-initialised at zero under
// the old one, and nothing would fail. This test is the join.
func TestNetflowKindsMatchTheDecoderVocabulary(t *testing.T) {
	pairs := map[string]string{
		KindUnknownField:       netflow.UnidentifiedField,
		KindOptionsTemplate:    netflow.UnidentifiedOptions,
		KindUnknownFlowset:     netflow.UnidentifiedFlowset,
		KindMalformed:          netflow.UnidentifiedMalformed,
		KindUnsupportedVersion: netflow.UnidentifiedVersion,
		KindVarLenRejected:     netflow.UnidentifiedVarLen,
		KindDecodeError:        netflow.UnidentifiedDecodeError,
		KindDatagram:           netflow.CapturedDatagram,
	}
	for here, there := range pairs {
		if here != there {
			t.Errorf("capture kind %q does not match the netflow constant %q", here, there)
		}
	}
	if got := len(capturedKinds[ReceiverNetflow]); got != len(pairs) {
		t.Fatalf("capturedKinds[%q] lists %d kinds, want %d - a kind added to one and not the "+
			"other leaves its counter without a pre-initialised zero", ReceiverNetflow, got, len(pairs))
	}
}

func TestReceiverSinkIsNilSafeAndFilesUnderItsReceiver(t *testing.T) {
	var none *ReceiverSink
	none.Capture(KindDatagram, map[string]any{"a": 1}) // must not panic

	var noCapturer *Capturer
	noCapturer.For(ReceiverNetflow).Capture(KindDatagram, map[string]any{"a": 1}) // must not panic

	c, err := New(Config{Dir: t.TempDir(), MaxBytes: 1 << 20}, nil, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.For(ReceiverNetflow).Capture(KindDatagram, map[string]any{"payload_b64": "AAk="})
	if err := c.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	// The receiver name is what picks the subdirectory, which is the whole reason the
	// sink owns it rather than the caller.
	if got := c.existingBytes(); got == 0 {
		t.Fatal("nothing was written under the netflow receiver")
	}
}

// The byte cap is the reason the NetFlow lane reuses this package rather than
// writing its own dump: an unbounded capture of a UDP flow export fills the disk.
// The cap governs the whole dir, so a netflow entry must be stopped by it exactly as
// a syslog one is — this pins that end to end rather than by inspection.
func TestByteCapAppliesToNetflowEntries(t *testing.T) {
	dir := t.TempDir()
	reg := prometheus.NewRegistry()
	c, err := New(Config{Dir: dir, MaxBytes: 150, PerFileBytes: 1 << 20}, reg, nil)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	sink := c.For(ReceiverNetflow)
	sink.Capture(KindDatagram, map[string]any{"n": "first", "payload_b64": strings.Repeat("A", 10)})
	for range 50 {
		sink.Capture(KindDatagram, map[string]any{"n": "later", "payload_b64": strings.Repeat("B", 60)})
	}
	if cerr := c.Close(); cerr != nil {
		t.Fatalf("Close: %v", cerr)
	}

	recs := readAll(t, dir, ReceiverNetflow)
	if len(recs) == 0 {
		t.Fatal("expected at least the first netflow datagram to survive")
	}
	if recs[0]["n"] != "first" {
		t.Fatalf("oldest not kept: %+v", recs[0])
	}
	if dropped := counterVal(t, c.m.dropped, ReceiverNetflow, "cap_reached"); dropped <= 0 {
		t.Fatalf("cap_reached not counted for the netflow receiver: %v", dropped)
	}
}
