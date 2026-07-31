package main

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rknightion/opnsense2otel/v4/internal/flow/netflow"
)

const fixturePath = "../../internal/flow/netflow/testdata/replay-v9.bin"

// captureLine renders one frame the way the debug capturer writes it, so the test
// exercises the real on-disk shape rather than a convenient invention. The key names
// are the ones internal/flow/netflow/capture.go publishes.
func captureLine(t *testing.T, f frame, kind string) []byte {
	t.Helper()
	obj := map[string]any{
		"ts":          time.Unix(0, f.recvUnix).UTC().Format(time.RFC3339Nano),
		"receiver":    "netflow",
		"kind":        kind,
		"payload_b64": base64.StdEncoding.EncodeToString(f.payload),
		"exporter":    f.exporter.String(),
		"received":    time.Unix(0, f.recvUnix).UTC().Format(time.RFC3339Nano),
		"bytes":       len(f.payload),
	}
	b, err := json.Marshal(obj)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return append(b, '\n')
}

func loadFixtureFrames(t *testing.T) []frame {
	t.Helper()
	raw, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	frames, err := readFrames(raw)
	if err != nil {
		t.Fatalf("readFrames: %v", err)
	}
	return frames
}

func assertSameFrames(t *testing.T, got, want []frame) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("read %d frames, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].idx != want[i].idx {
			t.Errorf("frame %d: idx = %d, want %d", i, got[i].idx, want[i].idx)
		}
		if got[i].exporter != want[i].exporter {
			t.Errorf("frame %d: exporter = %s, want %s", i, got[i].exporter, want[i].exporter)
		}
		if got[i].recvUnix != want[i].recvUnix {
			t.Errorf("frame %d: recvUnix = %d, want %d", i, got[i].recvUnix, want[i].recvUnix)
		}
		if string(got[i].payload) != string(want[i].payload) {
			t.Errorf("frame %d: payload differs (%d vs %d bytes)", i, len(got[i].payload), len(want[i].payload))
		}
	}
}

// The round trip that matters: an "all"-mode capture must reconstruct exactly the
// frames the raw format carried, or a fixture built from a capture would not be the
// datagrams the box actually sent.
func TestReadCapture_RoundTripsTheRawFrameFormat(t *testing.T) {
	want := loadFixtureFrames(t)

	var ndjson []byte
	for _, f := range want {
		ndjson = append(ndjson, captureLine(t, f, "datagram")...)
	}

	got, err := readCapture(ndjson)
	if err != nil {
		t.Fatalf("readCapture: %v", err)
	}
	assertSameFrames(t, got, want)
}

// readInput is what main calls, and it must not need to be told which format it was
// handed: a raw capture and a debug capture are both "the file the operator has".
func TestReadInput_AutoDetectsBothFormats(t *testing.T) {
	want := loadFixtureFrames(t)
	dir := t.TempDir()

	rawPath := filepath.Join(dir, "raw.bin")
	rawBytes, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := os.WriteFile(rawPath, rawBytes, 0o600); err != nil {
		t.Fatalf("write raw: %v", err)
	}

	var ndjson []byte
	for _, f := range want {
		ndjson = append(ndjson, captureLine(t, f, "datagram")...)
	}
	ndjsonPath := filepath.Join(dir, "capture-000.ndjson")
	if err := os.WriteFile(ndjsonPath, ndjson, 0o600); err != nil {
		t.Fatalf("write ndjson: %v", err)
	}

	for _, p := range []string{rawPath, ndjsonPath} {
		got, rerr := readInput(p)
		if rerr != nil {
			t.Fatalf("readInput(%s): %v", p, rerr)
		}
		assertSameFrames(t, got, want)
	}
}

// The capturer ROTATES: a real capture is capture-000.ndjson, capture-001.ndjson, …
// under <dir>/netflow/. Pointing flowanon at one file of a rotated set would silently
// use a fraction of the capture, so a directory is read whole, in file order.
func TestReadInput_ReadsARotatedCaptureDirectoryInOrder(t *testing.T) {
	want := loadFixtureFrames(t)
	dir := t.TempDir()

	split := len(want) / 2
	writeChunk := func(name string, frames []frame) {
		var b []byte
		for _, f := range frames {
			b = append(b, captureLine(t, f, "datagram")...)
		}
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}
	// Written out of order on purpose: correctness must come from the sorted NAME, not
	// from whatever order the filesystem hands back.
	writeChunk("capture-001.ndjson", want[split:])
	writeChunk("capture-000.ndjson", want[:split])

	got, err := readInput(dir)
	if err != nil {
		t.Fatalf("readInput(dir): %v", err)
	}
	assertSameFrames(t, got, want)
}

// A capture dir holds every receiver's subdirectory, and only netflow entries carry
// datagrams. A syslog line must be skipped, not mistaken for a truncated frame.
func TestReadCapture_SkipsEntriesFromOtherReceivers(t *testing.T) {
	want := loadFixtureFrames(t)

	other := []byte(`{"ts":"2020-01-01T00:00:00Z","receiver":"syslog","kind":"unparsed","line":"nope"}` + "\n")
	ndjson := append([]byte(nil), other...)
	for _, f := range want {
		ndjson = append(ndjson, captureLine(t, f, "datagram")...)
	}
	ndjson = append(ndjson, other...)

	got, err := readCapture(ndjson)
	if err != nil {
		t.Fatalf("readCapture: %v", err)
	}
	assertSameFrames(t, got, want)
}

// A capture killed mid-write leaves a partial last line. Raw frames already tolerate
// a truncated trailing frame; the NDJSON reader must match that, or the last file of
// a live capture is unreadable.
func TestReadCapture_ToleratesATruncatedFinalLine(t *testing.T) {
	want := loadFixtureFrames(t)

	var ndjson []byte
	for _, f := range want {
		ndjson = append(ndjson, captureLine(t, f, "datagram")...)
	}
	ndjson = append(ndjson, []byte(`{"receiver":"netflow","payload_b`)...)

	got, err := readCapture(ndjson)
	if err != nil {
		t.Fatalf("readCapture: %v", err)
	}
	assertSameFrames(t, got, want)
}

// A line that IS complete JSON but whose payload is not decodable is corruption, not
// truncation: silently dropping it would produce a fixture missing datagrams with
// nothing to say so.
func TestReadCapture_RejectsAnUndecodablePayload(t *testing.T) {
	line := []byte(`{"receiver":"netflow","kind":"datagram","payload_b64":"not!base64","exporter":"192.0.2.1","received":"2020-01-01T00:00:00Z"}` + "\n")
	if _, err := readCapture(line); err == nil {
		t.Fatal("an undecodable payload must be an error, not a silently dropped datagram")
	}
}

func TestReadCapture_RejectsAnEmptyCapture(t *testing.T) {
	if _, err := readCapture([]byte("\n\n")); err == nil {
		t.Fatal("a capture with no netflow entries must be an error, not an empty fixture")
	}
}

// The whole point of #360: a capture the EXPORTER took must produce a usable
// fixture. This runs the real pipeline — NDJSON in, selection, anonymisation, frame
// dump out — and then decodes the result with the real decoder, because a fixture
// that reads back as frames but no longer decodes would pass every other test here.
//
// The selection is overridden to the seven frames the committed fixture holds: a
// fresh capture is a different stream, so its case indices are found per capture (see
// the comment on fixtureFrames). What is being pinned is the PATH, not the choice.
func TestRun_EndToEndFromAnNDJSONCapture(t *testing.T) {
	want := loadFixtureFrames(t)

	prev := fixtureFrames
	t.Cleanup(func() { fixtureFrames = prev })
	fixtureFrames = make([]selection, 0, len(want))
	for i := range want {
		fixtureFrames = append(fixtureFrames, selection{frame: i, why: "round-trip"})
	}

	dir := t.TempDir()
	var ndjson []byte
	for _, f := range want {
		ndjson = append(ndjson, captureLine(t, f, "datagram")...)
	}
	inPath := filepath.Join(dir, "capture-000.ndjson")
	if err := os.WriteFile(inPath, ndjson, 0o600); err != nil {
		t.Fatalf("write capture: %v", err)
	}
	outPath := filepath.Join(dir, "replay.bin")

	if err := run(inPath, outPath); err != nil {
		t.Fatalf("run: %v", err)
	}

	out, err := os.ReadFile(outPath) //nolint:gosec // a path this test just wrote
	if err != nil {
		t.Fatalf("read output: %v", err)
	}
	got, err := readFrames(out)
	if err != nil {
		t.Fatalf("readFrames on the generated fixture: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("generated fixture has %d frames, want %d", len(got), len(want))
	}

	// Decoding is the real assertion. The frames were rewritten (addresses remapped,
	// times shifted), so they must not merely parse as frames — they must still be
	// NetFlow that yields records.
	dec := netflow.New()
	records := 0
	for i, f := range got {
		dg, derr := dec.Decode(f.payload, f.exporter, time.Unix(0, f.recvUnix))
		if derr != nil {
			t.Fatalf("frame %d of the generated fixture does not decode: %v", i, derr)
		}
		records += len(dg.Records)
	}
	if records == 0 {
		t.Fatal("the generated fixture decoded to zero records")
	}
}
