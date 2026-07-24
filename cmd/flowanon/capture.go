package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Reading the exporter's own debug capture (#360).
//
// Before this, the only input flowanon could read was a frame dump written by a
// throwaway tool that was never committed — so the fixture it produced was
// reproducible in principle and impossible in practice, and no NEW capture could be
// taken at all. The exporter now writes captures itself
// (--flow.netflow.debug-capture=all), as NDJSON under <capture-dir>/netflow/, and
// this reads that form back into the same frames the raw format yielded.
//
// Both formats stay supported: the raw one because the committed fixture is in it,
// the NDJSON one because it is the only form anything can produce from here on.

// captureEntry is the subset of a debug-capture line a datagram frame needs. Every
// other key the capturer writes (kind, bytes, version, sequence, source_id, records,
// unidentified, error) is diagnostic and deliberately ignored here.
type captureEntry struct {
	Receiver string `json:"receiver"`
	Payload  string `json:"payload_b64"`
	Exporter string `json:"exporter"`
	Received string `json:"received"`
}

// readInput reads either format, from a file or a whole capture directory, and
// returns frames in receive order.
//
// The format is detected rather than declared: an operator has "the capture", not a
// format, and getting the flag wrong would either fail loudly or — worse — read a
// few plausible frames out of the wrong parser.
func readInput(path string) ([]frame, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		raw, rerr := os.ReadFile(path) //nolint:gosec // an operator-supplied capture path is the input
		if rerr != nil {
			return nil, rerr
		}
		if isCaptureNDJSON(raw) {
			return readCapture(raw)
		}
		return readFrames(raw)
	}

	// A live capture ROTATES into capture-000.ndjson, capture-001.ndjson, … so a
	// directory is read whole, in sorted NAME order. Reading one file of a rotated set
	// would silently use a fraction of the capture.
	var names []string
	err = filepath.WalkDir(path, func(p string, d os.DirEntry, werr error) error {
		if werr != nil {
			return werr
		}
		if !d.IsDir() && strings.HasSuffix(p, ".ndjson") {
			names = append(names, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(names) == 0 {
		return nil, fmt.Errorf("no .ndjson capture files under %s", path)
	}
	sort.Strings(names)

	var all []byte
	for _, n := range names {
		b, rerr := os.ReadFile(n) //nolint:gosec // paths come from walking the operator's own capture dir
		if rerr != nil {
			return nil, rerr
		}
		all = append(all, b...)
		// A file that did not end in a newline (a capture killed mid-write) must not run
		// its partial last line into the next file's first one.
		if len(b) > 0 && b[len(b)-1] != '\n' {
			all = append(all, '\n')
		}
	}
	return readCapture(all)
}

// isCaptureNDJSON reports whether the input is the exporter's capture format. The
// raw frame format begins with an 8-byte big-endian nanosecond timestamp, whose
// first byte is 0x00 for every plausible date, so a leading '{' is unambiguous.
func isCaptureNDJSON(raw []byte) bool {
	trimmed := bytes.TrimLeft(raw, " \t\r\n")
	return len(trimmed) > 0 && trimmed[0] == '{'
}

// readCapture parses NDJSON debug-capture lines into frames.
//
// It tolerates a truncated FINAL line — a capture killed mid-write leaves one, and
// the raw reader tolerates the equivalent — but a complete line whose payload will
// not decode is an error: dropping it silently would produce a fixture quietly
// missing datagrams.
func readCapture(raw []byte) ([]frame, error) {
	lines := bytes.Split(raw, []byte{'\n'})
	var frames []frame
	idx := 0
	for i, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var e captureEntry
		if err := json.Unmarshal(line, &e); err != nil {
			if i == len(lines)-1 {
				// The trailing partial line of a live capture.
				break
			}
			return nil, fmt.Errorf("capture line %d: %w", i+1, err)
		}
		// A capture dir holds every receiver's entries. Only the netflow ones carry a
		// datagram; the rest are skipped rather than treated as corruption.
		if e.Receiver != "netflow" || e.Payload == "" {
			continue
		}
		payload, err := base64.StdEncoding.DecodeString(e.Payload)
		if err != nil {
			return nil, fmt.Errorf("capture line %d: payload_b64: %w", i+1, err)
		}
		addr, err := netip.ParseAddr(e.Exporter)
		if err != nil {
			return nil, fmt.Errorf("capture line %d: exporter %q: %w", i+1, e.Exporter, err)
		}
		recv, err := time.Parse(time.RFC3339Nano, e.Received)
		if err != nil {
			return nil, fmt.Errorf("capture line %d: received %q: %w", i+1, e.Received, err)
		}
		frames = append(frames, frame{
			idx:      idx,
			recvUnix: recv.UnixNano(),
			exporter: addr.Unmap(),
			payload:  payload,
		})
		idx++
	}
	if len(frames) == 0 {
		return nil, fmt.Errorf("no netflow datagrams read")
	}
	return frames, nil
}
