package syslog

import (
	"bufio"
	"io"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

const maxSyslogFuzzInput = 2 * (maxMessageBytes + scannerHeadroom)

// fuzzChunkReader forces bounded, varying TCP read boundaries without involving a
// socket. It never returns an empty successful read, which bufio.Scanner forbids.
type fuzzChunkReader struct {
	data  []byte
	chunk int
}

func (r *fuzzChunkReader) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, io.EOF
	}
	n := r.chunk
	if n > len(r.data) {
		n = len(r.data)
	}
	if n > len(p) {
		n = len(p)
	}
	copy(p[:n], r.data[:n])
	r.data = r.data[n:]
	return n, nil
}

// FuzzParseEnvelope covers both supported envelope forms and the malformed
// structured-data regressions. Messages arrive from the bounded framer, so the
// harness applies that same maximum before parsing.
func FuzzParseEnvelope(f *testing.F) {
	for _, line := range []string{
		`<134>1 2026-07-14T19:50:01+01:00 opnsense.localdomain filterlog 19325 - [meta sequenceId="590250"] 16,115,,0,vtnet2,match,pass,out,4`,
		`<134>Jul 14 19:50:01 opnsense filterlog[19325]: 16,115,,0,vtnet2,match,pass,out,4`,
		`<134>1 2026-07-14T19:50:01Z host app 1 - [ex a="b\\]c"][two x="y"] the message`,
		`<134>1 2026-07-14T19:50:01Z host app 1 - [meta x="y"`,
	} {
		f.Add([]byte(line))
	}

	now := time.Date(2026, 7, 14, 20, 0, 0, 0, time.UTC)
	f.Fuzz(func(t *testing.T, line []byte) {
		if len(line) > maxMessageBytes {
			t.Skip()
		}
		first, err := ParseEnvelope(line, now)
		second, againErr := ParseEnvelope(line, now)
		if !reflect.DeepEqual(err, againErr) || !reflect.DeepEqual(first, second) {
			t.Fatal("envelope parse is not deterministic")
		}
		if err == nil && (first.Facility < 0 || first.Facility > 23 || first.Severity < 0 || first.Severity > 7) {
			t.Fatalf("parsed invalid facility/severity %d/%d", first.Facility, first.Severity)
		}
	})
}

// FuzzTCPFrames drives one stateful splitter through a bounded TCP byte stream.
// bufio.Scanner supplies arbitrary read boundaries during fuzzing, while the
// splitter must never return a terminal scanner error or retain an oversized frame.
func FuzzTCPFrames(f *testing.F) {
	f.Add([]byte("5 hello6 world!"), uint8(1))
	f.Add([]byte("<134>one\r\n<134>two\n<134>three"), uint8(3))
	f.Add([]byte("20 short"), uint8(7))

	octetOversized := strconv.Itoa(maxMessageBytes+1) + " " + strings.Repeat("x", maxMessageBytes+1) + "5 good!"
	newlineOversized := strings.Repeat("x", maxMessageBytes+1) + "\n<134>good\n"
	f.Add([]byte(octetOversized), uint8(11))
	f.Add([]byte(newlineOversized), uint8(17))

	f.Fuzz(func(t *testing.T, wire []byte, chunk uint8) {
		if len(wire) > maxSyslogFuzzInput {
			t.Skip()
		}

		oversized := 0
		splitter := newFrameSplitter(func() { oversized++ })
		scanner := bufio.NewScanner(&fuzzChunkReader{data: wire, chunk: int(chunk%64) + 1})
		scanner.Buffer(make([]byte, 0, maxMessageBytes+scannerHeadroom), maxMessageBytes+scannerHeadroom)
		scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
			advance, token, err := splitter.split(data, atEOF)
			if len(splitter.pending) > maxMessageBytes {
				t.Fatalf("framer retained %d pending bytes, limit is %d", len(splitter.pending), maxMessageBytes)
			}
			return advance, token, err
		})

		tokenBytes := 0
		for scanner.Scan() {
			if len(scanner.Bytes()) > maxMessageBytes {
				t.Fatalf("framer returned a %d-byte token, limit is %d", len(scanner.Bytes()), maxMessageBytes)
			}
			tokenBytes += len(scanner.Bytes())
			if tokenBytes > len(wire) {
				t.Fatalf("framer returned %d token bytes from %d input bytes", tokenBytes, len(wire))
			}
		}
		if err := scanner.Err(); err != nil {
			t.Fatalf("stateful frame splitter returned a terminal scanner error: %v", err)
		}
		if oversized > len(wire)+1 {
			t.Fatalf("oversized callback count %d exceeds bounded input %d", oversized, len(wire))
		}
		if len(splitter.pending) > maxMessageBytes {
			t.Fatalf("framer retained %d pending bytes after EOF, limit is %d", len(splitter.pending), maxMessageBytes)
		}
	})
}
