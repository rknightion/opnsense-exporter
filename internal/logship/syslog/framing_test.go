package syslog

import (
	"bufio"
	"io"
	"strconv"
	"strings"
	"testing"
	"testing/iotest"
)

// scanWith runs a split func over r and returns every token. A scanner error is
// FATAL to the test: bufio.Scanner errors are terminal, and a terminal error on a
// TCP connection kills the connection (and loops a reconnecting syslog-ng).
func scanWith(t *testing.T, r io.Reader, split bufio.SplitFunc, max int) []string {
	t.Helper()
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, max), max)
	sc.Split(split)
	var out []string
	for sc.Scan() {
		out = append(out, sc.Text())
	}
	if err := sc.Err(); err != nil {
		t.Fatalf("scanner error (must never happen — errors are terminal): %v", err)
	}
	return out
}

func scanAll(t *testing.T, in string) []string {
	t.Helper()
	return scanWith(t, strings.NewReader(in), ScanFrames, maxMessageBytes)
}

// scanAllByteAtATime drives the scanner through a 1-byte reader so every token is
// necessarily split across reads and must be replayed.
func scanAllByteAtATime(t *testing.T, in string) []string {
	t.Helper()
	return scanWith(t, iotest.OneByteReader(strings.NewReader(in)), ScanFrames, maxMessageBytes)
}

func wantTokens(t *testing.T, got []string, want ...string) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

func TestScanFramesOctetCounting(t *testing.T) {
	wantTokens(t, scanAll(t, "5 hello6 world!"), "hello", "world!")
}

func TestScanFramesNewline(t *testing.T) {
	wantTokens(t, scanAll(t, "<134>one\r\n<134>two\n<134>three"), "<134>one", "<134>two", "<134>three")
}

// THE classic framing bug: a message straddling two TCP reads must not be
// truncated or lost. ScanFrames must return (0,nil,nil) to request more data
// rather than emit a short token.
func TestScanFramesSplitAcrossReads(t *testing.T) {
	body := "<134>1 2026-07-14T19:50:01+01:00 opnsense filterlog 1 - - a,b,c"
	octet := strconv.Itoa(len(body)) + " " + body + "3 xyz"
	wantTokens(t, scanAllByteAtATime(t, octet), body, "xyz")
	wantTokens(t, scanAllByteAtATime(t, body+"\n"+body+"\n"), body, body)
}

// An oversized declared length is SKIPPED, never returned as an error, and the
// scan CONTINUES: the next good frame must still arrive.
func TestScanFramesOversizedIsSkippedAndScanContinues(t *testing.T) {
	n := maxMessageBytes + 1000
	in := strconv.Itoa(n) + " " + strings.Repeat("A", n) + "5 good!"
	// The scanner buffer must exceed the frame for the stateless skip to see the
	// whole frame; the listener uses the stateful splitter below for the real case.
	got := scanWith(t, strings.NewReader(in), ScanFrames, 4*maxMessageBytes)
	wantTokens(t, got, "good!")
}

// The listener's per-connection splitter carries the remaining skip count across
// reads, so an oversized frame that CANNOT fit in the 64 KiB scanner buffer is
// still skipped cleanly — and counted — with the next good frame intact.
func TestFrameSplitterSkipsOversizedLargerThanBuffer(t *testing.T) {
	n := maxMessageBytes + 1000
	in := strconv.Itoa(n) + " " + strings.Repeat("A", n) + "5 good!"
	oversized := 0
	split := newFrameSplitter(func() { oversized++ })
	got := scanWith(t, strings.NewReader(in), split.splitFunc(), maxMessageBytes)
	wantTokens(t, got, "good!")
	if oversized != 1 {
		t.Fatalf("oversized count = %d, want 1", oversized)
	}
}

// Same, one byte at a time — the skip state must survive arbitrary read boundaries.
func TestFrameSplitterSkipsOversizedByteAtATime(t *testing.T) {
	n := maxMessageBytes + 3
	in := strconv.Itoa(n) + " " + strings.Repeat("B", n) + "5 good!"
	oversized := 0
	split := newFrameSplitter(func() { oversized++ })
	got := scanWith(t, iotest.OneByteReader(strings.NewReader(in)), split.splitFunc(), maxMessageBytes)
	wantTokens(t, got, "good!")
	if oversized != 1 {
		t.Fatalf("oversized count = %d, want 1", oversized)
	}
}

// A frame declared longer than what actually arrives: at EOF ship the remainder
// rather than dropping it.
func TestScanFramesPartialAtEOF(t *testing.T) {
	wantTokens(t, scanAll(t, "20 short"), "short")
}

func TestScanFramesEmpty(t *testing.T) {
	if got := scanAll(t, ""); len(got) != 0 {
		t.Fatalf("got %q, want none", got)
	}
}

// A digit-leading run with no space is not octet counting; it must fall back to
// newline framing rather than erroring or spinning.
func TestScanFramesDegenerateOctetPrefix(t *testing.T) {
	wantTokens(t, scanAll(t, "12345"), "12345")
	wantTokens(t, scanAll(t, "123abc\nnext\n"), "123abc", "next")
}

// #398: a newline-framed payload has NO length prefix, so bufio.Scanner has no way
// to know a line is oversized until it either finds the terminator or exhausts its
// buffer. Before the fix, a line over the cap with no '\n' anywhere produced a
// TERMINAL bufio.ErrTooLong, killing the connection and losing every subsequent
// frame. The exact boundary (cap-1 fine, cap fine, cap+1 rejected) must hold for
// LF, CRLF and octet-counted framing alike, with prefix/delimiter overhead never
// miscounted against the payload.
func TestScanFramesBoundary(t *testing.T) {
	good5 := "5 good!" // trailing octet-counted frame used to prove the scan continues

	for _, tc := range []struct {
		name    string
		payload int // payload size in bytes
		delim   string
		wantOK  bool
	}{
		{"LF cap-1", maxMessageBytes - 1, "\n", true},
		{"LF cap", maxMessageBytes, "\n", true},
		{"LF cap+1", maxMessageBytes + 1, "\n", false},
		{"CRLF cap-1", maxMessageBytes - 1, "\r\n", true},
		{"CRLF cap", maxMessageBytes, "\r\n", true},
		{"CRLF cap+1", maxMessageBytes + 1, "\r\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Repeat("A", tc.payload)
			in := body + tc.delim + good5
			// The whole payload must be visible to the stateless scanner in one go for
			// this table (a mid-stream partial-frame is exercised separately below); size
			// the buffer generously so ScanFrames itself performs the cap check rather
			// than bufio.Scanner's own ErrTooLong pre-empting it.
			oversized := 0
			split := newFrameSplitter(func() { oversized++ })
			got := scanWith(t, strings.NewReader(in), split.splitFunc(), 4*maxMessageBytes)
			if tc.wantOK {
				wantTokens(t, got, body, "good!")
				if oversized != 0 {
					t.Fatalf("oversized = %d, want 0 for an exactly-at-cap payload", oversized)
				}
			} else {
				wantTokens(t, got, "good!")
				if oversized != 1 {
					t.Fatalf("oversized = %d, want 1", oversized)
				}
			}
		})
	}

	for _, tc := range []struct {
		name    string
		payload int
		wantOK  bool
	}{
		{"octet-counted cap-1", maxMessageBytes - 1, true},
		{"octet-counted cap", maxMessageBytes, true},
		{"octet-counted cap+1", maxMessageBytes + 1, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := strings.Repeat("B", tc.payload)
			in := strconv.Itoa(tc.payload) + " " + body + good5
			oversized := 0
			split := newFrameSplitter(func() { oversized++ })
			got := scanWith(t, strings.NewReader(in), split.splitFunc(), 4*maxMessageBytes)
			if tc.wantOK {
				wantTokens(t, got, body, "good!")
				if oversized != 0 {
					t.Fatalf("oversized = %d, want 0 for an exactly-at-cap payload", oversized)
				}
			} else {
				wantTokens(t, got, "good!")
				if oversized != 1 {
					t.Fatalf("oversized = %d, want 1", oversized)
				}
			}
		})
	}
}

// A newline-delimited frame with NO terminator anywhere, arriving well beyond the
// cap before the connection's scanner buffer could hold it all, must be skipped and
// counted exactly once — never a terminal scanner error — and the next good frame
// on the same connection must still arrive.
func TestFrameSplitterSkipsOversizedNewlineFrame(t *testing.T) {
	n := maxMessageBytes + 1000
	in := strings.Repeat("A", n) + "\n<134>good\n"
	oversized := 0
	split := newFrameSplitter(func() { oversized++ })
	got := scanWith(t, strings.NewReader(in), split.splitFunc(), maxMessageBytes)
	wantTokens(t, got, "<134>good")
	if oversized != 1 {
		t.Fatalf("oversized count = %d, want 1", oversized)
	}
}

// Same, one byte at a time — the newline-skip state must survive arbitrary read
// boundaries exactly like the octet-counted skip state already does.
func TestFrameSplitterSkipsOversizedNewlineFrameByteAtATime(t *testing.T) {
	n := maxMessageBytes + 500
	in := strings.Repeat("C", n) + "\n<134>good\n"
	oversized := 0
	split := newFrameSplitter(func() { oversized++ })
	got := scanWith(t, iotest.OneByteReader(strings.NewReader(in)), split.splitFunc(), maxMessageBytes)
	wantTokens(t, got, "<134>good")
	if oversized != 1 {
		t.Fatalf("oversized count = %d, want 1", oversized)
	}
}

// A newline-delimited frame that never finds its terminator before the connection
// ends (EOF mid-oversized-line) must not be shipped as a giant token either.
func TestFrameSplitterOversizedNewlineFrameTruncatedAtEOF(t *testing.T) {
	n := maxMessageBytes + 200
	in := strings.Repeat("D", n) // no trailing newline at all
	oversized := 0
	split := newFrameSplitter(func() { oversized++ })
	got := scanWith(t, strings.NewReader(in), split.splitFunc(), maxMessageBytes)
	if len(got) != 0 {
		t.Fatalf("got %d tokens, want 0 (an oversized frame with no terminator must never be shipped)", len(got))
	}
	if oversized != 1 {
		t.Fatalf("oversized count = %d, want 1", oversized)
	}
}
