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
	got := scanWith(t, strings.NewReader(in), split, maxMessageBytes)
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
	got := scanWith(t, iotest.OneByteReader(strings.NewReader(in)), split, maxMessageBytes)
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
