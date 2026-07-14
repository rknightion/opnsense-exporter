package syslog

import (
	"strings"
	"sync"
	"testing"
	"time"
)

// A real multi-line message: a configd Python traceback, which is what actually
// produced the junk fragment records on the production box (#262). The framing eats
// the newlines, so this arrives as SIX newline-framed lines of which only the first
// carries a <PRI> header.
const configdTraceback = `<27>1 2026-07-14T18:22:03+00:00 OPNsense.localdomain configd.py 41234 - [meta sequenceId="1"] Traceback (most recent call last):
  File "/usr/local/opnsense/service/configd.py", line 128, in run
    self.handle_request(conn)
  File "/usr/local/opnsense/service/modules/processhandler.py", line 312, in handle_request
    raise ValueError("unexpected payload")
ValueError: unexpected payload)`

// recorder captures assembled messages in order.
type recorder struct {
	mu   sync.Mutex
	msgs []string
}

func (r *recorder) emit(msg []byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.msgs = append(r.msgs, string(msg))
}

func (r *recorder) all() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.msgs...)
}

// feed pushes each newline-framed line of s through the assembler, exactly as the
// connection's scanner does.
func feed(a *assembler, s string) {
	for _, line := range strings.Split(s, "\n") {
		a.add([]byte(line), false)
	}
}

// THE BUG: before this, the head shipped truncated at the first newline and the
// five remaining fragments each shipped as their own junk record.
func TestAssembler_MultiLineMessageBecomesOneRecord(t *testing.T) {
	var r recorder
	a := newAssembler(r.emit, nil)
	feed(a, configdTraceback)
	a.close()

	got := r.all()
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1 — the message was fragmented:\n%q", len(got), got)
	}
	if got[0] != configdTraceback {
		t.Errorf("message was not reassembled verbatim:\ngot:  %q\nwant: %q", got[0], configdTraceback)
	}
	// The specific symptom seen in production: a record whose whole body was ")".
	for _, m := range got {
		if m == ")" {
			t.Error("a bare continuation fragment shipped as its own record")
		}
	}
}

// Consecutive well-formed single-line messages must still be one record each — the
// continuation logic must not glue independent messages together.
func TestAssembler_SingleLineMessagesAreNotJoined(t *testing.T) {
	var r recorder
	a := newAssembler(r.emit, nil)
	feed(a, "<134>one\n<134>two\n<134>three")
	a.close()

	want := []string{"<134>one", "<134>two", "<134>three"}
	got := r.all()
	if len(got) != len(want) {
		t.Fatalf("got %q, want %q", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %q, want %q", got, want)
		}
	}
}

// Octet counting carries its own length, so the frame IS the message — embedded
// newlines and all. It must pass straight through, never be buffered or joined.
func TestAssembler_OctetCountedIsNeverAssembled(t *testing.T) {
	var r recorder
	a := newAssembler(r.emit, nil)
	a.add([]byte("<27>1 - - configd.py - - - line one\nline two"), true)
	a.add([]byte("<134>next"), true)
	a.close()

	got := r.all()
	if len(got) != 2 {
		t.Fatalf("got %d records, want 2: %q", len(got), got)
	}
	if got[0] != "<27>1 - - configd.py - - - line one\nline two" {
		t.Errorf("octet-counted frame was altered: %q", got[0])
	}
}

// A message pending a successor that never arrives must still ship. A firewall that
// logs one line an hour must not have that line held hostage until the next one.
func TestAssembler_IdleFlushShipsTheLastMessage(t *testing.T) {
	var r recorder
	a := newAssembler(r.emit, nil)
	a.add([]byte("<134>lonely"), false)

	if n := len(r.all()); n != 0 {
		t.Fatalf("message shipped immediately (%d records); it cannot be known complete yet", n)
	}
	// Not yet idle long enough.
	a.flushIdle(time.Hour)
	if n := len(r.all()); n != 0 {
		t.Fatalf("flushed before the idle window elapsed (%d records)", n)
	}
	// Idle window elapsed.
	time.Sleep(5 * time.Millisecond)
	a.flushIdle(time.Millisecond)

	got := r.all()
	if len(got) != 1 || got[0] != "<134>lonely" {
		t.Fatalf("idle flush did not ship the pending message: %q", got)
	}
}

// A peer emitting endless continuation lines must not grow the buffer without
// bound. The head is kept and shipped; the overflowing tail is dropped and counted
// ONCE for the message, not once per discarded line.
func TestAssembler_ContinuationBufferIsBounded(t *testing.T) {
	var r recorder
	truncations := 0
	a := newAssembler(r.emit, func() { truncations++ })

	a.add([]byte("<134>head"), false)
	chunk := strings.Repeat("x", 4096)
	for i := 0; i < 100; i++ { // ~400 KiB of continuation against a 64 KiB cap
		a.add([]byte(chunk), false)
	}
	a.close()

	got := r.all()
	if len(got) != 1 {
		t.Fatalf("got %d records, want 1: lengths %v", len(got), lens(got))
	}
	if len(got[0]) > maxMessageBytes {
		t.Errorf("assembled message is %d bytes, over the %d cap", len(got[0]), maxMessageBytes)
	}
	if !strings.HasPrefix(got[0], "<134>head") {
		t.Errorf("the head of the message was lost: %.40q", got[0])
	}
	if truncations != 1 {
		t.Errorf("truncations = %d, want exactly 1 (one per message, not one per dropped line)", truncations)
	}
}

// A connection that opens mid-message has nothing to attach the first fragment to.
// It must still ship (the receiver never drops), not panic or vanish.
func TestAssembler_LeadingContinuationWithNothingToContinue(t *testing.T) {
	var r recorder
	a := newAssembler(r.emit, nil)
	a.add([]byte("orphan fragment"), false)
	a.add([]byte("<134>real"), false)
	a.close()

	got := r.all()
	if len(got) != 2 || got[0] != "orphan fragment" || got[1] != "<134>real" {
		t.Fatalf("got %q, want [orphan fragment <134>real]", got)
	}
}

func lens(ss []string) []int {
	out := make([]int, len(ss))
	for i, s := range ss {
		out[i] = len(s)
	}
	return out
}
