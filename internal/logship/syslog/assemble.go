package syslog

import (
	"sync"
	"time"
)

// continuationWait bounds how long a finished message may sit in the assembler
// waiting to learn whether the next line belongs to it.
//
// A newline-framed message is only known to be COMPLETE when the next line turns
// up and proves to be a new header. On a busy connection that is microseconds
// away. On a quiet one there may be no next line for hours — and a firewall that
// logs one line an hour must still ship that line — so an idle assembler flushes
// on its own after this long. Every fragment of a real multi-line message is
// written by syslog-ng in a single write, so they arrive together and are never
// separated by anything close to this.
const continuationWait = 250 * time.Millisecond

// assembler rejoins the fragments of a multi-line syslog message arriving over ONE
// newline-framed TCP connection.
//
// syslog-ng frames with newlines, not octet counts. A syslog message may itself
// CONTAIN newlines — a configd Python traceback, a cron command spanning lines —
// and newline framing then shreds one message into several "lines". Before this
// existed, the head shipped truncated at the first newline and every subsequent
// fragment failed the envelope parse and shipped as a junk body-only record. On the
// production box that was 12 of 12,344 records: not much, but both halves of it
// were wrong (a truncated message AND a fabricated one).
//
// The rule is the one syslog itself gives us: a real message starts with a <PRI>
// header, so a line that does NOT start with '<' cannot be a new message and must
// be a continuation of the previous one.
//
// Concurrency: emit is called with the mutex held, from either the connection's
// scanner goroutine or its idle-flush ticker. That is deliberate — it serialises
// the two, which is what keeps a message and its own continuation lines in order.
// It is safe because emit lands in the pipeline's bounded drop-oldest queue, which
// never blocks.
type assembler struct {
	emit       func(msg []byte)
	onTruncate func()

	mu   sync.Mutex
	buf  []byte
	last time.Time // when buf was last appended to; drives the idle flush
	full bool      // buf hit the cap: further continuations are discarded, counted once
}

func newAssembler(emit func(msg []byte), onTruncate func()) *assembler {
	return &assembler{emit: emit, onTruncate: onTruncate}
}

// add takes one framed line. octet reports that it was octet-counted.
func (a *assembler) add(line []byte, octet bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// Octet counting delimits a message EXACTLY, embedded newlines and all: the frame
	// is the whole message, so there is nothing to reassemble and buffering it would
	// only add latency. Flush anything pending and pass it straight through.
	if octet {
		a.flushLocked()
		a.emit(line)
		return
	}

	if len(a.buf) > 0 && isContinuation(line) {
		a.appendLocked(line)
		return
	}

	// A new header (or a continuation with nothing to continue — a connection that
	// opened mid-message). Either way the previous message is now complete.
	a.flushLocked()
	a.buf = append(make([]byte, 0, len(line)), line...)
	a.last = time.Now()
}

// appendLocked joins a continuation line onto the pending message, rejoining the
// newline the framing ate.
func (a *assembler) appendLocked(line []byte) {
	// The cap applies to the ASSEMBLED message, not to each fragment: without that, a
	// peer emitting endless continuation lines would grow this buffer without bound.
	// The head is kept and shipped; only the overflowing tail is dropped, and it is
	// counted (once per message, not once per discarded line).
	if len(a.buf)+1+len(line) > maxMessageBytes {
		if !a.full {
			a.full = true
			if a.onTruncate != nil {
				a.onTruncate()
			}
		}
		return
	}
	a.buf = append(a.buf, '\n')
	a.buf = append(a.buf, line...)
	a.last = time.Now()
}

func (a *assembler) flushLocked() {
	if len(a.buf) == 0 {
		return
	}
	msg := a.buf
	a.buf, a.full = nil, false
	a.emit(msg)
}

// flushIdle emits the pending message if nothing has been appended to it for d.
// This is what stops the last message on a quiet connection waiting forever for a
// successor that never comes.
func (a *assembler) flushIdle(d time.Duration) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if len(a.buf) > 0 && time.Since(a.last) >= d {
		a.flushLocked()
	}
}

// close flushes whatever is still pending. The connection is ending, so there will
// be no further line to prove the message complete.
func (a *assembler) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.flushLocked()
}

// isContinuation reports whether a line cannot be the start of a syslog message.
// Every message — RFC5424 and RFC3164 alike — begins with a '<PRI>' header, so
// anything else is the remainder of the one before it.
func isContinuation(line []byte) bool {
	return len(line) == 0 || line[0] != '<'
}
