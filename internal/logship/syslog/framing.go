package syslog

import (
	"bufio"
	"bytes"
)

// maxMessageBytes caps a single syslog frame. Anything larger is skipped and
// counted, never errored: bufio.Scanner errors are TERMINAL, so returning one
// would kill the whole TCP connection and put a reconnecting syslog-ng into a
// reconnect loop. This cap applies uniformly to octet-counted AND newline-framed
// payloads (#398) — framing style must never change what "oversized" means.
const maxMessageBytes = 64 << 10

// scannerHeadroom gives the bufio.Scanner buffer room for framing bytes that ride
// alongside the maxMessageBytes payload cap itself: an octet-count prefix (up to
// maxLenDigits digits plus a space) and a newline delimiter (up to 2 bytes for
// "\r\n"). Without it, a nominally-legal maxMessageBytes payload could still trip
// bufio.ErrTooLong purely from prefix/delimiter bytes riding along with it (#398) —
// the scanner's max token size must exceed the payload cap, not equal it.
const scannerHeadroom = 32

// ScanFrames is a bufio.SplitFunc that auto-detects the two framings syslog-ng
// emits over TCP:
//
//   - octet counting (RFC6587 — what flags(syslog-protocol) produces): a decimal
//     length, a space, then exactly that many bytes.
//   - newline delimited (the classic form), with an optional trailing \r.
//
// It NEVER returns an error, and never returns a short token: a frame split across
// two reads yields (0, nil, nil) so the scanner replays it once the rest arrives.
// At EOF a partial frame is returned rather than dropped.
//
// An oversized frame — an octet-counted declared length over maxMessageBytes, OR a
// newline-delimited line whose content exceeds it (#398) — is skipped, not errored.
// Skipping one that is LARGER THAN THE SCANNER'S BUFFER cannot be done statelessly
// — the listener uses newFrameSplitter, which carries the remaining skip state
// across reads (a byte count for octet counting, a "still hunting for '\n'" flag
// for newline framing). Callers using ScanFrames directly must size the scanner
// buffer to hold the largest frame they expect to skip.
func ScanFrames(data []byte, atEOF bool) (int, []byte, error) {
	advance, token, _, _, _, _ := scanFrame(data, atEOF)
	return advance, token, nil
}

// scanFrame is the framing core. skip is the number of bytes of an octet-counted
// oversized frame still to be discarded after the returned advance (newline-framed
// oversize has no such count — see frameSplitter.lineSkip); oversized reports that
// an oversized frame was (started to be) skipped, so the caller can count it; octet
// reports that the token was delimited by an octet count rather than a newline,
// which is what tells the caller whether continuation lines are possible at all
// (see assembler) AND, when oversized is also true, which oversize-recovery mode
// the stateful splitter must enter.
//
// partial is set ONLY by newline framing, and says the frame's terminator is not in
// data. It is what separates the two newline oversize cases that must be handled
// differently — "oversized and already terminated" (nothing left to discard) from
// "oversized and still running" (discard until the terminator shows up) — and it
// also lets a stateful caller take custody of an as-yet-unterminated line instead of
// asking bufio.Scanner to hold it (see frameSplitter.pending). The octet path never
// sets it: an incomplete octet-counted frame is replayed by the scanner, because its
// declared length is already known to fit.
func scanFrame(data []byte, atEOF bool) (advance int, token []byte, skip int, oversized, octet, partial bool) {
	if len(data) == 0 {
		return 0, nil, 0, false, false, false
	}
	if data[0] >= '0' && data[0] <= '9' {
		if a, tok, sk, over, ok := scanOctetCounted(data, atEOF); ok {
			return a, tok, sk, over, true, false
		}
		// Not octet counting after all (a non-digit in the prefix, or digits with no
		// following space at EOF): fall through to newline framing.
	}
	a, tok, over, part := scanNewline(data, atEOF)
	return a, tok, 0, over, false, part
}

// scanOctetCounted handles "<n> <n bytes>". ok is false when the data does not
// look like an octet-counted frame and the caller should fall back to newline
// framing.
func scanOctetCounted(data []byte, atEOF bool) (advance int, token []byte, skip int, oversized, ok bool) {
	const maxLenDigits = 10
	sp := -1
	for i := 0; i < len(data) && i <= maxLenDigits; i++ {
		c := data[i]
		if c == ' ' {
			sp = i
			break
		}
		if c < '0' || c > '9' {
			return 0, nil, 0, false, false // not a length prefix
		}
	}
	if sp < 0 {
		if len(data) > maxLenDigits {
			return 0, nil, 0, false, false // absurd "length": not octet counting
		}
		if atEOF {
			return 0, nil, 0, false, false // trailing digits, no frame
		}
		return 0, nil, 0, false, true // need more data
	}

	n := 0
	for _, c := range data[:sp] {
		n = n*10 + int(c-'0')
	}
	prefix := sp + 1

	if n > maxMessageBytes {
		// Oversized: SKIP it, never error. If the whole frame is buffered we advance
		// past it in one go; otherwise consume what we hold and report the remainder
		// so a stateful caller can finish the skip.
		if prefix+n <= len(data) {
			return prefix + n, nil, 0, true, true
		}
		consumed := len(data)
		return consumed, nil, prefix + n - consumed, true, true
	}

	if prefix+n > len(data) {
		if atEOF {
			// Truncated frame: ship what actually arrived rather than dropping it.
			return len(data), data[prefix:], 0, false, true
		}
		return 0, nil, 0, false, true // request more data — NEVER a short token
	}
	return prefix + n, data[prefix : prefix+n], 0, false, true
}

// scanNewline is bufio.ScanLines with a \r strip, plus "return the remainder at
// EOF" so a partial final frame is not dropped.
//
// (#398) It also refuses to hand back — or wait forever for — a payload longer
// than maxMessageBytes: oversized reports that, either because a found line's
// content (after CR-stripping, so a CRLF frame's payload is never penalised for
// its own delimiter) exceeds the cap, or because no terminator has appeared at all
// even though more than a cap's worth of data has already arrived.
//
// partial distinguishes those two, and the distinction is load-bearing: when the
// terminator WAS found the frame is fully accounted for and the next byte starts a
// new frame, whereas when it was not, the rest of the same oversized line is still
// coming and must be discarded before framing can resume. Getting that wrong ate
// the frame that followed an oversized one. partial is also set for the ordinary
// "not oversized, just not terminated yet" case, so a stateful caller can take
// custody of the bytes rather than leave bufio.Scanner holding an ever-growing
// unterminated line (frameSplitter.pending) — this helper is stateless and can only
// ever report the condition and consume what it currently holds.
func scanNewline(data []byte, atEOF bool) (advance int, token []byte, oversized, partial bool) {
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		body := dropCR(data[:i])
		if len(body) > maxMessageBytes {
			// Terminated AND oversized: consume the whole line including its
			// delimiter. There is nothing further to discard.
			return i + 1, nil, true, false
		}
		return i + 1, body, false, false
	}
	if len(data) > maxMessageBytes {
		// No terminator yet, and already over the cap: this line is oversized
		// regardless of how it eventually ends. Consume what we have; the caller
		// tracks that more of the same frame may still be arriving.
		return len(data), nil, true, true
	}
	if atEOF {
		return len(data), dropCR(data), false, false
	}
	return 0, nil, false, true
}

func dropCR(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\r' {
		return b[:n-1]
	}
	return b
}

// frameSplitter is a stateful framer for ONE connection: ScanFrames plus recovery
// state, so an oversized frame larger than the scanner buffer is still discarded
// cleanly and the next good frame is recovered. Not safe for concurrent use — build
// one per connection.
//
// onOversized fires exactly once per skipped frame (the listener counts
// Rejected{oversized}), regardless of how many reads it takes to finish discarding it.
type frameSplitter struct {
	onOversized func()

	// skip is the number of remaining bytes to discard for an octet-counted
	// oversized frame — its length is known up front from the declared count.
	skip int
	// lineSkip is the newline-framed equivalent: true while discarding an oversized
	// line whose end (the next '\n') has not yet been seen. Unlike skip it carries
	// no count, because a newline frame's total length is never known in advance —
	// discarding continues until a terminator finally appears (or the connection
	// ends).
	lineSkip bool

	// accum/pending hold a newline-framed line whose terminator has not arrived yet.
	//
	// The splitter takes custody of those bytes instead of returning (0, nil, nil)
	// and letting bufio.Scanner hold them, because the scanner's answer to "the split
	// func wants more data and my buffer is full" is the TERMINAL error
	// bufio.ErrTooLong — which kills the connection and loses every frame after it,
	// the exact failure #398 is about. A newline frame carries no length prefix, so
	// the scanner cannot know an unterminated line will never fit; the splitter can,
	// because it stops accumulating the moment pending would exceed maxMessageBytes
	// and switches to lineSkip. Consuming on every call also means the split func
	// never asks the scanner to grow, so the connection's buffer stays bounded no
	// matter what a peer sends.
	//
	// accum is tracked separately from len(pending) because while it is set the
	// octet-counting probe must NOT run again: mid-line continuation bytes that
	// happen to start with a digit are not a length prefix.
	accum   bool
	pending []byte

	// octet reports whether the MOST RECENTLY returned token was octet-counted.
	// Read it only from the scanner's own goroutine, immediately after Scan returns
	// true — it is overwritten by the next token. The listener needs it because
	// octet-counted frames carry their own length and therefore cannot be split by
	// an embedded newline, whereas newline-framed ones can (see assembler).
	octet bool
}

func newFrameSplitter(onOversized func()) *frameSplitter {
	return &frameSplitter{onOversized: onOversized}
}

func (f *frameSplitter) split(data []byte, atEOF bool) (int, []byte, error) {
	off := 0
	// Loop rather than returning a bare skip advance: bufio.Scanner issues a fresh
	// Read after any nil-token return, so a frame already sitting behind the skipped
	// bytes would be stranded in the buffer until the peer happened to send more.
	for {
		if f.skip > 0 {
			if len(data) == 0 {
				return off, nil, nil
			}
			n := f.skip
			if n > len(data) {
				n = len(data)
			}
			f.skip -= n
			off += n
			data = data[n:]
			if f.skip > 0 {
				return off, nil, nil
			}
			continue
		}
		if f.lineSkip {
			// Discard through the next '\n', however many reads that takes. This is
			// what keeps the scanner's OWN buffer bounded (#398): each call here
			// consumes everything it is handed, so bufio never accumulates a giant
			// unterminated line while waiting for a delimiter that has not arrived yet.
			if i := bytes.IndexByte(data, '\n'); i >= 0 {
				off += i + 1
				data = data[i+1:]
				f.lineSkip = false
				continue
			}
			off += len(data)
			if atEOF {
				// The connection is ending mid-oversized-line: there is no terminator
				// coming, so there is nothing left to recover on this connection.
				f.lineSkip = false
			}
			return off, nil, nil
		}
		if f.accum {
			if i := bytes.IndexByte(data, '\n'); i >= 0 {
				f.pending = append(f.pending, data[:i]...)
				off += i + 1
				data = data[i+1:]
				body := dropCR(f.pending)
				f.accum = false
				if len(body) > maxMessageBytes {
					// The line only proved oversized once its terminator arrived. It is
					// fully consumed, so framing resumes at the next byte — entering
					// lineSkip here would eat the innocent frame behind it.
					f.pending = nil
					if f.onOversized != nil {
						f.onOversized()
					}
					continue
				}
				// Hand the accumulated bytes to the caller and drop our reference:
				// bufio.Scanner's token stays valid until the next Scan, so pending must
				// never be appended to again while the caller may still be reading it.
				f.pending = nil
				f.octet = false
				return off, body, nil
			}
			if len(f.pending)+len(data) > maxMessageBytes {
				// Oversized before the terminator was ever seen. Stop accumulating (the
				// whole point of the cap) and discard through the eventual '\n'.
				f.accum = false
				f.pending = nil
				if f.onOversized != nil {
					f.onOversized()
				}
				f.lineSkip = true
				continue
			}
			// Everything left is mid-line: take it all. Both paths below return, so
			// data is deliberately not re-sliced — the loop does not continue here.
			f.pending = append(f.pending, data...)
			off += len(data)
			if atEOF {
				// The connection ended mid-line. Ship what arrived rather than dropping
				// it, exactly as scanNewline does for a stateless truncated final frame.
				f.accum = false
				body := dropCR(f.pending)
				f.pending = nil
				if len(body) == 0 {
					return off, nil, nil
				}
				f.octet = false
				return off, body, nil
			}
			return off, nil, nil
		}
		advance, token, more, oversized, octet, partial := scanFrame(data, atEOF)
		if oversized {
			if f.onOversized != nil {
				f.onOversized()
			}
			switch {
			case octet:
				f.skip = more
			case partial:
				// Oversized with no terminator in sight: keep discarding until one shows up.
				f.lineSkip = true
			}
			off += advance
			data = data[advance:]
			continue
		}
		if partial {
			// Newline framing with the terminator still to come. Take custody rather
			// than returning (0, nil, nil), which is what risks bufio.ErrTooLong.
			f.accum = true
			continue
		}
		if token != nil {
			f.octet = octet
		}
		return off + advance, token, nil
	}
}

// splitFunc adapts the splitter to bufio.Scanner.
func (f *frameSplitter) splitFunc() bufio.SplitFunc { return f.split }
