package syslog

import (
	"bufio"
	"bytes"
)

// maxMessageBytes caps a single syslog frame. Anything larger is skipped and
// counted, never errored: bufio.Scanner errors are TERMINAL, so returning one
// would kill the whole TCP connection and put a reconnecting syslog-ng into a
// reconnect loop.
const maxMessageBytes = 64 << 10

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
// An oversized frame (declared length > maxMessageBytes) is skipped, not errored.
// Skipping one that is LARGER THAN THE SCANNER'S BUFFER cannot be done statelessly
// — the listener uses newFrameSplitter, which carries the remaining skip count
// across reads. Callers using ScanFrames directly must size the scanner buffer to
// hold the largest frame they expect to skip.
func ScanFrames(data []byte, atEOF bool) (int, []byte, error) {
	advance, token, _, _, _ := scanFrame(data, atEOF)
	return advance, token, nil
}

// scanFrame is the framing core. skip is the number of bytes of an oversized frame
// still to be discarded after the returned advance; oversized reports that an
// oversized frame was (started to be) skipped, so the caller can count it; octet
// reports that the token was delimited by an octet count rather than a newline,
// which is what tells the caller whether continuation lines are possible at all
// (see assembler).
func scanFrame(data []byte, atEOF bool) (advance int, token []byte, skip int, oversized, octet bool) {
	if len(data) == 0 {
		return 0, nil, 0, false, false
	}
	if data[0] >= '0' && data[0] <= '9' {
		if a, tok, sk, over, ok := scanOctetCounted(data, atEOF); ok {
			return a, tok, sk, over, true
		}
		// Not octet counting after all (a non-digit in the prefix, or digits with no
		// following space at EOF): fall through to newline framing.
	}
	a, tok := scanNewline(data, atEOF)
	return a, tok, 0, false, false
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
func scanNewline(data []byte, atEOF bool) (int, []byte) {
	if i := bytes.IndexByte(data, '\n'); i >= 0 {
		return i + 1, dropCR(data[:i])
	}
	if atEOF {
		return len(data), dropCR(data)
	}
	return 0, nil
}

func dropCR(b []byte) []byte {
	if n := len(b); n > 0 && b[n-1] == '\r' {
		return b[:n-1]
	}
	return b
}

// frameSplitter is a stateful framer for ONE connection: ScanFrames plus a skip
// counter, so an oversized frame larger than the scanner buffer is still discarded
// cleanly and the next good frame is recovered. Not safe for concurrent use — build
// one per connection.
//
// onOversized fires once per skipped frame (the listener counts Rejected{oversized}).
type frameSplitter struct {
	onOversized func()
	skip        int

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
		advance, token, more, oversized, octet := scanFrame(data, atEOF)
		if oversized {
			if f.onOversized != nil {
				f.onOversized()
			}
			f.skip = more
			off += advance
			data = data[advance:]
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
