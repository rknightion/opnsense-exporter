package capture

import (
	"strings"
	"sync"
	"time"
)

// Shape dedupe for the high-volume capture lanes (#362).
//
// The byte cap is GLOBAL and it STOPS rather than rotates: whichever lane fills the
// dir first wins it permanently, and everything else is silently starved. That is
// tolerable while every lane is bounded by "something we do not model arrived",
// which is rare. It stopped being tolerable when one lane's definition of unmodelled
// turned out to cover the majority of its input: a firewall's syslog is
// overwhelmingly programs with no dedicated parser, so the syslog capture wrote
// 60,073 entries and 31 MB in a day, 70% of it three repeated message shapes, and
// from the moment the cap was reached the NetFlow and Zenarmor captures — both
// genuinely bounded, both worth leaving on — could never write again. The failure
// mode is the bad one: it looks exactly like "nothing unrecognised has arrived".
//
// So a lane that captures a class of line rather than an event captures one EXAMPLE
// of each shape per window and counts the rest. The suppressed count is the load
// bearing half: without it a small file reads as a quiet lane instead of a busy one.
//
// This is deliberately a second, separate path (CaptureShape) rather than a change
// to Capture. The NetFlow and Zenarmor lanes are already bounded by design — a
// couple of datagrams at startup and nothing after — and putting them behind a
// window would throw away samples they need to be complete.

const (
	// shapePlaceholder stands in for every varying run in a message. One character
	// for digits and hex alike: the shape is "what kind of line is this", and
	// distinguishing a byte count from a status word does not change the answer.
	shapePlaceholder = '#'

	// maxShapeLen bounds a shape in RUNES. A shape becomes a map key held for a
	// window, and the message it is derived from comes off the wire — a program
	// logging a 64KB body must not be able to mint a 64KB key. 120 runes is past
	// the point where two lines sharing that much prefix are still different facts.
	maxShapeLen = 120

	// minHexRun is the shortest all-hex token collapsed as a whole. Below it, the
	// digit-run rule already does enough (86 -> #), and collapsing short tokens
	// would start eating ordinary words.
	minHexRun = 8

	// DefaultShapeWindow is how long a shape stays quiet after one example is kept.
	// It matches the netflow notice limiter's interval for the same reason: long
	// enough that a steady repeat costs one entry per quarter hour, short enough
	// that a shape which stops and restarts is visible as two events rather than
	// one.
	DefaultShapeWindow = 15 * time.Minute

	// DefaultMaxShapeKeys bounds the limiter's map. The netflow limiter uses 64
	// because its keys are a closed kind vocabulary crossed with a small detail;
	// shapes are open-ended — one per (program, message shape) — and a firewall
	// legitimately runs dozens of programs with several shapes each, so 64 would
	// spend most of its life folded and blind. 256 keys of at most maxShapeLen
	// runes is tens of KB, flat, and comfortably above a real box's distinct-shape
	// count while still bounding a runaway program or a hostile sender.
	DefaultMaxShapeKeys = 256

	// foldedShapeKey is the single slot everything past the bound shares, so memory
	// stays flat instead of growing with input nobody controls. The entry that wins
	// the slot is still written in full — only the SUPPRESSION is shared.
	foldedShapeKey = "\x00folded"
)

// NormaliseShape reduces a log message to its SHAPE: the parts that identify what
// kind of line it is, with everything that varies between occurrences collapsed.
//
// It is deliberately crude. It does not need to understand the message; it needs to
// stop 11,485 identical facts becoming 11,485 capture entries. Three rules:
//
//   - a run of decimal digits collapses, so a counter, a byte count, a PID, a port
//     and each octet of an address all fold ([367655] -> [#], 86.31.203.106 -> #.#.#.#);
//   - a hex-looking token collapses whole — an 0x-prefixed literal, or an all-hex
//     token of at least minHexRun characters that contains a digit (the digit is
//     what keeps English words out: no word of that length is written in [a-f] and
//     also carries a number);
//   - runs of whitespace collapse to one space, because a message that differs only
//     by column padding is the same message.
//
// The result is truncated to maxShapeLen runes, never mid-rune.
func NormaliseShape(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	pendingSpace := false
	for i := 0; i < len(s); {
		c := s[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\v' || c == '\f' {
			i++
			// Held, not written: a trailing run must not become a trailing space, and a
			// leading one must not become a leading space.
			pendingSpace = b.Len() > 0
			continue
		}
		if pendingSpace {
			b.WriteByte(' ')
			pendingSpace = false
		}
		// The hex rules apply only at a token boundary, so the "1" in "ixl1" is handled
		// by the digit rule and cannot be mistaken for the head of a hex literal.
		if atTokenStart(s, i) {
			if n := hexTokenLen(s, i); n > 0 {
				b.WriteByte(shapePlaceholder)
				i += n
				continue
			}
		}
		if isDigit(c) {
			for i < len(s) && isDigit(s[i]) {
				i++
			}
			b.WriteByte(shapePlaceholder)
			continue
		}
		b.WriteByte(c)
		i++
	}
	return truncateRunes(b.String(), maxShapeLen)
}

func atTokenStart(s string, i int) bool { return i == 0 || !isAlnum(s[i-1]) }

// hexTokenLen returns the byte length of the hex-looking token at i, or 0 if there
// is none. Two forms qualify: an 0x/0X literal with at least one hex digit, and a
// bare all-hex token of at least minHexRun characters carrying at least one decimal
// digit (a session id, a truncated UUID, a MAC without separators).
func hexTokenLen(s string, i int) int {
	end := i
	for end < len(s) && isAlnum(s[end]) {
		end++
	}
	tok := s[i:end]
	if len(tok) >= 3 && tok[0] == '0' && (tok[1] == 'x' || tok[1] == 'X') && allHex(tok[2:]) {
		return end - i
	}
	if len(tok) >= minHexRun && allHex(tok) && hasDigit(tok) {
		return end - i
	}
	return 0
}

func isDigit(c byte) bool { return c >= '0' && c <= '9' }

func isAlnum(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isHex(c byte) bool {
	return isDigit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')
}

func allHex(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isHex(s[i]) {
			return false
		}
	}
	return true
}

func hasDigit(s string) bool {
	for i := 0; i < len(s); i++ {
		if isDigit(s[i]) {
			return true
		}
	}
	return false
}

// truncateRunes cuts s to at most max runes. Ranging over a string yields rune
// start offsets, so the cut can never land inside a multi-byte rune and leave an
// invalid key behind.
func truncateRunes(s string, max int) string {
	if len(s) <= max { // bytes <= max implies runes <= max; the common case costs one compare
		return s
	}
	n := 0
	for i := range s {
		if n == max {
			return s[:i]
		}
		n++
	}
	return s
}

// ShapeLimiter suppresses repeats of the same shape within a window. It is the same
// device as noticeLimiter in internal/flow/netflow (deliberately: one proven shape,
// not two) — bounded key count, everything past the bound folded into one shared
// key, first occurrence of a key always allowed.
//
// It is called from receiver read goroutines, so every method takes the mutex. A nil
// *ShapeLimiter allows everything, matching the nil-is-a-no-op contract the rest of
// this package uses.
type ShapeLimiter struct {
	mu     sync.Mutex
	window time.Duration
	max    int
	seen   map[string]time.Time
}

// NewShapeLimiter builds a limiter. A non-positive window or max takes the package
// default rather than degenerating into "suppress everything" / "suppress nothing".
func NewShapeLimiter(window time.Duration, max int) *ShapeLimiter {
	if window <= 0 {
		window = DefaultShapeWindow
	}
	if max <= 0 {
		max = DefaultMaxShapeKeys
	}
	return &ShapeLimiter{window: window, max: max, seen: make(map[string]time.Time)}
}

// Allow reports whether this shape should be written now, and records that it was.
// The first occurrence of a key is always allowed — seeing a novel line the moment
// it appears is the entire point of the capture.
func (l *ShapeLimiter) Allow(key string, now time.Time) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, known := l.seen[key]; !known && len(l.seen) >= l.max {
		key = foldedShapeKey
	}
	last, known := l.seen[key]
	if known && now.Sub(last) < l.window {
		return false
	}
	l.seen[key] = now
	return true
}

func (l *ShapeLimiter) size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.seen)
}
