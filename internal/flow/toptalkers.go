package flow

import (
	"sort"
	"sync"
)

// Top-talker bounds. topN caps the emitted host series; maxKeys caps the live map so
// an unauthenticated NetFlow flood of novel hosts cannot grow it without bound. Both
// are hardcoded rather than flagged: the feature's only knob is --flow.top-talkers
// (whether the host label exists at all), and a busy firewall's talker set is
// well-characterised, so 100 emitted over a 10,000-key map covers it with headroom.
const (
	defaultTopTalkerTopN    = 100
	defaultTopTalkerMaxKeys = 10000
)

// talkerKey is one emitted series: an internal host and the flow's direction. The
// host is bounded ONLY by the caps and the fold below, which is exactly why this
// whole metric is opt-in (§9) — a host label is cardinality the other flow metrics
// deliberately refuse.
type talkerKey struct {
	host      string
	direction string
}

// talkerCell tracks a host's cumulative bytes and the watermark already folded into
// __other__, so a host that drops out of the top-N and later returns does not double
// its remainder contribution. Bytes-only ranking makes the cumulative fold monotone
// (see rollup.go's proof for the byte sort key), so no per-metric watermark subtlety
// beyond this one counter is needed.
type talkerCell struct {
	cum    uint64
	folded uint64
}

// TalkerEntry is one emitted (host, direction) byte total.
type TalkerEntry struct {
	Host      string
	Direction string
	Bytes     uint64
}

// TopTalkers ranks internal hosts by flow bytes, folding everything past the top-N
// into an __other__ series PER DIRECTION so a sum-by-direction stays exact at any N.
//
// It counts a SINGLE source (primary), because unlike opnsense_flow_bytes_total it
// carries no source label: on a box running both lanes, the same host's traffic is
// described by a NetFlow record AND a Zenarmor record, and adding both would double
// every host's bytes with no label to separate them. The rollup solves this with the
// source label; here the only correct fix is to count one lane.
type TopTalkers struct {
	mu      sync.Mutex
	enabled bool
	primary Source
	cells   map[talkerKey]*talkerCell
	other   map[string]*uint64 // remainder bytes, keyed by direction
	topN    int
	maxKeys int
	capped  uint64
}

// NewTopTalkers returns a disabled accumulator; Configure turns it on.
func NewTopTalkers() *TopTalkers {
	return &TopTalkers{
		cells:   make(map[talkerKey]*talkerCell),
		other:   make(map[string]*uint64),
		topN:    defaultTopTalkerTopN,
		maxKeys: defaultTopTalkerMaxKeys,
	}
}

// Configure enables the accumulator and pins the one source it counts. A primary of
// SourceUnknown counts every source, which is correct ONLY on a single-source
// deployment; main passes the source that is actually active so a dual-source box
// never double-counts.
func (t *TopTalkers) Configure(enabled bool, primary Source) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.enabled = enabled
	t.primary = primary
}

// Observe folds one record into the host ranking. A no-op when disabled, when the
// record is not from the counted source, when neither endpoint is a local host, or
// when the flow carried no bytes. Safe for concurrent callers.
func (t *TopTalkers) Observe(r Record) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.enabled {
		return
	}
	if t.primary != SourceUnknown && r.Source != t.primary {
		return
	}
	host, dir, ok := talkerOf(r)
	if !ok {
		return
	}
	b, _ := volumeOf(r)
	if b == 0 {
		return
	}

	k := talkerKey{host: host, direction: dir}
	c := t.cells[k]
	if c == nil {
		// Insert-time cap: a novel host beyond the bound folds straight into the
		// remainder rather than growing the map, and the fold is counted so saturation
		// is visible instead of silent.
		if t.maxKeys > 0 && len(t.cells) >= t.maxKeys {
			*t.otherFor(dir) += b
			t.capped++
			return
		}
		c = &talkerCell{}
		t.cells[k] = c
	}
	c.cum += b
}

// Snapshot returns the top-N hosts by bytes plus one __other__ remainder per
// direction. The sum over every returned entry equals the true observed total
// exactly, at every call; nothing is reset.
func (t *TopTalkers) Snapshot() []TalkerEntry {
	t.mu.Lock()
	defer t.mu.Unlock()

	ranked := make([]talkerKey, 0, len(t.cells))
	for k := range t.cells {
		ranked = append(ranked, k)
	}
	// Descending bytes, deterministic key tie-break — without it equal-valued hosts
	// swap top-N membership between scrapes and churn series.
	sort.Slice(ranked, func(i, j int) bool {
		ci, cj := t.cells[ranked[i]], t.cells[ranked[j]]
		if ci.cum != cj.cum {
			return ci.cum > cj.cum
		}
		if ranked[i].host != ranked[j].host {
			return ranked[i].host < ranked[j].host
		}
		return ranked[i].direction < ranked[j].direction
	})

	cut := len(ranked)
	if t.topN > 0 && cut > t.topN {
		cut = t.topN
	}

	out := make([]TalkerEntry, 0, cut+len(t.other))
	for i, k := range ranked {
		c := t.cells[k]
		if i < cut {
			out = append(out, TalkerEntry{Host: k.host, Direction: k.direction, Bytes: c.cum - c.folded})
			continue
		}
		// Outside the top-N: move the delta since the last fold into this direction's
		// remainder and advance the watermark, so the series folds rather than freezing.
		*t.otherFor(k.direction) += c.cum - c.folded
		c.folded = c.cum
	}
	for dir, v := range t.other {
		out = append(out, TalkerEntry{Host: OtherLabel, Direction: dir, Bytes: *v})
	}
	return out
}

// otherFor returns this direction's remainder, creating it on first fold. Callers
// hold the mutex.
func (t *TopTalkers) otherFor(dir string) *uint64 {
	v := t.other[dir]
	if v == nil {
		v = new(uint64)
		t.other[dir] = v
	}
	return v
}

// talkerOf picks the internal host whose traffic this record represents, and the
// direction to label it with. The source is the talker when it is a local/self
// address; otherwise the destination is, for inbound traffic to a local host.
// External-to-external transit (neither end local) has no talker to attribute and is
// skipped rather than credited to a remote address.
func talkerOf(r Record) (host, direction string, ok bool) {
	if isLocalScope(r.Enrich.SrcScope) && r.SrcAddr.IsValid() {
		return r.SrcAddr.String(), r.Direction.String(), true
	}
	if isLocalScope(r.Enrich.DstScope) && r.DstAddr.IsValid() {
		return r.DstAddr.String(), r.Direction.String(), true
	}
	return "", "", false
}

// isLocalScope reports whether an enrich.Snapshot scope names a host on the
// firewall's own networks. "self" (the firewall itself) counts as local: a service
// the box runs is still an internal talker.
func isLocalScope(s string) bool { return s == "local" || s == "self" }
