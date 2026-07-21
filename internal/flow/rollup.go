package flow

import (
	"sort"
	"sync"
)

// OtherLabel is the bucket every dimension beyond the bounds folds into. Folding
// rather than dropping is what keeps sum() over the family exact regardless of the
// bounds, so a dashboard's answer does not change when an operator retunes them.
const OtherLabel = "__other__"

// RollupKey is the complete, bounded label set of a flow metric series.
//
// Every field is a closed, code-or-taxonomy-defined value: interface names come
// from the OPNsense API, app_category is a 24-value Zenarmor taxonomy (measured
// across 20,476 live conn documents), and the rest are enumerations spelled in this
// package. The high-cardinality fields sitting right next to these on the same
// Record — any address or port, hostname, MAC, app_name, domain, JA3, community_id,
// conn_uuid — must NEVER be added. They stay on the shipped record, where they are
// still filterable. Same rule and same reasoning as
// internal/logship/logmetrics.go:49-53.
type RollupKey struct {
	Interface string
	Direction string
	Transport string
	Category  string
	Action    string
	Source    string
	Scope     string
}

// RollupLabelNames is the metric's label names, in the order RollupKey spells them.
//
// The collector spells this list as a LITERAL rather than calling this function.
// scripts/docgen resolves the labels argument STATICALLY (main.go:872
// resolveLabelSlice folds a composite literal, a local var assigned one, or an
// append chain — but not a function call), so passing a call yields zero documented
// labels and scripts/docgen/verify.go then fails the docs build. This exists so a
// test can assert the two spellings have not drifted apart.
func RollupLabelNames() []string {
	return []string{"interface", "direction", "transport", "category", "action", "source", "scope"}
}

// Values returns the label values in RollupLabelNames order.
func (k RollupKey) Values() []string {
	return []string{k.Interface, k.Direction, k.Transport, k.Category, k.Action, k.Source, k.Scope}
}

// RollupEntry is one emitted series.
type RollupEntry struct {
	Key     RollupKey
	Bytes   uint64
	Packets uint64
	Flows   uint64
}

// add accumulates other into e, leaving the key alone.
func (e *RollupEntry) add(bytes, packets, flows uint64) {
	e.Bytes += bytes
	e.Packets += packets
	e.Flows += flows
}

// RollupStats is the accumulator's own health, published as self-metrics.
//
// Without these an operator cannot distinguish "a few small categories folded into
// __other__" from "the map saturated weeks ago and every new dimension has been
// invisible since" — the two look identical from the outside.
type RollupStats struct {
	Keys       int    // live tracked keys
	MaxKeys    int    // configured insert cap; 0 = unbounded
	TopN       int    // configured emit cap; 0 = unbounded
	FoldedKeys int    // keys outside top-N as of the last Snapshot
	Capped     uint64 // observations folded because the map was already at MaxKeys
}

// rollupCell is one key's running state.
//
// folded is the WATERMARK: how much of cum has already been attributed to
// __other__. It is what keeps the remainder monotone under top-N membership churn.
//
// Folding the tail's CUMULATIVE totals — the obvious implementation — is monotone
// only for the sort key. For any N-subset S, sum_S bytes(t1) <= sum_topN bytes(t1)
// because top-N is the maximising subset, and every per-key delta is non-negative,
// so the byte remainder never decreases. Packets and records ride along on a
// bytes-only ranking, where that argument does not hold: a high-packet/low-byte key
// crossing the boundary drops the packet remainder by millions in a single
// interval, which Prometheus reads as a counter reset. Folding DELTAS against this
// watermark keeps all three monotone.
type rollupCell struct {
	cum    RollupEntry
	folded RollupEntry
}

// Rollup accumulates flow volume against a bounded key set.
//
// Two INDEPENDENT bounds, and conflating them is the classic mistake:
//
//   - maxKeys bounds the LIVE map between snapshots. It is the memory bound, and it
//     is the one that matters when the input is attacker-reachable (phase 2's
//     NetFlow listener is unauthenticated by nature — NetFlow has no auth).
//   - topN bounds the EMITTED series at snapshot time. It is the cardinality bound.
//
// topN alone leaves the map unbounded; maxKeys alone leaves the series count
// unbounded. Both are required, and each is tested separately. Zero means unbounded
// for either.
type Rollup struct {
	mu    sync.Mutex
	cells map[RollupKey]*rollupCell
	// other is the folded remainder, keyed by SOURCE rather than being a single
	// bucket. From phase 2 the family carries two sources' measurement of the same
	// traffic, so a query that does not pin source double-counts; collapsing source
	// into the sentinel as well would make the correct query impossible to express.
	other      map[string]*RollupEntry
	topN       int
	maxKeys    int
	capped     uint64
	foldedKeys int
}

// NewRollup returns an accumulator bounded by topN emitted series and maxKeys live
// keys. Zero disables either bound.
func NewRollup(topN, maxKeys int) *Rollup {
	return &Rollup{
		cells:   make(map[RollupKey]*rollupCell),
		other:   make(map[string]*RollupEntry),
		topN:    topN,
		maxKeys: maxKeys,
	}
}

// SetBounds retunes the caps in place.
//
// It takes the SAME mutex as Observe and Snapshot and swaps no pointer, so it is
// safe from any goroutine at any time and discards no accumulated total. That
// matters because StartPolling (main.go:596) launches a poller per collector:
// resizing by replacing the accumulator afterwards would be a genuine data race,
// and one that lives in untested main.go wiring where -race never reaches it.
func (r *Rollup) SetBounds(topN, maxKeys int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.topN, r.maxKeys = topN, maxKeys
}

// Observe folds one record into the accumulator. Safe for concurrent use: it is
// called from receiver goroutines while the collector snapshots.
func (r *Rollup) Observe(rec Record) {
	k := keyFor(rec)
	b, p := volumeOf(rec)

	r.mu.Lock()
	defer r.mu.Unlock()

	c, ok := r.cells[k]
	if !ok {
		// Insert-time cap: a novel key beyond the bound folds straight into this
		// source's remainder rather than growing the map. Existing keys keep
		// accumulating, so steady-state traffic is unaffected and only novelty is
		// bounded — and the fold is counted, so saturation is never silent.
		if r.maxKeys > 0 && len(r.cells) >= r.maxKeys {
			r.otherFor(k.Source).add(b, p, 1)
			r.capped++
			return
		}
		c = &rollupCell{cum: RollupEntry{Key: k}}
		r.cells[k] = c
	}
	c.cum.add(b, p, 1)
}

// Snapshot returns the top-N entries by bytes plus one folded remainder per source.
//
// Counters are cumulative — nothing is reset — and the sum over every returned
// series equals the true observed total exactly, at every call. A key outside top-N
// has its delta since the last fold moved into the remainder; a key inside emits
// what has not already been attributed there.
//
// Calling this twice with no intervening Observe returns identical values: the
// second pass folds a zero delta.
func (r *Rollup) Snapshot() []RollupEntry {
	r.mu.Lock()
	defer r.mu.Unlock()

	ranked := make([]*rollupCell, 0, len(r.cells))
	for _, c := range r.cells {
		ranked = append(ranked, c)
	}

	// Descending by bytes, with a total order on the key as tie-break. Without a
	// deterministic tie-break, equal-valued keys swap places between scrapes and
	// top-N membership flaps, churning series and corrupting rate().
	sort.Slice(ranked, func(i, j int) bool {
		if ranked[i].cum.Bytes != ranked[j].cum.Bytes {
			return ranked[i].cum.Bytes > ranked[j].cum.Bytes
		}
		return lessKey(ranked[i].cum.Key, ranked[j].cum.Key)
	})

	cut := len(ranked)
	if r.topN > 0 && cut > r.topN {
		cut = r.topN
	}
	r.foldedKeys = len(ranked) - cut

	out := make([]RollupEntry, 0, cut+len(r.other)+1)
	for i, c := range ranked {
		if i < cut {
			// Emit what has not already been attributed to the remainder. For a key
			// that has never been folded this is its lifetime total.
			out = append(out, RollupEntry{
				Key:     c.cum.Key,
				Bytes:   c.cum.Bytes - c.folded.Bytes,
				Packets: c.cum.Packets - c.folded.Packets,
				Flows:   c.cum.Flows - c.folded.Flows,
			})
			continue
		}
		// Outside top-N: move the delta since the last fold into this source's
		// remainder and advance the watermark. The series is not emitted, so it is
		// folded rather than frozen at its last value — the failure mode that makes a
		// top-K exporter lie indefinitely.
		r.otherFor(c.cum.Key.Source).add(
			c.cum.Bytes-c.folded.Bytes,
			c.cum.Packets-c.folded.Packets,
			c.cum.Flows-c.folded.Flows,
		)
		c.folded = c.cum
	}

	rem := make([]RollupEntry, 0, len(r.other))
	for _, e := range r.other {
		rem = append(rem, *e)
	}
	sort.Slice(rem, func(i, j int) bool { return rem[i].Key.Source < rem[j].Key.Source })
	return append(out, rem...)
}

// Stats reports the accumulator's own health.
func (r *Rollup) Stats() RollupStats {
	r.mu.Lock()
	defer r.mu.Unlock()
	return RollupStats{
		Keys:       len(r.cells),
		MaxKeys:    r.maxKeys,
		TopN:       r.topN,
		FoldedKeys: r.foldedKeys,
		Capped:     r.capped,
	}
}

// otherFor returns this source's remainder, creating it on first fold. Callers hold
// the mutex. Lazy creation means "__other__ exists" always implies "something
// folded", rather than every deployment carrying an idle sentinel series.
func (r *Rollup) otherFor(source string) *RollupEntry {
	e, ok := r.other[source]
	if !ok {
		e = &RollupEntry{Key: otherKey(source)}
		r.other[source] = e
	}
	return e
}

// otherKey collapses every dimension to the sentinel EXCEPT source. Collapsing the
// rest (rather than only the dimension that overflowed) keeps the remainder a
// single series instead of one per surviving combination, which is the whole point
// of the bound.
func otherKey(source string) RollupKey {
	return RollupKey{
		Interface: OtherLabel, Direction: OtherLabel, Transport: OtherLabel,
		Category: OtherLabel, Action: OtherLabel, Source: source, Scope: OtherLabel,
	}
}

func keyFor(rec Record) RollupKey {
	return RollupKey{
		Interface: rec.In.Label(),
		Direction: rec.Direction.String(),
		Transport: transportName(rec.Proto),
		Category:  rec.L7.AppCategory,
		Action:    rec.Verdict.String(),
		Source:    rec.Source.String(),
		Scope:     rec.Enrich.DstScope,
	}
}

// volumeOf picks the authoritative counters.
//
// Post-repair NetFlow wins when present because it counts at the packet path, while
// Zenarmor only sees flows it inspects. The two are NEVER summed — they measure at
// different points in the stack and will legitimately disagree (#346 decision 3),
// and the disagreement is itself a signal.
//
// In phase 1 only the Zenarmor branch is reachable, because the correlator that
// produces a record carrying both does not exist yet. The NetFlow branch is the
// seam phase 2 fills. Note that once it does, the family holds two independent
// measurements of the same traffic: a query must pin the source label or it
// double-counts, which is why the __other__ remainder keeps that label.
func volumeOf(rec Record) (bytes, packets uint64) {
	if rec.NF.Present {
		return rec.NF.Bytes(), rec.NF.Packets()
	}
	return rec.Zen.Bytes(), rec.Zen.Packets()
}

// transportName folds the protocol number to a bounded name. An unrecognised
// protocol becomes "other" rather than its number: the field is wire-derived and,
// on the phase-2 listener, attacker-controlled, so echoing it verbatim would let a
// misbehaving sender mint up to 256 label values.
func transportName(p uint8) string {
	switch p {
	case 1:
		return "icmp"
	case 6:
		return "tcp"
	case 17:
		return "udp"
	case 47:
		return "gre"
	case 50:
		return "esp"
	case 58:
		return "icmpv6"
	case 132:
		return "sctp"
	default:
		return "other"
	}
}

func lessKey(a, b RollupKey) bool {
	av, bv := a.Values(), b.Values()
	for i := range av {
		if av[i] != bv[i] {
			return av[i] < bv[i]
		}
	}
	return false
}
