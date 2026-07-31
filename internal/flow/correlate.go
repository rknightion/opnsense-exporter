package flow

import (
	"sync"
	"time"
)

// Correlator collapses NetFlow's 1:N fragmentation into one flow record per
// connection-window and, when a Zenarmor conn document describes the same
// conversation, merges its L7 classification onto that record.
//
// Why an accumulator and not a pairwise matcher (#346): one connection produces a
// mean of 3.75 NetFlow records — unidirectional split × inactive-timeout re-reporting
// × VLAN duplication — and the worst tuple in the reference capture produced 332
// records over 1,726s. Emitting one log per fragment would be 3.75× spam; matching
// them pairwise is impossible because the count is unbounded. So fragments accumulate
// under a key and emit once.
//
// The correlator ONLY ever emits NetFlow-derived records. Zenarmor conn documents are
// enrichment INPUT — they attach L7/verdict/domain to a matching NetFlow entry and
// otherwise vanish here, because the conn document already ships on its own lane with
// flow attributes added in place (#346 decision 2). That is what keeps the merged
// record from double-shipping the Zenarmor side.
//
// Emit is on window EXPIRY, not on Zenarmor arrival. The spec floated early-emit on
// arrival to shave latency, but expiry already bounds latency to one window, and
// emit-once-on-expiry removes an entire class of bug: a Zenarmor record arriving
// mid-window followed by more NetFlow fragments cannot emit the flow twice or split
// its bytes across a merged and a netflow-only record. For a flow LOG (not a metric) a
// sub-window delay is immaterial; correctness is not.
type Correlator struct {
	enabled    bool
	window     time.Duration
	maxEntries int
	emit       func(Record)

	mu    sync.Mutex
	cells map[corrKey]*corrEntry

	entries int // == len(cells); tracked so Stats never scans
	emitted uint64
	matched uint64
	evicted uint64
	expired uint64

	// enrichmentOverwrites and fragmentDisagreement are #590's self-observability
	// counters: every other bounded/lossy path in this pipeline counts its
	// refusals, and these two were the correlator's silent ones. See
	// observeZenarmorLocked and fragmentDisagrees for what each counts.
	enrichmentOverwrites uint64
	fragmentDisagreement uint64
	fragmentMirrored     uint64
}

// corrKey groups fragments of one conversation whose flow-end falls in the same
// window. A long connection spans several windows and therefore several keys, so it
// emits a partial per window — each carrying that window's NetFlow bytes — which is
// exactly what bounds emit latency for a flow that never ends.
type corrKey struct {
	community string
	bucket    int64 // floor(End / window)
}

// corrEntry is one key's running state. It emits at most once, when its window
// expires, is evicted under memory pressure, or the process flushes at shutdown.
type corrEntry struct {
	key corrKey
	// nf is the SAMPLE orientation's accumulated volume and nfMirror the mirror's,
	// kept apart because a NetFlow record is strictly unidirectional and all of its
	// volume lands in Tx (processor.go documents that OUT_BYTES/OUT_PKTS are declared
	// but always zero). Summing both halves into one accumulator made a merged record
	// report a 2 GB download as 2 GB transmitted and nothing received (#617).
	//
	// Which of the two becomes Tx is decided by orientation() at finalize, not here:
	// deciding it on arrival would make the split depend on datagram scheduling, which
	// is exactly what #605 removed.
	nf       Counters // Present once any NetFlow fragment lands
	nfMirror Counters
	sample   Record // the first NetFlow fragment: carries tuple, interfaces, direction, enrichment
	// mirror is the first fragment of the OPPOSITE orientation, if one arrived.
	//
	// A conversation has exactly two orientations and ng_netflow reports both, on
	// the same corrKey by construction (CanonicalTuple is direction-independent —
	// record.go:258). Keeping one representative of each is what lets finalize()
	// choose between them on evidence instead of on which datagram landed first,
	// and what lets fragmentDisagrees compare like with like (#605).
	mirror    *Record
	fragments int
	start     time.Time // earliest FIRST_SWITCHED across fragments
	end       time.Time // latest LAST_SWITCHED across fragments
	firstSeen time.Time // arrival of the first fragment: the expiry and eviction clock
	zen       *Record   // Zenarmor enrichment, if a conn document for this key arrived
	hasNF     bool      // false for a Zenarmor-only entry, which never emits
	// tcpFlags is OR-ed, not taken from the sample: the two directions of one
	// conversation arrive as separate NetFlow records, so the sample's byte alone reads
	// "SYN" on practically every TCP flow and a refused connection (client SYN, server
	// RST) becomes indistinguishable from a scan that got no reply at all (#585).
	tcpFlags uint8
	// repairs is the UNION of every fragment's repair markers, for the same reason
	// tcpFlags is unioned: finalize takes every non-volume dimension from ONE chosen
	// orientation, so a repair applied to any other fragment vanished at the merge.
	repairs Repairs
}

// CorrelatorStats is the correlator's own health, published as self-metrics so a
// correlation that never fires is distinguishable from one that is thrashing.
type CorrelatorStats struct {
	Entries int    // live accumulator entries
	Emitted uint64 // flow-log records emitted (netflow + merged)
	Matched uint64 // subset emitted as merged (Zenarmor enrichment found)
	Evicted uint64 // entries force-emitted early because the map hit MaxEntries
	Expired uint64 // entries emitted on the normal window-expiry path

	// EnrichmentOverwrites counts a second Zenarmor conn document landing for a key
	// that already held one: the second REPLACES the first wholesale (#590), so
	// whatever the first carried and the second didn't repeat is gone. Zero on
	// every deployment where each conversation gets one conn document, which is
	// the common case; a non-zero rate means Zenarmor is re-reporting a connection
	// and the correlator is silently keeping only the latest report.
	EnrichmentOverwrites uint64
	// FragmentDisagreements counts a NetFlow fragment whose interface, direction,
	// VLAN or enrichment dimensions differ from the sample OF ITS OWN ORIENTATION.
	// The disagreeing fragment's bytes still count toward the emitted total; only
	// its DIMENSIONS are dropped, silently until this counter.
	//
	// Two exclusions, both for the same reason - a field that differs by design is
	// not a disagreement. TCPFlags is unioned across fragments (#585), a merge
	// rather than a loss. And the reverse half of a bidirectional conversation
	// mirrors In/Out/Direction by construction (#605); before that exclusion this
	// counter fired on ordinary two-way traffic and read 48.6% of every fragment it
	// could examine on prod, which is not a rate anyone can act on.
	FragmentDisagreements uint64
	// FragmentMirrored counts fragments belonging to the conversation's OTHER
	// orientation - the reverse half. This is the expected case for any
	// bidirectional flow, not an anomaly, and it is counted rather than merely
	// excluded so the exclusion stays visible: a sudden collapse to zero would mean
	// the halves stopped sharing a key, which would break correlation itself.
	FragmentMirrored uint64
}

// CorrelatorConfig sizes the correlator.
type CorrelatorConfig struct {
	// Enabled false makes Observe a pass-through: NetFlow records emit raw and
	// per-fragment, Zenarmor records are dropped (their conn lane already ships them).
	// This is --flow.correlate=false, or a deployment with no second source to merge.
	Enabled    bool
	Window     time.Duration // grouping bucket AND the maximum an entry is held before emit
	MaxEntries int           // hard cap on live entries; 0 = unbounded (unwise on the unauth NetFlow path)
}

// NewCorrelator builds a correlator that hands finished records to emit. emit MUST NOT
// block or perform I/O on its own account beyond enqueuing — it is called from the
// receiver's goroutine (via Observe) and from the expiry ticker, and a stall there
// backs up flow ingestion. emit is always invoked with the correlator's lock released.
func NewCorrelator(cfg CorrelatorConfig, emit func(Record)) *Correlator {
	return &Correlator{
		enabled:    cfg.Enabled,
		window:     cfg.Window,
		maxEntries: cfg.MaxEntries,
		emit:       emit,
		cells:      make(map[corrKey]*corrEntry),
	}
}

// Observe folds one record into the correlator. Safe for concurrent callers.
func (c *Correlator) Observe(r Record) {
	if !c.enabled {
		// Pass-through. Only NetFlow emits: a Zenarmor conn already ships on its own
		// lane, so re-emitting it here would double it.
		if r.Source == SourceNetflow {
			c.mu.Lock()
			c.emitted++
			c.mu.Unlock()
			c.emit(r)
		}
		return
	}

	var pending []Record
	c.mu.Lock()
	switch r.Source {
	case SourceNetflow:
		pending = c.observeNetflowLocked(r)
	case SourceZenarmor:
		c.observeZenarmorLocked(r)
	}
	c.mu.Unlock()

	for _, rec := range pending {
		c.emit(rec)
	}
}

// observeNetflowLocked accumulates a NetFlow fragment, evicting the oldest entry first
// if the map is at capacity. It returns any record that eviction forced out, to be
// emitted after the lock is dropped.
func (c *Correlator) observeNetflowLocked(r Record) []Record {
	k := c.keyOf(r)
	e := c.cells[k]
	var pending []Record
	if e == nil {
		if c.maxEntries > 0 && c.entries >= c.maxEntries {
			// Emit the oldest immediately rather than dropping it: a forced early emit
			// loses no bytes, whereas a silent drop loses the whole flow. The counter
			// makes the pressure visible so the bound can be raised.
			if victim := c.oldestLocked(); victim != nil {
				if rec, ok := c.finalize(victim); ok {
					c.emitted++
					if rec.Source == SourceMerged {
						c.matched++
					}
					c.evicted++
					pending = append(pending, rec)
				}
				delete(c.cells, victim.key)
				c.entries--
			}
		}
		e = &corrEntry{key: k, firstSeen: r.Observed}
		c.cells[k] = e
		c.entries++
	}
	if !e.hasNF {
		// The entry's FIRST NetFlow fragment - whether this call created the entry
		// or a Zenarmor conn document created it earlier (order is not guaranteed;
		// see observeZenarmorLocked). This establishes the sample every non-volume
		// dimension (tuple, addresses, interfaces, direction, VLAN) comes from for
		// the entry's whole life, and the start/end window the loop below only
		// ever widens.
		//
		// #590: the OLD code set e.sample only inside the "e == nil" branch above,
		// so an entry a Zenarmor document created first NEVER received a sample
		// from the NetFlow fragment that landed afterwards - finalize() then
		// emitted the sample's ZERO VALUE (empty CommunityID, invalid SrcAddr,
		// empty interfaces), not merely "the first fragment's now-stale
		// dimensions" as originally reported. Proven by
		// TestCorrelator_ZenarmorFirstStillCarriesNetflowSample.
		e.sample = r
		e.start = r.Start
		e.end = r.End
	} else if isMirrorOf(e.sample, r) {
		// The conversation's other half. Expected, not anomalous - but keep the
		// first one we see, because finalize() chooses between the orientations on
		// evidence rather than on arrival order (#605).
		c.fragmentMirrored++
		if e.mirror == nil {
			m := r
			e.mirror = &m
		} else if fragmentDisagrees(*e.mirror, r) {
			c.fragmentDisagreement++
		}
	} else if fragmentDisagrees(e.sample, r) {
		c.fragmentDisagreement++
	}
	// Volume goes to the accumulator for the half that reported it. A fragment's own
	// Rx rides with it rather than being dropped: it is always zero on this export,
	// but discarding volume on the strength of that assumption is not a trade worth
	// making.
	half := &e.nf
	if e.mirror != nil && isMirrorOf(e.sample, r) {
		half = &e.nfMirror
	}
	half.TxBytes += r.NF.TxBytes
	half.RxBytes += r.NF.RxBytes
	half.TxPackets += r.NF.TxPackets
	half.RxPackets += r.NF.RxPackets
	half.Present = true
	e.nf.Present = true
	e.hasNF = true
	e.tcpFlags |= r.TCPFlags
	e.repairs.merge(r.Repairs)
	e.fragments += fragmentsOf(r)
	if r.Start.Before(e.start) {
		e.start = r.Start
	}
	if r.End.After(e.end) {
		e.end = r.End
	}
	return pending
}

// fragmentDisagrees reports whether r's non-volume dimensions - the ones
// finalize() takes wholesale from the entry's sample and never merges across
// fragments - differ from what the sample already recorded (#590). Interface,
// direction and VLAN are each resolved once per NetFlow record from a FIB/VLAN
// lookup that should agree fragment to fragment for one real conversation, so a
// mismatch means the fragments disagree about the conversation's own identity -
// today dropped with no trace, since only the sample's copy is ever emitted.
//
// TCPFlags is deliberately NOT compared: it is unioned across fragments (#585),
// a merge by design, not a dimension finalize() takes from the sample alone.
//
// Callers must only compare fragments of the SAME orientation. The reverse half
// mirrors every field this function looks at, so comparing across orientations
// reports a disagreement on every ordinary bidirectional conversation (#605) -
// route with isMirrorOf first.
func fragmentDisagrees(sample, r Record) bool {
	return sample.In != r.In || sample.Out != r.Out ||
		sample.Direction != r.Direction || sample.VLANID != r.VLANID ||
		sample.Enrich != r.Enrich
}

// isMirrorOf reports whether r describes the same conversation as sample, seen from
// the other direction: r's source endpoint is sample's destination and vice versa.
//
// Endpoints are compared rather than orientation being derived from In/Out or
// Direction, because those are exactly the fields whose disagreement is in
// question - deriving orientation from them would assume the answer. Addresses are
// Unmapped for the same reason CanonicalTuple does it: ::ffff:192.0.2.5 and
// 192.0.2.5 are one host, and netip compares them as two.
func isMirrorOf(sample, r Record) bool {
	return r.SrcAddr.Unmap() == sample.DstAddr.Unmap() && r.SrcPort == sample.DstPort &&
		r.DstAddr.Unmap() == sample.SrcAddr.Unmap() && r.DstPort == sample.SrcPort
}

// observeZenarmorLocked stashes a Zenarmor conn document as enrichment for a matching
// NetFlow entry. It never emits: the conn document ships on its own lane. If no NetFlow
// entry exists yet, it holds the enrichment so a fragment arriving later — order is not
// guaranteed — can still merge it. A Zenarmor-only entry that never gains NetFlow
// expires silently.
func (c *Correlator) observeZenarmorLocked(r Record) {
	k := c.keyOf(r)
	e := c.cells[k]
	if e == nil {
		// Holding Zenarmor-only state costs a map slot, so respect the cap here too;
		// dropping the enrichment (rather than evicting a real NetFlow entry) is the
		// right sacrifice, because the conn document still ships regardless.
		if c.maxEntries > 0 && c.entries >= c.maxEntries {
			return
		}
		e = &corrEntry{key: k, firstSeen: r.Observed}
		c.cells[k] = e
		c.entries++
	}
	if e.zen != nil {
		// A second Zenarmor conn document for the same key OVERWRITES the first
		// rather than merging (#590): zc below replaces e.zen wholesale, so
		// anything the first document carried that the second doesn't repeat -
		// L7, verdict, enrichment, geo - is gone with no trace. A conn document is
		// a point-in-time close event, not a fragment stream like NetFlow, so
		// there is no established merge rule to apply here; counting the
		// overwrite is what makes the loss visible instead of invisible.
		c.enrichmentOverwrites++
	}
	zc := r
	e.zen = &zc
}

// Expire emits every entry whose window has elapsed. Called from a ticker, never on
// the hot path. now is injected so tests need no real clock.
func (c *Correlator) Expire(now time.Time) {
	var pending []Record
	c.mu.Lock()
	for k, e := range c.cells {
		if now.Sub(e.firstSeen) < c.window {
			continue
		}
		if rec, ok := c.finalize(e); ok {
			c.emitted++
			c.expired++
			if rec.Source == SourceMerged {
				c.matched++
			}
			pending = append(pending, rec)
		}
		delete(c.cells, k)
		c.entries--
	}
	c.mu.Unlock()

	for _, rec := range pending {
		c.emit(rec)
	}
}

// Flush emits every pending NetFlow entry regardless of window, for a clean shutdown.
// After it returns the accumulator is empty.
func (c *Correlator) Flush() {
	var pending []Record
	c.mu.Lock()
	for k, e := range c.cells {
		if rec, ok := c.finalize(e); ok {
			c.emitted++
			if rec.Source == SourceMerged {
				c.matched++
			}
			pending = append(pending, rec)
		}
		delete(c.cells, k)
	}
	c.entries = 0
	c.mu.Unlock()

	for _, rec := range pending {
		c.emit(rec)
	}
}

// Stats reports the correlator's own health.
func (c *Correlator) Stats() CorrelatorStats {
	c.mu.Lock()
	defer c.mu.Unlock()
	return CorrelatorStats{
		Entries:               c.entries,
		Emitted:               c.emitted,
		Matched:               c.matched,
		Evicted:               c.evicted,
		Expired:               c.expired,
		EnrichmentOverwrites:  c.enrichmentOverwrites,
		FragmentDisagreements: c.fragmentDisagreement,
		FragmentMirrored:      c.fragmentMirrored,
	}
}

// finalize builds the record an entry emits. ok is false for a Zenarmor-only entry,
// which carries no NetFlow side to emit — its conn document already shipped. Callers
// hold the lock.
func (c *Correlator) finalize(e *corrEntry) (Record, bool) {
	if !e.hasNF {
		return Record{}, false
	}
	out, chosenIsMirror := e.orientation()
	// The chosen orientation's volume is Tx, the other half's is Rx (#617). Bytes()
	// and Packets() are unchanged by the split, so opnsense_flow_bytes_total does not
	// move for any existing consumer — what changes is that Rx finally means something.
	fwd, rev := e.nf, e.nfMirror
	if chosenIsMirror {
		fwd, rev = e.nfMirror, e.nf
	}
	out.NF = Counters{
		TxBytes:   fwd.TxBytes + fwd.RxBytes,
		RxBytes:   rev.TxBytes + rev.RxBytes,
		TxPackets: fwd.TxPackets + fwd.RxPackets,
		RxPackets: rev.TxPackets + rev.RxPackets,
		Present:   e.nf.Present,
	}
	out.TCPFlags = e.tcpFlags
	// Every fragment's markers, not just the chosen orientation's.
	out.Repairs.merge(e.repairs)
	out.Fragments = e.fragments
	out.Start = e.start
	out.End = e.end
	if e.zen != nil {
		out.Source = SourceMerged
		// Zenarmor is the only source of L7 and a verdict; take them wholesale. The
		// NetFlow side keeps its repaired interfaces and direction, which are the whole
		// reason the merged record is worth more than either source alone.
		out.L7 = e.zen.L7
		out.Verdict = e.zen.Verdict
		out.Zen = e.zen.Zen
		if out.Enrich.DstDomain == "" {
			out.Enrich.DstDomain = e.zen.Enrich.DstDomain
		}
		// Zenarmor's geo is an enrichment input, not the answer: MergeGeo re-applies
		// #520's per-field precedence so a merged record means the same thing as a
		// Zenarmor-only one. The NetFlow side already carries OUR lookup.
		MergeGeo(&out.Geo, e.zen.Geo)
		// The BYTE BASIS of the figure the delta ratio is about to compare (#604).
		// out came from a NetFlow half, so the Zenarmor lane's own record-level flag
		// does not survive the merge unless it is carried explicitly.
		out.Repairs.ZenBytesArePayload = e.zen.Repairs.PayloadByteFallback
		// And whether the two sides are totalling the same thing at all. A conn
		// document whose own span crosses a window boundary describes a connection
		// this bucket's NetFlow fragments cover only part of — the Zenarmor side is
		// the whole connection, the NetFlow side is one window of it. Read from the
		// ZENARMOR side's clock alone, so it needs no agreement between the two
		// sources' timestamps.
		out.Repairs.WindowPartial = c.spansWindows(e.zen.Start, e.zen.End)
	} else {
		out.Source = SourceNetflow
	}
	return out, true
}

// spansWindows reports whether [start, end] falls in more than one correlator
// window bucket, using the SAME arithmetic corrKey does.
//
// A zero start states nothing (a conn document that reported no open time), and a
// zero window would divide by zero, so both answer false: the marker suppresses a
// comparison, and suppressing one on no evidence is its own kind of wrong.
func (c *Correlator) spansWindows(start, end time.Time) bool {
	if c.window <= 0 || start.IsZero() || end.IsZero() {
		return false
	}
	w := int64(c.window)
	return start.UnixNano()/w != end.UnixNano()/w
}

// orientation picks which of the conversation's two halves describes the emitted
// record — the tuple, In, Out, Direction and the scopes, all from that ONE half.
//
// There is no coherent "merged" answer to build instead. Those fields form a
// consistent set on each half (In=LAN, Out=WAN, Direction=outbound, src=local on
// the forward half; the exact mirror on the reverse), and interfaceLabel
// (processor.go:387) reads Direction to decide WHICH of In/Out it labels by — so
// taking Direction from one half and Out from the other would describe a
// conversation that never happened. Picking a whole half keeps the record
// internally consistent.
//
// Evidence, strongest first (the decision recorded on #605):
//
//  1. Zenarmor's stated direction, when a conn document merged. It is the only
//     connection-oriented source in the pipeline — one document per connection —
//     so it is the only thing here that knows who INITIATED. NetFlow's
//     FIRST_SWITCHED is initiation evidence by inference; a conn document is
//     initiation evidence by construction.
//  2. The earlier Start (FIRST_SWITCHED, firewall clock). The initiator's half
//     starts first by definition, and the firewall clock is independent of the
//     order datagrams reached us — which is the whole point, since arrival order
//     is what this replaces.
//  3. The local->remote half. A tie on Start means we cannot tell who initiated;
//     describing the conversation from the local end is the more useful reading
//     and is what the rest of the pipeline assumes.
//  4. Canonical endpoint order, so the result is total and deterministic even for
//     two internal hosts where none of the above discriminates.
//
// Rule 2 ranking above rule 3 is load-bearing, not an ordering detail: an
// inbound-initiated conversation (a port-forwarded service) must stay inbound, and
// the obvious "always orient local->remote" rule would flip every one of them to
// outbound.
//
// The bool reports whether the MIRROR was chosen, so finalize knows which
// accumulator holds the forward volume (#617).
func (e *corrEntry) orientation() (Record, bool) {
	if e.mirror == nil {
		return e.sample, false
	}
	a, b := e.sample, *e.mirror

	// 1. Zenarmor stated the conversation's direction.
	if e.zen != nil && e.zen.Direction != DirectionUnknown {
		switch {
		case a.Direction == e.zen.Direction && b.Direction != e.zen.Direction:
			return a, false
		case b.Direction == e.zen.Direction && a.Direction != e.zen.Direction:
			return b, true
		}
	}
	// 2. Whichever half started first.
	if a.Start.Before(b.Start) {
		return a, false
	}
	if b.Start.Before(a.Start) {
		return b, true
	}
	// 3. The local->remote half.
	const remote = "remote"
	aLocalOut := a.Enrich.SrcScope != remote && a.Enrich.DstScope == remote
	bLocalOut := b.Enrich.SrcScope != remote && b.Enrich.DstScope == remote
	if aLocalOut != bLocalOut {
		if aLocalOut {
			return a, false
		}
		return b, true
	}
	// 4. Canonical endpoint order — the same comparison CanonicalTuple uses, so
	// this agrees with the community id rather than inventing a second ordering.
	if endpointLess(a.SrcAddr.Unmap(), a.SrcPort, a.DstAddr.Unmap(), a.DstPort) {
		return a, false
	}
	return b, true
}

// oldestLocked returns the entry with the earliest firstSeen, or nil if the map is
// empty. Callers hold the lock. A linear scan is acceptable because eviction only runs
// at capacity, which a correctly-sized deployment never reaches.
func (c *Correlator) oldestLocked() *corrEntry {
	var oldest *corrEntry
	for _, e := range c.cells {
		if oldest == nil || e.firstSeen.Before(oldest.firstSeen) {
			oldest = e
		}
	}
	return oldest
}

// keyOf groups a record by its community id and the window its flow-end falls in.
func (c *Correlator) keyOf(r Record) corrKey {
	var bucket int64
	if secs := int64(c.window / time.Second); secs > 0 {
		bucket = r.End.Unix() / secs
	}
	return corrKey{community: r.CommunityID, bucket: bucket}
}

// fragmentsOf reports how many raw NetFlow records a fragment represents. A normalized
// NetFlow record is one fragment; a record that already carries a count (never, today,
// but the seam allows it) is trusted. Zero is treated as one so a fragment always
// advances the count.
func fragmentsOf(r Record) int {
	if r.Fragments > 0 {
		return r.Fragments
	}
	return 1
}
