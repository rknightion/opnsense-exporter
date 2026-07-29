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
	key       corrKey
	nf        Counters // accumulated across fragments; Present once any NetFlow fragment lands
	sample    Record   // the first NetFlow fragment: carries tuple, interfaces, direction, enrichment
	fragments int
	start     time.Time // earliest FIRST_SWITCHED across fragments
	end       time.Time // latest LAST_SWITCHED across fragments
	firstSeen time.Time // arrival of the first fragment: the expiry and eviction clock
	zen       *Record   // Zenarmor enrichment, if a conn document for this key arrived
	hasNF     bool      // false for a Zenarmor-only entry, which never emits
}

// CorrelatorStats is the correlator's own health, published as self-metrics so a
// correlation that never fires is distinguishable from one that is thrashing.
type CorrelatorStats struct {
	Entries int    // live accumulator entries
	Emitted uint64 // flow-log records emitted (netflow + merged)
	Matched uint64 // subset emitted as merged (Zenarmor enrichment found)
	Evicted uint64 // entries force-emitted early because the map hit MaxEntries
	Expired uint64 // entries emitted on the normal window-expiry path
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
		e = &corrEntry{key: k, sample: r, firstSeen: r.Observed, start: r.Start, end: r.End}
		c.cells[k] = e
		c.entries++
	}
	e.nf.TxBytes += r.NF.TxBytes
	e.nf.RxBytes += r.NF.RxBytes
	e.nf.TxPackets += r.NF.TxPackets
	e.nf.RxPackets += r.NF.RxPackets
	e.nf.Present = true
	e.hasNF = true
	e.fragments += fragmentsOf(r)
	if r.Start.Before(e.start) {
		e.start = r.Start
	}
	if r.End.After(e.end) {
		e.end = r.End
	}
	return pending
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
		Entries: c.entries,
		Emitted: c.emitted,
		Matched: c.matched,
		Evicted: c.evicted,
		Expired: c.expired,
	}
}

// finalize builds the record an entry emits. ok is false for a Zenarmor-only entry,
// which carries no NetFlow side to emit — its conn document already shipped. Callers
// hold the lock.
func (c *Correlator) finalize(e *corrEntry) (Record, bool) {
	if !e.hasNF {
		return Record{}, false
	}
	out := e.sample
	out.NF = e.nf
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
	} else {
		out.Source = SourceNetflow
	}
	return out, true
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
