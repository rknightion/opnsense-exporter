package flow

import "sync"

// deltaRatioBounds are the upper bounds of the byte-delta-ratio histogram, in
// NF/Zen ratio units. 1.0 is agreement, so the buckets cluster tightly just above
// it — the interesting range is "NetFlow saw a little more" (per-packet header
// overhead Zenarmor's payload accounting misses) versus "NetFlow saw a lot more"
// (traffic Zenarmor never inspected, which is the security signal §8 names). A ratio
// below 1 (Zenarmor counted MORE than NetFlow) is rare but real on the short-UDP
// payload-fallback flows, so the range opens slightly below 1 as well.
//
// Frozen: the collector emits these as a ConstHistogram, and Prometheus forbids a
// histogram's buckets changing shape between scrapes, so a value added here is a
// break unless every series resets.
var deltaRatioBounds = []float64{0.9, 1, 1.05, 1.1, 1.25, 1.5, 2, 3, 5, 10, 100}

// HistogramData is one interface's accumulated delta-ratio histogram, in the shape
// prometheus.MustNewConstHistogram consumes: Buckets maps each finite upper bound to
// the CUMULATIVE count at or below it, and the implicit +Inf bucket equals Count
// (so an observation past the last bound rides only in Count, never in Buckets).
type HistogramData struct {
	Count   uint64
	Sum     float64
	Buckets map[float64]uint64
}

// DeltaRatio accumulates, per interface, the ratio between the two sources' byte
// counts on a MERGED flow record — the whole payoff of correlating them (#346
// decision 3, "the disagreement is the signal"). It is fed only from records that
// carry BOTH sources' counters, which today means only the correlator's merged
// output, so a deployment without both a NetFlow and a Zenarmor lane accumulates
// nothing and the metric is legitimately absent rather than a flat zero.
//
// NF is authoritative (it counts at the packet path); the ratio is NF/Zen, so a
// value well above 1 means Zenarmor inspected far fewer bytes than actually crossed
// the wire. A merged record whose Zenarmor side is present but zero bytes yields an
// overflow observation (+Inf bucket): Zenarmor saw the flow but accounted no volume
// for it, which is exactly the total-blindness case worth surfacing.
type DeltaRatio struct {
	mu    sync.Mutex
	cells map[string]*ratioCell
	// excluded counts merged records deliberately kept OUT of the histogram because
	// the two sides are not comparable (#604). Every other bounded or lossy path in
	// this pipeline counts its refusals, and a histogram that silently drops a
	// population is a histogram nobody can size the bias of.
	excluded uint64
}

// ratioCell is one interface's running histogram. counts is indexed by bucket, with
// one extra trailing slot (index len(bounds)) for the +Inf overflow, so no
// observation is ever dropped for being off the top of the scale.
type ratioCell struct {
	counts []uint64
	sum    float64
	total  uint64
}

// NewDeltaRatio returns an empty accumulator.
func NewDeltaRatio() *DeltaRatio {
	return &DeltaRatio{cells: make(map[string]*ratioCell)}
}

// Observe folds one flow record's source disagreement into the histogram. It is a
// no-op unless both sources reported: without both counters there is no disagreement
// to measure, and folding a NetFlow-only or Zenarmor-only record as if the missing
// side were zero would invent a 100% discrepancy on every unmatched flow. Safe for
// concurrent callers; called from the correlator's emit path.
func (d *DeltaRatio) Observe(r Record) {
	if !r.NF.Present || !r.Zen.Present {
		return
	}
	if r.Repairs.WindowPartial {
		// A window partial compares this window's NetFlow bytes against the WHOLE
		// connection's Zenarmor bytes. That is not a disagreement between the two
		// sources, it is a difference in what each one is totalling, and folding it in
		// puts an impossible sub-1.0 tail into a metric whose entire job is to make a
		// real disagreement legible. Excluded and counted, never silently dropped.
		d.mu.Lock()
		d.excluded++
		d.mu.Unlock()
		return
	}
	ratio := ratioOf(r.NF.Bytes(), r.Zen.Bytes())
	iface := interfaceLabel(r)

	d.mu.Lock()
	defer d.mu.Unlock()

	c := d.cells[iface]
	if c == nil {
		c = &ratioCell{counts: make([]uint64, len(deltaRatioBounds)+1)}
		d.cells[iface] = c
	}
	c.counts[bucketOf(ratio)]++
	c.sum += ratio
	c.total++
}

// Excluded is how many merged records were kept out of the histogram because their
// two sides were not comparable. It is published as a self-metric so the histogram's
// coverage is knowable rather than assumed.
func (d *DeltaRatio) Excluded() uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.excluded
}

// Snapshot returns each interface's histogram with cumulative bucket counts. Calling
// it twice with no intervening Observe returns identical values — nothing is reset.
func (d *DeltaRatio) Snapshot() map[string]HistogramData {
	d.mu.Lock()
	defer d.mu.Unlock()

	out := make(map[string]HistogramData, len(d.cells))
	for iface, c := range d.cells {
		buckets := make(map[float64]uint64, len(deltaRatioBounds))
		var cum uint64
		for i, b := range deltaRatioBounds {
			cum += c.counts[i]
			buckets[b] = cum
		}
		out[iface] = HistogramData{Count: c.total, Sum: c.sum, Buckets: buckets}
	}
	return out
}

// ratioOf is NF bytes over Zen bytes. A zero Zenarmor side (present but no accounted
// bytes) is total blindness, mapped to an overflow value so it lands in +Inf rather
// than dividing by zero.
func ratioOf(nf, zen uint64) float64 {
	if zen == 0 {
		return deltaRatioBounds[len(deltaRatioBounds)-1] + 1 // overflow past the last finite bound
	}
	return float64(nf) / float64(zen)
}

// bucketOf returns the index of the first bound at or above ratio, or the trailing
// overflow slot when ratio exceeds every finite bound.
func bucketOf(ratio float64) int {
	for i, b := range deltaRatioBounds {
		if ratio <= b {
			return i
		}
	}
	return len(deltaRatioBounds)
}
