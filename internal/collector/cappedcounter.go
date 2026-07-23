package collector

// cappedCounter is a counter map with an insert-time key budget.
//
// The derived log_events families are fed by PUSH receivers, so their label
// values are sender-controlled — and syslog over UDP has a spoofable source, so a
// peer allowlist does not bound who can supply them. Without a budget, a sender
// mints process-lifetime map entries (and Prometheus series) without limit.
//
// The bound is INSERT-TIME, not emit-time, and that distinction is the whole
// point: capping only the emitted series still lets the map grow without limit,
// which is the memory half of the problem. Modelled on flow.Rollup, which solves
// exactly this for the equally-unauthenticated NetFlow listener.
//
// Saturation is never silent. A novel key beyond the budget folds into a counted
// overflow total, so the sum over the emitted series plus the overflow series
// equals the true observed count exactly, at every scrape. Keys already in the map
// keep accumulating, so ordinary steady-state traffic is unaffected once the
// working set is established — only NOVELTY is bounded.
//
// Not safe for concurrent use on its own: every caller in this package already
// holds LogEventStore's mutex, and taking a second lock here would buy nothing.
type cappedCounter[K comparable] struct {
	m   map[K]float64
	max int
	// overflow accumulates observations for keys refused by the budget. It is a
	// float64 for the same reason the per-key values are: it is emitted as a
	// counter and must survive the same conversion.
	overflow float64
}

func newCappedCounter[K comparable](max int) *cappedCounter[K] {
	return &cappedCounter[K]{m: map[K]float64{}, max: max}
}

// inc records one observation for k, folding into the overflow total when k is
// novel and the budget is already met. max <= 0 disables the budget.
func (c *cappedCounter[K]) inc(k K) {
	if _, ok := c.m[k]; !ok && c.max > 0 && len(c.m) >= c.max {
		c.overflow++
		return
	}
	c.m[k]++
}

// snapshot returns the live keys and the folded overflow total. The map is the
// live one — callers hold the store mutex for the duration of a scrape, and every
// existing call site already copies out of it.
func (c *cappedCounter[K]) snapshot() (map[K]float64, float64) {
	return c.m, c.overflow
}

// setMax retunes the budget in place. Lowering it below the current size does not
// evict: existing keys are already-paid-for memory and dropping them would reset
// live counters, which Prometheus reads as a counter reset. Only new inserts are
// refused until the map drains (which, for process-lifetime counters, is never) —
// so lowering the cap bounds growth from here, it does not shrink the map.
func (c *cappedCounter[K]) setMax(max int) { c.max = max }

// len reports the live key count, for the saturation gauge.
func (c *cappedCounter[K]) len() int { return len(c.m) }
