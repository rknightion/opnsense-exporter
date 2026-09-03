package collector

// filterlogDomainCounter is a bounded heavy-hitter candidate tracker for
// resolved filterlog domains. Unlike cappedCounter, which folds every novel
// key after its insert budget into overflow, this tracker replaces the least
// observed candidate when it is full. That admission rule matters here: a
// domain first seen after the candidate map fills must still be able to become
// a heavy hitter if it is subsequently busy.
//
// Counts for retained candidates are exact for the time they have been
// retained. Counts for a candidate that is evicted are folded into the total
// represented by the `other` output series. This keeps the aggregate lossless
// while keeping sender-controlled domain state bounded. The candidate set is
// deliberately larger than the 50 emitted series so ordinary churn does not
// make the output unstable.
//
// Not safe for concurrent use on its own: LogEventStore's owner goroutine is
// the only caller.
type filterlogDomainCounter struct {
	m     map[string]float64
	max   int
	total float64
	bytes int
}

func newFilterlogDomainCounter(max int) *filterlogDomainCounter {
	return &filterlogDomainCounter{m: map[string]float64{}, max: max}
}

// inc records one domain observation. Novel domains replace the least
// observed candidate once the bounded candidate map is full. Ties are broken
// lexically so the candidate set and metric output are deterministic.
func (c *filterlogDomainCounter) inc(domain string) {
	c.total++
	if domain == filterlogDomainOther {
		// `other` is reserved for the aggregate output label. Keep a real domain
		// with that spelling out of the candidate map to avoid duplicate series.
		return
	}

	if count, ok := c.m[domain]; ok {
		c.m[domain] = count + 1
		return
	}

	cost, valid := retainedStringBytes(domain)
	if !valid {
		return
	}

	if (c.max <= 0 || len(c.m) < c.max) && c.bytes+cost <= maxRetainedFamilyBytes {
		c.m[domain] = 1
		c.bytes += cost
		return
	}

	// The family byte budget is a hard bound too. If the new key cannot fit
	// after replacing the least candidate, its observation remains represented
	// by total and is emitted through `other`.
	victim, victimCount, found := c.least()
	if !found {
		return
	}
	victimCost, _ := retainedStringBytes(victim)
	if c.bytes-victimCost+cost > maxRetainedFamilyBytes {
		return
	}
	delete(c.m, victim)
	c.bytes = c.bytes - victimCost + cost
	c.m[domain] = 1
	_ = victimCount // retained for least's comparison and future diagnostics
}

// least returns the candidate that should be replaced. It scans at most the
// fixed candidate budget; keeping this path allocation-free is preferable to
// maintaining a heap that must also be repaired on every ordinary increment.
func (c *filterlogDomainCounter) least() (string, float64, bool) {
	var victim string
	var count float64
	found := false
	for domain, candidateCount := range c.m {
		if !found || candidateCount < count || (candidateCount == count && domain < victim) {
			victim = domain
			count = candidateCount
			found = true
		}
	}
	return victim, count, found
}

func (c *filterlogDomainCounter) snapshot() (map[string]float64, float64) {
	return c.m, c.total
}
