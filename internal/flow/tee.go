package flow

// Tee fans one record out to several sinks in order. It is how a receiver lane feeds
// both the metric rollup (which counts every raw per-source record) and the correlator
// (which collapses fragments and emits merged log records) from a single Observe call,
// without either knowing about the other.
//
// The order is fixed and matters only in that the rollup — the thing metrics depend on
// — is updated before the correlator does any work, so a slow correlator can never
// delay a metric (spec §8: metrics never wait on the correlator). Observe on each sink
// is itself non-blocking, so the fan-out adds no latency of its own.
type teeSink []Sink

// Tee returns a Sink that forwards to each of sinks in turn. A single sink is returned
// as-is (no wrapper), and no sinks yields a no-op, so callers can build one
// unconditionally.
func Tee(sinks ...Sink) Sink {
	nonNil := make([]Sink, 0, len(sinks))
	for _, s := range sinks {
		if s != nil {
			nonNil = append(nonNil, s)
		}
	}
	switch len(nonNil) {
	case 0:
		return teeSink(nil)
	case 1:
		return nonNil[0]
	default:
		return teeSink(nonNil)
	}
}

// Observe forwards to every sink. Callers are receiver goroutines, so this must not
// block — it relies on each sink's own non-blocking Observe.
func (t teeSink) Observe(r Record) {
	for _, s := range t {
		s.Observe(r)
	}
}

var _ Sink = teeSink(nil)
