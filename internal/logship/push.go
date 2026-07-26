package logship

import (
	"context"

	"github.com/prometheus/client_golang/prometheus"
)

// PushSource is a long-lived source that emits records as they ARRIVE rather
// than being polled. It is the push-shaped counterpart of Source: a syslog
// receiver has no cursor to poll — OPNsense pushes to us — so the pipeline
// hands it an emit callback instead of asking it for a batch.
//
// Run blocks until ctx is cancelled and MUST return promptly on it: the
// pipeline waits on it (unbounded) during shutdown, so a Run that ignores ctx
// hangs the exporter forever. Everything downstream of emit is the same shared
// machinery a poll Source feeds: the pipeline stamps `source` from Name() and
// strips the reserved attribute keys, exactly as pollOnce does.
type PushSource interface {
	// Name is a stable identifier (e.g. "syslog"). It becomes the `source`
	// attribute value and keys the source's self-metrics.
	Name() string
	// Run receives records until ctx is cancelled. emit is safe to call from the
	// goroutine Run is invoked on; a returned error is counted and logged, and the
	// source is NOT restarted.
	Run(ctx context.Context, emit func(Record)) error
}

// PushSourceFactory builds a PushSource from shared dependencies, or returns
// (nil, nil) when the source is disabled by its own config flag (the pipeline
// skips it). A non-nil error aborts Start. Mirrors SourceFactory.
type PushSourceFactory func(Deps) (PushSource, error)

// registeredPushFactories collects the factories registered via
// RegisterPushSource in package init() functions, mirroring registeredFactories.
var registeredPushFactories []PushSourceFactory

// RegisterPushSource records a factory to be built at pipeline Start. Call it
// from an init() in a push-source lane's file (mirrors RegisterSource).
func RegisterPushSource(f PushSourceFactory) {
	registeredPushFactories = append(registeredPushFactories, f)
}

// buildPushSources instantiates every registered push factory with deps,
// dropping the ones that report themselves disabled (nil PushSource). The first
// factory error aborts.
func buildPushSources(deps Deps) ([]PushSource, error) {
	out := make([]PushSource, 0, len(registeredPushFactories))
	for _, f := range registeredPushFactories {
		s, err := f(deps)
		if err != nil {
			return nil, err
		}
		if s == nil {
			continue
		}
		out = append(out, s)
	}
	return out, nil
}

// runPushSource feeds one push source's records into the shared bounded queue.
// It blocks until the source's Run returns (i.e. until ctx is cancelled).
func (p *pipeline) runPushSource(ctx context.Context, s PushSource) {
	name := s.Name()
	// Hoist the default gauge ONCE; WithLabelValues takes a mutex and emit runs on the
	// receiver goroutine thousands of times a second. Pre-hoist any override sources this
	// source declares so the override path stays mutex-free too.
	lastReceivedDefault := p.metrics.lastReceived.WithLabelValues(name)
	extraLastReceived := map[string]prometheus.Gauge{}
	if es, ok := s.(ExtraSourceNames); ok {
		for _, n := range es.ExtraSourceNames() {
			if n != "" && n != name {
				extraLastReceived[n] = p.metrics.lastReceived.WithLabelValues(n)
			}
		}
	}
	emit := func(r Record) {
		r.Attributes = sanitizeAttributes(r.Attributes)
		src := name
		lr := lastReceivedDefault
		if r.Source != "" && r.Source != name {
			src = r.Source
			if g, ok := extraLastReceived[src]; ok {
				lr = g
			} else {
				lr = p.metrics.lastReceived.WithLabelValues(src)
			}
		}
		// enqueue applies the per-record size cap before the record can reach the
		// queue (#318). A rejected record must NOT advance the receive gauge: it was
		// never accepted, and claiming progress for data we dropped would hide the
		// loss behind a healthy-looking cursor.
		//
		// The gauge is set from enqueue's ADMISSION stamp, not from r.Timestamp (#394).
		// This is the path that made the old gauge forgeable: with the syslog receiver
		// enabled, UDP listens on all interfaces and an empty peer allowlist accepts any
		// sender, so a single future-dated line used to pin the gauge into the future and
		// suppress the stalled-source alert indefinitely. An admitted record now advances
		// it by exactly one clock read, whatever the sender claimed the time was — and a
		// zero-timestamp record, which used to advance nothing at all, now counts as the
		// arrival it plainly is.
		recv, ok := p.enqueue(Entry{Source: src, Record: r})
		if !ok {
			return
		}
		lr.Set(unixSeconds(recv))
	}
	if err := s.Run(ctx, emit); err != nil && ctx.Err() == nil {
		p.metrics.pollErrors.WithLabelValues(name).Inc()
		p.log.Error("push source stopped with error", "source", name, "err", err)
	}
}
