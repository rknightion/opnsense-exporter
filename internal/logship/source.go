package logship

import (
	"context"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v5/internal/flow"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/capture"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

// Source is the minimal contract every log source lane implements. The pipeline
// stamps the `source` attribute from Name() automatically, so records must not
// set it themselves. Each Source owns its own cursor (digest / validFrom /
// timestamp+dedup) internally: Poll returns the newest batch of events observed
// since the last call.
type Source interface {
	// Name is a stable identifier (e.g. "firewall"). It becomes the `source`
	// attribute value and keys the source's state-file entry and self-metrics.
	Name() string
	// Poll returns the events observed since the previous call. It should honour
	// ctx cancellation. A returned error is counted and logged; the poller
	// continues on its next tick.
	Poll(ctx context.Context) ([]Record, error)
}

// StatefulSource is implemented by sources that can resume across restarts when
// --logs.state-file is set. LoadState is called once at Start with the persisted
// blob (if any); SaveState is called periodically and on shutdown.
type StatefulSource interface {
	Source
	// LoadState restores cursor state from a previously persisted blob. It is
	// called at most once, before the first Poll.
	LoadState(data []byte)
	// SaveState returns the current cursor state to persist and whether there is
	// anything to persist. Returning false skips the write for this source.
	SaveState() (data []byte, ok bool)
}

// IntervalSource lets a source raise the poll floor above the global
// --logs.poll-interval (e.g. unbound 15s, crowdsec 60s). The pipeline polls at
// max(global, MinInterval()).
type IntervalSource interface {
	Source
	MinInterval() time.Duration
}

// GapReportingSource is implemented by a source whose only view of its underlying
// data is a BOUNDED WINDOW rather than a true cursor, so it can silently skip data
// between polls and detect that it did (see recordPossibleGap in metrics.go). The
// unbound per-query DNS source is the only implementer today: OPNsense exposes only
// the newest 1000 rows resolver-wide, so a busy resolver can push older rows out of
// the window before we ever fetch them.
//
// It exists so the pipeline can pre-initialise logs_possible_gap_total{source} to
// zero for exactly these sources (#280). Implementing it is a claim that the source
// actively watches for gaps; a cursor-based source must NOT implement it, because a
// permanent zero there would advertise a check that never runs.
type GapReportingSource interface {
	Source
	// ReportsGaps marks the source as gap-detecting. It is a marker: the pipeline
	// only asks whether the source implements it.
	ReportsGaps()
}

// ExtraSourceNames, when implemented by a Source or PushSource, reports the extra
// `source` values it may stamp on records via a Record.Source override, beyond its own
// Name(). The pipeline pre-initialises per-source counter metrics (#280) for these, so a
// source that only ever arrives by override still reads a flat zero rather than nothing.
type ExtraSourceNames interface {
	ExtraSourceNames() []string
}

// Deps are the shared dependencies handed to every SourceFactory and
// PushSourceFactory.
//
// Cache/Miss/Registerer serve the push (syslog) path. They are plumbed through
// Deps rather than reached for directly because the pipeline's own `metrics` type
// is unexported and a source package cannot see it — and because a source package
// importing logship (as the syslog receiver must, for Record and PushSource) means
// logship cannot import it back. Handing over a Registerer lets each source
// package own and register its own metrics without a cycle.
type Deps struct {
	Client *opnsense.Client
	Logger *slog.Logger
	// AfterSourcesStopped runs during pipeline shutdown after every poll and push
	// source has returned, but before the queue is closed and drained. main uses
	// this lifecycle seam to quiesce external NetFlow producers and flush their
	// correlator into the still-live queue. Sources must not call it.
	AfterSourcesStopped func()

	// Cache is the log-enrichment snapshot cache. Reads are lock-free. It is never
	// nil when the pipeline is started by main; a cold cache simply misses every
	// lookup and records ship unenriched.
	Cache *enrich.Cache
	// Miss reports an enrichment lookup miss for the named table. It MUST NOT block
	// and MUST NOT perform I/O — it is called on the receiver goroutine, and a
	// synchronous API call there would stall the socket read loop and silently drop
	// datagrams. May be nil (misses are then simply not reported).
	Miss func(table string)
	// Registerer is where a source registers its own self-metrics.
	Registerer prometheus.Registerer
	// MetricSink receives derived-metric observations from parsed programs
	// (#258). It is nil when metric derivation is disabled (the log_events
	// collector is off); the receiver substitutes a NopMetricSink.
	MetricSink MetricSink
	// FlowSink receives normalized flow records derived from a receiver's own
	// documents (#346). It is nil when flow rollups are off (the flow collector is
	// disabled, or --flow.enabled=false), and a receiver that sees nil skips
	// derivation entirely rather than building records nothing consumes.
	//
	// Observe MUST NOT block and MUST NOT perform I/O — same contract as Miss above.
	FlowSink flow.Sink
	// FlowDNSCache is the (client, answer) -> qname answer cache (#353). A receiver's
	// dns family feeds it and its flow family reads it for dst.domain. nil when domain
	// enrichment is off (--flow.dns-cache.size=0 or flow disabled); a nil cache is a
	// safe no-op, so receivers hold and call it unconditionally.
	FlowDNSCache *flow.DNSCache
	// DebugCapture is the shared debug-capture sink (#330), or nil when
	// --logs.debug-capture.dir is unset. A receiver uses it only when its own
	// --logs.<recv>.debug-capture is on; a nil *capture.Capturer is a safe no-op, so
	// receivers may hold and call it unconditionally.
	DebugCapture *capture.Capturer
}

// SourceFactory builds a Source from shared dependencies, or returns (nil, nil)
// when the source is disabled by its own config flag (the pipeline skips it).
// A non-nil error aborts Start.
type SourceFactory func(Deps) (Source, error)

// registeredFactories collects the factories registered via RegisterSource in
// package init() functions — mirroring the collector registration idiom. Each
// source lane adds one internal/logship/<name>.go file with an init() that calls
// RegisterSource.
var registeredFactories []SourceFactory

// RegisterSource records a factory to be built at pipeline Start. Call it from
// an init() in a source lane's file.
func RegisterSource(f SourceFactory) {
	registeredFactories = append(registeredFactories, f)
}

// buildSources instantiates every registered factory with deps, dropping the
// ones that report themselves disabled (nil Source). The first factory error
// aborts.
func buildSources(deps Deps) ([]Source, error) {
	sources := make([]Source, 0, len(registeredFactories))
	for _, f := range registeredFactories {
		s, err := f(deps)
		if err != nil {
			return nil, err
		}
		if s == nil {
			continue
		}
		sources = append(sources, s)
	}
	return sources, nil
}
