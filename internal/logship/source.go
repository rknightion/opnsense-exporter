package logship

import (
	"context"
	"log/slog"
	"time"

	"github.com/rknightion/opnsense-exporter/opnsense"
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

// Deps are the shared dependencies handed to every SourceFactory.
type Deps struct {
	Client *opnsense.Client
	Logger *slog.Logger
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
