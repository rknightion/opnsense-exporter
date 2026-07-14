package syslog

import (
	"context"
	"log/slog"
	"net/netip"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
	"github.com/rknightion/opnsense-exporter/internal/options"
)

// sourceName is the stable source identifier; it becomes the `source` attribute
// value on every record the receiver ships.
const sourceName = "syslog"

func init() {
	logship.RegisterPushSource(func(d logship.Deps) (logship.PushSource, error) {
		cfg, enabled, err := options.LogsSyslog()
		if err != nil {
			return nil, err
		}
		if !enabled {
			return nil, nil
		}
		s := newSource(cfg, d)
		// Bind EAGERLY, here in the factory rather than in Run: a port that is already
		// in use is a configuration error the operator must see at startup, not a
		// receiver that is silently dead for the life of the process.
		if err := s.Start(); err != nil {
			return nil, err
		}
		return s, nil
	})
}

// source implements logship.PushSource. It owns the listeners, turns each received
// line into a Record, enriches it from the lock-free snapshot, and hands it to emit.
//
// Enrichment happens HERE, on the receiver goroutine, before the record enters the
// pipeline queue: it is a pure map lookup costing nanoseconds, and it keeps the queue
// holding finished records. Nothing on this path may ever make a network call — see
// enrich.Refresher.NoteMiss, which is deliberately non-blocking for exactly this reason.
type source struct {
	l      *Listener
	cache  *enrich.Cache
	miss   func(table string)
	m      *Metrics
	filter *Filter
	log    *slog.Logger

	// emit is set by Run before the listener's read goroutines exist. Goroutine
	// creation is a happens-before edge, so a plain field is safe here: no reader
	// can observe it before Run has written it.
	emit func(logship.Record)
}

func newSource(cfg *options.SyslogConfig, d logship.Deps) *source {
	cache := d.Cache
	if cache == nil {
		// Enrichment disabled (--logs.syslog.enrich=false) or not wired: serve a cold
		// cache that misses every lookup, so records still ship — just unenriched.
		cache = enrich.NewCache()
	}
	s := &source{
		cache:  cache,
		miss:   d.Miss,
		m:      NewMetrics(d.Registerer),
		filter: NewFilter(cfg.IncludePrograms, cfg.ExcludePrograms, cfg.MinSeverity, cfg.HasMinSeverity),
		log:    d.Logger,
	}
	s.l = NewListener(Config{
		UDPAddr:      cfg.UDPAddr,
		TCPAddr:      cfg.TCPAddr,
		AllowedPeers: cfg.AllowedPeers,
		MaxConns:     cfg.MaxConns,
	}, s.handle, s.m, d.Logger)
	return s
}

// Start binds the listeners. A bind failure is fatal to startup.
func (s *source) Start() error { return s.l.Start() }

func (s *source) Name() string { return sourceName }

// Run blocks until ctx is cancelled. The listener closes its own sockets on
// cancellation, which is what lets the pipeline's shutdown drain complete.
func (s *source) Run(ctx context.Context, emit func(logship.Record)) error {
	s.emit = emit
	s.l.Run(ctx)
	return nil
}

// handle is invoked per received line, on the listener's read goroutine.
func (s *source) handle(line []byte, _ netip.Addr) {
	emit := s.emit
	if emit == nil {
		return // not running yet; drop rather than panic
	}
	env, err := ParseEnvelope(line, time.Now())
	if err != nil {
		// NEVER drop: an unparseable line still ships, with its raw bytes as the body.
		// A receiver that silently discards what it cannot understand is worse than
		// useless — it looks healthy while losing data.
		s.m.parseError("envelope")
		emit(logship.Record{Timestamp: time.Now(), Body: string(line)})
		return
	}
	// Filtering is opt-in and defaults to passing everything. It is applied AFTER the
	// envelope parse because that is where the program and severity come from, and
	// BEFORE the (more expensive) body parse and enrichment -- no point enriching a
	// record we are about to drop.
	if s.filter.Enabled() && !s.filter.Allow(env.Program, env.Severity) {
		s.m.reject("filtered")
		return
	}
	emit(BuildRecord(env, s.cache.Load(), s.miss))
}

var _ logship.PushSource = (*source)(nil)
