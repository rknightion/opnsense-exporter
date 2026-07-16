package zenarmor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
)

// sourceName is the stable source identifier; it becomes the `source` attribute
// value on every record the receiver ships and keys its self-metrics.
const sourceName = "zenarmor"

// shutdownGrace bounds how long Run waits for in-flight bulk writes to finish once
// ctx is cancelled.
const shutdownGrace = 5 * time.Second

func init() {
	logship.RegisterPushSource(func(d logship.Deps) (logship.PushSource, error) {
		// TODO(task 8): options.LogsZenarmor() — replace loadConfig with it. It returns
		// the same (config, enabled, error) shape, so this body does not change.
		cfg, enabled, err := loadConfig()
		if err != nil {
			return nil, err
		}
		if !enabled {
			return nil, nil
		}
		return newSource(d, cfg)
	})
}

// loadConfig is the seam Task 8 replaces with options.LogsZenarmor(). Until the flag
// family exists the receiver reports itself disabled, so the registered factory is
// inert and binds nothing.
func loadConfig() (Config, bool, error) { return Config{}, false, nil }

// zenarmorSource implements logship.PushSource: an HTTP server posing as
// Elasticsearch, turning each document Zenarmor writes into a Record.
//
// Records are built and enriched HERE, on the request goroutine, before entering the
// pipeline queue — it is a handful of map lookups costing nanoseconds and it keeps
// the queue holding finished records. Nothing on this path may ever make a network
// call.
type zenarmorSource struct {
	srv *http.Server
	ln  net.Listener

	cfg      Config
	cache    *enrich.Cache
	sink     logship.MetricSink
	m        *metrics
	families map[string]bool // nil = all

	// emit is set by Run before the server that reads it exists. Goroutine creation is
	// a happens-before edge, so a plain field is safe: no request can observe it
	// before Run has written it.
	emit func(logship.Record)
}

func newSource(d logship.Deps, cfg Config) (*zenarmorSource, error) {
	cache := d.Cache
	if cache == nil {
		// Enrichment off, or not wired: a cold cache misses every lookup, so records
		// still ship — just unenriched.
		cache = enrich.NewCache()
	}
	sink := d.MetricSink
	if sink == nil {
		sink = logship.NopMetricSink{}
	}
	s := &zenarmorSource{
		cfg:      cfg,
		cache:    cache,
		sink:     sink,
		m:        newMetrics(d.Registerer),
		families: familyAllowSet(cfg.Families),
	}

	// Bind EAGERLY, here in the factory rather than in Run: a port already in use is a
	// configuration error the operator must see at startup, not a receiver that is
	// silently dead for the life of the process.
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("zenarmor: listen %s: %w", cfg.Addr, err)
	}
	s.ln = ln
	s.srv = &http.Server{
		Handler:           newServer(cfg, s.handleDoc, s.m),
		TLSConfig:         cfg.TLSConfig,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return s, nil
}

func (s *zenarmorSource) Name() string { return sourceName }

// Run serves until ctx is cancelled, then drains. It must return promptly on
// cancellation: the pipeline waits on it unbounded during shutdown, so a Run that
// ignores ctx hangs the exporter forever on SIGTERM.
func (s *zenarmorSource) Run(ctx context.Context, emit func(logship.Record)) error {
	s.emit = emit

	errc := make(chan error, 1)
	go func() {
		var err error
		if s.srv.TLSConfig != nil {
			// The certificates already live on the TLSConfig, so the file arguments are empty.
			err = s.srv.ServeTLS(s.ln, "", "")
		} else {
			err = s.srv.Serve(s.ln)
		}
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errc <- err
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
	}

	// Shutdown gets a FRESH context: ctx is already cancelled, and handing it over
	// would make Shutdown return instantly and abandon the in-flight bulk writes it
	// exists to drain.
	sctx, cancel := context.WithTimeout(context.Background(), shutdownGrace)
	defer cancel()
	return s.srv.Shutdown(sctx)
}

// handleDoc is invoked per document in a bulk write, on the request goroutine.
func (s *zenarmorSource) handleDoc(index string, doc []byte) {
	emit := s.emit
	if emit == nil {
		return // not running yet; drop rather than panic
	}
	family := familyFor(index)
	if family == "" {
		s.m.reject("unknown_family")
		return
	}
	if s.families != nil && !s.families[family] {
		s.m.reject("filtered")
		return
	}

	var snap *enrich.Snapshot
	if s.cfg.Enrich {
		snap = s.cache.Load()
	}
	rec, parsed := parseDoc(family, doc, snap)
	if !parsed {
		// Counted, never dropped: the record ships below with its raw body.
		s.m.parseError("document")
	}
	observeDerived(s.sink, family, rec.Attributes)
	emit(rec)
}

// familyAllowSet resolves the configured family list into the set to ship; nil means
// all.
//
// Entries may be spelled either as Zenarmor's index token (conn, http) or as our
// family name (flow, web). The flag's vocabulary is the index token, but the two are
// trivially confusable and getting it wrong in either direction would silently ship
// nothing, so both are accepted.
func familyAllowSet(names []string) map[string]bool {
	if len(names) == 0 {
		return nil
	}
	set := make(map[string]bool, len(names))
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
		if n == "" {
			continue
		}
		if fam, ok := indexFamilies[n]; ok {
			set[fam] = true
			continue
		}
		set[n] = true
	}
	if len(set) == 0 {
		return nil
	}
	return set
}

var _ logship.PushSource = (*zenarmorSource)(nil)
