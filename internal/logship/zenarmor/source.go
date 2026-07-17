package zenarmor

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/rknightion/opnsense-exporter/internal/logship"
	"github.com/rknightion/opnsense-exporter/internal/logship/enrich"
	"github.com/rknightion/opnsense-exporter/internal/options"
)

// sourceName is the stable source identifier; it becomes the `source` attribute
// value on every record the receiver ships and keys its self-metrics.
const sourceName = "zenarmor"

// RejectReasons and ParseStages are this receiver's CLOSED label vocabulary, used
// to pre-initialise logs_rejected_total / logs_parse_errors_total to zero at
// startup (#280) so a healthy receiver reports a flat 0 instead of nothing.
//
// Both are enforced against their call sites by TestReceiverVocabulariesMatchCallSites
// in the parent package: adding a reject("x") without listing "x" here fails the
// build, and so does listing a value nothing rejects with. Never add a value that
// comes off the wire — these must stay code-defined and closed. In particular the
// Zenarmor family and category values are NOT vocabulary: they arrive in the
// payload, so pre-initialising them would trade a dozen zeroes for unbounded
// cardinality.
var (
	// RejectReasons: peer/auth/unhandled_endpoint/body are the HTTP receiver's
	// (server.go); unknown_family/filtered/self_traffic/excluded are the record's
	// (source.go). There is no "oversized" here — that is a syslog framing concern only.
	RejectReasons = []string{
		"peer", "auth", "unhandled_endpoint", "body",
		"unknown_family", "filtered", "self_traffic", "excluded",
	}
	// ParseStages: bulk is the _bulk envelope (server.go), document one record inside
	// it (source.go).
	ParseStages = []string{"bulk", "document"}
)

// shutdownGrace bounds how long Run waits for in-flight bulk writes to finish once
// ctx is cancelled.
const shutdownGrace = 5 * time.Second

func init() {
	logship.RegisterPushSource(func(d logship.Deps) (logship.PushSource, error) {
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

// loadConfig resolves the flag family into the package's own Config. The two structs
// are deliberately separate types — options owns the flags, this package owns what a
// receiver needs — so the copy is field-for-field and stays here, at the seam.
func loadConfig() (Config, bool, error) {
	oc, enabled, err := options.LogsZenarmor()
	if err != nil || !enabled {
		return Config{}, false, err
	}
	// Parsed HERE rather than in options: the field name is validated against
	// KnownAttributeKeys, which lives beside the parser that produces those keys, and
	// options cannot import this package (this package imports options). A bad rule
	// fails the factory, which aborts logship.Start and exits — a startup error, never
	// a silent no-op.
	excludes, err := parseExcludeRules(oc.Excludes)
	if err != nil {
		return Config{}, false, err
	}
	return Config{
		Excludes:        excludes,
		Addr:            oc.Addr,
		AllowedPeers:    oc.AllowedPeers,
		Families:        oc.Families,
		Enrich:          oc.Enrich,
		AuthUser:        oc.AuthUser,
		AuthPassword:    oc.AuthPassword,
		TLSConfig:       oc.TLSConfig,
		DropSelfTraffic: oc.DropSelfTraffic,
	}, true, nil
}

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

	// listenPort is read from the BOUND listener, not from cfg.Addr: a configured
	// ":0" resolves to a real port only once bound, and that is the port records
	// about our own ingest are addressed to. 0 disables the self-traffic filter.
	listenPort int

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
		m:        newMetrics(d.Registerer, cfg.Excludes),
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
	s.listenPort = listenPortOf(ln.Addr().String())
	s.srv = &http.Server{
		Handler:           newServer(cfg, s.handleDoc, s.m, d.Logger),
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

// handleDoc is invoked per document in a bulk write, on the request goroutine. peer
// is the address that sent the bulk, used to recognise records describing our own
// ingest connection.
func (s *zenarmorSource) handleDoc(index string, doc []byte, peer netip.Addr) {
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

	// Before observeDerived, deliberately: a record about our own ingest connection
	// is an artefact of measuring, not traffic, so counting it would put our own
	// bookkeeping into the figures the operator reads as their network. The reject
	// counter still fires, so the drop is visible rather than silent (#278).
	if s.cfg.DropSelfTraffic && isSelfTraffic(rec.Attributes, peer, s.listenPort) {
		s.m.reject("self_traffic")
		return
	}

	// Derive BEFORE excluding, deliberately, and unlike the self-traffic drop above.
	// Self-traffic is an artefact of measuring, so counting it would put our own
	// bookkeeping into the operator's figures. An excluded record is real traffic the
	// operator merely does not want stored, so its shape must still reach the derived
	// counters — those outlive both the exclusion and Loki's retention, and they are
	// all that remains of it.
	observeDerived(s.sink, family, rec.Attributes)

	if rule, ok := excludedBy(s.cfg.Excludes, rec.Attributes); ok {
		s.m.exclude(rule)
		return
	}
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
