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
	"github.com/rknightion/opnsense-exporter/internal/logship/syslog"
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

// HTTP server timeouts (#289). ReadHeaderTimeout alone stops a slow-HEADER client but
// stops applying the moment the headers land, so a peer can then trickle the body
// forever and pin a goroutine (slowloris). ReadTimeout bounds the WHOLE request —
// headers, body, and the gzip decode handleBulk drives off it — and IdleTimeout bounds
// a kept-alive connection between requests.
const (
	readHeaderTimeout = 10 * time.Second
	// readTimeout is generous next to a real write (live bulk writes ran a few hundred
	// KB, sub-second) yet large enough to admit the 64 MiB maxBodyBytes ceiling on a slow
	// (~0.5 MB/s) deployment before it trips. A hostile peer's body still dies here.
	readTimeout = 120 * time.Second
	idleTimeout = 120 * time.Second
)

func init() {
	logship.RegisterPushSource(func(d logship.Deps) (logship.PushSource, error) {
		cfg, enabled, err := loadConfig()
		if err != nil || !enabled {
			return nil, err
		}
		if options.LogsZenarmorTransport() == "syslog" {
			// Driven by the syslog receiver, not an independent listener: register the
			// shared processor and return no push source at all.
			proc := newDocProcessor(d, cfg) // listenPort is supplied per-call by the syslog receiver
			syslog.RegisterProgramProcessor(&syslogProcessor{proc: proc})
			return nil, nil
		}
		return newSource(d, cfg) // transport=elasticsearch (default): today's HTTP receiver
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

	proc docProcessor

	// listenPorts is read from the BOUND listener, not from cfg.Addr: a configured
	// ":0" resolves to a real port only once bound, and that is the port records
	// about our own ingest are addressed to. An all-zero/empty set disables the
	// self-traffic filter. The ES receiver binds exactly one HTTP port, so this holds
	// a single element; it is a []int (not an int) only so process's self-traffic
	// signature is shared with the syslog receiver, which can bind several (#299).
	//
	// It is a field on zenarmorSource, not on docProcessor: this is the ES source's
	// own bound HTTP port, fixed once at bind time and passed by reference to every
	// process call, whereas docProcessor.process takes listenPorts as a call
	// parameter so a concurrent caller (the syslog receiver, driving process from
	// many read goroutines with its own listener ports) never mutates shared state.
	listenPorts []int

	// emit is set by Run before the server that reads it exists. Goroutine creation is
	// a happens-before edge, so a plain field is safe: no request can observe it
	// before Run has written it.
	emit func(logship.Record)
}

// docProcessor runs the shared per-record pipeline: enrichment, self-traffic
// filtering, derived-metric observation, and exclusion. Both the ES source and
// (from a later change) the syslog receiver drive records through the same
// docProcessor, so the pipeline behaves identically regardless of transport.
type docProcessor struct {
	cfg      Config
	cache    *enrich.Cache
	sink     logship.MetricSink
	m        *metrics
	families map[string]bool // nil = all
}

// newDocProcessor builds the shared processor: metrics are registered and the
// family allow-set is resolved exactly once here, then reused across every call
// to process — never per-record and never per-caller.
func newDocProcessor(d logship.Deps, cfg Config) *docProcessor {
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
	return &docProcessor{
		cfg:      cfg,
		cache:    cache,
		sink:     sink,
		m:        newMetrics(d.Registerer, cfg.Excludes),
		families: familyAllowSet(cfg.Families),
	}
}

// process runs the full per-record pipeline and emits at most one record. family
// is the resolved family name (the unknown_family reject lives on the caller's
// resolution side, not here, since resolution differs per transport). peer +
// listenPorts drive self-traffic detection (an empty/all-zero set disables it; a
// record matches on any bound port — #299). emit MUST be non-nil. listenPorts is a
// PARAMETER, never a struct field: the syslog receiver calls process concurrently
// from many read goroutines, so per-call state must not be mutated on the shared
// processor. Callers pass a slice they built once (never per-record), so this adds
// no allocation on the hot path.
func (p *docProcessor) process(family string, doc []byte, peer netip.Addr, listenPorts []int, emit func(logship.Record)) {
	if p.families != nil && !p.families[family] {
		p.m.reject("filtered")
		return
	}

	var snap *enrich.Snapshot
	if p.cfg.Enrich {
		snap = p.cache.Load()
	}
	rec, parsed := parseDoc(family, doc, snap)
	rec.Source = sourceName
	if !parsed {
		// Counted, never dropped: the record ships below with its raw body.
		p.m.parseError("document")
	}

	// Before observeDerived, deliberately: a record about our own ingest connection
	// is an artefact of measuring, not traffic, so counting it would put our own
	// bookkeeping into the figures the operator reads as their network. The reject
	// counter still fires, so the drop is visible rather than silent (#278).
	if p.cfg.DropSelfTraffic && isSelfTraffic(rec.Attributes, peer, listenPorts) {
		p.m.reject("self_traffic")
		return
	}

	// Derive BEFORE excluding, deliberately, and unlike the self-traffic drop above.
	// Self-traffic is an artefact of measuring, so counting it would put our own
	// bookkeeping into the operator's figures. An excluded record is real traffic the
	// operator merely does not want stored, so its shape must still reach the derived
	// counters — those outlive both the exclusion and Loki's retention, and they are
	// all that remains of it.
	observeDerived(p.sink, family, rec.Attributes)

	if rule, ok := excludedBy(p.cfg.Excludes, rec.Attributes); ok {
		p.m.exclude(rule)
		return
	}
	emit(rec)
}

func newSource(d logship.Deps, cfg Config) (*zenarmorSource, error) {
	s := &zenarmorSource{
		proc: *newDocProcessor(d, cfg),
	}

	// Bind EAGERLY, here in the factory rather than in Run: a port already in use is a
	// configuration error the operator must see at startup, not a receiver that is
	// silently dead for the life of the process.
	ln, err := net.Listen("tcp", cfg.Addr)
	if err != nil {
		return nil, fmt.Errorf("zenarmor: listen %s: %w", cfg.Addr, err)
	}
	s.ln = ln
	s.listenPorts = []int{listenPortOf(ln.Addr().String())}
	s.srv = &http.Server{
		Handler:           newServer(cfg, s.handleDoc, s.proc.m, d.Logger),
		TLSConfig:         cfg.TLSConfig,
		ReadHeaderTimeout: readHeaderTimeout,
		ReadTimeout:       readTimeout,
		IdleTimeout:       idleTimeout,
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
	family := familyFor(index) // ES index-name form (zenarmor_..._conn_write)
	if family == "" {
		s.proc.m.reject("unknown_family")
		return
	}
	s.proc.process(family, doc, peer, s.listenPorts, emit)
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
