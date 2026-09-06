package syslog

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"time"

	"github.com/rknightion/opnsense2otel/v5/internal/flow"
	"github.com/rknightion/opnsense2otel/v5/internal/logship"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/capture"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
	"github.com/rknightion/opnsense2otel/v5/internal/options"
)

// sourceName is the stable source identifier; it becomes the `source` attribute
// value on every record the receiver ships.
const sourceName = "syslog"

// envelopeShapeKey stands in for the program in a debug-capture shape key when the
// ENVELOPE itself would not parse, so there is no program to key on. It is bracketed
// because angle brackets delimit the syslog PRI and therefore cannot appear in a
// program token — a malformed frame can never share a shape slot with a real program.
const envelopeShapeKey = "<envelope>"

// RejectReasons and ParseStages are this receiver's CLOSED label vocabulary, used
// to pre-initialise logs_rejected_total / logs_parse_errors_total to zero at
// startup (#280) so a healthy receiver reports a flat 0 instead of nothing.
//
// Both are enforced against their call sites by TestReceiverVocabulariesMatchCallSites
// in the parent package: adding a Reject("x") without listing "x" here fails the
// build, and so does listing a value nothing rejects with. Never add a value that
// comes off the wire — these must stay code-defined and closed.
var (
	// RejectReasons: peer/oversized/queue_full/conn_limit/tls_timeout/tls_auth_failed/
	// tls_deadline_error are the listener's (listener.go), filtered is the
	// program/severity filter and sampled is --logs.syslog.sample (source.go).
	//
	// conn_limit covers BOTH the plaintext and TLS connection-cap refusal, exactly
	// like peer is not split by transport either — the listener holds SEPARATE
	// per-transport budgets, but which budget was full is not a distinction an
	// operator alerting on capacity pressure needs (#399).
	//
	// tls_timeout/tls_auth_failed classify a failed pre-authentication TLS
	// handshake: a timeout (the client stalled or never spoke) versus anything else
	// (an invalid/missing client certificate, a protocol/cipher mismatch, or any
	// other handshake-layer rejection) — never the raw error text or peer identity.
	// tls_deadline_error covers the listener's OWN local SetDeadline calls around
	// the handshake failing, which is a distinct (and previously invisible) failure
	// mode from the handshake itself.
	RejectReasons = []string{
		"peer", "oversized", "queue_full", "filtered", "sampled",
		"conn_limit", "tls_timeout", "tls_auth_failed", "tls_deadline_error",
	}
	// ParseStages: an unparseable line still ships with its raw bytes, so the only
	// stage that can fail is the envelope. Body parsers never report a parse error —
	// a program with no registered parser is normal, not an error.
	ParseStages = []string{"envelope"}
)

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
	l        *Listener
	cache    *enrich.Cache
	dnsCache *flow.DNSCache
	miss     func(table string)
	m        *logship.ReceiverMetrics
	filter   *Filter
	log      *slog.Logger

	// sink receives derived-metric observations (#258). Never nil: a NopMetricSink is
	// substituted when metric derivation is disabled (log_events collector off).
	sink logship.MetricSink
	// unparsed records parser-coverage misses under the bounded subsystem vocabulary.
	unparsed func(subsystem string)
	// sample drops high-volume raw lines after their metrics are derived.
	sample bool
	// sampledAttr stamps sampled="true" on shipped lines while sample is on.
	sampledAttr bool
	// cap is the debug-capture sink, or nil when this receiver did not opt in. A nil
	// *capture.Capturer is a no-op, so it is called unconditionally.
	cap *capture.Capturer

	// ports holds the receiver's bound listen ports (UDP/TCP/TLS), parsed from the
	// configured addresses in newSource. Passed to proc.Process for self-traffic
	// recognition.
	ports []int
	// proc is the optional registered ProgramProcessor, read once in Run (all source
	// factories have run by then, so any processor registered during the build phase
	// is guaranteed visible here). Nil when nothing is registered.
	proc ProgramProcessor

	// emit is set by Run before the listener's read goroutines exist. Goroutine
	// creation is a happens-before edge, so a plain field is safe here: no reader
	// can observe it before Run has written it.
	emit func(logship.Record)
}

// portOf parses the port off a "host:port" listen address. Returns 0, false when
// addr is empty or does not parse — never panics.
func portOf(addr string) (int, bool) {
	if addr == "" {
		return 0, false
	}
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, false
	}
	return port, true
}

func newSource(cfg *options.SyslogConfig, d logship.Deps) *source {
	cache := d.Cache
	if cache == nil {
		// Enrichment disabled (--logs.syslog.enrich=false) or not wired: serve a cold
		// cache that misses every lookup, so records still ship — just unenriched.
		cache = enrich.NewCache()
	}
	sink := d.MetricSink
	if sink == nil {
		sink = logship.NopMetricSink{}
	}
	s := &source{
		cache:    cache,
		dnsCache: d.FlowDNSCache,
		miss:     d.Miss,
		m: logship.NewReceiverMetrics(d.Registerer, sourceName, logship.ReceiverVocab{
			Reasons:    RejectReasons,
			Stages:     ParseStages,
			Subsystems: Subsystems,
		}),
		filter:      NewFilter(cfg.IncludePrograms, cfg.ExcludePrograms, cfg.MinSeverity, cfg.HasMinSeverity),
		log:         d.Logger,
		sink:        sink,
		sample:      cfg.Sample,
		sampledAttr: cfg.SampledAttr,
	}
	s.unparsed = func(subsystem string) { observeUnparsed(s.m, subsystem) }
	// The shared sink arrives via Deps; it is used only when this receiver opted in.
	if cfg.DebugCapture {
		s.cap = d.DebugCapture
	}
	for _, addr := range []string{cfg.UDPAddr, cfg.TCPAddr, cfg.TLSAddr} {
		if port, ok := portOf(addr); ok {
			s.ports = append(s.ports, port)
		}
	}
	s.l = NewListener(Config{
		UDPAddr:          cfg.UDPAddr,
		UDPReceiveBuffer: cfg.UDPReceiveBuffer,
		TCPAddr:          cfg.TCPAddr,
		TLSAddr:          cfg.TLSAddr,
		TLSConfig:        cfg.TLSConfig,
		AllowedPeers:     cfg.AllowedPeers,
		MaxConns:         cfg.MaxConns,
		// Same registerer the ReceiverMetrics counters use, so the slot gauges land
		// beside logs_rejected_total{reason="conn_limit"} — the wall-hit counter they
		// give headroom context to (#592).
		Registerer: d.Registerer,
	}, s.handle, s.m, d.Logger)
	return s
}

// Start binds the listeners. A bind failure is fatal to startup.
func (s *source) Start() error { return s.l.Start() }

func (s *source) Name() string { return sourceName }

// ExtraSourceNames reports the source a registered ProgramProcessor stamps on its
// records, so the pipeline pre-initialises that source's counter metrics (#280). It reads
// the package registration directly (set during the build phase, before collectSourceNames
// runs), not s.proc (which is only assigned at Run()).
func (s *source) ExtraSourceNames() []string {
	if p := registeredProgramProcessor(); p != nil {
		if es := p.EmittedSource(); es != "" {
			return []string{es}
		}
	}
	return nil
}

// Run blocks until ctx is cancelled. The listener closes its own sockets on
// cancellation, which is what lets the pipeline's shutdown drain complete.
func (s *source) Run(ctx context.Context, emit func(logship.Record)) error {
	s.emit = emit
	s.proc = registeredProgramProcessor()
	s.l.Run(ctx)
	return nil
}

// handle is invoked per received line. UDP calls arrive from the listener's worker
// pool; TCP and TLS calls arrive from their connection goroutines.
func (s *source) handle(line []byte, peer netip.Addr) {
	emit := s.emit
	if emit == nil {
		return // not running yet; drop rather than panic
	}
	line = []byte(redactAPIAuthFailure(string(line)))
	now := time.Now()
	env, err := ParseEnvelope(line, now)
	if err != nil {
		if safeEnv, safeRaw, recognized := sanitizeMalformedFreeRADIUS(line, now); recognized {
			// The original envelope was malformed, so retain the closed parse-error
			// signal, but never let its identity-bearing bytes reach capture,
			// generic shipping, shape keys, parsers, filters or processors.
			s.m.ParseError("envelope")
			env = safeEnv
			line = safeRaw
		} else {
			// NEVER drop: an unparseable line still ships, with its raw bytes as the body.
			// A receiver that silently discards what it cannot understand is worse than
			// useless — it looks healthy while losing data.
			s.m.ParseError("envelope")
			if s.cap != nil {
				// Deduped by shape for the same reason the unparsed capture below is: a device
				// spamming malformed frames floods the SHARED byte cap and starves every other
				// lane (#362). There is no program to key on — the parse that would have found
				// one is what failed — so the raw line is the whole key, behind a prefix that a
				// program name cannot collide with (angle brackets delimit the PRI, so no
				// program token can be "<envelope>").
				s.cap.CaptureShape(sourceName, capture.KindUnparsed,
					envelopeShapeKey+"|"+capture.NormaliseShape(string(line)),
					map[string]any{
						"parse_error": "envelope",
						"raw":         string(line),
					})
			}
			emit(logship.Record{Timestamp: time.Now(), Body: string(line)})
			return
		}
	}
	if safeEnv, safeRaw, recognized := sanitizeFreeRADIUS(env, line); recognized {
		env = safeEnv
		line = safeRaw
	}
	if s.proc != nil && s.proc.Handles(env.Program) {
		if s.proc.Process(env, peer, s.ports, emit) {
			return // fully handled by the processor (built, counted, emitted)
		}
		// processor declined this line — fall through to generic dispatch below.
	}
	// Filtering is opt-in and defaults to passing everything. It is applied AFTER the
	// envelope parse because that is where the program and severity come from, and
	// BEFORE the (more expensive) body parse and enrichment -- no point enriching a
	// record we are about to drop.
	if s.filter.Enabled() && !s.filter.Allow(env.Program, env.Severity) {
		s.m.Reject("filtered")
		return
	}
	_, parserDispatched := parserFor(env.Program)
	rec, parsed := buildRecord(env, s.cache.Load(), s.miss)
	unknown := !parsed && rec.Attributes["syslog.parse_status"] != "known"
	if unknown && s.cap != nil {
		// A line no primary/supplemental parser or known-pass-through grammar
		// recognised: exactly
		// the "signal we do not model" the debug capture exists to surface. Captured
		// BEFORE any sample drop so nothing an operator might want to model is lost.
		//
		// Deduped by SHAPE, not captured per line (#362). On a real firewall this branch
		// is the majority of all traffic — most programs have no dedicated parser — which
		// made it 31 MB/day of overwhelmingly repeated text, and because the byte cap
		// governs the whole capture dir and STOPS when reached, it permanently starved the
		// NetFlow and Zenarmor captures that share it. One example per (program, shape)
		// per window is what an operator needs to decide whether to model the line; the
		// repeats behind it are counted as duplicate_shape, so the real rate is still
		// visible even though the file holds one of each. The line itself still ships —
		// dedupe governs the debug capture and nothing else.
		s.cap.CaptureShape(sourceName, capture.KindUnparsed,
			env.Program+"|"+capture.NormaliseShape(env.Message), map[string]any{
				"program":   env.Program,
				"subsystem": subsystemFor(env.Program),
				"severity":  env.Severity,
				"message":   env.Message,
				"raw":       string(line),
			})
	}
	if unknown && (parserDispatched || len(capturedRules[env.Program]) > 0) {
		if s.unparsed != nil {
			s.unparsed(subsystemFor(env.Program))
		} else {
			observeUnparsed(s.m, subsystemFor(env.Program))
		}
	}

	// filterlog has no domain in its wire row. The shared flow DNS answer cache
	// already joins the same (client, answer) pair for NetFlow and Zenarmor; read it
	// here as well, without a resolver fallback or any other I/O (#0038).
	if parsed && env.Program == "filterlog" {
		if domain := enrichFilterlogDomain(&rec, s.dnsCache, now); domain != "" {
			observeFilterlogDomain(s.sink, domain)
		}
	}

	// Derive Prometheus counters from the parsed record (#258). counted reports
	// whether we actually incremented a counter for this line — it gates sampling so a
	// line we did not count is never dropped.
	counted := observeDerived(s.sink, env.Program, rec.Attributes)

	if s.sample {
		if !sampleKeep(env.Program, rec, counted) {
			// The line's metric is already counted; drop the raw line to save log volume.
			s.m.Reject("sampled")
			return
		}
		// Mark surviving derived-program lines so consumers know the stream is sampled
		// and must use the derived counters for totals, not a count of log lines.
		if s.sampledAttr && counted {
			if rec.Attributes == nil {
				rec.Attributes = map[string]string{}
			}
			rec.Attributes["sampled"] = "true"
		}
	}
	emit(rec)
}

var _ logship.PushSource = (*source)(nil)
