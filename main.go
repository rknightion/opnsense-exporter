package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	promcollectors "github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/exporter-toolkit/web"
	"github.com/rknightion/opnsense2otel/v5/internal/annotations"
	"github.com/rknightion/opnsense2otel/v5/internal/collector"
	"github.com/rknightion/opnsense2otel/v5/internal/cpustream"
	"github.com/rknightion/opnsense2otel/v5/internal/fetchshare"
	"github.com/rknightion/opnsense2otel/v5/internal/flow"
	"github.com/rknightion/opnsense2otel/v5/internal/flow/netflow"
	"github.com/rknightion/opnsense2otel/v5/internal/geoip"
	"github.com/rknightion/opnsense2otel/v5/internal/healthprobe"
	"github.com/rknightion/opnsense2otel/v5/internal/logship"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/capture"
	_ "github.com/rknightion/opnsense2otel/v5/internal/logship/configsnapshot" // registers opt-in configuration snapshot sources
	"github.com/rknightion/opnsense2otel/v5/internal/logship/enrich"
	"github.com/rknightion/opnsense2otel/v5/internal/logship/flowlog"
	logshipsyslog "github.com/rknightion/opnsense2otel/v5/internal/logship/syslog" // registers the syslog push source; also the log-lane GeoIP enricher (#528)
	_ "github.com/rknightion/opnsense2otel/v5/internal/logship/zenarmor"           // registers the zenarmor push source
	"github.com/rknightion/opnsense2otel/v5/internal/metricsnap"
	"github.com/rknightion/opnsense2otel/v5/internal/options"
	"github.com/rknightion/opnsense2otel/v5/internal/profiling"
	"github.com/rknightion/opnsense2otel/v5/internal/server"
	"github.com/rknightion/opnsense2otel/v5/internal/telemetry"
	"github.com/rknightion/opnsense2otel/v5/internal/webui"
	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

var version = ""

// collector.LogEvents is handed to the syslog receiver as its logship.MetricSink
// (#258). Assert the seam here so a signature drift on either side fails the build.
var _ logship.MetricSink = collector.LogEvents

// enableAllAvailableBudgetReminderThreshold is the number of collector switches
// --exporter.enable-all-available (#517) can turn on before main also reminds
// the operator to check --exporter.series-budget (design constraint: "the
// availability report is the right place to say so up front").
const enableAllAvailableBudgetReminderThreshold = 5

// otlpShutdownTimeout bounds the final OTLP flush on graceful shutdown so a dead
// export endpoint cannot hang process exit.
const otlpShutdownTimeout = 10 * time.Second

// logsShutdownTimeout bounds the log pipeline drain (queue flush + sink flush) on
// graceful shutdown so a dead logs endpoint cannot hang process exit.
const logsShutdownTimeout = 10 * time.Second

// httpShutdownTimeout bounds the graceful HTTP drain on SIGTERM/SIGINT so an in-flight
// scrape can finish, while staying comfortably under Kubernetes' default 30s
// termination grace period so the container is never SIGKILLed mid-drain (#161).
const httpShutdownTimeout = 10 * time.Second

// flowDedupeEntries bounds the VLAN de-duplication table. Sized above the observed
// in-flight instance count on the reference box (9,657 duplicate instances across a
// whole capture, only a fraction ever concurrent) so the bound is memory insurance
// rather than something steady-state traffic pushes against — at capacity the
// oldest entry goes and a later duplicate is no longer suppressed.
const flowDedupeEntries = 20000

// flowHoldEntries bounds the VLAN hold buffer — records parked for up to two seconds
// while a more specific copy on a VLAN child could still arrive (#357).
//
// It is deliberately smaller than flowDedupeEntries and is a different KIND of bound:
// the de-dup table holds keys remembering decisions already taken, while this holds
// whole Records nobody downstream has seen yet. Sized for two seconds of a sustained
// 5,000 records/second burst on a box where every record touches the trunk, which is
// several times the reference box's peak. At capacity the oldest held record is
// released early rather than dropped, so overrunning it costs attribution on that
// record, never the record itself.
const flowHoldEntries = 10000

// flowHoldReleaseInterval drives the hold buffer's release on a lane that has gone
// quiet. Every datagram arrival already drains what is due, so this only matters when
// the exporter stops sending — and then it bounds how long the last records of a burst
// sit unreported.
const flowHoldReleaseInterval = time.Second

// ifIndexRefreshInterval rebuilds the NetFlow ifIndex map. Frequent because the
// mapping is positional: an interface added or removed renumbers everything.
const ifIndexRefreshInterval = 60 * time.Second

// ifIndexColdRetryInterval is how fast the ifIndex map is retried BEFORE the first
// successful publish. Until a map exists no record can be labelled and none can be
// resolved, so the cold window is pure loss - it is worth spending a poll per
// second to close it, and it stops the moment a map lands (#365).
const ifIndexColdRetryInterval = time.Second

// pfStateRefreshInterval rebuilds the pf state snapshot the policy-route repair
// resolves against (#603, re-costed by #620).
//
// ONE MINUTE. This was five, on the reasoning that "the flows the repair recovers are
// long, so a shorter interval buys nothing". That reasoning was WRONG and is recorded
// here so it does not get re-derived: measured on the production box 2026-07-31, the
// policy-routed population is 19 states of which EIGHTEEN are sub-90-second TCP
// connections, one arriving about every ten seconds. With a five-minute poll those
// states were born, used and closed entirely between two snapshots, appeared in
// neither, and were refused every time — about 30% of decoded records.
//
// The cost is real and was weighed rather than waved through: the full table is 3.3
// MB and ~650 ms for 6,602 rows on that box, and every API request also costs two
// configd RPCs on OPNsense's auth middleware whatever it asks for. So this is 5x the
// request load of the old cadence. Two cheaper options were investigated and do not
// exist: query_states' searchPhrase cannot select route-to-carrying states — it is a
// post-parse AND-substring match over record VALUES applied after pfctl has already
// dumped and Python has already parsed the whole table, so it saves bytes but none of
// the firewall-side work — and a rolling union alone reaches only states that expired,
// not states created after the last poll, which is where this population lives.
//
// One minute reaches a ~90-second state most of the time. It does NOT reach a
// 30-second one, and nothing short of a poll faster than the state lifetime would;
// those stay refused and counted, which is honest.
//
// Still deliberately not a flag. The only thing tuning it changes is firewall API
// load, and the staleness it trades against is bounded by pf's state lifetimes.
const pfStateRefreshInterval = time.Minute

// pfStateRetention is how long a pf state stays answerable after it stops appearing
// in snapshots — the rolling union half of #620's fix.
//
// Three minutes, i.e. three poll intervals of grace. It closes the OTHER half of the
// miss window: a state alive at a poll that expires before its NetFlow record lands
// (the reference box runs inactiveTimeout=15, so a record can arrive 15-30s after the
// conversation ended). Without it the grace period is whatever is left of the current
// poll interval, so an identical flow is resolvable or not depending on where in the
// cycle it died — this makes it uniform.
//
// Sized against being WRONG rather than against memory, which is negligible here. A
// carried entry is a claim about a state that no longer exists, and it goes bad on a
// WAN failover: pf re-routes, the tuple stops appearing, and until it ages out the
// table keeps naming the dead egress. Three intervals is comfortably longer than any
// plausible export delay and short enough that a failover mislabels for seconds, not
// minutes. Do not raise it to "cover more" — past the export delay it buys nothing
// and only widens that window.
const pfStateRetention = 3 * time.Minute

// ifIndexNamelessDeadline bounds the cold retry when the map keeps arriving with
// indices but no interface NAMES.
//
// The enumeration and the interface metadata are two sequential API calls, so the
// first map built after a restart routinely has every index right and not one name,
// and Iface.Label falls back to the device — labelling records "ixl0" instead of
// "LAN" and splitting every series in two until the next rebuild (#522). Staying on
// the 1s cadence until names land closes that in about one API call instead of a
// minute.
//
// The deadline exists for the box that genuinely reports no descriptions: without
// it, that box would poll its API once a second forever. Reaching it publishes the
// device-labelled map as final and settles to the normal cadence.
const ifIndexNamelessDeadline = 5 * time.Minute

// enableAllAvailableProbeTimeout bounds the one startup availability pass behind
// --exporter.enable-all-available. It gates which collectors exist, so it has to
// finish before the collector set is built — and must therefore never be able to
// hang a start. Expiring falls open and enables everything.
const enableAllAvailableProbeTimeout = 15 * time.Second

// ifIndexSettled reports whether a built ifIndex map may be treated as final, so
// the rebuild ticker can drop from the cold retry to the normal interval.
//
// named is IfMapStats.Named and coldFor is how long maps have been building without
// one. A map carrying names is final; a map carrying none is provisional until the
// deadline, after which the box is taken at its word.
func ifIndexSettled(named int, coldFor time.Duration) bool {
	return named > 0 || coldFor >= ifIndexNamelessDeadline
}

// flowExpireTick is how often the correlator sweeps for windows that have elapsed. An
// entry therefore emits within its window plus at most one tick; the sweep is a whole-map
// scan, so the tick is coarse rather than sub-second.
const flowExpireTick = 30 * time.Second

// flowCorrelateMinWindow is the floor below which a correlate window is almost certainly
// a misconfiguration: NetFlow export lag runs to minutes (mean 1m34s on the reference
// box, #346), so a sub-minute window would split nearly every connection into partials.
const flowCorrelateMinWindow = time.Minute

// flowDNSCacheTTL is how long a DNS answer stays usable for domain enrichment (#353).
// There is no operator flag by design (§11 lists only --flow.dns-cache.size); one hour
// comfortably spans the correlator window plus the worst measured NetFlow export lag
// (~30m), so an answer is still resolvable when the flow it explains finally arrives,
// while being short enough that a shared CDN address is not handed a stale domain for
// long. dst.domain is metadata only, never a label, so a modest staleness rate is
// acceptable where a wrong metric label would not be.
const flowDNSCacheTTL = time.Hour

// readyCacheTTL caches /-/ready probe results (success and failure). 10s
// matches the default kubelet probe period, bounding upstream health calls to
// roughly one per probe period regardless of how many probers hit the
// endpoint, while keeping readiness staleness within a single probe cycle.
const readyCacheTTL = 10 * time.Second

// errSnapshotWarming is the readiness failure raised while the poll scheduler is
// still filling its first snapshot: the box is reachable, but a scrape now would
// return only the collectors that have already polled (#341).
var errSnapshotWarming = errors.New("poll scheduler is still warming: not every collector has completed its first poll")

// resolveInstanceLabel deterministically chooses the opnsense_instance label
// value (baked into every metric, the OTLP resource identity and Pyroscope
// tags). An explicit --exporter.instance-label always wins. Otherwise the
// configured address is used — unless useHostname is set, in which case the
// OPNsense hostname is looked up and, if unavailable, startup fails rather than
// silently falling back to the address (which would make the label depend on
// startup timing and differ across restarts). See #75.
func resolveInstanceLabel(explicit, addr string, useHostname bool, lookup func() (string, error), logger *slog.Logger) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	if !useHostname {
		logger.Info("instance label not set; using configured OPNsense address", "instance", addr)
		return addr, nil
	}
	hostname, err := lookup()
	if err != nil {
		return "", fmt.Errorf("hostname lookup failed (set --exporter.instance-label explicitly, "+
			"or unset --exporter.instance-use-hostname to use the configured address %q): %w", addr, err)
	}
	if hostname == "" {
		return "", fmt.Errorf("OPNsense reported an empty hostname (set --exporter.instance-label explicitly)")
	}
	logger.Info("instance label not set; using OPNsense hostname", "instance", hostname)
	return hostname, nil
}

// collectorNames returns the name of every registered collector (enabled or
// not), so the web UI can show which collectors are disabled/skipped.
func collectorNames() []string {
	all := collector.AllCollectors()
	names := make([]string, 0, len(all))
	for _, c := range all {
		names = append(names, c.Name())
	}
	return names
}

// startupConfig is every configuration value main() needs, resolved and validated
// in one place by resolveOptions.
//
// It exists so the --config.check preflight (#446) and a real start cannot drift:
// main() has no other route to a configuration value, so anything it can act on
// has already been through the preflight. TestConfigValidationCannotDriftFromStartup
// enforces that structurally — an error-returning options accessor called directly
// from main() fails the build's tests.
type startupConfig struct {
	OPNsense       *options.OPNSenseConfig
	CacheTTLs      options.EndpointCacheTTLs
	AbsentCacheTTL time.Duration
	Collectors     options.CollectorsDisableSwitch
	// AutoEnabledFeatures is what --exporter.enable-all-available turned on that
	// the operator had not already set themselves (#517), in options.CollectorFlags
	// order. Empty when the flag is off. Logged individually once the logger
	// exists (resolveOptions runs before it does).
	AutoEnabledFeatures []options.AutoEnabledFeature
	Flow                options.FlowConfig
	Netflow             options.NetflowConfig
	NetflowCapture      netflow.CaptureMode
	PollOverrides       map[string]time.Duration
	Pyroscope           *options.PyroscopeConfig
	PyroscopeOn         bool
	OTLP                *options.OTLPConfig
	OTLPOn              bool
	Logs                *options.LogsConfig
	LogsOn              bool
	// LogsOTLP is the OTLP transport the log pipeline ships over. Resolved
	// independently of --otlp.enabled (logs may ship with metrics OTLP off) and
	// nil unless the logs sink is "otlp".
	LogsOTLP *options.OTLPConfig
	Syslog   *options.SyslogConfig
	SyslogOn bool
	// Annotations writes OPNsense change events into Grafana's annotation store
	// (#421). Opt-in, and the exporter's only outbound write.
	Annotations   *options.AnnotationsConfig
	AnnotationsOn bool
	// GeoIP is the local MaxMind enrichment of flow records (#520). Opt-in, and
	// fail-open: a missing or unreadable database leaves the geo attributes absent
	// rather than failing the start.
	GeoIP options.GeoIPConfig
}

// resolveOptions parses nothing and starts nothing: it reads the already-parsed
// flag/env values, reads the files they reference (API key/secret, TLS keypairs),
// and returns either a usable configuration or every reason it is not.
//
// Every error is collected rather than returned at the first failure, because the
// preflight's job is to let an operator fix a deployment in one pass instead of
// one restart per mistake.
//
// Deliberately NOT done here, and therefore not covered by --config.check:
//   - any OPNsense API call, including the hostname lookup that
//     --exporter.instance-use-hostname needs and the /-/ready health check;
//   - binding a listener (metrics port, syslog, Zenarmor HTTP, NetFlow UDP), so a
//     port collision still surfaces only at a real start;
//   - creating the --logs.debug-capture.dir capture directory, which is a write;
//   - reaching the OTLP endpoint or the Pyroscope server.
//
// Reachability belongs to /-/ready at runtime; a preflight that dialled the
// firewall would fail for reasons that have nothing to do with the configuration
// it is being asked about.
func resolveOptions() (*startupConfig, []error) {
	var errs []error
	cfg := &startupConfig{
		CacheTTLs:      options.CacheTTLs(),
		AbsentCacheTTL: options.AbsentCacheTTL(),
	}
	// --exporter.enable-all-available (#517) turns on every opt-in collector
	// switch the operator has not set themselves; ApplyEnableAllAvailable is a
	// no-op returning the switches unchanged and a nil list when the flag is off.
	cfg.Collectors, cfg.AutoEnabledFeatures = options.ApplyEnableAllAvailable(options.CollectorsSwitches())

	opns, err := options.OPNSense()
	if err != nil {
		errs = append(errs, fmt.Errorf("opnsense connection (--opnsense.*): %w", err))
	}
	cfg.OPNsense = opns

	// The two per-query DNS routes ship the same queries by different transports, so
	// enabling both doubles per-query Loki volume and every panel reading it (#659).
	// Refused here rather than at the flag layer so --config.check reports it too.
	if err := options.ValidateUnboundPerQueryRoutes(); err != nil {
		errs = append(errs, err)
	}

	// The metrics path is validated against the fixed routes the server package
	// owns. They are passed in rather than imported by internal/options, which
	// keeps that package free of an import edge into internal/server.
	if err := options.ValidateMetricsPath(*options.MetricsPath, server.HealthyPath, server.ReadyPath); err != nil {
		errs = append(errs, err)
	}

	// TLS/basic-auth material for the metrics port. web.Validate reads the config
	// file and the certificates it names WITHOUT binding a listener, so a broken
	// keypair is caught here rather than at ListenAndServe.
	if options.WebConfig != nil && options.WebConfig.WebConfigFile != nil {
		if err := web.Validate(*options.WebConfig.WebConfigFile); err != nil {
			errs = append(errs, fmt.Errorf("--web.config.file: %w", err))
		}
		// #562: exporter-toolkit's VerifyPeerCertificate callback indexes
		// rawCerts[0] unconditionally, and installs itself whenever
		// client_allowed_sans is set even under a client_auth_type that lets a
		// handshake complete with no client certificate at all. Reject that
		// combination here, before it can ever reach a handshake.
		if err := options.ValidateWebTLSConfig(*options.WebConfig.WebConfigFile); err != nil {
			errs = append(errs, err)
		}
	}

	flowCfg, ferr := options.Flow()
	if ferr != nil {
		errs = append(errs, fmt.Errorf("invalid flow configuration: %w", ferr))
	} else {
		cfg.Flow = flowCfg
		mode, cmErr := netflow.ParseCaptureMode(flowCfg.NetflowDebugCapture)
		if cmErr != nil {
			errs = append(errs, fmt.Errorf("invalid --flow.netflow.debug-capture: %w", cmErr))
		}
		cfg.NetflowCapture = mode
	}

	netflowCfg, nerr := options.Netflow()
	if nerr != nil {
		errs = append(errs, fmt.Errorf("invalid NetFlow worker-pool configuration: %w", nerr))
	} else {
		cfg.Netflow = netflowCfg
	}

	geoCfg, gerr := options.GeoIP()
	if gerr != nil {
		errs = append(errs, fmt.Errorf("invalid geoip configuration: %w", gerr))
	} else {
		cfg.GeoIP = geoCfg
	}

	// Validate the collector-name half of every override BEFORE parsing durations
	// (#387). A typo used to be accepted and then silently ignored forever, because
	// the scheduler matches the map by exact collector name and an unmatched entry
	// simply never fires — so the operator's rate/cost control did nothing and
	// nothing said so. Names are checked against every REGISTERED collector, not the
	// enabled ones, so a config that names a currently-disabled collector still
	// starts and keeps working when that feature flag is flipped on.
	overrideNames := make([]string, 0, len(*options.CollectorPollIntervalOverrides))
	for name := range *options.CollectorPollIntervalOverrides {
		overrideNames = append(overrideNames, name)
	}
	if verr := collector.ValidatePollOverrideNames(overrideNames); verr != nil {
		errs = append(errs, fmt.Errorf("invalid --collector.poll-interval-override: %w", verr))
	}
	cfg.PollOverrides = make(map[string]time.Duration, len(*options.CollectorPollIntervalOverrides))
	for name, v := range *options.CollectorPollIntervalOverrides {
		d, perr := time.ParseDuration(v)
		if perr != nil {
			errs = append(errs, fmt.Errorf("invalid --collector.poll-interval-override for collector %q: %q: %w", name, v, perr))
			continue
		}
		cfg.PollOverrides[name] = d
	}

	cfg.Pyroscope, cfg.PyroscopeOn, err = options.Pyroscope()
	if err != nil {
		errs = append(errs, fmt.Errorf("invalid pyroscope configuration: %w", err))
	}

	cfg.OTLP, cfg.OTLPOn, err = options.OTLP()
	if err != nil {
		errs = append(errs, fmt.Errorf("invalid otlp configuration: %w", err))
	}

	cfg.Annotations, cfg.AnnotationsOn, err = options.Annotations()
	if err != nil {
		errs = append(errs, fmt.Errorf("invalid annotations configuration: %w", err))
	}

	cfg.Logs, cfg.LogsOn, err = options.Logs()
	if err != nil {
		errs = append(errs, fmt.Errorf("invalid logs configuration: %w", err))
	}
	logsSink := ""
	if cfg.Logs != nil {
		logsSink = cfg.Logs.Sink
	}
	if err := options.ValidateLogsSelf(options.LogsSelfEnabled(), cfg.LogsOn, logsSink); err != nil {
		errs = append(errs, fmt.Errorf("invalid self-log configuration: %w", err))
	}
	if cfg.LogsOn && cfg.Logs.Sink == "otlp" {
		// Resolved WITHOUT the --otlp.enabled gate so logs can ship even when metrics
		// OTLP export is off. A resolution error names the offending --otlp.* flag.
		cfg.LogsOTLP, err = options.OTLPTransport()
		if err != nil {
			errs = append(errs, fmt.Errorf("invalid otlp transport for the logs sink: %w", err))
		}
	}

	cfg.Syslog, cfg.SyslogOn, err = options.LogsSyslog()
	if err != nil {
		errs = append(errs, fmt.Errorf("invalid syslog receiver configuration: %w", err))
	}
	// Sampling drops raw lines only after their metrics are derived, so it is
	// meaningless (pure data loss) with the log_events collector off.
	if cfg.SyslogOn && cfg.Syslog.Sample && !cfg.Collectors.LogEvents {
		errs = append(errs, errors.New(
			"invalid syslog receiver configuration: --logs.syslog.sample requires the log_events collector; remove --exporter.disable-log-events"))
	}

	// The Zenarmor receiver resolves its own configuration inside logship at start,
	// so without this the preflight would miss its TLS keypair and its
	// transport/capture cross-checks entirely. Resolution is pure — the value is
	// discarded here and re-resolved by the receiver.
	if _, _, zerr := options.LogsZenarmor(); zerr != nil {
		errs = append(errs, fmt.Errorf("invalid zenarmor receiver configuration: %w", zerr))
	}

	return cfg, errs
}

// runConfigCheck is the --config.check path: report the outcome and return the
// process exit code. It never starts anything — everything it knows came from
// resolveOptions, which does no I/O beyond reading the files the configuration
// names.
func runConfigCheck(cfg *startupConfig, errs []error, stdout, stderr io.Writer) int {
	if len(errs) > 0 {
		fmt.Fprintf(stderr, "config check FAILED: %d problem(s)\n", len(errs))
		for _, err := range errs {
			fmt.Fprintf(stderr, "  - %v\n", err)
		}
		return 1
	}
	fmt.Fprintln(stdout, "config check OK")
	options.WriteEffectiveConfig(stdout)
	fmt.Fprintln(stdout, "\nNot checked: OPNsense API reachability, listener binding, OTLP/Pyroscope "+
		"endpoint reachability. Runtime reachability is reported by /-/ready.")
	if cfg != nil && *options.InstanceLabel == "" && *options.InstanceUseHostname {
		fmt.Fprintln(stdout, "Note: --exporter.instance-use-hostname resolves the instance label from the "+
			"OPNsense API at startup; that lookup cannot be validated offline and will fail the start if the box is unreachable.")
	}
	return 0
}

// dispatchSubcommand handles the argv-selected subcommands the binary owns,
// returning the process exit code and whether it handled the invocation at all.
// It runs BEFORE kingpin sees anything, which is the point: the exporter's own
// flag set has required flags (--opnsense.protocol, --opnsense.address), so a
// probe expressed as a flag could never run from a container healthcheck or a
// kubelet exec probe, where those are not supplied. Anything that is not a known
// subcommand is left entirely alone for the normal flag parser.
func dispatchSubcommand(args []string, stdout, stderr io.Writer) (code int, handled bool) {
	if len(args) == 0 {
		return 0, false
	}
	switch args[0] {
	case healthprobe.Command:
		return healthprobe.Run(args[1:], stdout, stderr), true
	default:
		return 0, false
	}
}

// startGeoIP opens the configured MaxMind databases, installs the process-wide flow
// enricher (and the syslog log lanes' enricher, per the per-lane opt-out), wires the
// self-metrics and starts the download/reload updater. It returns a stop function, or
// nil when geo enrichment is off.
//
// Nothing here can fail the start. That is the whole contract: geo is an enrichment
// on top of telemetry the exporter would ship anyway, so a bad path, an expired
// license key or a truncated download degrades the attributes and nothing else.
//
// logsGeoIPEnabled is the resolved --logs.syslog.geoip opt-out (#528): --geoip.enabled
// is the single master switch and covers filterlog/sshd/Suricata log lines by default,
// but an operator who wants GeoIP on flow records only sets --logs.syslog.geoip=false,
// and this is where that is honoured — the syslog package's enricher is left nil
// rather than wired to db.
// annotationKinds resolves the configured push set for the startup log line. An
// operator debugging "why is there no annotation for X" reads that line first, and
// an empty --annotations.kinds means the defaults, not nothing.
func annotationKinds(configured []string) []string {
	if len(configured) == 0 {
		return annotations.DefaultKinds()
	}
	return configured
}

func startGeoIP(cfg options.GeoIPConfig, logsGeoIPEnabled bool, logger *slog.Logger) func() {
	if !cfg.Enabled {
		return nil
	}

	// Open returns a USABLE *DB alongside any error: whatever loaded is serving and
	// whatever did not is simply absent, and the configured paths are retained either
	// way so a later reload picks up a corrected file. A path that does not exist yet
	// is not an error at all — the scheduled download may not have landed.
	db, err := geoip.Open(geoip.Options{CountryPath: cfg.CountryPath, ASNPath: cfg.ASNPath})
	if err != nil {
		logger.Warn("geoip database could not be loaded; enrichment will be absent until it can",
			"err", err, "country_database", cfg.CountryPath, "asn_database", cfg.ASNPath)
	}

	flow.ConfigureGeoIP(db, cfg.MetricDims)
	collector.Flow.SetGeoIPStats(func() collector.GeoIPStats {
		return collector.GeoIPStats{DB: db.Stats(), Flow: flow.GeoEnrichment.Stats()}
	})

	// The SAME *DB is handed to the log lanes -- never a second Open call, never a
	// second set of databases in memory. logsGeoIPEnabled false leaves the syslog
	// package's enricher nil, its documented fail-open no-op state.
	if logsGeoIPEnabled {
		logshipsyslog.ConfigureGeoIP(db)
	}

	var fetcher geoip.Fetcher
	if cfg.DownloadEnabled {
		fetcher = &geoip.Downloader{
			AccountID:  cfg.DownloadAccount,
			LicenseKey: cfg.DownloadKey,
			Dir:        cfg.DownloadDir,
			Timeout:    cfg.DownloadTimeout,
		}
	}
	updater := geoip.NewUpdater(geoip.UpdaterOptions{
		DB:               db,
		Fetcher:          fetcher,
		Editions:         cfg.DownloadEditions,
		DownloadInterval: cfg.DownloadInterval,
		ReloadInterval:   cfg.ReloadInterval,
		Logger:           logger,
	})
	ctx, cancel := context.WithCancel(context.Background())
	go updater.Run(ctx)

	st := db.Stats()
	logger.Info("geoip enrichment enabled",
		"country_database", cfg.CountryPath, "country_type", st.CountryType,
		"asn_database", cfg.ASNPath, "asn_type", st.ASNType,
		"download", cfg.DownloadEnabled, "metric_country_label", cfg.MetricDims)
	if db.Empty() {
		// Loud, because this is the state that looks identical to a quiet network:
		// every attribute absent, every counter at zero, and nothing failing.
		logger.Warn("geoip is enabled but no database is loaded; flow records will carry no geo " +
			"attributes until one appears at the configured path")
	}

	return func() {
		cancel()
		db.Close()
	}
}

func main() {
	// The `health` subcommand (#438) is dispatched from argv first, before any
	// flag parsing or env inspection, so the probe works in a container whose
	// exporter configuration is broken or absent — which is exactly when a
	// healthcheck is being consulted.
	if code, handled := dispatchSubcommand(os.Args[1:], os.Stdout, os.Stderr); handled {
		os.Exit(code)
	}
	// Register --version before flag parsing so `opnsense2otel --version`
	// prints the ldflags-embedded version and exits — used by the publish/CI
	// smoke check to prove the built image embeds a real version (see #79).
	kingpin.Version(version)
	// Fail fast on settings retired by the syslog receiver (#248) BEFORE parsing.
	// kingpin rejects an unknown --flag on its own, but a retired ENV VAR would just
	// be read by nothing — the user would get an empty log stream and no explanation.
	if err := options.CheckRemovedFlagsFromProcess(); err != nil {
		fmt.Fprintln(os.Stderr, "error: "+err.Error())
		os.Exit(1)
	}
	options.Init()

	// Resolve and validate the whole configuration in one pass, before anything is
	// constructed or started. --config.check (#446) stops here and reports; a real
	// start continues from the same values, so the preflight cannot pass a
	// configuration the exporter would then reject.
	cfg, cfgErrs := resolveOptions()
	if *options.ConfigCheck {
		os.Exit(runConfigCheck(cfg, cfgErrs, os.Stdout, os.Stderr))
	}

	baseLogger := promslog.New(options.PromLogConfig)
	logger := baseLogger
	var selfLogHandler *logship.SelfLogHandler
	if options.LogsSelfEnabled() {
		selfLogHandler = logship.NewSelfLogHandler(baseLogger.Handler())
		logger = slog.New(selfLogHandler)
	}

	logger.Info("starting opnsense2otel", "version", version)

	if len(cfgErrs) > 0 {
		for _, cErr := range cfgErrs {
			logger.Error("invalid configuration", "err", cErr)
		}
		logger.Error("refusing to start with an invalid configuration",
			"problems", len(cfgErrs), "hint", "run with --config.check to validate without starting")
		os.Exit(1)
	}
	// --exporter.enable-all-available (#517): log every collector switch it
	// turned on, individually and with its reason, so the blanket switch is
	// never a silent convenience toggle - plus a --exporter.series-budget
	// reminder once more than 5 are enabled in one run.
	for _, f := range cfg.AutoEnabledFeatures {
		logger.Info("collector switch enabled by --exporter.enable-all-available",
			"flag", "--"+f.Flag, "collector", f.Subsystem, "reason", f.Reason)
	}
	if len(cfg.AutoEnabledFeatures) > enableAllAvailableBudgetReminderThreshold {
		logger.Info("--exporter.enable-all-available turned on several collectors at once; "+
			"check --exporter.series-budget against the resulting series count",
			"enabled", len(cfg.AutoEnabledFeatures), "series_budget", *options.SeriesBudget)
	}

	opnsConfig := cfg.OPNsense
	collectorsSwitches := cfg.Collectors
	flowCfg := cfg.Flow
	netflowCfg := cfg.Netflow

	// GeoIP enrichment (#520). Started here, before any receiver exists, because
	// flow.ConfigureGeoIP has to be in place before the first record is normalised —
	// a record enriched before the enricher is installed silently ships with no geo
	// and nothing says so.
	//
	// EVERY failure below is logged and continued, never fatal. A missing, unreadable
	// or corrupt database means the geo attributes are absent; it must not be able to
	// stop an exporter whose real job is metrics. The database identity and the
	// enrichment counters are published as opnsense_flow_geoip_*, which is how an
	// operator sees the degradation the fail-open design otherwise hides.
	// The per-lane opt-out (#528) only means something when the syslog receiver is
	// even running; cfg.Syslog is nil otherwise, so this must not dereference it.
	logsSyslogGeoIPEnabled := cfg.SyslogOn && cfg.Syslog.GeoIP
	stopGeoIP := startGeoIP(cfg.GeoIP, logsSyslogGeoIPEnabled, logger)
	if stopGeoIP != nil {
		defer stopGeoIP()
	}

	opnsenseClient, err := opnsense.NewClient(
		*opnsConfig,
		version,
		logger,
	)
	if err != nil {
		logger.Error("opnsense client build failed", "err", err)
		os.Exit(1)
	}

	logger.Debug(fmt.Sprintf("OPNsense registered endpoints %s", opnsenseClient.Endpoints()))

	// The shared-result seam (#571). Collector polls publish their decoded results
	// here; the syslog enrichment refresher reads one instead of asking the box for
	// an endpoint a collector decoded moments ago. Wired unconditionally and before
	// the client is cloned per scrape (WithContext), for the same reason as the
	// response cache: clones share the seam pointer, but only one that already
	// exists. It costs a map write per published poll when nothing reads it.
	resultSeam := fetchshare.New()
	opnsenseClient.SetResultSeam(resultSeam)

	// Slow-moving endpoints are served from an in-memory cache rather than re-fetched
	// every scrape. Must happen before the client is cloned per scrape (WithContext):
	// clones share the cache, but only one that already exists.
	for endpoint, ttl := range cfg.CacheTTLs {
		opnsenseClient.SetEndpointCacheTTL(opnsense.EndpointName(endpoint), ttl)
		logger.Debug("caching API endpoint responses", "endpoint", endpoint, "ttl", ttl)
	}

	// Remember that a plugin-gated endpoint is absent (404) instead of re-asking on
	// every scrape. Only the 404 is cached: where these endpoints do answer, their
	// payload is live data and still fetched every scrape.
	if absentTTL := cfg.AbsentCacheTTL; absentTTL > 0 {
		for _, endpoint := range opnsense.NegativeCacheable404Endpoints() {
			opnsenseClient.SetEndpointAbsentTTL(endpoint, absentTTL)
		}
		logger.Info("caching plugin-absent (404) endpoint responses",
			"endpoints", len(opnsense.NegativeCacheable404Endpoints()), "ttl", absentTTL)
	}

	// --exporter.enable-all-available means what its name says: gate it on what the
	// box actually has (#525 decision 4). This runs HERE because it needs the client,
	// and it deliberately does NOT run inside resolveOptions — the --config.check
	// preflight must never touch the network, so there it keeps the fail-open answer.
	//
	// Bounded, and it cannot fail the start. On a timeout or an unreachable firewall
	// the probe map comes back empty (or partial) and every unprobed collector is
	// enabled, which is the pre-#525 behaviour. A box that is briefly down must not
	// come back up as a smaller exporter than the operator asked for.
	//
	// Known consequence, documented at the flag: a plugin installed LATER will not
	// self-activate under this flag until the next restart, where previously the
	// collector was on unconditionally and lit up on its own.
	if options.EnableAllAvailable() && len(cfg.AutoEnabledFeatures) > 0 {
		probeCtx, cancelProbe := context.WithTimeout(context.Background(), enableAllAvailableProbeTimeout)
		available := collector.ProbeFeatureAvailability(probeCtx, &opnsenseClient)
		cancelProbe()

		if len(available) == 0 {
			logger.Warn("availability probe returned nothing; enabling every opt-in collector",
				"component", "startup",
				"hint", "the firewall was unreachable or too slow to answer; a collector whose plugin is absent stays silent anyway",
				"timeout", enableAllAvailableProbeTimeout)
		} else {
			probed, autoEnabled := options.ApplyEnableAllAvailableProbed(options.CollectorsSwitches(), available)
			skipped := len(cfg.AutoEnabledFeatures) - len(autoEnabled)
			collectorsSwitches = probed
			cfg.AutoEnabledFeatures = autoEnabled
			logger.Info("resolved enable-all-available against probed feature availability",
				"component", "startup",
				"enabled", len(autoEnabled),
				"left_off_plugin_absent", skipped,
				"probed", len(available))
		}
	}

	// Everything is resolved by here — file-based secrets, the blanket enable switch
	// and its availability probe — so this is the first point at which the rendered
	// config is what is actually in force rather than what was typed (#526).
	options.SetResolvedCollectorSwitches(collectorsSwitches)
	options.LogEffectiveConfig(logger)

	// selfMetricsRegistry holds exporter self-metrics (process_*, go_*). It is
	// gathered on every /metrics request alongside the per-request collector view.
	selfMetricsRegistry := prometheus.NewRegistry()

	if !*options.DisableExporterMetrics {
		selfMetricsRegistry.MustRegister(
			promcollectors.NewProcessCollector(promcollectors.ProcessCollectorOpts{}),
		)
		selfMetricsRegistry.MustRegister(promcollectors.NewGoCollector())
	}

	startTime := time.Now()
	// statusTracker retains per-collector run history (recorded from every scrape)
	// for the web UI status page; it is also updated by on-demand Run Now triggers.
	statusTracker := collector.NewStatusTracker()

	collectorOptionFuncs := []collector.Option{
		collector.WithBuildInfo(version),
		collector.WithStatusTracker(statusTracker),
	}

	if !collectorsSwitches.Unbound {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutUnboundCollector())
		logger.Info("unbound collector disabled")
	}
	if !collectorsSwitches.Wireguard {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutWireguardCollector())
		logger.Info("wireguard collector disabled")
	}
	if !collectorsSwitches.IPsec {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutIPsecCollector())
		logger.Info("ipsec collector disabled")
	}
	if collectorsSwitches.IPsecLeaseDetails {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithIPsecLeaseDetails())
		logger.Info("ipsec per-lease details enabled")
	}
	if !collectorsSwitches.Cron {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutCronCollector())
		logger.Info("cron collector disabled")
	}
	if !collectorsSwitches.ARP {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutArpTableCollector())
		logger.Info("arp collector disabled")
	}
	if !collectorsSwitches.Interfaces {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutInterfacesCollector())
		logger.Info("interfaces collector disabled")
	}
	if !collectorsSwitches.Protocol {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutProtocolCollector())
		logger.Info("protocol collector disabled")
	}
	if !collectorsSwitches.Services {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutServicesCollector())
		logger.Info("services collector disabled")
	}
	if !collectorsSwitches.LogEvents {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutLogEventsCollector())
		logger.Info("log_events collector disabled")
	}
	// Flow rollups (#346). SIZED HERE, before collector.New and therefore before
	// StartPolling launches a poller per collector. ConfigureFlow is safe to call at
	// any time — it retunes under the accumulator's own mutex rather than replacing
	// it — but doing it before the pollers exist keeps the ordering obviously correct
	// as well as actually correct. (flowCfg itself came from resolveOptions.)
	// flowSink is what the two receiver lanes feed. By default it is the metric rollup
	// alone; when flow-log emission is on it becomes a tee that also feeds the correlator,
	// so metrics and logs are derived from one Observe without either lane knowing about
	// the log path.
	var flowSink flow.Sink = collector.Flow
	var stopFlowLog func()
	// flowDNSCache is shared by both receiver lanes: the Zenarmor lane feeds it from the
	// dns family and reads it on the conn family, the NetFlow lane reads it in enrich.
	// Built once here so both see the same answers; nil (and a safe no-op) when flow is
	// off or --flow.dns-cache.size=0.
	var flowDNSCache *flow.DNSCache
	if !collectorsSwitches.Flow {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutFlowCollector())
		logger.Info("flow collector disabled")
	} else if flowCfg.Enabled {
		collector.ConfigureFlow(flowCfg.TopN, flowCfg.MaxKeys)
		logger.Info("flow rollups enabled", "top_n", flowCfg.TopN, "max_keys", flowCfg.MaxKeys)

		// DNS answer cache (#353 §7). NewDNSCache treats size<=0 as disabled, so this is
		// safe to build unconditionally; the stats accessor publishes its self-metrics from
		// zero so an empty cache reads as "on but idle" rather than absent.
		flowDNSCache = flow.NewDNSCache(flowCfg.DNSCacheSize, flowDNSCacheTTL)
		collector.Flow.SetDNSCacheStats(flowDNSCache.Stats)

		// Top-talkers (#353 §9), opt-in. Pin the counted source so a two-source box does
		// not double a host's bytes: prefer Zenarmor (one document per connection, no
		// fragmentation) when its lane is on, else NetFlow.
		if flowCfg.TopTalkers {
			primary := flow.SourceNetflow
			if flowCfg.Zenarmor {
				primary = flow.SourceZenarmor
			}
			collector.ConfigureTopTalkers(true, primary)
			logger.Info("flow top-talkers enabled", "primary_source", primary.String())
		}

		// Flow-log lane (#346 phase 3): the correlator collapses NetFlow fragments and
		// merges Zenarmor L7, emitting one OTLP log record per connection-window. Built
		// only when --flow.log-mode=per_flow; off leaves the lanes feeding metrics alone.
		// Configured BEFORE logship.Start so its registered push source sees the mode.
		if flowCfg.LogMode == flowlog.LogModePerFlow {
			flowlog.Sink.Configure(flowCfg.LogMode, flowCfg.MaxLogsPerWindow)
			if flowCfg.Correlate && flowCfg.CorrelateWindow < flowCorrelateMinWindow {
				logger.Warn("flow correlate window is shorter than typical NetFlow export lag; "+
					"most connections will emit partials rather than one joined record",
					"window", flowCfg.CorrelateWindow, "floor", flowCorrelateMinWindow)
			}
			// Observe the NF-vs-Zen byte disagreement (#353 §9) at emit time, before
			// shipping the log: a merged record is the only place both sources' counters
			// meet, and this is that place. Metrics-first, so a stalled log sink never
			// starves the histogram.
			emit := func(r flow.Record) {
				collector.Flow.ObserveDelta(r)
				flowlog.Sink.Emit(r)
			}
			corr := flow.NewCorrelator(flow.CorrelatorConfig{
				Enabled:    flowCfg.Correlate,
				Window:     flowCfg.CorrelateWindow,
				MaxEntries: flowCfg.CorrelateMaxEntries,
			}, emit)
			flowSink = flow.Tee(collector.Flow, corr)
			collector.Flow.SetCorrelatorStats(corr.Stats)
			collector.Flow.SetFlowLogStats(func() collector.FlowLogStats {
				s := flowlog.Sink.Stats()
				return collector.FlowLogStats{Emitted: s.Emitted, Truncated: s.Truncated, Dropped: s.Dropped}
			})
			flowCtx, cancelFlow := context.WithCancel(context.Background())
			flowDone := make(chan struct{})
			// Flush drains pending entries into the still-live log pipeline, so it MUST run
			// after every NetFlow producer has quiesced and before the pipeline drains.
			stopFlowLog = func() {
				cancelFlow()
				<-flowDone
				corr.Flush()
				// Bridge.Run returns when the pipeline cancels push sources, which happens
				// before AfterSourcesStopped invokes this closure. Keep its callback live
				// through the final flush above, then clear it so any later emission is
				// counted as dropped rather than enqueued after the queue closes.
				flowlog.Sink.Unbind()
			}
			go func() {
				defer close(flowDone)
				t := time.NewTicker(flowExpireTick)
				defer t.Stop()
				for {
					select {
					case <-flowCtx.Done():
						return
					case now := <-t.C:
						corr.Expire(now)
					}
				}
			}()
			logger.Info("flow log emission enabled",
				"mode", flowCfg.LogMode, "correlate", flowCfg.Correlate, "window", flowCfg.CorrelateWindow)
		}
	}
	if !collectorsSwitches.Firewall {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutFirewallCollector())
		logger.Info("firewall collector disabled")
	}
	if collectorsSwitches.FirewallNATCounts {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithFirewallNATCounts())
		logger.Info("firewall NAT rule inventory counts enabled")
	}
	if !collectorsSwitches.FirewallRules {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutFirewallRulesCollector())
		logger.Info("firewall rules collector disabled")
	}
	if !collectorsSwitches.Firmware {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutFirmwareCollector())
		logger.Info("firmware collector disabled")
	}
	if collectorsSwitches.FirmwarePackageDetails {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithFirmwarePackageDetails())
		logger.Info("firmware per-package details enabled")
	}
	if !collectorsSwitches.OpenVPN {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutOpenVPNCollector())
		logger.Info("openvpn collector disabled")
	}
	if !collectorsSwitches.Gateways {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutGatewaysCollector())
		logger.Info("gateways collector disabled")
	}
	if !collectorsSwitches.GatewayGroups {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutGatewayGroupsCollector())
		logger.Info("gateway groups collector disabled")
	}
	if !collectorsSwitches.FirewallMigration {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutFirewallMigrationCollector())
		logger.Info("firewall migration collector disabled")
	}
	if collectorsSwitches.OpenVPNDetails {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithOpenVPNDetails())
		logger.Info("openvpn per-session details enabled")
	}
	if collectorsSwitches.UnboundInfra {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithUnboundInfra())
		logger.Info("unbound per-upstream infra cache metrics enabled")
	}
	if collectorsSwitches.UnboundQStats {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithUnboundQStats())
		logger.Info("unbound DNSBL query-stats totals and blocklist size metrics enabled")
	}
	if !collectorsSwitches.Dnsmasq {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutDnsmasqCollector())
		logger.Info("dnsmasq collector disabled")
	}
	if !collectorsSwitches.System {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutSystemCollector())
		logger.Info("system collector disabled")
	}
	if !collectorsSwitches.Temperature {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutTemperatureCollector())
		logger.Info("temperature collector disabled")
	}
	if !collectorsSwitches.Mbuf {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutMbufCollector())
		logger.Info("mbuf collector disabled")
	}
	if !collectorsSwitches.KernelMemory {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutKernelMemoryCollector())
		logger.Info("kernel memory collector disabled")
	}
	if !collectorsSwitches.NTP {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutNTPCollector())
		logger.Info("ntp collector disabled")
	}
	if !collectorsSwitches.Certificates {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutCertificatesCollector())
		logger.Info("certificates collector disabled")
	}
	if collectorsSwitches.DnsmasqDetails {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithDnsmasqDetails())
		logger.Info("dnsmasq per-lease details enabled")
	}
	if !collectorsSwitches.CARP {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutCARPCollector())
		logger.Info("carp collector disabled")
	}
	if !collectorsSwitches.Activity {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutActivityCollector())
		logger.Info("activity collector disabled")
	}
	if !collectorsSwitches.CPU {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutCPUCollector())
		logger.Info("cpu collector disabled")
	}
	if !collectorsSwitches.Kea {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutKeaCollector())
		logger.Info("kea collector disabled")
	}
	if collectorsSwitches.KeaDetails {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithKeaDetails())
		logger.Info("kea per-lease details enabled")
	}
	if collectorsSwitches.FirewallRulesDetails {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithFirewallRulesDetails())
		logger.Info("firewall rules per-rule details enabled")
	}
	if !collectorsSwitches.NetworkDiagnostics {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutNetworkDiagnosticsCollector())
	} else {
		logger.Info("network diagnostics collector enabled")
	}
	if !collectorsSwitches.NetisrPerCPU {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutNetisrPerCPU())
		logger.Info("netisr per-CPU series disabled")
	}
	if !collectorsSwitches.Netflow {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutNetflowCollector())
	} else {
		logger.Info("netflow collector enabled")
	}
	if !collectorsSwitches.Pftop {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutPftopCollector())
	} else {
		logger.Info("pftop collector enabled")
	}
	if !collectorsSwitches.PFStats {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutPFStatsCollector())
		logger.Info("pf stats collector disabled")
	}
	if !collectorsSwitches.NDP {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutNDPCollector())
		logger.Info("ndp collector disabled")
	}
	if !collectorsSwitches.Dhcpv4 {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutDhcpv4Collector())
		logger.Info("dhcpv4 collector disabled")
	}
	if collectorsSwitches.Dhcpv4Details {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithDhcpv4Details())
		logger.Info("dhcpv4 per-lease details enabled")
	}
	if !collectorsSwitches.ACME {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutACMECollector())
		logger.Info("acme collector disabled")
	}
	if !collectorsSwitches.SMART {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutSMARTCollector())
		logger.Info("smart collector disabled (opt-in via --exporter.enable-smart)")
	}
	if !collectorsSwitches.Tor {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutTorCollector())
		logger.Info("tor collector disabled (opt-in via --exporter.enable-tor)")
	} else {
		logger.Info("tor collector enabled")
	}
	if !collectorsSwitches.DynDNS {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutDynDNSCollector())
		logger.Info("dyndns collector disabled")
	}
	if !collectorsSwitches.Syslog {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutSyslogCollector())
		logger.Info("syslog collector disabled")
	}
	if !collectorsSwitches.QFeeds {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutQFeedsCollector())
		logger.Info("qfeeds collector disabled")
	}
	if !collectorsSwitches.Tailscale {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutTailscaleCollector())
		logger.Info("tailscale collector disabled")
	}
	if collectorsSwitches.TailscalePeerDetails {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithTailscalePeerDetails())
		logger.Info("tailscale per-peer details enabled")
	}
	if !collectorsSwitches.Alias {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutAliasCollector())
		logger.Info("alias collector disabled")
	}
	if collectorsSwitches.AliasDetails {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithAliasDetails())
		logger.Info("alias per-table details enabled")
	}
	if !collectorsSwitches.HAProxy {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutHAProxyCollector())
		logger.Info("haproxy collector disabled")
	}
	if !collectorsSwitches.Nginx {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutNginxCollector())
		logger.Info("nginx collector disabled")
	}
	if !collectorsSwitches.FRR {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutFRRCollector())
		logger.Info("frr collector disabled")
	}
	if collectorsSwitches.FRRRoutes {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithFRRRoutesEnabled())
		logger.Info("frr routing-state volume gauges enabled")
	}
	if !collectorsSwitches.Monit {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutMonitCollector())
		logger.Info("monit collector disabled")
	}
	if !collectorsSwitches.CrowdSec {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutCrowdSecCollector())
		logger.Info("crowdsec collector disabled")
	}
	if !collectorsSwitches.NUT {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutNUTCollector())
		logger.Info("nut collector disabled")
	}
	if !collectorsSwitches.Apcupsd {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutApcupsdCollector())
		logger.Info("apcupsd collector disabled")
	}
	if !collectorsSwitches.CaptivePortal {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutCaptivePortalCollector())
		logger.Info("captiveportal collector disabled")
	}
	if !collectorsSwitches.TrafficShaper {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutTrafficShaperCollector())
		logger.Info("trafficshaper collector disabled")
	}
	if !collectorsSwitches.Hasync {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutHasyncCollector())
		logger.Info("hasync collector disabled (opt-in via --exporter.enable-hasync)")
	}
	if !collectorsSwitches.Chrony {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutChronyCollector())
		logger.Info("chrony collector disabled")
	}
	if !collectorsSwitches.Dhcpv6 {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutDhcpv6Collector())
		logger.Info("dhcpv6 collector disabled")
	}
	if collectorsSwitches.Dhcpv6Details {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithDhcpv6Details())
		logger.Info("dhcpv6 per-lease details enabled")
	}
	if collectorsSwitches.ArpDetails {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithArpDetails())
		logger.Info("arp per-entry details enabled")
	}
	if collectorsSwitches.NdpDetails {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithNdpDetails())
		logger.Info("ndp per-entry details enabled")
	}
	if !collectorsSwitches.BPF {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutBPFCollector())
		logger.Info("bpf collector disabled")
	}
	if !collectorsSwitches.Backup {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutBackupCollector())
		logger.Info("backup collector disabled")
	}
	if !collectorsSwitches.Snapshots {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutSnapshotsCollector())
		logger.Info("snapshots collector disabled")
	}
	if !collectorsSwitches.ClamAV {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutClamAVCollector())
		logger.Info("clamav collector disabled")
	}
	if !collectorsSwitches.IDS {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutIDSCollector())
		logger.Info("ids collector disabled")
	}
	if collectorsSwitches.IDSAlerts {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithIDSAlerts(*options.IDSAlertLookback))
		logger.Info("ids recent-alerts enabled", "lookback", options.IDSAlertLookback.String())
	}
	if !collectorsSwitches.LLDPD {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutLLDPCollector())
		logger.Info("lldpd collector disabled")
	}
	if !collectorsSwitches.Hardware {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutHardwareCollector())
		logger.Info("hardware collector disabled")
	}
	if !collectorsSwitches.Vnstat {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutVnstatCollector())
		logger.Info("vnstat collector disabled (opt-in via --exporter.enable-vnstat)")
	}
	if !collectorsSwitches.Netbird {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutNetbirdCollector())
		logger.Info("netbird collector disabled")
	}
	if collectorsSwitches.NetbirdDetails {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithNetbirdPeerDetails())
		logger.Info("netbird per-peer details enabled")
	}
	if !collectorsSwitches.Beats {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutBeatsCollector())
		logger.Info("beats collector disabled")
	}
	if !collectorsSwitches.Collectd {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutCollectdCollector())
		logger.Info("collectd collector disabled")
	}
	if !collectorsSwitches.MuninNode {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutMuninNodeCollector())
		logger.Info("munin-node collector disabled")
	}
	if !collectorsSwitches.NetSNMP {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutNetSNMPCollector())
		logger.Info("net-snmp collector disabled")
	}
	if !collectorsSwitches.Netdata {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutNetdataCollector())
		logger.Info("netdata collector disabled")
	}
	if !collectorsSwitches.NodeExporter {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutNodeExporterCollector())
		logger.Info("node-exporter collector disabled")
	}
	if !collectorsSwitches.NRPE {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutNRPECollector())
		logger.Info("nrpe collector disabled")
	}
	if !collectorsSwitches.PuppetAgent {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutPuppetAgentCollector())
		logger.Info("puppet-agent collector disabled")
	}
	if !collectorsSwitches.QemuGuestAgent {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutQemuGuestAgentCollector())
		logger.Info("qemu-guest-agent collector disabled")
	}
	if !collectorsSwitches.Telegraf {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutTelegrafCollector())
		logger.Info("telegraf collector disabled")
	}
	if !collectorsSwitches.WazuhAgent {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutWazuhAgentCollector())
		logger.Info("wazuh-agent collector disabled")
	}
	if !collectorsSwitches.ZabbixAgent {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutZabbixAgentCollector())
		logger.Info("zabbix-agent collector disabled")
	}
	if !collectorsSwitches.ZabbixProxy {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutZabbixProxyCollector())
		logger.Info("zabbix-proxy collector disabled")
	}
	if !collectorsSwitches.ZeroTier {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutZeroTierCollector())
		logger.Info("zerotier collector disabled")
	}
	if !collectorsSwitches.Auth {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutAuthCollector())
		logger.Info("auth collector disabled")
	}
	if !collectorsSwitches.HostDiscovery {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutHostDiscoveryCollector())
		logger.Info("hostdiscovery collector disabled")
	}
	if !collectorsSwitches.Relayd {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutRelaydCollector())
		logger.Info("relayd collector disabled")
	}
	if !collectorsSwitches.Siproxd {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutSiproxdCollector())
		logger.Info("siproxd collector disabled")
	}
	if !collectorsSwitches.FeatureAvailability {
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithoutFeatureAvailabilityCollector())
		logger.Info("feature-availability collector disabled")
	}
	// The feature-availability collector's "enabled" and observed-route inputs are
	// wired inside collector.New, from collectorStates and the Collector's own
	// request observer (#525). They used to be a hand-written subsystem-to-switch
	// mapping here that covered three of thirty families.

	// Resolve the instance label deterministically (see #75). The label is baked
	// once into every metric, the OTLP resource identity and Pyroscope tags, so it
	// must not depend on startup timing or the box's momentary reachability — that
	// would split a deployment's series across restarts.
	instanceLabel, err := resolveInstanceLabel(
		*options.InstanceLabel, opnsConfig.Host, *options.InstanceUseHostname,
		func() (string, error) {
			hostname, hErr := opnsenseClient.FetchSystemHostname()
			if hErr != nil {
				return "", hErr
			}
			return hostname, nil
		}, logger)
	if err != nil {
		logger.Error("could not resolve instance label", "err", err)
		os.Exit(1)
	}
	logSelfMetricsRegisterer := logship.SelfMetricsRegisterer(selfMetricsRegistry, instanceLabel)

	// Continuous profiling is opt-in: enabled only when a Pyroscope server
	// address is configured. An invalid configuration is fatal; a transient
	// start failure is logged but non-fatal so the exporter keeps serving
	// metrics. A stopProfiling closure (rather than a *pyroscope.Profiler) keeps
	// the SDK out of main's imports.
	pyroCfg, pyroEnabled := cfg.Pyroscope, cfg.PyroscopeOn
	var stopProfiling func()
	if pyroEnabled {
		profiler, perr := profiling.Start(pyroCfg, instanceLabel, version, logger)
		if perr != nil {
			logger.Error("failed to start pyroscope profiling", "err", perr)
		} else {
			stopProfiling = func() {
				// Flush the final profiling window before stopping — profiler.Stop()
				// alone drops the in-progress heap/alloc/mutex/block window (#121).
				profiling.Stop(profiler, logger)
			}
			logger.Info(
				"pyroscope continuous profiling enabled",
				"server", pyroCfg.ServerAddress,
				"application", pyroCfg.ApplicationName,
				"mutex_block", !pyroCfg.DisableMutexBlock,
				"goroutine_leak", profiling.GoroutineLeakAvailable(),
			)
		}
	}

	// Assemble the OTLP config before building the collector so the OTLP export
	// interval can bound the OTLP-bridge gather path. An invalid configuration is fatal.
	otlpCfg, otlpEnabled := cfg.OTLP, cfg.OTLPOn

	// --exporter.max-scrape-duration is now the per-poll API deadline. The OTLP
	// bridge separately uses the smaller of its export interval and that value to
	// bound snapshot gathering; neither setting is derived from Prometheus.
	collectorOptionFuncs = append(collectorOptionFuncs, collector.WithMaxScrapeDuration(*options.MaxScrapeDuration))
	collectorOptionFuncs = append(collectorOptionFuncs, collector.WithPollInterval(*options.CollectorPollInterval))
	collectorOptionFuncs = append(collectorOptionFuncs, collector.WithHealthPollInterval(*options.CollectorHealthPollInterval))
	// Poll-interval overrides were name-checked and duration-parsed by resolveOptions
	// (#387/#446); an unknown collector name or an unparseable duration never reaches
	// here.
	collectorOptionFuncs = append(collectorOptionFuncs, collector.WithPollIntervalOverrides(cfg.PollOverrides))
	if otlpEnabled {
		// Poll cadence follows the lane that consumes the snapshot (#550). Without
		// this the collector has no idea how often anything reads what it polls, and
		// a push-only deployment polls the firewall four times per exported point.
		collectorOptionFuncs = append(collectorOptionFuncs,
			collector.WithExportLanes(otlpCfg.ExportInterval, otlpCfg.FastExportInterval))

		gatherTimeout := *options.MaxScrapeDuration
		if otlpCfg.ExportInterval > 0 && otlpCfg.ExportInterval < gatherTimeout {
			gatherTimeout = otlpCfg.ExportInterval
		}
		collectorOptionFuncs = append(collectorOptionFuncs, collector.WithOTLPGatherTimeout(gatherTimeout))
	}

	collectorInstance, err := collector.New(&opnsenseClient, logger, instanceLabel, collectorOptionFuncs...)
	if err != nil {
		logger.Error("failed to construct the collector", "err", err)
		os.Exit(1)
	}

	// collectorRegistry holds the default (unfiltered, no-deadline) view of the
	// collector. It is never served over HTTP — /metrics builds a per-request
	// ScrapeView — but the OTLP bridge gathers it on its own export interval.
	collectorRegistry := prometheus.NewRegistry()
	collectorRegistry.MustRegister(collectorInstance)

	// Start the internal poll scheduler (#336): each collector now polls the OPNsense
	// API on its own interval into an in-memory snapshot, decoupled from the Prometheus
	// scrape. /metrics (ScrapeView) and the OTLP bridge both replay that snapshot with
	// no live API call. StopPolling is invoked from gracefulShutdown.
	collectorInstance.StartPolling(context.Background())

	var stopCPUStream func()
	// The CPU stream is the one collector that is fed by a connection rather than a
	// poll (#559). It holds a single long-lived SSE connection to
	// api/diagnostics/cpu_usage/stream and accumulates its 1-second samples into
	// cumulative counters; the cpu collector's Update just copies the accumulator,
	// so the scheduler and the serving path need no special case.
	//
	// The grace window is one export interval: long enough that a reconnect covered
	// by it never gaps the graph, short enough that a real outage withdraws the
	// counters rather than freezing them at a value that reads as an idle CPU.
	if collectorsSwitches.CPU {
		grace := cpustream.DefaultGracePeriod
		if otlpEnabled && otlpCfg.ExportInterval > grace {
			grace = otlpCfg.ExportInterval
		}
		stream := cpustream.New(opnsenseClient.OpenCPUStream, cpustream.Config{
			GracePeriod: grace,
			Logger:      logger,
		})
		collector.CPUStream.Configure(stream.Snapshot)
		stream.Start(context.Background())
		stopCPUStream = stream.Close
		logger.Info("cpu usage stream enabled",
			"endpoint", "api/diagnostics/cpu_usage/stream", "grace_period", grace.String())
	}

	// Annotation writing is opt-in (--annotations.enabled). It diffs the watched
	// instant-valued metrics on the SAME registry the OTLP bridge gathers, so it
	// makes no OPNsense API call of its own: it reads the snapshot the poll
	// scheduler already filled. Each annotation is stamped with the event's own
	// timestamp, so a cold-tier collector noticing fifteen minutes late still
	// places the marker correctly (#421).
	// Cancelled from gracefulShutdown so an in-flight annotation write cannot
	// outlive the process's other subsystems.
	annotationCtx, stopAnnotations := context.WithCancel(context.Background())
	defer stopAnnotations()
	if cfg.AnnotationsOn {
		annotationWatcher := annotations.New(annotations.Config{
			URL:         cfg.Annotations.GrafanaURL,
			Token:       cfg.Annotations.Token,
			Interval:    cfg.Annotations.Interval,
			Timeout:     cfg.Annotations.Timeout,
			Lookback:    cfg.Annotations.Lookback,
			ExtraTags:   cfg.Annotations.ExtraTags,
			Kinds:       cfg.Annotations.Kinds,
			MaxPerCycle: cfg.Annotations.MaxPerCycle,
		}, collectorRegistry, logship.SelfMetricsRegisterer(selfMetricsRegistry, instanceLabel), logger)
		go annotationWatcher.Run(annotationCtx)
		logger.Info("grafana annotation writing enabled",
			"url", cfg.Annotations.GrafanaURL,
			"interval", cfg.Annotations.Interval.String(),
			"lookback", cfg.Annotations.Lookback.String(),
			"kinds", strings.Join(annotationKinds(cfg.Annotations.Kinds), ","))
	}

	// metricsRecorder passively captures the collector family set of each real
	// scrape (the unfiltered /metrics path and the OTLP bridge) so the web UI can
	// read a last-scrape snapshot without ever gathering — and thus re-scraping
	// the firewall — itself.
	metricsRecorder := metricsnap.New()

	// Soft total-series budget (#494): metricsRecorder already sees every real
	// scrape's/OTLP export's family set through the Tee/TeeLane it is about to
	// wrap below, so the check rides along there rather than adding a timer or
	// a Gather() of its own — see metricsnap.SeriesBudget's doc comment.
	// Observed feeds opnsense_exporter_series (collectorInstance's own
	// self-metric) on every real capture, independent of whether a budget is
	// even configured. The same number reaches the console's /cardinality report
	// via webui.Deps.SeriesBudget below.
	metricsRecorder.ConfigureSeriesBudget(metricsnap.SeriesBudget{
		Total:    *options.SeriesBudget,
		Logger:   logger,
		Observed: collectorInstance.SetObservedSeriesTotal,
	})

	// OTLP metrics export is opt-in (--otlp.enabled). It pushes the exact metrics
	// exposed at /metrics to an OTLP endpoint via a Prometheus bridge producer over
	// the same registry, so names, labels and values stay in parity. A transient
	// start/export failure is logged but non-fatal so the exporter keeps serving
	// /metrics. A stopOTLP closure (rather than the MeterProvider) keeps the OTEL SDK
	// out of main's imports beyond Start. (otlpCfg/otlpEnabled were assembled above so
	// the export interval could bound the OTLP-bridge gather.)
	var stopOTLP func()
	if otlpEnabled {
		// The OTLP delivery-health series (#388) — exports_total,
		// consecutive_failures, last_success_timestamp and enabled — are registered
		// through logSelfMetricsRegisterer, NOT bare onto selfMetricsRegistry. They
		// are the only local evidence that push is actually reaching the backend
		// (Start performs no network I/O, so a successful Start proves nothing), and
		// evidence with no instance identity is useless on a multi-firewall stack.
		//
		// This was the raw registry until #466. The family carried no
		// opnsense_instance label, so the four OTLP delivery panels — which filter on
		// it with `=~`, and `=~` never matches an absent label — were structurally
		// guaranteed to render empty for every instance selection.
		//
		// selfMetricsRegistry itself is still the GATHERER below: gathering reads
		// whatever was registered, wrapper or not.
		// Default: one gatherer set, one reader, exactly as before.
		otlpGatherers := []prometheus.Gatherer{selfMetricsRegistry, metricsRecorder.Tee(collectorRegistry)}
		var fastGatherers []prometheus.Gatherer

		// Optional two-lane split (#390). Polling already runs the fast tier at 15s,
		// but OTLP re-exported the WHOLE snapshot on one interval — so buying 15s
		// resolution for gateways/interfaces/pf meant re-sending every cold and medium
		// series four times a minute too. Measured live on the deployment box: 494 of
		// 7,226 series (6.8%) are fast-tier, so 15s-everything is 4.00x the 60s
		// baseline DPM while a 15s fast lane over a 60s base is 1.21x.
		//
		// The two lane views are disjoint by construction: the base lane carries every
		// non-fast collector plus the health/self/always-on block, the fast lane
		// carries fast-tier collectors only. Each is teed into the recorder under its
		// own lane key so the console still sees the UNION and its family/series and
		// cardinality figures stay complete.
		if otlpCfg.FastExportInterval > 0 {
			baseRegistry := prometheus.NewRegistry()
			baseRegistry.MustRegister(collectorInstance.OTLPBaseView())
			fastRegistry := prometheus.NewRegistry()
			fastRegistry.MustRegister(collectorInstance.OTLPFastView())

			otlpGatherers = []prometheus.Gatherer{selfMetricsRegistry, metricsRecorder.TeeLane("otlp-base", baseRegistry)}
			fastGatherers = []prometheus.Gatherer{metricsRecorder.TeeLane("otlp-fast", fastRegistry)}

			logger.Info("otlp fast export lane enabled",
				"fast_interval", otlpCfg.FastExportInterval.String(),
				"base_interval", otlpCfg.ExportInterval.String(),
				"fast_collectors", strings.Join(collectorInstance.FastCollectorNames(), ","),
			)
		}

		shutdown, terr := telemetry.Start(context.Background(), otlpGatherers, otlpCfg, version, instanceLabel, logSelfMetricsRegisterer, logger, fastGatherers...)
		if terr != nil {
			// Fatal, not logged-and-continued (#388). The operator explicitly asked
			// for OTLP; starting anyway would leave a permanently dead push pipeline
			// behind a log line that scrolls away, which is precisely the silent
			// zero-delivery failure this issue exists to end. This is construction
			// failure only — EXPORT failure stays non-fatal and is now counted, so
			// the pull exporter is never taken down by a flaky backend.
			logger.Error("otlp metrics export requested but could not be started", "err", terr)
			os.Exit(1)
		}
		stopOTLP = func() {
			ctx, cancel := context.WithTimeout(context.Background(), otlpShutdownTimeout)
			defer cancel()
			if err := shutdown(ctx); err != nil {
				logger.Error("failed to flush final otlp export", "err", err)
			}
		}
		logger.Info(
			"otlp metrics export enabled (lazy connect: delivery is proven by opnsense_exporter_otlp_* , not by this line)",
			"endpoint", otlpCfg.Endpoint,
			"protocol", otlpCfg.Protocol,
			"interval", otlpCfg.ExportInterval.String(),
		)
	}

	// Log shipping is opt-in (--logs.enabled) and fully independent of OTLP metrics
	// (--otlp.enabled): registered sources poll OPNsense event APIs on a background
	// loop and ship to Loki via OTLP logs (reusing the --otlp.* transport) or stdout.
	// It is long-lived, never a scrape-time collector. An invalid configuration is
	// fatal; a transient sink outage degrades to counted loss (never blocks /metrics).
	logsCfg, logsEnabled := cfg.Logs, cfg.LogsOn
	// Bound the derived log_events label tuples before any receiver can start feeding
	// them (#311/#326/#327). Both receivers are push-based and syslog over UDP has a
	// spoofable source, so these values are sender-controlled: without a budget a
	// sender grows process-lifetime metric state without limit. Applied here rather
	// than at store construction because the store is a package-level singleton that
	// exists before flags are parsed.
	if logsEnabled {
		collector.LogEvents.SetMaxKeys(logsCfg.MaxMetricKeys)
	}
	var stopLogs func()
	// logThroughput feeds the console's emitted-throughput chart. It stays nil unless
	// a log pipeline actually starts: this is a Prometheus PULL exporter, so with log
	// shipping off there is no emit boundary at all, and the console must draw nothing
	// rather than a flat 0/s that would read as "shipping nothing".
	var logThroughput func() (shipped, dropped uint64)
	// Declared before the log pipeline so its shutdown closure can capture it: the
	// NetFlow lane reads the same enrichment snapshot, so it must be stopped BEFORE
	// the refresher that feeds it.
	var stopNetflow func()

	// netflowProc is hoisted out of the receiver block so the operator console can
	// render the resolved ifIndex map. That map was wrong in production for months
	// and nothing in the product ever showed it, which is why the console page is
	// part of the fix rather than a nicety (#361). Nil when the lane is off, which
	// is what makes the console route 404 rather than render an empty table.
	var netflowProc *flow.Processor

	// The NetFlow lane's debug-capture mode (#360). Resolved here rather than at the
	// receiver because whether the shared sink below is built at all depends on it.
	// options.Flow has already rejected an unknown mode, so an error here would be a
	// programming fault — it is still fatal rather than silently off, because an
	// operator who asked for a capture and got none finds out only when they go
	// looking for the samples.
	netflowCaptureMode := cfg.NetflowCapture
	netflowWantsCapture := collectorsSwitches.Flow && flowCfg.Enabled && flowCfg.NetflowEnabled &&
		netflowCaptureMode != netflow.CaptureOff

	// Debug-capture sink (#330, extended to the NetFlow lane by #360): shared across
	// receivers, constructed once when --logs.debug-capture.dir is set. A per-receiver
	// toggle (--logs.<recv>.debug-capture, --flow.netflow.debug-capture) is what
	// actually routes signals into it; a receiver that did not opt in never touches it.
	// A construction failure (unwritable dir) is fatal — the operator asked for capture
	// and must know it is not happening.
	//
	// Built OUTSIDE the log-pipeline block because the NetFlow lane runs even with log
	// shipping off entirely and needs the same sink — but built only when one of the
	// two will actually feed it, since a capturer nobody writes to is a writer
	// goroutine that, with log shipping off, nothing would own closing.
	var debugCapturer *capture.Capturer
	if options.LogsDebugCaptureEnabled() && (logsEnabled || netflowWantsCapture) {
		dc, cerr := capture.New(capture.Config{
			Dir:      options.LogsDebugCaptureDir(),
			MaxBytes: options.LogsDebugCaptureMaxBytes(),
		}, logSelfMetricsRegisterer, logger)
		if cerr != nil {
			logger.Error("invalid debug-capture configuration", "err", cerr)
			os.Exit(1)
		}
		debugCapturer = dc
		logger.Info("debug capture enabled",
			"dir", options.LogsDebugCaptureDir(), "max_bytes", options.LogsDebugCaptureMaxBytes())
	}

	// Log enrichment is shared by the log pipeline and the NetFlow lane, and is built
	// at most ONCE: both want the same snapshot of interface names, local subnets and
	// hostnames, and giving them a refresher each would double the API poll for
	// identical data. Built lazily because the common case wants neither.
	var enrichCache *enrich.Cache
	var enrichRefresher *enrich.Refresher
	var stopEnrich context.CancelFunc
	ensureEnrich := func() *enrich.Cache {
		if enrichCache != nil {
			return enrichCache
		}
		enrichCache = enrich.NewCache()
		enrichRefresher = enrich.NewRefresher(
			&opnsenseClient, enrichCache, enrich.NewMetrics(logSelfMetricsRegisterer), logger).
			WithResultSeam(resultSeam)
		ectx, cancel := context.WithCancel(context.Background())
		stopEnrich = cancel
		go enrichRefresher.Run(ectx)
		logger.Info("api enrichment enabled",
			"lookups", "rule descriptions, interface names, hostnames, MACs, scope, services")
		return enrichCache
	}

	if logsEnabled {
		// The OTLP transport for the logs sink is resolved WITHOUT the --otlp.enabled
		// gate (logs may ship with metrics OTLP off) and is nil unless the sink is otlp.
		logsTransport := cfg.LogsOTLP
		// Log enrichment: a lock-free snapshot of OPNsense API data (firewall rule
		// descriptions, interface names, DHCP hostnames, MACs, local subnets) that the
		// syslog receiver reads per log line. The refresher owns the network I/O on its
		// own goroutine; the receiver never makes an API call on its read path.
		deps := logship.Deps{
			Client:     &opnsenseClient,
			Logger:     logger,
			Registerer: selfMetricsRegistry,
			// Zenarmor is a correlator producer owned by the log pipeline, while
			// NetFlow is external to it. This hook runs only after Zenarmor and every
			// other log source has returned, then quiesces NetFlow and performs the
			// one final correlator flush before the log queue closes.
			AfterSourcesStopped: func() {
				stopFlowProducers(stopNetflow, stopFlowLog)
			},
		}
		// Feed the log_events collector's running totals from the syslog receiver
		// (#258), unless the collector is disabled — in which case the receiver sees a
		// nil sink and skips derivation entirely.
		if collectorsSwitches.LogEvents {
			deps.MetricSink = collector.LogEvents
		}
		// Flow records are derived only when something consumes them: the collector is
		// on, the feature is on, and this lane is selected. A nil sink means the
		// Zenarmor lane skips building records entirely rather than building them for
		// nobody.
		if collectorsSwitches.Flow && flowCfg.Enabled && flowCfg.Zenarmor {
			deps.FlowSink = flowSink
		}
		// The DNS answer cache is wired whenever flow is enabled, independent of the
		// Zenarmor flow lane: the dns family feeds the cache for the NetFlow lane's
		// benefit even when conn-derivation (--flow.zenarmor) is off. nil is a safe no-op.
		if collectorsSwitches.Flow && flowCfg.Enabled {
			deps.FlowDNSCache = flowDNSCache
		}
		// The shared sink is built above, before this block, because the NetFlow lane
		// needs it too and runs with log shipping off. nil when no dir is configured,
		// which every receiver treats as capture-off.
		deps.DebugCapture = debugCapturer
		syslogCfg, syslogEnabled := cfg.Syslog, cfg.SyslogOn
		// Enrichment is shared by every receiver that wants it, so the gate must ask
		// about all of them. It used to ask only about syslog — which meant a
		// zenarmor-only box got a nil Cache, fell back to a cold one, and missed EVERY
		// lookup forever with no error, no log and no metric, while
		// --logs.zenarmor.enrich defaulted to true and said otherwise.
		// LogsZenarmorEnrichWanted() is transport-independent (elasticsearch or
		// syslog), so zenarmor-over-syslog enrichment is already covered here too —
		// no extra branch needed.
		if (syslogEnabled && syslogCfg.Enrich) || options.LogsZenarmorEnrichWanted() {
			deps.Cache = ensureEnrich()
			deps.Miss = enrichRefresher.NoteMiss
		}

		stop, lerr := logship.Start(
			context.Background(), logsCfg, logsTransport,
			deps,
			version, instanceLabel, selfMetricsRegistry,
			selfLogHandler,
		)
		if lerr != nil {
			if stopEnrich != nil {
				stopEnrich()
			}
			logger.Error("failed to start log shipping", "err", lerr)
			os.Exit(1)
		}
		logThroughput = logship.Throughput
		stopLogs = func() {
			ctx, cancel := context.WithTimeout(context.Background(), logsShutdownTimeout)
			defer cancel()
			if err := stop(ctx); err != nil {
				logger.Error("failed to flush log pipeline on shutdown", "err", err)
			}
			// Stop the enrichment refresher only after the pipeline has drained: records
			// still in flight are enriched from the snapshot, and a refresher torn down
			// first would strand them. The NetFlow lane was quiesced before the flow-log
			// flush above, so it is safe to stop the refresher now.
			if stopEnrich != nil {
				stopEnrich()
			}
			// Flush and stop the debug-capture writer last: it is fed from the receiver
			// goroutines the pipeline drain has just quiesced, so closing it now cannot
			// drop an in-flight capture.
			if debugCapturer != nil {
				_ = debugCapturer.Close()
			}
		}
	}

	// NetFlow receiver (#346 phase 2). Opt-in, and bound EAGERLY so a port already in
	// use is a startup error rather than a receiver that is silently never there.
	//
	// It shares the enrichment snapshot with the log pipeline but does not depend on
	// it: with log shipping off entirely this still runs, which is the "works
	// standalone with Zenarmor absent" requirement.
	if collectorsSwitches.Flow && flowCfg.Enabled && flowCfg.NetflowEnabled {
		cache := ensureEnrich()
		repairer := flow.NewRepairer(flowDedupeEntries, flowHoldEntries)
		proc := flow.NewProcessor(flowSink, repairer, cache)
		netflowProc = proc
		// Read dst.domain from the same answer cache the Zenarmor dns family fills (#353),
		// so a bare NetFlow flow to an IP recovers the domain a client looked up.
		proc.SetDNSCache(flowDNSCache)
		decoder := netflow.New()

		// Debug capture (#360). Resolved above, alongside the shared sink it writes to.
		var captureSink netflow.CaptureSink
		if netflowWantsCapture && debugCapturer != nil {
			captureSink = debugCapturer.For(capture.ReceiverNetflow)
			logger.Warn("netflow debug capture enabled; RAW datagrams are being written to disk",
				"mode", netflowCaptureMode.String(),
				"dir", options.LogsDebugCaptureDir(),
				"max_bytes", options.LogsDebugCaptureMaxBytes())
		}

		listener := netflow.NewListener(netflow.ListenerConfig{
			Addr:             flowCfg.NetflowListen,
			UDPReceiveBuffer: flowCfg.NetflowUDPReceiveBuffer,
			AllowedPeers:     flowCfg.NetflowAllowedPeers,
			Workers:          netflowCfg.Workers,
			QueueSize:        netflowCfg.QueueSize,
			Capture:          captureSink,
			CaptureMode:      netflowCaptureMode,
		}, decoder, func(dg *netflow.Datagram, _ netip.Addr) {
			proc.ObserveDatagram(dg, time.Now())
		}, logger)
		if lerr := listener.Start(); lerr != nil {
			logger.Error("failed to start netflow receiver", "err", lerr)
			os.Exit(1)
		}
		listenerDone := make(chan struct{})
		go func() {
			defer close(listenerDone)
			listener.Serve()
		}()

		// Rebuild the ifIndex map on a ticker. ng_netflow numbers interfaces
		// POSITIONALLY over ifinfo output, so adding or removing any interface
		// renumbers every index and silently remaps historical series; a map that
		// stops refreshing is a correctness problem, not a staleness nuisance.
		//
		// The ENUMERATION comes from snap.IfaceOrder and nothing else. An empty one
		// means the fetch has never succeeded, and a map built from it would resolve
		// nothing — so the previous map is kept and ifindex_map_age_seconds is left
		// to rise. There is deliberately no fallback to counting snap.Ifaces: that
		// derivation is the bug (#361), and a wrong label is worse than a missing one.
		nfCtx, cancelNetflow := context.WithCancel(context.Background())
		go func() {
			// Until the first map is published, retry FAST. The enrichment refresher
			// fetches the enumeration on its own schedule, and the first tick here
			// fires before that has completed — so settling straight into the 60s
			// interval left up to a minute in which every record was unlabellable.
			// On a busy WAN that is gigabytes into the empty-label bucket on every
			// restart (#365).
			ticker := time.NewTicker(ifIndexColdRetryInterval)
			defer ticker.Stop()
			var published bool
			var lastUnmapped uint64
			// The deadline runs from the FIRST map built, not from startup: an
			// enumeration that itself took minutes to arrive would otherwise blow
			// straight through it and latch on the nameless map it produced.
			var firstBuild time.Time
			for {
				if snap := cache.Load(); snap != nil && len(snap.IfaceOrder) > 0 {
					m := flow.BuildIfMap(flow.IfMapInput{
						Order:    snap.IfaceOrder,
						Ifaces:   snap.Ifaces,
						Stated:   snap.IfaceStatedIndex,
						Override: flowCfg.NetflowIfIndexMap,
						Built:    time.Now(),
					})
					proc.SetIfMap(m)
					if firstBuild.IsZero() {
						firstBuild = time.Now()
					}
					// Publishing the map and CALLING IT FINAL are two different
					// things. The map above is always published — a device label
					// beats no label, and withholding it would leave records
					// unlabelled — but a map with no names is provisional, and
					// dropping to the 60s cadence on one freezes that degraded
					// labelling in for a full minute (#522).
					if named := m.Stats().Named; !published && ifIndexSettled(named, time.Since(firstBuild)) {
						if named == 0 {
							logger.Warn("netflow ifIndex map has no interface names; "+
								"labelling flow records by device from here",
								"deadline", ifIndexNamelessDeadline,
								"entries", m.Stats().Entries,
								"hint", "the firewall reports no interface descriptions, or the interface metadata fetch is failing")
						}
						published = true
						ticker.Reset(ifIndexRefreshInterval)
					}
				}
				// An ifIndex the map could not resolve is direct evidence the
				// enumeration moved, and is worth re-reading well before the hourly
				// tick. It is sampled HERE, once per rebuild, rather than signalled
				// from the lookup itself: the NetFlow socket is unauthenticated, and
				// a hook on the per-record path would let anything that can reach
				// port 2055 drive both our CPU and the firewall's API load. The
				// refresher rate-limits it again on its own side.
				if m := proc.IfMap(); m != nil && enrichRefresher != nil {
					if now := m.Stats().UnmappedLookups; now > lastUnmapped {
						lastUnmapped = now
						enrichRefresher.NoteIfIndexUnresolved()
					}
				}
				select {
				case <-nfCtx.Done():
					return
				case <-ticker.C:
				}
			}
		}()

		// Refresh the pf state snapshot on the cold tier (#603). ng_netflow's
		// OUTPUT_SNMP is a FIB lookup while OPNsense's multi-WAN policy routing
		// happens in pf, so the PRE-NAT copy of a policy-routed flow — the only copy
		// that can correlate with Zenarmor — names the default-route WAN whatever pf
		// actually did. pf's own state table carries the decision verbatim.
		//
		// A failed fetch leaves the PREVIOUS table published rather than clearing it:
		// a stale routing picture is bounded by pf's own state lifetimes and still
		// beats no picture at all, and pf_state_age_seconds is what makes the
		// staleness visible. The first fetch runs immediately so the repair is live
		// well inside the first tick.
		go func() {
			// The table this goroutine last published, so the next build can union
			// the still-valid part of it forward (#620). Held as a plain local
			// rather than read back off the Repairer because this goroutine is the
			// only writer, so there is no state to share and nothing to lock.
			var previous *flow.RouteTable
			// The NAT index is built from the SAME rows on the same poll, with the
			// same retention, so the two tables can never describe different
			// instants (#623).
			var previousNAT *flow.NATTable
			refresh := func() {
				states, ferr := opnsenseClient.FetchFirewallStates()
				if ferr != nil {
					logger.Warn("pf state fetch failed; policy-route repair is resolving against the previous snapshot",
						"err", ferr.Error())
					return
				}
				rows := make([]flow.StateRow, 0, len(states.States))
				for _, st := range states.States {
					rows = append(rows, flow.StateRow{
						Proto:         st.Proto,
						Direction:     st.Direction,
						SrcAddr:       st.SrcAddr,
						SrcPort:       st.SrcPort,
						DstAddr:       st.DstAddr,
						DstPort:       st.DstPort,
						RouteToDevice: st.RouteToDevice,
						NatAddr:       st.NatAddr,
						NatPort:       st.NatPort,
					})
				}
				built := time.Now()
				table := flow.BuildRouteTable(flow.RouteTableInput{
					Rows:     rows,
					Built:    built,
					Previous: previous,
					Retain:   pfStateRetention,
				})
				previous = table
				repairer.SetRouteTable(table)

				nats := flow.BuildNATTable(flow.NATTableInput{
					Rows:     rows,
					Built:    built,
					Previous: previousNAT,
					Retain:   pfStateRetention,
				})
				previousNAT = nats
				repairer.SetNATTable(nats)
			}
			refresh()
			ticker := time.NewTicker(pfStateRefreshInterval)
			defer ticker.Stop()
			for {
				select {
				case <-nfCtx.Done():
					return
				case <-ticker.C:
					refresh()
				}
			}
		}()

		// Release the VLAN hold buffer on a ticker. ObserveDatagram already drains what
		// is due on every datagram, so this covers only the lane that has gone quiet —
		// and the shutdown Flush covers the records still parked when it does.
		netflowReleaseDone := make(chan struct{})
		go func() {
			defer close(netflowReleaseDone)
			ticker := time.NewTicker(flowHoldReleaseInterval)
			defer ticker.Stop()
			for {
				select {
				case <-nfCtx.Done():
					return
				case <-ticker.C:
					proc.ReleaseDue(time.Now())
				}
			}
		}()

		collector.Flow.SetNetflowStats(func() collector.NetflowStats {
			var mapStats flow.IfMapStats
			var age time.Duration
			var entries []flow.IfaceEntry
			if m := proc.IfMap(); m != nil {
				mapStats = m.Stats()
				age = m.Age(time.Now())
				// Entries allocates and sorts, so it is a render path, never a
				// lookup path. This closure runs once per poll of the flow
				// collector over ~17 interfaces, which is that, not a hot path.
				entries = m.Entries()
			}
			return collector.NetflowStats{
				Listener:     listener.Stats(),
				Decoder:      decoder.Stats(),
				Pipeline:     proc.Stats(),
				Repair:       repairer.Stats(),
				IfMap:        mapStats,
				IfMapAge:     age,
				IfMapEntries: entries,
			}
		})

		stopNetflow = func() {
			cancelNetflow()
			_ = listener.Close()
			// Serve closes its work queue and waits for every decoder worker after the
			// socket closes. The release ticker can also emit held records, so wait for
			// it before the final processor flush; otherwise either producer could add
			// a correlator entry after its one final flush.
			<-listenerDone
			<-netflowReleaseDone
			// Flush synchronously after all NetFlow producers have stopped, so records
			// still parked in the hold buffer are reported rather than abandoned.
			proc.Flush(time.Now())
		}
		// An empty allowlist is legitimate but it is a decision, not a default to
		// drift into: NetFlow has no authentication, so anything that can reach this
		// port can inject flow records and move every number on the dashboard.
		if len(flowCfg.NetflowAllowedPeers) == 0 {
			logger.Warn("netflow receiver accepts records from ANY peer",
				"addr", listener.Addr(),
				"fix", "restrict with --flow.netflow.allowed-peers or firewall the port")
		}
		logger.Info("netflow receiver listening",
			"addr", listener.Addr(), "allowed_peers", len(flowCfg.NetflowAllowedPeers))
	}

	// With log shipping off, the NetFlow lane owns the enrichment refresher's
	// lifetime, so it borrows the pipeline's shutdown slot rather than leaking both.
	// stopFlowLog rides along here too: with no log pipeline its flushed records have
	// nowhere to go (and are counted as dropped), but the expiry ticker still needs
	// cancelling so it does not leak.
	if stopNetflow != nil && stopLogs == nil {
		stopLogs = func() {
			stopFlowProducers(stopNetflow, stopFlowLog)
			if stopEnrich != nil {
				stopEnrich()
			}
			// Same ordering rule as the log-pipeline path: the capture writer is fed
			// from the receiver goroutines, so it closes only once they are quiesced.
			if debugCapturer != nil {
				_ = debugCapturer.Close()
			}
		}
	} else if stopFlowLog != nil && stopLogs == nil {
		// Flow-log lane on but neither the log pipeline nor the NetFlow receiver exists
		// to own shutdown: take the slot so the ticker is cancelled cleanly.
		stopLogs = stopFlowLog
	}

	// Register on a private mux rather than http.DefaultServeMux: all exporter-owned
	// routes are then explicit and self-contained, so a future fixed route can't collide
	// with the global mux via some other package's init, and the collision surface stays
	// exactly the reserved set resolveOptions validated --web.telemetry-path against
	// (net/http.ServeMux panics on an empty, non-"/"-prefixed or duplicate pattern).
	mux := http.NewServeMux()

	metricsHandler := server.NewMetricsHandler(
		collectorInstance,
		selfMetricsRegistry,
		logger,
		metricsRecorder,
		// The handler's own request/duration/rejection/gather-error metrics
		// (#426) reuse the same instance-stamping wrapper as logship and the
		// annotation writer, rather than registering bare onto
		// selfMetricsRegistry — that bare path is exactly how the
		// opnsense_exporter_otlp_* family ended up with no opnsense_instance
		// label at all (#466). logShip's SelfMetricsRegisterer is a generic
		// "wrap with instance identity" helper despite its package name; it is
		// already reused this way for the non-logship annotation writer above.
		logSelfMetricsRegisterer,
	)
	mux.Handle(*options.MetricsPath, metricsHandler)

	mux.Handle(server.HealthyPath, server.Healthy())
	mux.Handle(server.ReadyPath, server.NewReady(func(ctx context.Context) error {
		if _, err := opnsenseClient.WithContext(ctx).HealthCheck(); err != nil {
			return err
		}
		// Reachable is not the same as serving a complete snapshot: since #336 the
		// scrape replays whatever the poll scheduler has filled in, so a just-started
		// exporter answers /metrics with only the collectors that have polled so far.
		// Readiness holds until every collector has had its first poll (#341).
		if !collectorInstance.SnapshotWarm() {
			return errSnapshotWarming
		}
		return nil
	}, readyCacheTTL, logger))

	// The console (like the stock landing page) can only own "/" when the metrics
	// path is not itself "/", else mux.Handle("/", …) double-registers and panics.
	if *options.MetricsPath != "/" && *options.MetricsPath != "" {
		if *options.WebUIEnabled {
			webSrv := webui.NewServer(webui.Deps{
				Version:       version,
				GoVersion:     runtime.Version(),
				Host:          opnsConfig.Host,
				InstanceLabel: instanceLabel,
				StartTime:     startTime,
				Tracker:       statusTracker,
				Capture:       metricsRecorder.Capture,
				SeriesBudget:  *options.SeriesBudget,
				// Passive upstream health (#384). Without this the console's badge is
				// derived from collector run history alone, which is silent during
				// exactly the outage it most needs to report: an unreachable box makes
				// the scheduler SKIP collector polls, so no failed run is ever recorded
				// and the last successes keep the badge green while opnsense_up is 0.
				Health:          collectorInstance.HealthSnapshot,
				Cache:           opnsenseClient.CacheSnapshot,
				EffectiveConfig: options.EffectiveConfig,
				Devices: func(ctx context.Context) (webui.DeviceReport, error) {
					return webui.FetchDevices(ctx, &opnsenseClient)
				},
				IfIndexMap:        ifIndexReportFunc(netflowProc),
				LogThroughput:     logThroughput,
				AllCollectorNames: collectorNames(),
				RefreshSeconds:    int((*options.WebUIRefreshInterval).Seconds()),
				DisableConfig:     *options.WebUIDisableConfig,
				DisableDevices:    *options.WebUIDisableDevices,
			})
			webSrv.StartBackground()
			defer webSrv.Close()
			mux.Handle("/", webSrv.Handler())
		} else {
			landingConfig := web.LandingConfig{
				Name:        "opnsense2otel",
				Description: "Prometheus OPNsense Firewall Exporter",
				Version:     version,
				Links: []web.LandingLinks{
					{Address: *options.MetricsPath, Text: "Metrics"},
					{Address: server.HealthyPath, Text: "Healthy"},
					{Address: server.ReadyPath, Text: "Ready"},
				},
			}
			landingPage, err := web.NewLandingPage(landingConfig)
			if err != nil {
				logger.Error("failed to construct landing page", "err", err)
				os.Exit(1)
			}
			mux.Handle("/", landingPage)
		}
	}

	term := make(chan os.Signal, 1)
	srvClose := make(chan struct{})
	signal.Notify(term, os.Interrupt, syscall.SIGTERM)

	// ReadHeaderTimeout protects the metrics port against Slowloris-style
	// connection exhaustion; IdleTimeout reaps abandoned keep-alive connections.
	// WriteTimeout stays unset so large scrape responses are never cut short.
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	go func() {
		// srv.Shutdown makes ListenAndServe return http.ErrServerClosed — that's the
		// normal graceful-exit path, not an error, so don't treat it as a crash.
		if err := web.ListenAndServe(srv, options.WebConfig, logger); err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("Error received from the HTTP server", "err", err)
			close(srvClose)
		}
	}()

	for {
		select {
		case sig := <-term:
			gracefulShutdown(srv, sig, collectorInstance.StopPolling, stopCPUStream, stopLogs, stopOTLP,
				stopProfiling, stopAnnotations, logger)
			return
		case <-srvClose:
			os.Exit(1)
		}
	}
}

// stopFlowProducers owns the shutdown boundary between the external NetFlow
// receiver and the correlator. With log shipping enabled it is invoked by the
// pipeline only after its own push sources (including Zenarmor) have stopped and
// while its output queue is still live. The standalone path calls it directly.
func stopFlowProducers(stopNetflow, stopFlowLog func()) {
	if stopNetflow != nil {
		stopNetflow()
	}
	if stopFlowLog != nil {
		stopFlowLog()
	}
}

// gracefulShutdown drains in-flight scrapes with a bounded deadline before flushing
// telemetry and returning, so a scrape landing mid-response during a rollout/redeploy
// finishes instead of being severed (which Prometheus records as up=0). The log line
// reports the actual signal received rather than a hardcoded "SIGTERM" (#161).
func gracefulShutdown(srv *http.Server, sig os.Signal, stopPolling, stopCPUStream, stopLogs, stopOTLP, stopProfiling, stopAnnotations func(), logger *slog.Logger) {
	logger.Info("received signal, shutting down gracefully", "signal", sig.String())
	ctx, cancel := context.WithTimeout(context.Background(), httpShutdownTimeout)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		logger.Error("graceful HTTP shutdown failed; in-flight scrapes may have been cut", "err", err)
	}
	// Order: drain HTTP -> stop the poll scheduler and the CPU stream (no new firewall
	// API calls, and the held php-cgi worker released) -> stop log pollers + flush the
	// sink -> flush OTLP metrics -> flush profiling. Logs drain before OTLP metrics so
	// a final scrape's data and the last log batch both leave before the process exits.
	if stopPolling != nil {
		stopPolling()
	}
	if stopCPUStream != nil {
		stopCPUStream()
	}
	if stopLogs != nil {
		stopLogs()
	}
	if stopOTLP != nil {
		stopOTLP()
	}
	if stopProfiling != nil {
		stopProfiling()
	}
	if stopAnnotations != nil {
		stopAnnotations()
	}
}

// ifIndexReportFunc adapts the NetFlow processor's ifIndex map to the operator
// console's view of it, or returns nil when the lane is off so the console route
// 404s instead of rendering an empty table as though the map were empty.
//
// The two types are deliberately separate: internal/webui must not import
// internal/flow, because a console handler that can reach the pipeline is one
// refactor away from a console handler that can scrape the firewall.
func ifIndexReportFunc(proc *flow.Processor) func() webui.IfIndexReport {
	if proc == nil {
		return nil
	}
	return func() webui.IfIndexReport {
		m := proc.IfMap()
		stats := m.Stats()
		entries := m.Entries()
		rows := make([]webui.IfIndexRow, 0, len(entries))
		for _, e := range entries {
			source := "derived"
			if e.Overridden {
				source = "override"
			}
			rows = append(rows, webui.IfIndexRow{
				Index:     e.Index,
				Device:    e.Device,
				Name:      e.Name,
				Source:    source,
				Stated:    e.Stated,
				Disagrees: e.Disagrees,
			})
		}
		return webui.IfIndexReport{
			Rows:       rows,
			Built:      m.BuiltAt(),
			Entries:    stats.Entries,
			Overridden: stats.Overridden,
			Conflicts:  stats.Conflicts,
			// Both guards land in one number on the page; the metric carries the
			// breakdown by reason for anything that needs to tell them apart.
			Disagreements: stats.StatedIndexDisagreements + stats.UnlistedDevices,
			Unmapped:      stats.UnmappedLookups,
		}
	}
}
