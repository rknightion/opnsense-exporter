package collector

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/internal/options"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// FeatureAvailabilitySubsystem is declared in collector.go (see its comment
// there for why it must live in that file's const block).

// maxAvailabilityProbeConcurrency bounds in-flight availability probes (#517
// decision D). Only three probes exist today, well under the cap - it exists
// so a future addition to featureAvailabilityProbes cannot fan out an
// unbounded burst against the firewall.
const maxAvailabilityProbeConcurrency = 4

// AvailabilityProbe is one PLUGIN-GATED collector family and the endpoint that
// answers whether its plugin is installed.
//
// It carries no flag, env var or reason of its own: those live in
// options.CollectorFlags and are looked up by subsystem when the report is
// logged. Copying them here would be two spellings of one fact, and the one
// that drifts is the one an operator reads.
type AvailabilityProbe struct {
	// Feature is the collector subsystem name, used verbatim as the "feature"
	// label so it joins to opnsense_exporter_collector_enabled{collector=...}.
	Feature string
	// Endpoint is the endpoint NAME to probe, resolved through
	// Client.ProbeEndpoint. Must be a cheap route that does not fan out per item.
	Endpoint opnsense.EndpointName
}

// featureAvailabilityProbes maps every PLUGIN-GATED collector family to the one
// cheap endpoint that answers "is this plugin installed".
//
// It is data on purpose (#525). The first cut of this carried a closure per
// feature calling a bespoke Fetch*Available wrapper, which was fine for three
// features and would have been thirty near-identical wrappers here — thirty
// places for the next plugin to be forgotten. Client.ProbeEndpoint is generic,
// so an entry is a row.
//
// Choosing the endpoint, in order of preference: a service-status or list route
// that returns a small fixed payload. NEVER one that fans out per item — probing
// SMART must not run smartctl against every disk, which is the very cost its
// opt-in flag exists to avoid. The probe's method comes from postEndpoints, so a
// POST-only route (smartList) needs nothing said here.
//
// Absent from this table, deliberately: every collector gated on API COST or
// CARDINALITY rather than on a plugin (network diagnostics, netflow, hasync, the
// *-details flags). There is no plugin to detect, so a probe has nothing to
// discover about them and they must not be reported as "unavailable" — they are
// available and merely expensive. TestEveryPluginGatedFamilyIsProbed enforces
// the other direction.
var featureAvailabilityProbes = []AvailabilityProbe{
	{Feature: ACMESubsystem, Endpoint: "acmeCertificates"},
	{Feature: ApcupsdSubsystem, Endpoint: "apcupsdServiceStatus"},
	{Feature: BPFSubsystem, Endpoint: "bpfStatistics"},
	{Feature: CaptivePortalSubsystem, Endpoint: "captivePortalZones"},
	{Feature: ChronySubsystem, Endpoint: "chronyServiceStatus"},
	{Feature: ClamAVSubsystem, Endpoint: "clamavVersion"},
	{Feature: CrowdSecSubsystem, Endpoint: "crowdsecServiceStatus"},
	{Feature: Dhcpv4Subsystem, Endpoint: "dhcpv4"},
	{Feature: Dhcpv6Subsystem, Endpoint: "dhcpv6Leases"},
	{Feature: DnsmasqSubsystem, Endpoint: "dnsmasqServiceStatus"},
	{Feature: DynDNSSubsystem, Endpoint: "dyndnsServiceStatus"},
	{Feature: FRRSubsystem, Endpoint: "quaggaServiceStatus"},
	{Feature: HAProxySubsystem, Endpoint: "haproxyServiceStatus"},
	{Feature: HardwareSubsystem, Endpoint: "dmidecodeInfo"},
	{Feature: IPsecSubsystem, Endpoint: "ipsecServiceStatus"},
	{Feature: KeaSubsystem, Endpoint: "keaServiceStatus"},
	{Feature: LLDPSubsystem, Endpoint: "lldpdNeighbors"},
	{Feature: MonitSubsystem, Endpoint: "monitServiceStatus"},
	{Feature: NUTSubsystem, Endpoint: "nutServiceStatus"},
	{Feature: NetbirdSubsystem, Endpoint: "netbirdServiceStatus"},
	{Feature: NginxSubsystem, Endpoint: "nginxServiceStatus"},
	{Feature: QFeedsSubsystem, Endpoint: "qfeedsStats"},
	{Feature: SMARTSubsystem, Endpoint: "smartList"},
	{Feature: SyslogSubsystem, Endpoint: "syslogServiceStatus"},
	{Feature: TailscaleSubsystem, Endpoint: "tailscaleServiceStatus"},
	{Feature: TorSubsystem, Endpoint: "torCircuits"},
	{Feature: TrafficShaperSubsystem, Endpoint: "trafficShaperStatistics"},
	{Feature: UnboundDNSSubsystem, Endpoint: "unboundServiceStatus"},
	{Feature: VnstatSubsystem, Endpoint: "vnstatInterfaceList"},
	{Feature: WireguardSubsystem, Endpoint: "wireguardServiceStatus"},
}

// FeatureEnabledFunc reports whether the collector switch for a probed
// feature (an AvailabilityProbe.Feature value) is currently turned on. main
// wires this from the resolved CollectorsDisableSwitch before StartPolling,
// mirroring the LogEvents/Flow out-of-band injection seam: Update's
// CollectorInstance signature carries no switches, so the enabled label needs
// a side channel.
type FeatureEnabledFunc func(feature string) bool

// RouteObservedFunc reports whether the client's own traffic has already
// established that an endpoint's route exists, and whether it knows at all.
//
// This is what makes "probe only what nothing else is asking about" possible: an
// enabled collector hits its gating endpoint every poll, and the request and
// cache observers already see the status code (a replayed 404 included). Asking
// them is free; probing the same route again is not.
type RouteObservedFunc func(endpoint opnsense.EndpointName) (exists bool, known bool)

// SetRouteObserved wires the observed-route lookup into the availability
// collector. Same out-of-band seam as SetFeatureEnabled, for the same reason.
func SetRouteObserved(fn RouteObservedFunc) {
	for _, inst := range collectorInstances {
		if ac, ok := inst.(*availabilityCollector); ok {
			ac.mu.Lock()
			ac.observedFn = fn
			ac.mu.Unlock()
		}
	}
}

type availabilityCollector struct {
	// subsystem mirrors every other CollectorInstance's convention (see
	// smart.go, tor.go): scripts/docgen's AST parser locates a collector's
	// subsystem by finding this exact `subsystem: XxxSubsystem` field in its
	// init() struct literal, so Name() must read it from here rather than
	// returning the constant directly.
	subsystem string
	log       *slog.Logger
	instance  string

	available *prometheus.Desc

	mu        sync.Mutex
	enabledFn FeatureEnabledFunc
	// observedFn answers "did the collectors' own traffic already establish
	// whether this route exists", so an enabled collector's endpoint is not
	// probed a second time. nil until wired.
	observedFn RouteObservedFunc
	// lastResults is nil until the first probe completes, then holds every
	// probed feature's most recent availability. nil (rather than an empty
	// map) is what makes the very first probe unconditionally "changed" for
	// the log-once-on-change rule (#517 decision E).
	lastResults map[string]bool
}

func init() {
	collectorInstances = append(collectorInstances, &availabilityCollector{
		subsystem: FeatureAvailabilitySubsystem,
		enabledFn: func(string) bool { return false },
	})
}

// SetFeatureEnabled wires the feature-availability collector to the resolved
// collector switches so its "enabled" label reflects the real configuration.
// main calls it once, after resolving CollectorsDisableSwitch and before
// StartPolling; a probe emitted before this call reports enabled="false" for
// everything; not wired at all, the exact pre-#517 information gap.
func SetFeatureEnabled(fn FeatureEnabledFunc) {
	if fn == nil {
		return
	}
	for _, inst := range collectorInstances {
		if ac, ok := inst.(*availabilityCollector); ok {
			ac.mu.Lock()
			ac.enabledFn = fn
			ac.mu.Unlock()
		}
	}
}

func (c *availabilityCollector) Name() string { return c.subsystem }

// PollInterval reuses the existing cold tier (15m) rather than adding a new
// tunable (#517 decision D). Declaring it here (IntervalCollector) rather than
// via the collectorTiers table keeps this collector's cadence next to the
// probes it governs.
func (c *availabilityCollector) PollInterval() time.Duration { return IntervalCold }

func (c *availabilityCollector) Register(_, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.available = buildPrometheusDesc(FeatureAvailabilitySubsystem, "available",
		"Whether a plugin-gated OPNsense feature is installed on this firewall: 1 if its API "+
			"endpoint answered, 0 if it returned 404 (the plugin is absent). The series is present "+
			"for every plugin-gated collector family, so a 0 means 'this box does not have it' and "+
			"ABSENCE means only that availability has never been determined - an unreachable "+
			"firewall leaves the previous verdict in place rather than reporting everything as gone. "+
			"enabled reflects whether that collector is currently switched on, so available=1 with "+
			"enabled=\"false\" is the actionable state: a plugin you have but are not scraping, "+
			"whether it is an opt-in collector or a default-on one you disabled. Refreshed on the "+
			"cold poll tier (15m) independent of --exporter.cache-ttl, and a collector that is "+
			"already enabled is not re-probed - its own polling answers the same question (#517, #525).",
		[]string{"feature", "enabled"},
	)
}

func (c *availabilityCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.available
}

// Update refreshes availability for every plugin-gated family and emits the
// gauge, logging the availability report only when the set has CHANGED.
//
// Two things it deliberately does not do:
//
//   - It does not probe a family whose collector is enabled and whose route has
//     already been observed. That collector calls the same endpoint every poll,
//     so a probe would be duplicate load on the firewall for a question its own
//     polling already answered (#525). What is left to probe is precisely what
//     nothing else is asking about.
//   - It does not turn an unanswerable probe into "absent". A firewall that is
//     briefly unreachable would otherwise read as every plugin having been
//     uninstalled at once, which would fire an alert and, through
//     --exporter.enable-all-available, could shrink the exporter on the next
//     restart. The previous verdict is carried forward instead.
func (c *availabilityCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	c.mu.Lock()
	enabledFn, observedFn, previous := c.enabledFn, c.observedFn, c.lastResults
	c.mu.Unlock()

	results := make(map[string]bool, len(featureAvailabilityProbes))
	var resultsMu sync.Mutex
	probeClient := client.WithContext(ctx).WithoutCache()

	sem := make(chan struct{}, maxAvailabilityProbeConcurrency)
	var wg sync.WaitGroup
	for _, probe := range featureAvailabilityProbes {
		// Already answered by the collector's own traffic: record and move on.
		// Under resultsMu like every other write: probe goroutines spawned by
		// earlier iterations are already writing this map concurrently, so an
		// unguarded write here races them (#532).
		if enabledFn(probe.Feature) && observedFn != nil {
			if exists, known := observedFn(probe.Endpoint); known {
				resultsMu.Lock()
				results[probe.Feature] = exists
				resultsMu.Unlock()
				continue
			}
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(probe AvailabilityProbe) {
			defer wg.Done()
			defer func() { <-sem }()
			available, err := probeClient.ProbeEndpoint(probe.Endpoint)
			resultsMu.Lock()
			defer resultsMu.Unlock()
			if err != nil {
				// Unanswerable, not absent. Carry the previous verdict; drop the
				// family entirely if there has never been one, so the metric says
				// nothing rather than guessing.
				if prev, ok := previous[probe.Feature]; ok {
					results[probe.Feature] = prev
				}
				return
			}
			results[probe.Feature] = available
		}(probe)
	}
	wg.Wait()

	c.mu.Lock()
	changed := c.lastResults == nil
	if !changed {
		changed = len(results) != len(c.lastResults)
	}
	if !changed {
		for feature, available := range results {
			if prev, ok := c.lastResults[feature]; !ok || prev != available {
				changed = true
				break
			}
		}
	}
	c.lastResults = results
	c.mu.Unlock()

	// 0 as well as 1, for every family with a verdict (#525 decision 2): a panel
	// can then show the plugins this box does NOT have, and a plugin vanishing is
	// alertable. Absence now means only "never determined".
	for _, probe := range featureAvailabilityProbes {
		available, ok := results[probe.Feature]
		if !ok {
			continue
		}
		enabledLabel := "false"
		if enabledFn(probe.Feature) {
			enabledLabel = "true"
		}
		ch <- prometheus.MustNewConstMetric(c.available, prometheus.GaugeValue,
			boolToGauge(available), probe.Feature, enabledLabel, c.instance)
	}

	if changed {
		c.logAvailabilityReport(results, enabledFn)
	}

	return nil
}

// logAvailabilityReport names every plugin that is installed but whose collector
// is switched off — #517's primary ask, widened by #525 to include a DEFAULT-ON
// collector somebody disabled. That case is the one most likely to be a genuine
// mistake (a --exporter.disable-* set once and forgotten) and nothing reported it
// before.
//
// The flag, env var and reason are read from options.CollectorFlags rather than
// stored on the probe, so there is exactly one place each is authored.
func (c *availabilityCollector) logAvailabilityReport(results map[string]bool, enabledFn FeatureEnabledFunc) {
	// The inventory block (#526). It leads, so the counts frame the per-feature lines
	// that follow, and it is the reason this cannot be emitted with the startup config
	// block: availability is not known at process start, and printing a confidently
	// empty list while the firewall is unreachable would be worse than printing it
	// late.
	var installed, scraped, unscraped, absent []string
	for _, probe := range featureAvailabilityProbes {
		available, ok := results[probe.Feature]
		switch {
		case !ok:
			continue
		case !available:
			absent = append(absent, probe.Feature)
		default:
			installed = append(installed, probe.Feature)
			if enabledFn(probe.Feature) {
				scraped = append(scraped, probe.Feature)
			} else {
				unscraped = append(unscraped, probe.Feature)
			}
		}
	}
	c.log.Info("plugin inventory",
		"component", "collector",
		"installed", len(installed),
		"scraped", len(scraped),
		"installed_not_scraped", len(unscraped),
		"absent", len(absent),
		"scraping", strings.Join(scraped, ","),
		"available_but_off", strings.Join(unscraped, ","),
		"not_installed", strings.Join(absent, ","),
	)

	for _, probe := range featureAvailabilityProbes {
		available, ok := results[probe.Feature]
		switch {
		case !ok:
			c.log.Debug("feature availability undetermined",
				"component", "collector", "feature", probe.Feature)
		case available && !enabledFn(probe.Feature):
			flag, envar, reason := featureFlagMeta(probe.Feature)
			c.log.Info("feature available but its collector is not enabled",
				"component", "collector",
				"feature", probe.Feature,
				"flag", flag,
				"envar", envar,
				"reason", reason,
			)
		case available:
			c.log.Debug("feature available and enabled",
				"component", "collector", "feature", probe.Feature)
		default:
			c.log.Debug("feature not available",
				"component", "collector", "feature", probe.Feature)
		}
	}
}

// featureFlagMeta resolves a subsystem to the flag an operator would set, its env
// var, and why the collector is off by default. reason is empty for a default-on
// collector: there is no cost or cardinality justification to give when the
// answer is simply "you disabled it".
func featureFlagMeta(feature string) (flag, envar, reason string) {
	for _, cf := range options.CollectorFlags {
		if cf.Subsystem != feature {
			continue
		}
		return "--" + cf.Flag, envarForFlag(cf.Flag), cf.Reason
	}
	return "", "", ""
}

// envarForFlag derives a flag's environment variable the same way every flag
// registration in internal/options spells it out by hand: uppercase, dots and
// dashes to underscores, OPN2OTEL_ prefix, and the redundant leading
// "exporter." segment dropped.
func envarForFlag(flag string) string {
	name := strings.TrimPrefix(flag, "exporter.")
	name = strings.NewReplacer(".", "_", "-", "_").Replace(name)
	return "OPN2OTEL_" + strings.ToUpper(name)
}

// ProbeFeatureAvailability probes every plugin-gated family once and reports which
// answered. Used at STARTUP, before any collector exists, so
// --exporter.enable-all-available can gate on what the box actually has (#525).
//
// It probes everything, because at startup nothing has been observed yet — this is
// the one pass where the duplicate-load argument does not apply.
//
// A family whose probe could not be answered is OMITTED rather than recorded as
// absent, so the caller's "missing means enable it" rule fails open per family. If
// the firewall is unreachable the map comes back empty and every collector is
// enabled, which is the correct answer: a box that is briefly down must not come
// back up as a smaller exporter than the operator asked for.
func ProbeFeatureAvailability(ctx context.Context, client *opnsense.Client) map[string]bool {
	out := make(map[string]bool, len(featureAvailabilityProbes))
	var mu sync.Mutex
	probeClient := client.WithContext(ctx).WithoutCache()

	sem := make(chan struct{}, maxAvailabilityProbeConcurrency)
	var wg sync.WaitGroup
	for _, probe := range featureAvailabilityProbes {
		wg.Add(1)
		sem <- struct{}{}
		go func(probe AvailabilityProbe) {
			defer wg.Done()
			defer func() { <-sem }()
			available, err := probeClient.ProbeEndpoint(probe.Endpoint)
			if err != nil {
				return
			}
			mu.Lock()
			out[probe.Feature] = available
			mu.Unlock()
		}(probe)
	}
	wg.Wait()
	return out
}
