package collector

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

// FeatureAvailabilitySubsystem is declared in collector.go (see its comment
// there for why it must live in that file's const block).

// maxAvailabilityProbeConcurrency bounds in-flight availability probes (#517
// decision D). Only three probes exist today, well under the cap - it exists
// so a future addition to featureAvailabilityProbes cannot fan out an
// unbounded burst against the firewall.
const maxAvailabilityProbeConcurrency = 4

// AvailabilityProbe describes one opt-in, PLUGIN-GATED feature the
// feature-availability collector checks for. Scope is deliberately narrow
// (#517): only enable-* collectors whose availability is a plugin-installed
// question, answered through the SAME PluginGatedEndpoints() primitive the
// negative cache and cmd/apidrift already use (#495) - not a new mechanism.
// Cost-only or cardinality-only enable-* flags (network diagnostics, netflow,
// hasync, every *-details flag) have no plugin to detect, so there is nothing
// for a probe to discover about them; they are absent from this table on
// purpose, not an oversight.
type AvailabilityProbe struct {
	// Feature is the "feature" label value on opnsense_feature_available. It
	// is also the collector subsystem name so the label is legible without a
	// lookup table.
	Feature string
	// Flag and Envar are what an operator would set to turn the feature on,
	// surfaced verbatim in the one-shot availability log line.
	Flag  string
	Envar string
	// Reason is why the collector defaults to off, sourced from the same
	// options.CollectorFlags entry --exporter.enable-all-available reads (#517
	// design constraint: "reasons sourced from existing flag help text").
	Reason string
	// check performs ONE lightweight probe call - the plugin's own gating
	// endpoint only, never the collector's full per-item fan-out (e.g. never
	// SMART's per-disk smartctl POSTs) - and reports availability. It MUST
	// bypass the negative-cache TTL (opnsense.Client.WithoutCache) so a plugin
	// installed after startup is noticed on the next probe rather than up to
	// --exporter.cache-ttl later (#517 decision D).
	check func(ctx context.Context, client *opnsense.Client) (bool, *opnsense.APICallError)
}

// featureAvailabilityProbes is the frozen probe set (#517). Extend it only for
// a future enable-* collector that is itself plugin-gated the same way.
var featureAvailabilityProbes = []AvailabilityProbe{
	{
		Feature: SMARTSubsystem,
		Flag:    "exporter.enable-smart",
		Envar:   "OPNSENSE_EXPORTER_ENABLE_SMART",
		Reason:  "each scheduled poll runs `smartctl -a` per disk on the firewall and can wake spun-down disks",
		check: func(ctx context.Context, client *opnsense.Client) (bool, *opnsense.APICallError) {
			return client.WithContext(ctx).WithoutCache().FetchSMARTAvailable()
		},
	},
	{
		Feature: TorSubsystem,
		Flag:    "exporter.enable-tor",
		Envar:   "OPNSENSE_EXPORTER_ENABLE_TOR",
		Reason:  "each scheduled poll does two extra configd execs to query the Tor control port",
		check: func(ctx context.Context, client *opnsense.Client) (bool, *opnsense.APICallError) {
			data, err := client.WithContext(ctx).WithoutCache().FetchTorCircuits()
			return data.Present, err
		},
	},
	{
		Feature: VnstatSubsystem,
		Flag:    "exporter.enable-vnstat",
		Envar:   "OPNSENSE_EXPORTER_ENABLE_VNSTAT",
		Reason:  "each scheduled poll does one interface_list call plus one get_json_data call per interface vnstat tracks",
		check: func(ctx context.Context, client *opnsense.Client) (bool, *opnsense.APICallError) {
			return client.WithContext(ctx).WithoutCache().FetchVnstatAvailable()
		},
	},
}

// FeatureEnabledFunc reports whether the collector switch for a probed
// feature (an AvailabilityProbe.Feature value) is currently turned on. main
// wires this from the resolved CollectorsDisableSwitch before StartPolling,
// mirroring the LogEvents/Flow out-of-band injection seam: Update's
// CollectorInstance signature carries no switches, so the enabled label needs
// a side channel.
type FeatureEnabledFunc func(feature string) bool

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
		"Whether an opt-in, plugin-gated feature answered its OPNsense API endpoint successfully on the "+
			"most recent availability probe (1) or not (absent otherwise; #517). enabled reflects whether "+
			"the matching --exporter.enable-* collector switch is currently on. Probed on a fixed 15-minute "+
			"cadence (the cold poll tier) independent of --exporter.cache-ttl, so a plugin installed after "+
			"startup is noticed within 15 minutes rather than only after that TTL. Today covers smart, tor "+
			"and vnstat - the only opt-in collectors whose availability is a plugin-installed question; "+
			"cost-only and cardinality-only opt-in collectors have no plugin to probe for and never appear.",
		[]string{"feature", "enabled"},
	)
}

func (c *availabilityCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.available
}

// Update probes every registered feature concurrently (bounded by
// maxAvailabilityProbeConcurrency), emits the gauge for each currently
// available feature, and - only when the availability SET CHANGED since the
// last probe, including the very first one - logs the one-shot availability
// report (#517 decisions A and E).
func (c *availabilityCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	results := make(map[string]bool, len(featureAvailabilityProbes))
	var resultsMu sync.Mutex

	sem := make(chan struct{}, maxAvailabilityProbeConcurrency)
	var wg sync.WaitGroup
	for _, probe := range featureAvailabilityProbes {
		wg.Add(1)
		sem <- struct{}{}
		go func(probe AvailabilityProbe) {
			defer wg.Done()
			defer func() { <-sem }()
			// A probe error (anything other than the "plugin absent, no error"
			// shape every Fetch* already implements) is treated the same as
			// "not available": the metric answers whether the probe succeeded,
			// and an erroring one did not.
			available, _ := probe.check(ctx, client)
			resultsMu.Lock()
			results[probe.Feature] = available
			resultsMu.Unlock()
		}(probe)
	}
	wg.Wait()

	c.mu.Lock()
	changed := c.lastResults == nil
	if !changed {
		for feature, available := range results {
			if c.lastResults[feature] != available {
				changed = true
				break
			}
		}
	}
	c.lastResults = results
	enabledFn := c.enabledFn
	c.mu.Unlock()

	for _, probe := range featureAvailabilityProbes {
		if !results[probe.Feature] {
			// Left ABSENT rather than emitting a 0: this metric answers "did the
			// probe succeed", and a dashboard's "available but off" panel wants
			// present()/absent(), not a 0/1 gauge that needs filtering.
			continue
		}
		enabledLabel := "false"
		if enabledFn(probe.Feature) {
			enabledLabel = "true"
		}
		ch <- prometheus.MustNewConstMetric(c.available, prometheus.GaugeValue, 1, probe.Feature, enabledLabel, c.instance)
	}

	if changed {
		c.logAvailabilityReport(results, enabledFn)
	}

	return nil
}

// logAvailabilityReport emits the one-shot friendly log line for every
// available-but-not-enabled feature (#517's primary ask), naming the flag and
// env var that would turn it on and the reason it defaults to off.
func (c *availabilityCollector) logAvailabilityReport(results map[string]bool, enabledFn FeatureEnabledFunc) {
	for _, probe := range featureAvailabilityProbes {
		available := results[probe.Feature]
		enabled := enabledFn(probe.Feature)
		switch {
		case available && !enabled:
			c.log.Info("feature available but not enabled",
				"component", "collector",
				"feature", probe.Feature,
				"flag", "--"+probe.Flag,
				"envar", probe.Envar,
				"reason", probe.Reason,
			)
		case available && enabled:
			c.log.Info("feature available and enabled",
				"component", "collector",
				"feature", probe.Feature,
			)
		default:
			c.log.Debug("feature not available",
				"component", "collector",
				"feature", probe.Feature,
			)
		}
	}
}
