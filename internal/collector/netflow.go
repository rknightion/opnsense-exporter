package collector

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type netflowCollector struct {
	log *slog.Logger

	// isEnabled metrics
	enabled                *prometheus.Desc
	localCollectionEnabled *prometheus.Desc

	// status metrics
	active          *prometheus.Desc
	collectorsCount *prometheus.Desc

	// cacheStats metrics (per-interface)
	cachePacketsTotal   *prometheus.Desc
	cacheSrcIPAddresses *prometheus.Desc
	cacheDstIPAddresses *prometheus.Desc

	// getconfig metrics: what the box is CONFIGURED to capture, crossed with when
	// our own receiver last heard from each interface (#366).
	captureExpected   *prometheus.Desc
	captureLastRecord *prometheus.Desc
	captureActiveTO   *prometheus.Desc
	captureInactiveTO *prometheus.Desc

	// store supplies the last-record times. nil means the process-wide singleton,
	// which is what main uses; tests set it to an isolated store rather than
	// mutating a global.
	store *FlowStore

	subsystem string
	instance  string
}

// flowStore resolves the store this collector reads last-record times from.
func (c *netflowCollector) flowStore() *FlowStore {
	if c.store != nil {
		return c.store
	}
	return Flow
}

func init() {
	collectorInstances = append(collectorInstances, &netflowCollector{
		subsystem: NetflowSubsystem,
	})
}

func (c *netflowCollector) Name() string {
	return c.subsystem
}

func (c *netflowCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.enabled = buildPrometheusDesc(c.subsystem, "enabled",
		"Whether netflow capture is enabled (1 = enabled, 0 = disabled)",
		nil,
	)
	c.localCollectionEnabled = buildPrometheusDesc(c.subsystem, "local_collection_enabled",
		"Whether local netflow collection is enabled (1 = enabled, 0 = disabled)",
		nil,
	)

	c.active = buildPrometheusDesc(c.subsystem, "active",
		"Whether the netflow service is active (1 = active, 0 = inactive)",
		nil,
	)
	c.collectorsCount = buildPrometheusDesc(c.subsystem, "collectors_count",
		"Number of active netflow collectors",
		nil,
	)

	c.cachePacketsTotal = buildPrometheusDesc(c.subsystem, "cache_packets_total",
		"Total packets observed in netflow cache by interface",
		[]string{"interface"},
	)
	c.cacheSrcIPAddresses = buildPrometheusDesc(c.subsystem, "cache_source_ip_addresses",
		"Number of unique source IP addresses in netflow cache by interface",
		[]string{"interface"},
	)
	c.cacheDstIPAddresses = buildPrometheusDesc(c.subsystem, "cache_destination_ip_addresses",
		"Number of unique destination IP addresses in netflow cache by interface",
		[]string{"interface"},
	)

	c.captureExpected = buildPrometheusDesc(c.subsystem, "capture_expected",
		"Whether the box is configured to capture NetFlow on this interface (1 = selected, "+
			"0 = listed in the config but not selected). This is the half no counter can supply: an "+
			"interface producing nothing is indistinguishable from an idle one unless you know it was "+
			"supposed to be producing something. The set is closed - it comes from the firewall's own "+
			"netflow config - so cardinality is bounded by the number of interfaces. An interface with "+
			"records but capture_expected=0 is NOT a fault: ng_netflow names the far side of a flow "+
			"from a FIB lookup, so an interface can be labelled without being captured on.",
		[]string{"interface"},
	)
	c.captureLastRecord = buildPrometheusDesc(c.subsystem, "capture_last_record_seconds",
		"Seconds since this exporter last received a NetFlow record attributed to this interface. "+
			"A RAW AGE, not a verdict: a guest VLAN can be legitimately silent for hours, so the "+
			"threshold is the operator's to choose - compare against capture_active_timeout_seconds. "+
			"Interfaces that have produced NO record since the exporter started are ABSENT here "+
			"rather than reported as a large age, because every interface is silent at startup and a "+
			"number there would make a fresh boot look like a box-wide outage; \"never seen\" and "+
			"\"seen, then stopped\" are different states. IMPORTANT: a fresh age proves the interface "+
			"is being NAMED, not that its own capture hook is alive - ng_netflow fills one side of "+
			"each flow from a FIB lookup, so records captured elsewhere name it too. For per-hook "+
			"liveness use opnsense_netflow_cache_packets_total, which is the box's own per-node view.",
		[]string{"interface"},
	)
	c.captureActiveTO = buildPrometheusDesc(c.subsystem, "capture_active_timeout_seconds",
		"The box's configured ACTIVE flow timeout: how long a long-running flow sits in the cache "+
			"before ng_netflow exports it anyway. Exported so a \"this interface has gone quiet\" "+
			"threshold is derived from what the firewall actually applies rather than guessed - an "+
			"interface cannot be judged silent until well past this.",
		nil,
	)
	c.captureInactiveTO = buildPrometheusDesc(c.subsystem, "capture_inactive_timeout_seconds",
		"The box's configured INACTIVE flow timeout: how long an idle flow waits before export. "+
			"The floor on how quickly any interface can be observed to have stopped.",
		nil,
	)
}

func (c *netflowCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.enabled
	ch <- c.localCollectionEnabled
	ch <- c.active
	ch <- c.collectorsCount
	ch <- c.cachePacketsTotal
	ch <- c.cacheSrcIPAddresses
	ch <- c.cacheDstIPAddresses
	ch <- c.captureExpected
	ch <- c.captureLastRecord
	ch <- c.captureActiveTO
	ch <- c.captureInactiveTO
}

func (c *netflowCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	// The three netflow endpoints are independent, so fetch them concurrently — wall
	// time is bounded by the slowest single call, not the sum (#129). Emission and the
	// fail-fast error ordering (is-enabled → status → cache) below are unchanged.
	var (
		enabledData opnsense.NetflowEnabled
		statusData  opnsense.NetflowStatus
		cacheData   []opnsense.NetflowCacheStats
		captureData opnsense.NetflowCaptureConfig
		enabledErr  *opnsense.APICallError
		statusErr   *opnsense.APICallError
		cacheErr    *opnsense.APICallError
		captureErr  *opnsense.APICallError
	)
	var wg sync.WaitGroup
	wg.Add(4)
	go func() { defer wg.Done(); enabledData, enabledErr = client.FetchNetflowIsEnabled() }()
	go func() { defer wg.Done(); statusData, statusErr = client.FetchNetflowStatus() }()
	go func() { defer wg.Done(); cacheData, cacheErr = client.FetchNetflowCacheStats() }()
	go func() { defer wg.Done(); captureData, captureErr = client.FetchNetflowCaptureConfig() }()
	wg.Wait()

	// The capture config is emitted FIRST and its failure is warned rather than
	// returned. The other three carry the service's live state and are the more
	// important signal, so losing the configured capture set must cost only the
	// configured capture set — not the whole collector.
	c.emitCaptureConfig(captureData, captureErr, ch)

	if enabledErr != nil {
		return enabledErr
	}

	var enabledVal, localVal float64
	if enabledData.Netflow {
		enabledVal = 1
	}
	if enabledData.Local {
		localVal = 1
	}

	ch <- prometheus.MustNewConstMetric(
		c.enabled,
		prometheus.GaugeValue,
		enabledVal,
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.localCollectionEnabled,
		prometheus.GaugeValue,
		localVal,
		c.instance,
	)

	if statusErr != nil {
		return statusErr
	}

	var activeVal float64
	if statusData.Active {
		activeVal = 1
	}

	ch <- prometheus.MustNewConstMetric(
		c.active,
		prometheus.GaugeValue,
		activeVal,
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.collectorsCount,
		prometheus.GaugeValue,
		float64(statusData.Collectors),
		c.instance,
	)

	if cacheErr != nil {
		return cacheErr
	}

	for _, entry := range cacheData {
		ch <- prometheus.MustNewConstMetric(
			c.cachePacketsTotal,
			prometheus.CounterValue,
			float64(entry.Packets),
			entry.Interface,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.cacheSrcIPAddresses,
			prometheus.GaugeValue,
			float64(entry.SrcIPAddresses),
			entry.Interface,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.cacheDstIPAddresses,
			prometheus.GaugeValue,
			float64(entry.DstIPAddresses),
			entry.Interface,
			c.instance,
		)
	}

	return nil
}

// emitCaptureConfig publishes the configured capture set and, for interfaces that
// have actually produced a record, how long ago that was (#366).
//
// The two together are the signal: "configured to capture" crossed with "has said
// nothing for longer than the box's own active timeout". Neither half is a verdict
// on its own, and no verdict is computed here — the raw age is exported and the
// threshold is the operator's, because a guest VLAN can be legitimately silent for
// hours and every interface is silent at startup.
func (c *netflowCollector) emitCaptureConfig(
	cfg opnsense.NetflowCaptureConfig, err *opnsense.APICallError, ch chan<- prometheus.Metric,
) {
	if err != nil {
		c.log.Warn("netflow capture config sub-call failed", "endpoint", "netflowGetConfig", "error", err)
		return
	}

	for iface, selected := range cfg.Interfaces {
		var v float64
		if selected {
			v = 1
		}
		ch <- prometheus.MustNewConstMetric(c.captureExpected, prometheus.GaugeValue, v, iface, c.instance)
	}

	// Zero means "the box reported no timeout", which only happens on a response
	// that carried none — emitting 0 there would claim a real configured value of
	// zero seconds, which the model's own minimum of 1 forbids.
	if cfg.ActiveTimeout > 0 {
		ch <- prometheus.MustNewConstMetric(c.captureActiveTO, prometheus.GaugeValue,
			cfg.ActiveTimeout.Seconds(), c.instance)
	}
	if cfg.InactiveTimeout > 0 {
		ch <- prometheus.MustNewConstMetric(c.captureInactiveTO, prometheus.GaugeValue,
			cfg.InactiveTimeout.Seconds(), c.instance)
	}

	// Only interfaces that have produced a record appear. Absence is the "never seen
	// since start" state and is deliberately not rendered as a number.
	now := time.Now()
	for iface, at := range c.flowStore().netflowLastSeen() {
		ch <- prometheus.MustNewConstMetric(c.captureLastRecord, prometheus.GaugeValue,
			now.Sub(at).Seconds(), iface, c.instance)
	}
}
