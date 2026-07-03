package collector

import (
	"context"
	"log/slog"
	"sync"

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

	subsystem string
	instance  string
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
}

func (c *netflowCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.enabled
	ch <- c.localCollectionEnabled
	ch <- c.active
	ch <- c.collectorsCount
	ch <- c.cachePacketsTotal
	ch <- c.cacheSrcIPAddresses
	ch <- c.cacheDstIPAddresses
}

func (c *netflowCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	// The three netflow endpoints are independent, so fetch them concurrently — wall
	// time is bounded by the slowest single call, not the sum (#129). Emission and the
	// fail-fast error ordering (is-enabled → status → cache) below are unchanged.
	var (
		enabledData opnsense.NetflowEnabled
		statusData  opnsense.NetflowStatus
		cacheData   []opnsense.NetflowCacheStats
		enabledErr  *opnsense.APICallError
		statusErr   *opnsense.APICallError
		cacheErr    *opnsense.APICallError
	)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() { defer wg.Done(); enabledData, enabledErr = client.FetchNetflowIsEnabled() }()
	go func() { defer wg.Done(); statusData, statusErr = client.FetchNetflowStatus() }()
	go func() { defer wg.Done(); cacheData, cacheErr = client.FetchNetflowCacheStats() }()
	wg.Wait()

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
