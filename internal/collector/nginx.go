package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type nginxCollector struct {
	log *slog.Logger

	serviceRunning *prometheus.Desc

	// connection gauges
	connActive  *prometheus.Desc
	connReading *prometheus.Desc
	connWriting *prometheus.Desc
	connWaiting *prometheus.Desc

	// connection / request counters
	connAccepted *prometheus.Desc
	connHandled  *prometheus.Desc
	reqTotal     *prometheus.Desc

	// shared memory zone gauges
	sharedMaxBytes  *prometheus.Desc
	sharedUsedBytes *prometheus.Desc
	sharedUsedNodes *prometheus.Desc

	// per-server-zone counters + responses
	szRequests  *prometheus.Desc
	szBytesIn   *prometheus.Desc
	szBytesOut  *prometheus.Desc
	szResponses *prometheus.Desc // labels: zone, code

	// per-upstream-server counters + gauges
	usRequests     *prometheus.Desc
	usBytesIn      *prometheus.Desc
	usBytesOut     *prometheus.Desc
	usResponses    *prometheus.Desc // labels: upstream, server, code
	usDown         *prometheus.Desc
	usResponseTime *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &nginxCollector{
		subsystem: NginxSubsystem,
	})
}

func (c *nginxCollector) Name() string { return c.subsystem }

func (c *nginxCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	zoneLabels := []string{"zone"}
	upstreamLabels := []string{"upstream", "server"}

	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the nginx service is running (1 = running, 0 = stopped/disabled)", nil)

	c.connActive = buildPrometheusDesc(c.subsystem, "connections_active",
		"Current active connections", nil)
	c.connReading = buildPrometheusDesc(c.subsystem, "connections_reading",
		"Current connections reading request headers", nil)
	c.connWriting = buildPrometheusDesc(c.subsystem, "connections_writing",
		"Current connections writing responses", nil)
	c.connWaiting = buildPrometheusDesc(c.subsystem, "connections_waiting",
		"Current idle (keep-alive) connections", nil)

	c.connAccepted = buildPrometheusDesc(c.subsystem, "connections_accepted_total",
		"Cumulative accepted connections", nil)
	c.connHandled = buildPrometheusDesc(c.subsystem, "connections_handled_total",
		"Cumulative handled connections", nil)
	c.reqTotal = buildPrometheusDesc(c.subsystem, "requests_total",
		"Cumulative total requests", nil)

	c.sharedMaxBytes = buildPrometheusDesc(c.subsystem, "shared_memory_max_bytes",
		"Maximum size of the VTS shared memory zone in bytes", nil)
	c.sharedUsedBytes = buildPrometheusDesc(c.subsystem, "shared_memory_used_bytes",
		"Currently used bytes of the VTS shared memory zone", nil)
	c.sharedUsedNodes = buildPrometheusDesc(c.subsystem, "shared_memory_used_nodes",
		"Number of nodes in use in the VTS shared memory zone", nil)

	c.szRequests = buildPrometheusDesc(c.subsystem, "server_zone_requests_total",
		"Cumulative requests to this server zone", zoneLabels)
	c.szBytesIn = buildPrometheusDesc(c.subsystem, "server_zone_bytes_in_total",
		"Cumulative bytes received by this server zone", zoneLabels)
	c.szBytesOut = buildPrometheusDesc(c.subsystem, "server_zone_bytes_out_total",
		"Cumulative bytes sent by this server zone", zoneLabels)
	c.szResponses = buildPrometheusDesc(c.subsystem, "server_zone_responses_total",
		"Cumulative responses by HTTP status code class for this server zone",
		[]string{"zone", "code"})

	c.usRequests = buildPrometheusDesc(c.subsystem, "upstream_server_requests_total",
		"Cumulative requests forwarded to this upstream server", upstreamLabels)
	c.usBytesIn = buildPrometheusDesc(c.subsystem, "upstream_server_bytes_in_total",
		"Cumulative bytes received from this upstream server", upstreamLabels)
	c.usBytesOut = buildPrometheusDesc(c.subsystem, "upstream_server_bytes_out_total",
		"Cumulative bytes sent to this upstream server", upstreamLabels)
	c.usResponses = buildPrometheusDesc(c.subsystem, "upstream_server_responses_total",
		"Cumulative responses from this upstream server by HTTP status code class",
		[]string{"upstream", "server", "code"})
	c.usDown = buildPrometheusDesc(c.subsystem, "upstream_server_down",
		"Whether this upstream server is marked down (1 = down, 0 = up)", upstreamLabels)
	c.usResponseTime = buildPrometheusDesc(c.subsystem, "upstream_server_response_time_seconds",
		"Average response time of this upstream server in seconds", upstreamLabels)
}

func (c *nginxCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.serviceRunning,
		c.connActive, c.connReading, c.connWriting, c.connWaiting,
		c.connAccepted, c.connHandled, c.reqTotal,
		c.sharedMaxBytes, c.sharedUsedBytes, c.sharedUsedNodes,
		c.szRequests, c.szBytesIn, c.szBytesOut, c.szResponses,
		c.usRequests, c.usBytesIn, c.usBytesOut, c.usResponses,
		c.usDown, c.usResponseTime,
	} {
		ch <- d
	}
}

func (c *nginxCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchNginxVTS()
	if err != nil {
		return err
	}

	// Plugin absent (VTS endpoint 404): fully silent, no service-status probe.
	// A stopped nginx also 404s on the VTS endpoint, so this also covers that
	// case. The accepted consequence is that a stopped nginx emits nothing
	// (skip-on-absent pattern, D1).
	if !data.Present {
		return nil
	}

	// Connection gauges
	ch <- prometheus.MustNewConstMetric(c.connActive, prometheus.GaugeValue,
		data.ConnectionsActive, c.instance)
	ch <- prometheus.MustNewConstMetric(c.connReading, prometheus.GaugeValue,
		data.ConnectionsReading, c.instance)
	ch <- prometheus.MustNewConstMetric(c.connWriting, prometheus.GaugeValue,
		data.ConnectionsWriting, c.instance)
	ch <- prometheus.MustNewConstMetric(c.connWaiting, prometheus.GaugeValue,
		data.ConnectionsWaiting, c.instance)

	// Connection / request counters
	ch <- prometheus.MustNewConstMetric(c.connAccepted, prometheus.CounterValue,
		data.ConnectionsAccepted, c.instance)
	ch <- prometheus.MustNewConstMetric(c.connHandled, prometheus.CounterValue,
		data.ConnectionsHandled, c.instance)
	ch <- prometheus.MustNewConstMetric(c.reqTotal, prometheus.CounterValue,
		data.RequestsTotal, c.instance)

	// Shared memory gauges
	ch <- prometheus.MustNewConstMetric(c.sharedMaxBytes, prometheus.GaugeValue,
		data.SharedMaxBytes, c.instance)
	ch <- prometheus.MustNewConstMetric(c.sharedUsedBytes, prometheus.GaugeValue,
		data.SharedUsedBytes, c.instance)
	ch <- prometheus.MustNewConstMetric(c.sharedUsedNodes, prometheus.GaugeValue,
		data.SharedUsedNodes, c.instance)

	// Per-server-zone metrics (zone "*" already excluded by the fetcher)
	for _, sz := range data.ServerZones {
		ch <- prometheus.MustNewConstMetric(c.szRequests, prometheus.CounterValue,
			sz.Requests, sz.Zone, c.instance)
		ch <- prometheus.MustNewConstMetric(c.szBytesIn, prometheus.CounterValue,
			sz.BytesIn, sz.Zone, c.instance)
		ch <- prometheus.MustNewConstMetric(c.szBytesOut, prometheus.CounterValue,
			sz.BytesOut, sz.Zone, c.instance)
		for code, v := range sz.ResponsesByCode {
			ch <- prometheus.MustNewConstMetric(c.szResponses, prometheus.CounterValue,
				v, sz.Zone, code, c.instance)
		}
	}

	// Per-upstream-server metrics
	for _, us := range data.UpstreamServers {
		ch <- prometheus.MustNewConstMetric(c.usRequests, prometheus.CounterValue,
			us.Requests, us.Upstream, us.Server, c.instance)
		ch <- prometheus.MustNewConstMetric(c.usBytesIn, prometheus.CounterValue,
			us.BytesIn, us.Upstream, us.Server, c.instance)
		ch <- prometheus.MustNewConstMetric(c.usBytesOut, prometheus.CounterValue,
			us.BytesOut, us.Upstream, us.Server, c.instance)
		for code, v := range us.ResponsesByCode {
			ch <- prometheus.MustNewConstMetric(c.usResponses, prometheus.CounterValue,
				v, us.Upstream, us.Server, code, c.instance)
		}
		downVal := 0.0
		if us.Down {
			downVal = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.usDown, prometheus.GaugeValue,
			downVal, us.Upstream, us.Server, c.instance)
		ch <- prometheus.MustNewConstMetric(c.usResponseTime, prometheus.GaugeValue,
			us.ResponseTimeSeconds, us.Upstream, us.Server, c.instance)
	}

	// Service status — fetched last; absent (404) means we skip gracefully
	status, present, sErr := client.FetchServiceStatusOptional("nginxServiceStatus")
	if sErr != nil {
		c.log.Warn("failed to fetch nginx service status", "err", sErr)
	} else if present {
		running := 0.0
		if status == "running" {
			running = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.serviceRunning, prometheus.GaugeValue,
			running, c.instance)
	}

	return nil
}
