package collector

import (
	"context"
	"fmt"
	"log/slog"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type networkDiagCollector struct {
	log *slog.Logger

	// netisr metrics
	netisrDispatched       *prometheus.Desc
	netisrHybridDispatched *prometheus.Desc
	netisrQueued           *prometheus.Desc
	netisrHandled          *prometheus.Desc
	netisrQueueDrops       *prometheus.Desc
	netisrQueueLength      *prometheus.Desc
	netisrQueueWatermark   *prometheus.Desc
	netisrQueueLimit       *prometheus.Desc

	// netisr protocol metadata + derived per-protocol summaries
	netisrProtocolInfo          *prometheus.Desc
	netisrActiveWorkstreams     *prometheus.Desc
	netisrWorkstreamsAtLimit    *prometheus.Desc
	netisrQueueImbalanceRatio   *prometheus.Desc
	netisrDropConcentrationRate *prometheus.Desc

	// netisr per-workstream (per-CPU) series
	netisrCPUDispatched       *prometheus.Desc
	netisrCPUHybridDispatched *prometheus.Desc
	netisrCPUQueued           *prometheus.Desc
	netisrCPUHandled          *prometheus.Desc
	netisrCPUQueueDrops       *prometheus.Desc
	netisrCPUQueueLength      *prometheus.Desc
	netisrCPUQueueWatermark   *prometheus.Desc

	// netisrPerCPU gates the per-workstream series. Default ON — it is set
	// explicitly in init() because a bare bool zero-values to false.
	netisrPerCPU bool

	// socket metrics
	socketsActive    *prometheus.Desc
	socketsUnixTotal *prometheus.Desc

	// route metrics
	routesTotal *prometheus.Desc

	// pfsync metrics
	pfsyncNodesTotal *prometheus.Desc
	pfsyncNodeInfo   *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &networkDiagCollector{
		subsystem: NetworkDiagSubsystem,
		// Default ON. Must be set explicitly: the zero value is false, which
		// would ship the per-CPU series silently disabled.
		netisrPerCPU: true,
	})
}

// SetNetisrPerCPUEnabled controls whether the per-workstream `netisr_cpu_*`
// series are emitted. Default true; --exporter.disable-netisr-percpu turns it
// off. The derived summaries and netisr_protocol_info are never gated by it.
func (c *networkDiagCollector) SetNetisrPerCPUEnabled(v bool) {
	c.netisrPerCPU = v
}

func (c *networkDiagCollector) Name() string {
	return c.subsystem
}

func (c *networkDiagCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.netisrDispatched = buildPrometheusDesc(c.subsystem, "netisr_dispatched_total",
		"Total number of netisr dispatches by protocol",
		[]string{"protocol"},
	)
	c.netisrHybridDispatched = buildPrometheusDesc(c.subsystem, "netisr_hybrid_dispatched_total",
		"Total number of netisr hybrid dispatches by protocol",
		[]string{"protocol"},
	)
	c.netisrQueued = buildPrometheusDesc(c.subsystem, "netisr_queued_total",
		"Total number of netisr packets queued by protocol",
		[]string{"protocol"},
	)
	c.netisrHandled = buildPrometheusDesc(c.subsystem, "netisr_handled_total",
		"Total number of netisr packets handled by protocol",
		[]string{"protocol"},
	)
	c.netisrQueueDrops = buildPrometheusDesc(c.subsystem, "netisr_queue_drops_total",
		"Total number of netisr queue drops by protocol",
		[]string{"protocol"},
	)
	c.netisrQueueLength = buildPrometheusDesc(c.subsystem, "netisr_queue_length",
		"Current maximum netisr queue length across workstreams by protocol",
		[]string{"protocol"},
	)
	c.netisrQueueWatermark = buildPrometheusDesc(c.subsystem, "netisr_queue_watermark",
		"High watermark of netisr queue length across workstreams by protocol",
		[]string{"protocol"},
	)
	c.netisrQueueLimit = buildPrometheusDesc(c.subsystem, "netisr_queue_limit",
		"Configured netisr queue limit by protocol",
		[]string{"protocol"},
	)

	c.netisrProtocolInfo = buildPrometheusDesc(c.subsystem, "netisr_protocol_info",
		"Static netisr protocol configuration (value is always 1). Join on `protocol` to interpret the "+
			"other netisr series. `policy_type` is the one that matters: `cpu` and `flow` protocols are "+
			"meant to spread across every netisr workstream, whereas `source` protocols are single-lane "+
			"BY DESIGN and will always show one active workstream — alerting on workstream imbalance "+
			"without excluding them fires falsely on igmp/rtsock/arp on every box. `policy` is the "+
			"dispatch mode (direct/hybrid/deferred/default) and `flags` the raw netisr flag string.",
		[]string{"protocol", "protocol_id", "policy", "policy_type", "flags"},
	)
	c.netisrActiveWorkstreams = buildPrometheusDesc(c.subsystem, "netisr_active_workstreams",
		"Number of netisr workstreams that have carried any traffic for this protocol (handled, queued, "+
			"dispatched or hybrid-dispatched greater than zero). Compare against the CPU count: a "+
			"cpu-policy protocol showing 4 on a 12-core box means eight cores do no work for it at all, "+
			"which is a net.isr.maxthreads/bindthreads or NIC RSS problem, not a queue-size problem. "+
			"A value of 1 is normal and expected for source-policy protocols.",
		[]string{"protocol"},
	)
	c.netisrWorkstreamsAtLimit = buildPrometheusDesc(c.subsystem, "netisr_workstreams_at_limit",
		"Number of netisr workstreams whose high watermark has reached this protocol's configured queue "+
			"limit. Non-zero means at least one lane has actually run out of queue at some point since "+
			"boot. Because the watermark is a since-boot high water mark and never decays, this stays "+
			"non-zero after the condition clears — it records that it happened, not that it is happening. "+
			"Always 0 when the queue limit is 0 (unset).",
		[]string{"protocol"},
	)
	c.netisrQueueImbalanceRatio = buildPrometheusDesc(c.subsystem, "netisr_queue_imbalance_ratio",
		"Maximum netisr queue watermark divided by the mean watermark, computed over ACTIVE workstreams "+
			"only. 1.0 is a perfectly even spread across the lanes that are working; higher means one "+
			"lane absorbs disproportionately more depth. Idle workstreams are excluded on purpose — "+
			"including them would dilute the mean and make an affinity problem look milder the more CPUs "+
			"the box has. Emitted as 0 when the ratio is undefined: fewer than two active workstreams, or "+
			"every active watermark still zero. Read alongside netisr_active_workstreams, which is what "+
			"tells you whether a 0 means 'even' or 'single-lane'.",
		[]string{"protocol"},
	)
	c.netisrDropConcentrationRate = buildPrometheusDesc(c.subsystem, "netisr_drop_concentration_ratio",
		"Largest per-workstream netisr queue-drop count divided by the total across all workstreams. "+
			"1.0 means every drop landed on a single lane, which points at CPU affinity — raising "+
			"net.isr.maxqlen would mask the symptom rather than fix it. A value near 1/N means the drops "+
			"are spread and the protocol is genuinely over its queue limit. Emitted as 0 when nothing has "+
			"dropped, so gate any alert on the drop counter itself, not on this ratio alone.",
		[]string{"protocol"},
	)

	c.netisrCPUDispatched = buildPrometheusDesc(c.subsystem, "netisr_cpu_dispatched_total",
		"Packets dispatched directly on this netisr workstream, without being queued. "+
			"Per-workstream breakdown of netisr_dispatched_total.",
		[]string{"protocol", "cpu", "workstream"},
	)
	c.netisrCPUHybridDispatched = buildPrometheusDesc(c.subsystem, "netisr_cpu_hybrid_dispatched_total",
		"Packets hybrid-dispatched on this netisr workstream (handled inline because the queue was "+
			"empty). Per-workstream breakdown of netisr_hybrid_dispatched_total.",
		[]string{"protocol", "cpu", "workstream"},
	)
	c.netisrCPUQueued = buildPrometheusDesc(c.subsystem, "netisr_cpu_queued_total",
		"Packets enqueued onto this netisr workstream for deferred processing. "+
			"Per-workstream breakdown of netisr_queued_total.",
		[]string{"protocol", "cpu", "workstream"},
	)
	c.netisrCPUHandled = buildPrometheusDesc(c.subsystem, "netisr_cpu_handled_total",
		"Packets processed by this netisr workstream. Per-workstream breakdown of netisr_handled_total. "+
			"A row is emitted for EVERY workstream the box reports, including ones that are entirely "+
			"idle — a run of zero-valued CPUs is the finding, not missing data, and suppressing those "+
			"rows would hide exactly the affinity problem this breakdown exists to show. Labelled with "+
			"both `workstream` (the netisr stream index) and `cpu` (the core it is bound to); they "+
			"coincide on a default configuration but are not the same thing when net.isr.bindthreads "+
			"is off.",
		[]string{"protocol", "cpu", "workstream"},
	)
	c.netisrCPUQueueDrops = buildPrometheusDesc(c.subsystem, "netisr_cpu_queue_drops_total",
		"Packets dropped because this netisr workstream's queue was full. Per-workstream breakdown of "+
			"netisr_queue_drops_total — this is the series that shows whether drops are concentrated on "+
			"one core or spread across all of them.",
		[]string{"protocol", "cpu", "workstream"},
	)
	c.netisrCPUQueueLength = buildPrometheusDesc(c.subsystem, "netisr_cpu_queue_length",
		"Instantaneous depth of this netisr workstream's queue at scrape time. Almost always 0 on a "+
			"healthy box and a poor sampling of a bursty signal — use netisr_cpu_queue_watermark for "+
			"whether the queue has ever filled.",
		[]string{"protocol", "cpu", "workstream"},
	)
	c.netisrCPUQueueWatermark = buildPrometheusDesc(c.subsystem, "netisr_cpu_queue_watermark",
		"Highest queue depth this netisr workstream has ever reached. A since-boot high water mark: it "+
			"never decays, so it records that the queue filled, not that it is full now. Equal to the "+
			"protocol's queue limit means this lane has hit its ceiling and dropped.",
		[]string{"protocol", "cpu", "workstream"},
	)

	c.socketsActive = buildPrometheusDesc(c.subsystem, "sockets_active",
		"Number of active sockets by type",
		[]string{"type"},
	)
	c.socketsUnixTotal = buildPrometheusDesc(c.subsystem, "sockets_unix_total",
		"Total number of active Unix domain sockets",
		nil,
	)

	c.routesTotal = buildPrometheusDesc(c.subsystem, "routes_total",
		"Number of routing table entries by protocol",
		[]string{"proto"},
	)

	c.pfsyncNodesTotal = buildPrometheusDesc(c.subsystem, "pfsync_nodes_total",
		"Total number of pfsync cluster nodes",
		nil,
	)
	c.pfsyncNodeInfo = buildPrometheusDesc(c.subsystem, "pfsync_node_info",
		"PFSync node information (value is always 1)",
		[]string{"creatorid", "is_local"},
	)
}

func (c *networkDiagCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.netisrDispatched
	ch <- c.netisrHybridDispatched
	ch <- c.netisrQueued
	ch <- c.netisrHandled
	ch <- c.netisrQueueDrops
	ch <- c.netisrQueueLength
	ch <- c.netisrQueueWatermark
	ch <- c.netisrQueueLimit
	// Emitted unconditionally: Describe() must not depend on the per-CPU toggle.
	ch <- c.netisrProtocolInfo
	ch <- c.netisrActiveWorkstreams
	ch <- c.netisrWorkstreamsAtLimit
	ch <- c.netisrQueueImbalanceRatio
	ch <- c.netisrDropConcentrationRate
	ch <- c.netisrCPUDispatched
	ch <- c.netisrCPUHybridDispatched
	ch <- c.netisrCPUQueued
	ch <- c.netisrCPUHandled
	ch <- c.netisrCPUQueueDrops
	ch <- c.netisrCPUQueueLength
	ch <- c.netisrCPUQueueWatermark
	ch <- c.socketsActive
	ch <- c.socketsUnixTotal
	ch <- c.routesTotal
	ch <- c.pfsyncNodesTotal
	ch <- c.pfsyncNodeInfo
}

func (c *networkDiagCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	// Fetch netisr statistics
	netisrData, err := client.FetchNetisrStatistics()
	if err != nil {
		return err
	}

	for proto, stats := range netisrData {
		ch <- prometheus.MustNewConstMetric(
			c.netisrDispatched,
			prometheus.CounterValue,
			float64(stats.Dispatched),
			proto,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.netisrHybridDispatched,
			prometheus.CounterValue,
			float64(stats.HybridDispatched),
			proto,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.netisrQueued,
			prometheus.CounterValue,
			float64(stats.Queued),
			proto,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.netisrHandled,
			prometheus.CounterValue,
			float64(stats.Handled),
			proto,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.netisrQueueDrops,
			prometheus.CounterValue,
			float64(stats.QueueDrops),
			proto,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.netisrQueueLength,
			prometheus.GaugeValue,
			float64(stats.Length),
			proto,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.netisrQueueWatermark,
			prometheus.GaugeValue,
			float64(stats.Watermark),
			proto,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.netisrQueueLimit,
			prometheus.GaugeValue,
			float64(stats.QueueLimit),
			proto,
			c.instance,
		)

		ch <- prometheus.MustNewConstMetric(
			c.netisrProtocolInfo,
			prometheus.GaugeValue,
			1,
			proto,
			strconv.Itoa(stats.Protocol),
			stats.Policy,
			stats.PolicyType,
			stats.Flags,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.netisrActiveWorkstreams,
			prometheus.GaugeValue,
			float64(stats.ActiveWorkstreams()),
			proto,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.netisrWorkstreamsAtLimit,
			prometheus.GaugeValue,
			float64(stats.WorkstreamsAtLimit()),
			proto,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.netisrQueueImbalanceRatio,
			prometheus.GaugeValue,
			stats.QueueImbalanceRatio(),
			proto,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.netisrDropConcentrationRate,
			prometheus.GaugeValue,
			stats.DropConcentrationRatio(),
			proto,
			c.instance,
		)

		if !c.netisrPerCPU {
			continue
		}
		for _, w := range stats.Workstreams {
			cpu := strconv.Itoa(w.CPU)
			ws := strconv.Itoa(w.Workstream)
			for _, m := range []struct {
				desc  *prometheus.Desc
				kind  prometheus.ValueType
				value float64
			}{
				{c.netisrCPUDispatched, prometheus.CounterValue, float64(w.Dispatched)},
				{c.netisrCPUHybridDispatched, prometheus.CounterValue, float64(w.HybridDispatched)},
				{c.netisrCPUQueued, prometheus.CounterValue, float64(w.Queued)},
				{c.netisrCPUHandled, prometheus.CounterValue, float64(w.Handled)},
				{c.netisrCPUQueueDrops, prometheus.CounterValue, float64(w.QueueDrops)},
				{c.netisrCPUQueueLength, prometheus.GaugeValue, float64(w.Length)},
				{c.netisrCPUQueueWatermark, prometheus.GaugeValue, float64(w.Watermark)},
			} {
				ch <- prometheus.MustNewConstMetric(m.desc, m.kind, m.value, proto, cpu, ws, c.instance)
			}
		}
	}

	// Fetch socket statistics
	socketData, err := client.FetchSocketStatistics()
	if err != nil {
		return err
	}

	for sockType, count := range socketData.ByType {
		ch <- prometheus.MustNewConstMetric(
			c.socketsActive,
			prometheus.GaugeValue,
			float64(count),
			sockType,
			c.instance,
		)
	}

	ch <- prometheus.MustNewConstMetric(
		c.socketsUnixTotal,
		prometheus.GaugeValue,
		float64(socketData.UnixTotal),
		c.instance,
	)

	// Fetch route statistics
	routeData, err := client.FetchRouteStatistics()
	if err != nil {
		return err
	}

	for proto, count := range routeData.ByProto {
		ch <- prometheus.MustNewConstMetric(
			c.routesTotal,
			prometheus.GaugeValue,
			float64(count),
			proto,
			c.instance,
		)
	}

	// Fetch pfsync nodes
	pfsyncData, pfsyncErr := client.FetchPFSyncNodes()
	if pfsyncErr != nil {
		c.log.Warn("failed to fetch pfsync nodes", "error", pfsyncErr.Error())
	} else {
		ch <- prometheus.MustNewConstMetric(
			c.pfsyncNodesTotal,
			prometheus.GaugeValue,
			float64(pfsyncData.Total),
			c.instance,
		)
		for _, node := range pfsyncData.Nodes {
			ch <- prometheus.MustNewConstMetric(
				c.pfsyncNodeInfo,
				prometheus.GaugeValue,
				1,
				node.CreatorID,
				fmt.Sprintf("%t", node.IsLocal),
				c.instance,
			)
		}
	}

	return nil
}
