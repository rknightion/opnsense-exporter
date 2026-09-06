package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

type trafficShaperCollector struct {
	log *slog.Logger

	pipesTotal    *prometheus.Desc
	queuesTotal   *prometheus.Desc
	pipeFlows     *prometheus.Desc
	pipePackets   *prometheus.Desc
	pipeBytes     *prometheus.Desc
	pipeDropPkts  *prometheus.Desc
	pipeDropBytes *prometheus.Desc
	queueFlows    *prometheus.Desc
	queuePackets  *prometheus.Desc
	queueBytes    *prometheus.Desc
	queueDropPkts *prometheus.Desc
	queueDropByt  *prometheus.Desc
	rulePackets   *prometheus.Desc
	ruleBytes     *prometheus.Desc
	ruleLastMatch *prometheus.Desc

	// Configured-capacity gauges (#584) -- the limits the live counters above
	// are measured against. Presence-gated: an unconfigured/unparseable value
	// (see opnsense.TrafficShaperEntity's *OK companions) emits no series.
	pipeConfiguredBandwidth  *prometheus.Desc
	pipeConfiguredBurst      *prometheus.Desc
	pipeConfiguredDelay      *prometheus.Desc
	pipeConfiguredQueueSize  *prometheus.Desc
	pipeConfiguredWeight     *prometheus.Desc
	queueConfiguredQueueSize *prometheus.Desc
	queueConfiguredWeight    *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &trafficShaperCollector{
		subsystem: TrafficShaperSubsystem,
	})
}

func (c *trafficShaperCollector) Name() string { return c.subsystem }

func (c *trafficShaperCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	pipeLabels := []string{"pipe", "description"}
	queueLabels := []string{"queue", "pipe", "description"}
	ruleLabels := []string{"rule", "attached_to", "target_type", "description"}

	c.pipesTotal = buildPrometheusDesc(c.subsystem, "pipes",
		"Current number of configured traffic shaper pipes", nil)
	c.queuesTotal = buildPrometheusDesc(c.subsystem, "queues",
		"Current number of configured traffic shaper queues (excluding template queues)", nil)

	c.pipeFlows = buildPrometheusDesc(c.subsystem, "pipe_active_flows",
		"Number of currently active flows on this pipe", pipeLabels)
	c.pipePackets = buildPrometheusDesc(c.subsystem, "pipe_packets",
		"Total packets processed by this pipe (gauge: flow stats expire with idle flows)", pipeLabels)
	c.pipeBytes = buildPrometheusDesc(c.subsystem, "pipe_bytes",
		"Total bytes processed by this pipe (gauge: flow stats expire with idle flows)", pipeLabels)
	c.pipeDropPkts = buildPrometheusDesc(c.subsystem, "pipe_drop_packets",
		"Total packets dropped by this pipe (gauge)", pipeLabels)
	c.pipeDropBytes = buildPrometheusDesc(c.subsystem, "pipe_drop_bytes",
		"Total bytes dropped by this pipe (gauge)", pipeLabels)

	c.queueFlows = buildPrometheusDesc(c.subsystem, "queue_active_flows",
		"Number of currently active flows on this queue", queueLabels)
	c.queuePackets = buildPrometheusDesc(c.subsystem, "queue_packets",
		"Total packets processed by this queue (gauge)", queueLabels)
	c.queueBytes = buildPrometheusDesc(c.subsystem, "queue_bytes",
		"Total bytes processed by this queue (gauge)", queueLabels)
	c.queueDropPkts = buildPrometheusDesc(c.subsystem, "queue_drop_packets",
		"Total packets dropped by this queue (gauge)", queueLabels)
	c.queueDropByt = buildPrometheusDesc(c.subsystem, "queue_drop_bytes",
		"Total bytes dropped by this queue (gauge)", queueLabels)

	c.rulePackets = buildPrometheusDesc(c.subsystem, "rule_packets_total",
		"Cumulative packets matched by this traffic shaper rule", ruleLabels)
	c.ruleBytes = buildPrometheusDesc(c.subsystem, "rule_bytes_total",
		"Cumulative bytes matched by this traffic shaper rule", ruleLabels)
	c.ruleLastMatch = buildPrometheusDesc(c.subsystem, "rule_last_match_timestamp_seconds",
		"Unix timestamp of the last time this traffic shaper rule matched traffic. Absent for a rule that has never matched.",
		ruleLabels)

	// Configured-capacity gauges (#584): the limits the live counters above
	// are measured against, so an operator can tell "saturated" from "just
	// busy" rather than only seeing drop counters with no denominator.
	//
	// bandwidth/burst/delay are pipe-only (dn_link fields -- FreeBSD's
	// dummynet.c never attaches them to a queue). queue_size/weight apply to
	// BOTH kinds: a "queue" entity carries its own flowset config directly,
	// while a "pipe" entity's queue_size/weight are folded from its
	// auto-attached template queue (the same attribution the existing
	// pipe_active_flows/pipe_packets/... gauges above already use for
	// template-queue data) -- this is a deliberate naming split from the
	// issue's literal "pipe_configured_*" for all five fields: queue_size and
	// weight are genuinely per-QUEUE config (an explicit Queues-tab entry has
	// its own independent depth/weight, unrelated to any pipe), so folding
	// them under "pipe_configured_*" only for queues would either silently
	// drop standalone queues' own capacity or conflate two different queues
	// under one series.
	c.pipeConfiguredBandwidth = buildPrometheusDesc(c.subsystem, "pipe_configured_bandwidth_bps",
		"Configured bandwidth limit for this pipe, normalized to bits per second. Not emitted for "+
			"a pipe with no bandwidth cap configured (dnctl reports \"unlimited\", not 0 bps).",
		pipeLabels)
	c.pipeConfiguredBurst = buildPrometheusDesc(c.subsystem, "pipe_configured_burst_bytes",
		"Configured burst allowance for this pipe in bytes.",
		pipeLabels)
	c.pipeConfiguredDelay = buildPrometheusDesc(c.subsystem, "pipe_configured_delay_milliseconds",
		"Configured added delay for this pipe in milliseconds. 0 is a real \"no added delay\" "+
			"configuration, not an absence.",
		pipeLabels)
	queueSizeHelp := "Configured queue depth, either in packets (slot-count mode) or bytes " +
		"(byte-count mode) -- see the unit label. The two modes are different physical " +
		"quantities and must not be compared across a mixed unit selector."
	c.pipeConfiguredQueueSize = buildPrometheusDesc(c.subsystem, "pipe_configured_queue_size",
		queueSizeHelp+" Folded from this pipe's own auto-attached (template) queue.",
		append(append([]string{}, pipeLabels...), "unit"))
	c.pipeConfiguredWeight = buildPrometheusDesc(c.subsystem, "pipe_configured_weight",
		"Configured WF2Q+ scheduling weight of this pipe's own auto-attached (template) queue. "+
			"A relative value with meaning only alongside sibling weights on the same scheduler.",
		pipeLabels)
	c.queueConfiguredQueueSize = buildPrometheusDesc(c.subsystem, "queue_configured_queue_size",
		queueSizeHelp,
		append(append([]string{}, queueLabels...), "unit"))
	c.queueConfiguredWeight = buildPrometheusDesc(c.subsystem, "queue_configured_weight",
		"Configured WF2Q+ scheduling weight of this queue. A relative value with meaning only "+
			"alongside sibling weights on the same scheduler.",
		queueLabels)
}

func (c *trafficShaperCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.pipesTotal, c.queuesTotal,
		c.pipeFlows, c.pipePackets, c.pipeBytes, c.pipeDropPkts, c.pipeDropBytes,
		c.queueFlows, c.queuePackets, c.queueBytes, c.queueDropPkts, c.queueDropByt,
		c.rulePackets, c.ruleBytes, c.ruleLastMatch,
		c.pipeConfiguredBandwidth, c.pipeConfiguredBurst, c.pipeConfiguredDelay,
		c.pipeConfiguredQueueSize, c.pipeConfiguredWeight,
		c.queueConfiguredQueueSize, c.queueConfiguredWeight,
	} {
		ch <- d
	}
}

func (c *trafficShaperCollector) Update(_ context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchTrafficShaperStatistics()
	if err != nil {
		return err
	}

	// Feature absent (404) or status != "ok": stay completely silent.
	if !data.Present {
		return nil
	}

	// Shaper present but unconfigured (empty items): stay completely silent.
	// This matches plugin-collector convention, and this silence IS what hides the
	// dashboard's Traffic Shaper tab: its presence sentinel tests whether
	// pipes EXISTS (#414). Emitting zeros here would show an empty tab on
	// every box with the plugin installed.
	if len(data.Pipes) == 0 && len(data.Queues) == 0 {
		return nil
	}

	ch <- prometheus.MustNewConstMetric(c.pipesTotal, prometheus.GaugeValue,
		float64(len(data.Pipes)), c.instance)
	ch <- prometheus.MustNewConstMetric(c.queuesTotal, prometheus.GaugeValue,
		float64(len(data.Queues)), c.instance)

	for _, pipe := range data.Pipes {
		ch <- prometheus.MustNewConstMetric(c.pipeFlows, prometheus.GaugeValue,
			pipe.ActiveFlows, pipe.ID, pipe.Description, c.instance)
		ch <- prometheus.MustNewConstMetric(c.pipePackets, prometheus.GaugeValue,
			pipe.Packets, pipe.ID, pipe.Description, c.instance)
		ch <- prometheus.MustNewConstMetric(c.pipeBytes, prometheus.GaugeValue,
			pipe.Bytes, pipe.ID, pipe.Description, c.instance)
		ch <- prometheus.MustNewConstMetric(c.pipeDropPkts, prometheus.GaugeValue,
			pipe.DropPackets, pipe.ID, pipe.Description, c.instance)
		ch <- prometheus.MustNewConstMetric(c.pipeDropBytes, prometheus.GaugeValue,
			pipe.DropBytes, pipe.ID, pipe.Description, c.instance)

		// Configured-capacity gauges (#584), each independently presence-gated:
		// an "unlimited" bandwidth, or a field the box simply never sent,
		// must emit no series rather than a fabricated 0/absent-as-zero.
		if pipe.ConfiguredBandwidthOK {
			ch <- prometheus.MustNewConstMetric(c.pipeConfiguredBandwidth, prometheus.GaugeValue,
				pipe.ConfiguredBandwidthBps, pipe.ID, pipe.Description, c.instance)
		}
		if pipe.ConfiguredBurstOK {
			ch <- prometheus.MustNewConstMetric(c.pipeConfiguredBurst, prometheus.GaugeValue,
				pipe.ConfiguredBurstBytes, pipe.ID, pipe.Description, c.instance)
		}
		if pipe.ConfiguredDelayOK {
			ch <- prometheus.MustNewConstMetric(c.pipeConfiguredDelay, prometheus.GaugeValue,
				pipe.ConfiguredDelayMs, pipe.ID, pipe.Description, c.instance)
		}
		if pipe.ConfiguredQueueSizeOK {
			ch <- prometheus.MustNewConstMetric(c.pipeConfiguredQueueSize, prometheus.GaugeValue,
				pipe.ConfiguredQueueSize, pipe.ID, pipe.Description, pipe.ConfiguredQueueSizeUnit, c.instance)
		}
		if pipe.ConfiguredWeightOK {
			ch <- prometheus.MustNewConstMetric(c.pipeConfiguredWeight, prometheus.GaugeValue,
				pipe.ConfiguredWeight, pipe.ID, pipe.Description, c.instance)
		}
	}

	for _, queue := range data.Queues {
		ch <- prometheus.MustNewConstMetric(c.queueFlows, prometheus.GaugeValue,
			queue.ActiveFlows, queue.ID, queue.Pipe, queue.Description, c.instance)
		ch <- prometheus.MustNewConstMetric(c.queuePackets, prometheus.GaugeValue,
			queue.Packets, queue.ID, queue.Pipe, queue.Description, c.instance)
		ch <- prometheus.MustNewConstMetric(c.queueBytes, prometheus.GaugeValue,
			queue.Bytes, queue.ID, queue.Pipe, queue.Description, c.instance)
		ch <- prometheus.MustNewConstMetric(c.queueDropPkts, prometheus.GaugeValue,
			queue.DropPackets, queue.ID, queue.Pipe, queue.Description, c.instance)
		ch <- prometheus.MustNewConstMetric(c.queueDropByt, prometheus.GaugeValue,
			queue.DropBytes, queue.ID, queue.Pipe, queue.Description, c.instance)

		if queue.ConfiguredQueueSizeOK {
			ch <- prometheus.MustNewConstMetric(c.queueConfiguredQueueSize, prometheus.GaugeValue,
				queue.ConfiguredQueueSize, queue.ID, queue.Pipe, queue.Description, queue.ConfiguredQueueSizeUnit, c.instance)
		}
		if queue.ConfiguredWeightOK {
			ch <- prometheus.MustNewConstMetric(c.queueConfiguredWeight, prometheus.GaugeValue,
				queue.ConfiguredWeight, queue.ID, queue.Pipe, queue.Description, c.instance)
		}
	}

	for _, rule := range data.Rules {
		ch <- prometheus.MustNewConstMetric(c.rulePackets, prometheus.CounterValue,
			rule.Packets, rule.Rule, rule.AttachedTo, rule.TargetType, rule.Description, c.instance)
		ch <- prometheus.MustNewConstMetric(c.ruleBytes, prometheus.CounterValue,
			rule.Bytes, rule.Rule, rule.AttachedTo, rule.TargetType, rule.Description, c.instance)
		// accessed_epoch=0 is the "never matched" sentinel (scripts/shaper/lib/
		// __init__.py), not a real Unix timestamp — omit rather than report 1970.
		if rule.LastMatchEpoch > 0 {
			ch <- prometheus.MustNewConstMetric(c.ruleLastMatch, prometheus.GaugeValue,
				rule.LastMatchEpoch, rule.Rule, rule.AttachedTo, rule.TargetType, rule.Description, c.instance)
		}
	}

	return nil
}
