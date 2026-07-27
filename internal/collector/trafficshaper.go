package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
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

	c.pipesTotal = buildPrometheusDesc(c.subsystem, "pipes_total",
		"Total number of configured traffic shaper pipes", nil)
	c.queuesTotal = buildPrometheusDesc(c.subsystem, "queues_total",
		"Total number of configured traffic shaper queues (excluding template queues)", nil)

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
}

func (c *trafficShaperCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.pipesTotal, c.queuesTotal,
		c.pipeFlows, c.pipePackets, c.pipeBytes, c.pipeDropPkts, c.pipeDropBytes,
		c.queueFlows, c.queuePackets, c.queueBytes, c.queueDropPkts, c.queueDropByt,
		c.rulePackets, c.ruleBytes, c.ruleLastMatch,
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
	// pipes_total EXISTS (#414). Emitting zeros here would show an empty tab on
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
