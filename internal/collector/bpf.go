package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type bpfCollector struct {
	log *slog.Logger

	listenersTotal   *prometheus.Desc
	receivedPackets  *prometheus.Desc
	droppedPackets   *prometheus.Desc
	matchedPackets   *prometheus.Desc
	storeBufferBytes *prometheus.Desc
	holdBufferBytes  *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &bpfCollector{
		subsystem: BPFSubsystem,
	})
}

func (c *bpfCollector) Name() string { return c.subsystem }

func (c *bpfCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	perListenerLabels := []string{"process", "interface"}

	c.listenersTotal = buildPrometheusDesc(c.subsystem, "listeners_total",
		"Total number of active BPF listeners (raw entry count before aggregation)", nil)
	c.receivedPackets = buildPrometheusDesc(c.subsystem, "received_packets_total",
		"Cumulative packets received by BPF listeners for this process/interface pair",
		perListenerLabels)
	c.droppedPackets = buildPrometheusDesc(c.subsystem, "dropped_packets_total",
		"Cumulative packets dropped by BPF listeners for this process/interface pair",
		perListenerLabels)
	c.matchedPackets = buildPrometheusDesc(c.subsystem, "matched_packets_total",
		"Cumulative packets matched by BPF filter for this process/interface pair",
		perListenerLabels)
	c.storeBufferBytes = buildPrometheusDesc(c.subsystem, "store_buffer_bytes",
		"Current store buffer length in bytes for this process/interface pair",
		perListenerLabels)
	c.holdBufferBytes = buildPrometheusDesc(c.subsystem, "hold_buffer_bytes",
		"Current hold buffer length in bytes for this process/interface pair",
		perListenerLabels)
}

func (c *bpfCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.listenersTotal,
		c.receivedPackets,
		c.droppedPackets,
		c.matchedPackets,
		c.storeBufferBytes,
		c.holdBufferBytes,
	} {
		ch <- d
	}
}

func (c *bpfCollector) Update(_ context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchBPFStatistics()
	if err != nil {
		return err
	}

	// Core endpoint — always emit listeners_total even when zero BPF listeners
	// are active, so the absence of BPF activity is distinguishable from the
	// metric being absent entirely.
	ch <- prometheus.MustNewConstMetric(c.listenersTotal, prometheus.GaugeValue,
		float64(data.ListenersTotal), c.instance)

	for _, l := range data.Listeners {
		ch <- prometheus.MustNewConstMetric(c.receivedPackets, prometheus.CounterValue,
			l.ReceivedPackets, l.Process, l.Interface, c.instance)
		ch <- prometheus.MustNewConstMetric(c.droppedPackets, prometheus.CounterValue,
			l.DroppedPackets, l.Process, l.Interface, c.instance)
		ch <- prometheus.MustNewConstMetric(c.matchedPackets, prometheus.CounterValue,
			l.MatchedPackets, l.Process, l.Interface, c.instance)
		ch <- prometheus.MustNewConstMetric(c.storeBufferBytes, prometheus.GaugeValue,
			l.StoreBufferBytes, l.Process, l.Interface, c.instance)
		ch <- prometheus.MustNewConstMetric(c.holdBufferBytes, prometheus.GaugeValue,
			l.HoldBufferBytes, l.Process, l.Interface, c.instance)
	}

	return nil
}
