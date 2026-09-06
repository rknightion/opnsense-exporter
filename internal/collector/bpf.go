package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

type bpfCollector struct {
	log *slog.Logger

	listenersTotal   *prometheus.Desc
	receivedPackets  *prometheus.Desc
	droppedPackets   *prometheus.Desc
	matchedPackets   *prometheus.Desc
	storeBufferBytes *prometheus.Desc
	holdBufferBytes  *prometheus.Desc

	directionListeners       *prometheus.Desc
	directionReceivedPackets *prometheus.Desc
	directionDroppedPackets  *prometheus.Desc
	directionMatchedPackets  *prometheus.Desc

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

	c.listenersTotal = buildPrometheusDesc(c.subsystem, "listeners",
		"Current number of active BPF listeners (raw entry count before aggregation)", nil)
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

	perDirectionLabels := []string{"process", "interface", "direction"}
	directionHelp := "`direction` is the capture direction the kernel recorded for the BPF " +
		"descriptor: `input`, `output`, `bidirectional`, or `unknown` when the box reported none. " +
		"It is a closed three-value vocabulary, so this breakdown stays bounded at three times the " +
		"pair count. "

	c.directionListeners = buildPrometheusDesc(c.subsystem, "direction_listeners",
		"Number of open BPF descriptors for this process/interface/direction. "+directionHelp+
			"A process holding one descriptor per port (lldpd does) shows one series per port here, "+
			"which is normal; a count that climbs without the process count changing is a "+
			"descriptor leak.",
		perDirectionLabels)
	c.directionReceivedPackets = buildPrometheusDesc(c.subsystem, "direction_received_packets_total",
		"Cumulative packets received by BPF listeners for this process/interface/direction. "+
			"Per-direction breakdown of bpf_received_packets_total, which remains the sum across "+
			"directions. "+directionHelp,
		perDirectionLabels)
	c.directionDroppedPackets = buildPrometheusDesc(c.subsystem, "direction_dropped_packets_total",
		"Cumulative packets dropped by BPF listeners for this process/interface/direction — the "+
			"consumer could not read the buffer fast enough, so the capture is incomplete. "+
			"Per-direction breakdown of bpf_dropped_packets_total. "+directionHelp,
		perDirectionLabels)
	c.directionMatchedPackets = buildPrometheusDesc(c.subsystem, "direction_matched_packets_total",
		"Cumulative packets matched by the BPF filter for this process/interface/direction. "+
			"Per-direction breakdown of bpf_matched_packets_total. "+directionHelp,
		perDirectionLabels)
}

func (c *bpfCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.listenersTotal,
		c.receivedPackets,
		c.droppedPackets,
		c.matchedPackets,
		c.storeBufferBytes,
		c.holdBufferBytes,
		c.directionListeners,
		c.directionReceivedPackets,
		c.directionDroppedPackets,
		c.directionMatchedPackets,
	} {
		ch <- d
	}
}

func (c *bpfCollector) Update(_ context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchBPFStatistics()
	if err != nil {
		return err
	}

	// Core endpoint — always emit listeners even when zero BPF listeners
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

	// Same data with the capture direction kept on the key rather than summed
	// away (#544). The buffer-length gauges are deliberately NOT repeated here:
	// they are instantaneous per-descriptor depths whose sum is already only
	// loosely meaningful, and splitting them further adds no diagnostic value.
	for _, d := range data.ByDirection {
		ch <- prometheus.MustNewConstMetric(c.directionListeners, prometheus.GaugeValue,
			float64(d.Listeners), d.Process, d.Interface, d.Direction, c.instance)
		ch <- prometheus.MustNewConstMetric(c.directionReceivedPackets, prometheus.CounterValue,
			d.ReceivedPackets, d.Process, d.Interface, d.Direction, c.instance)
		ch <- prometheus.MustNewConstMetric(c.directionDroppedPackets, prometheus.CounterValue,
			d.DroppedPackets, d.Process, d.Interface, d.Direction, c.instance)
		ch <- prometheus.MustNewConstMetric(c.directionMatchedPackets, prometheus.CounterValue,
			d.MatchedPackets, d.Process, d.Interface, d.Direction, c.instance)
	}

	return nil
}
