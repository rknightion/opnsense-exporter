package collector

import (
	"context"
	"log/slog"
	"sync/atomic"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/rknightion/opnsense2otel/v5/internal/cpustream"
	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

// CPUStream is the process-wide seam between the SSE stream consumer and this
// collector (#559). A package-level value for the same reason as Flow and LogEvents:
// the collector self-registers via init() while the stream is constructed separately
// in main, so neither package can hand the other a reference directly.
//
// Nil source is the normal pre-wiring state and is handled: the collector then
// reports the stream down rather than emitting nothing, so a misconfiguration is
// visible instead of silent.
var CPUStream = &cpuStreamHolder{}

type cpuStreamHolder struct {
	src atomic.Pointer[func() cpustream.Snapshot]
}

// Configure wires the snapshot source. Called once from main after the stream is
// built.
func (h *cpuStreamHolder) Configure(src func() cpustream.Snapshot) {
	h.src.Store(&src)
}

func (h *cpuStreamHolder) snapshot() cpustream.Snapshot {
	if fn := h.src.Load(); fn != nil && *fn != nil {
		return (*fn)()
	}
	return cpustream.Snapshot{Seconds: map[string]float64{}}
}

// cpuCollector publishes cumulative CPU counters reconstructed from OPNsense's
// cpu_usage SSE stream, plus the stream's own health.
//
// It makes NO API call of its own. Update simply copies the accumulator's current
// values into the snapshot the serving path replays, so the poll scheduler and the
// serving path need no special case: this fills a snapshot entry from a stream
// instead of from a poll. Its poll interval therefore costs the firewall nothing and
// only controls how often the counter is re-read, which a cumulative counter is
// indifferent to.
type cpuCollector struct {
	log *slog.Logger

	seconds       *prometheus.Desc
	streamUp      *prometheus.Desc
	lastFrameAge  *prometheus.Desc
	reconnects    *prometheus.Desc
	framesTotal   *prometheus.Desc
	countersFresh *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &cpuCollector{subsystem: CPUSubsystem})
}

func (c *cpuCollector) Name() string { return c.subsystem }

func (c *cpuCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.seconds = buildPrometheusDesc(c.subsystem, "seconds_total",
		"Cumulative CPU seconds by mode, reconstructed from the api/diagnostics/cpu_usage "+
			"SSE stream as (percent/100 * measured elapsed time between frames). This is a "+
			"reconstruction from integer-percentage samples, NOT a kernel tick counter: each "+
			"sample carries up to +/-0.5% quantisation noise, which is unbiased and so does not "+
			"accumulate systematically. Absent while the stream has been silent for longer than "+
			"its grace window, because a frozen counter is indistinguishable from an idle CPU. "+
			"NOTE the difference from node_exporter's identically-named metric: OPNsense reports "+
			"CPU AGGREGATED ACROSS ALL CORES, not per core, so there is no cpu label and "+
			"sum(rate(...)) by mode is 1, not the core count. Multiply a rate by 100 to read it as "+
			"a percentage of the whole machine.",
		[]string{"mode"},
	)
	c.streamUp = buildPrometheusDesc(c.subsystem, "stream_up",
		"1 when the CPU usage SSE stream is connected, 0 otherwise. Always exported, "+
			"including while seconds_total is absent, so a stalled stream is visible rather than inferred.",
		nil,
	)
	c.lastFrameAge = buildPrometheusDesc(c.subsystem, "stream_last_frame_age_seconds",
		"Seconds since the last CPU sample was received. Absent until the first frame ever arrives. "+
			"This is the signal to alert on: the documented failure mode of this endpoint is that "+
			"keepalives keep flowing after the data has stopped, so connection liveness alone proves nothing.",
		nil,
	)
	c.reconnects = buildPrometheusDesc(c.subsystem, "stream_reconnects_total",
		"Number of times the CPU usage stream has been re-dialled since exporter start. "+
			"A steadily climbing value means the connection is being torn down repeatedly.",
		nil,
	)
	c.framesTotal = buildPrometheusDesc(c.subsystem, "stream_frames_total",
		"Number of CPU samples accepted from the stream since exporter start.",
		nil,
	)
	c.countersFresh = buildPrometheusDesc(c.subsystem, "stream_counters_published",
		"1 when seconds_total is being published, 0 when it has been withdrawn because the "+
			"stream went silent for longer than the grace window.",
		nil,
	)
}

func (c *cpuCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.seconds
	ch <- c.streamUp
	ch <- c.lastFrameAge
	ch <- c.reconnects
	ch <- c.framesTotal
	ch <- c.countersFresh
}

func (c *cpuCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	snap := CPUStream.snapshot()

	up := 0.0
	if snap.Connected {
		up = 1
	}
	fresh := 0.0
	if snap.Fresh {
		fresh = 1
	}
	ch <- prometheus.MustNewConstMetric(c.streamUp, prometheus.GaugeValue, up, c.instance)
	ch <- prometheus.MustNewConstMetric(c.countersFresh, prometheus.GaugeValue, fresh, c.instance)
	ch <- prometheus.MustNewConstMetric(c.reconnects, prometheus.CounterValue, float64(snap.Reconnects), c.instance)
	ch <- prometheus.MustNewConstMetric(c.framesTotal, prometheus.CounterValue, float64(snap.Frames), c.instance)
	// Age is emitted only once it means something. Before the first frame there is
	// no "since", and a zero would read as a perfectly fresh stream.
	if snap.HaveFrame {
		ch <- prometheus.MustNewConstMetric(
			c.lastFrameAge, prometheus.GaugeValue, snap.LastFrameAge.Seconds(), c.instance)
	}

	// The counters are withdrawn, not frozen, once the stream has been silent past
	// the grace window (#559 decision 2). Reconnect bounds an outage but cannot
	// remove it — during a firewall reboot there is nothing to reconnect to for
	// minutes. A frozen counter reads as exactly zero when the whole rate() window
	// falls inside the freeze and understates proportionally otherwise; either way
	// it is silently wrong, so absent is the honest answer.
	if !snap.Fresh {
		return nil
	}
	for _, mode := range cpustream.Modes {
		ch <- prometheus.MustNewConstMetric(
			c.seconds, prometheus.CounterValue, snap.Seconds[mode], mode, c.instance)
	}
	return nil
}
