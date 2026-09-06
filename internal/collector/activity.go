package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

// activityCollector exports thread-state counts from api/diagnostics/activity.
//
// CPU utilisation used to live here too and no longer does (#559): it comes from the
// cpu_usage SSE stream as cumulative counters instead. What remains is the only thing
// this endpoint uniquely provides — and it is expensive, at a measured 2.15 s of
// firewall work per call, because OPNsense's activity.py runs `top -aHSTn -d2` and
// waits out top's inter-display delay. Thread counts are instantaneous gauges with no
// sub-minute alerting story, so the collector sits on the medium tier: that alone
// takes this endpoint from a 14% firewall duty cycle to 3.6%.
type activityCollector struct {
	log *slog.Logger

	threadsTotal    *prometheus.Desc
	threadsRunning  *prometheus.Desc
	threadsSleeping *prometheus.Desc
	threadsWaiting  *prometheus.Desc

	arcComponent    *prometheus.Desc
	arcCompressed   *prometheus.Desc
	arcUncompressed *prometheus.Desc

	userCPU        *prometheus.Desc
	userMemory     *prometheus.Desc
	commandCPU     *prometheus.Desc
	commandMemory  *prometheus.Desc
	commandThreads *prometheus.Desc

	commandsTracked *prometheus.Desc
	commandsCapped  *prometheus.Desc

	// commandsCappedTotal accumulates the per-poll fold counts into the monotonic
	// counter the metric exposes. The aggregation itself is rebuilt from scratch on
	// every poll, so its own figure is a per-poll delta, not a running total.
	commandsCappedTotal float64

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &activityCollector{
		subsystem: ActivitySubsystem,
	})
}

func (c *activityCollector) Name() string {
	return c.subsystem
}

func (c *activityCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.threadsTotal = buildPrometheusDesc(c.subsystem, "threads",
		"Current number of threads on the system",
		nil,
	)
	c.threadsRunning = buildPrometheusDesc(c.subsystem, "threads_running",
		"Number of running threads on the system",
		nil,
	)
	c.threadsSleeping = buildPrometheusDesc(c.subsystem, "threads_sleeping",
		"Number of sleeping threads on the system",
		nil,
	)
	c.threadsWaiting = buildPrometheusDesc(c.subsystem, "threads_waiting",
		"Number of waiting threads on the system",
		nil,
	)
	// ZFS ARC composition (#551), free from the payload this collector already
	// fetches. The ARC TOTAL stays on opnsense_system_memory_arc_bytes and is
	// deliberately not re-exported here — one series with two differently-timed
	// sources would disagree with itself. These series are ABSENT on a non-ZFS box.
	c.arcComponent = buildPrometheusDesc(c.subsystem, "arc_component_bytes",
		"ZFS ARC size by component (MFU, MRU, anonymous, header, other), from top's ARC header. "+
			"MFU versus MRU is the standard read on whether the cache is serving a working set or "+
			"thrashing. Absent entirely on a non-ZFS install. The ARC total is opnsense_system_memory_arc_bytes.",
		[]string{"component"},
	)
	c.arcCompressed = buildPrometheusDesc(c.subsystem, "arc_compressed_bytes",
		"Size of ZFS ARC contents as held in memory, compressed. Divide the uncompressed figure by "+
			"this to get the compression ratio at query time.",
		nil,
	)
	c.arcUncompressed = buildPrometheusDesc(c.subsystem, "arc_uncompressed_bytes",
		"Logical size of ZFS ARC contents before compression. Absent when top reports no compression line.",
		nil,
	)

	// Process-table aggregates (#552), free from the payload this collector already
	// fetches. Aggregated only — never one series per PID or per thread, because those
	// identifiers churn on a timescale of minutes and abandoned series make rate()
	// meaningless.
	const idleNote = "The kernel idle threads are EXCLUDED from every process aggregate: on a healthy box " +
		"they are the top rows at ~98% CPU, one per core, and would dominate every panel. Their absence " +
		"is deliberate, not a gap."
	const cappedNote = "The command label set is bounded; commands past the cap fold into command=\"__other__\" " +
		"and are counted by opnsense_activity_commands_capped_total."

	c.userCPU = buildPrometheusDesc(c.subsystem, "user_cpu_percent",
		"Weighted CPU percentage summed across every thread owned by this username, from top's WCPU "+
			"column. Sums per thread, so a busy multi-threaded process can exceed 100. "+idleNote,
		[]string{"user"},
	)
	c.userMemory = buildPrometheusDesc(c.subsystem, "user_memory_bytes",
		"Resident memory summed across the processes owned by this username, from top's RES column. "+
			"Counted once per PROCESS: top prints one row per thread and every thread repeats its "+
			"process's RES, so the rows are deduplicated by PID before summing. "+idleNote,
		[]string{"user"},
	)
	c.commandCPU = buildPrometheusDesc(c.subsystem, "command_cpu_percent",
		"Weighted CPU percentage summed across every thread of this command, from top's WCPU column. "+
			"The command name is normalised: the {thread-name} suffix and [] kernel brackets are "+
			"stripped. "+idleNote+" "+cappedNote,
		[]string{"command"},
	)
	c.commandMemory = buildPrometheusDesc(c.subsystem, "command_memory_bytes",
		"Resident memory summed across the processes running this command, from top's RES column. "+
			"Counted once per PROCESS, deduplicated by PID — every thread row repeats its process's "+
			"RES, so summing the rows would multiply a process's memory by its thread count. "+
			idleNote+" "+cappedNote,
		[]string{"command"},
	)
	c.commandThreads = buildPrometheusDesc(c.subsystem, "command_threads",
		"Number of threads running this command. The one signal here that no other exported metric "+
			"carries: a process leaking threads is invisible everywhere else. "+idleNote+" "+cappedNote,
		[]string{"command"},
	)
	c.commandsTracked = buildPrometheusDesc(c.subsystem, "commands_tracked",
		"Number of distinct command labels in the process aggregates this poll, against a cap of "+
			"128. At the cap the label set has saturated and new commands are invisible except "+
			"through the __other__ bucket.",
		nil,
	)
	c.commandsCapped = buildPrometheusDesc(c.subsystem, "commands_capped_total",
		"Cumulative count of process-table rows folded into command=\"__other__\" because the "+
			"command label set was already at its cap. Zero on any normal firewall; a rising rate "+
			"means the aggregates are no longer naming everything they measure.",
		nil,
	)
}

func (c *activityCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.threadsTotal
	ch <- c.threadsRunning
	ch <- c.threadsSleeping
	ch <- c.threadsWaiting
	ch <- c.arcComponent
	ch <- c.arcCompressed
	ch <- c.arcUncompressed
	ch <- c.userCPU
	ch <- c.userMemory
	ch <- c.commandCPU
	ch <- c.commandMemory
	ch <- c.commandThreads
	ch <- c.commandsTracked
	ch <- c.commandsCapped
}

func (c *activityCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchActivity()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(
		c.threadsTotal,
		prometheus.GaugeValue,
		float64(data.ThreadsTotal),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.threadsRunning,
		prometheus.GaugeValue,
		float64(data.ThreadsRunning),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.threadsSleeping,
		prometheus.GaugeValue,
		float64(data.ThreadsSleeping),
		c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.threadsWaiting,
		prometheus.GaugeValue,
		float64(data.ThreadsWaiting),
		c.instance,
	)

	c.collectProcesses(data.Processes, ch)

	// Absent means absent. A UFS box has no ARC at all, and it does not announce that
	// by omitting the header — it emits a bare "ARC: " with nothing after it — so
	// publishing zeros here would show every non-ZFS firewall as having a real,
	// permanently empty cache.
	if !data.ARC.Present {
		return nil
	}
	for component, value := range map[string]float64{
		"mfu":    data.ARC.MFUBytes,
		"mru":    data.ARC.MRUBytes,
		"anon":   data.ARC.AnonBytes,
		"header": data.ARC.HeaderBytes,
		"other":  data.ARC.OtherBytes,
	} {
		ch <- prometheus.MustNewConstMetric(
			c.arcComponent, prometheus.GaugeValue, value, component, c.instance)
	}
	if data.ARC.HasCompression {
		ch <- prometheus.MustNewConstMetric(
			c.arcCompressed, prometheus.GaugeValue, data.ARC.CompressedBytes, c.instance)
		ch <- prometheus.MustNewConstMetric(
			c.arcUncompressed, prometheus.GaugeValue, data.ARC.UncompressedBytes, c.instance)
	}
	return nil
}

// collectProcesses emits the aggregated process-table series (#552).
//
// The aggregation is rebuilt from the payload on every poll, so a command that stops
// running goes ABSENT on the next scrape rather than freezing at its last value —
// which is the correct reading of "this process is no longer here".
func (c *activityCollector) collectProcesses(p opnsense.ProcessAggregate, ch chan<- prometheus.Metric) {
	for user, value := range p.CPUPercentByUser {
		ch <- prometheus.MustNewConstMetric(c.userCPU, prometheus.GaugeValue, value, user, c.instance)
	}
	for user, value := range p.MemoryBytesByUser {
		ch <- prometheus.MustNewConstMetric(c.userMemory, prometheus.GaugeValue, value, user, c.instance)
	}
	for command, value := range p.CPUPercentByCommand {
		ch <- prometheus.MustNewConstMetric(c.commandCPU, prometheus.GaugeValue, value, command, c.instance)
	}
	for command, value := range p.MemoryBytesByCommand {
		ch <- prometheus.MustNewConstMetric(c.commandMemory, prometheus.GaugeValue, value, command, c.instance)
	}
	for command, value := range p.ThreadsByCommand {
		ch <- prometheus.MustNewConstMetric(c.commandThreads, prometheus.GaugeValue, value, command, c.instance)
	}

	stats := p.Stats()
	c.commandsCappedTotal += float64(stats.Capped)
	ch <- prometheus.MustNewConstMetric(
		c.commandsTracked, prometheus.GaugeValue, float64(stats.Commands), c.instance)
	ch <- prometheus.MustNewConstMetric(
		c.commandsCapped, prometheus.CounterValue, c.commandsCappedTotal, c.instance)
}
