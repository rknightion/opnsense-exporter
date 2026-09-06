package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

type chronyCollector struct {
	log *slog.Logger

	serviceRunning       *prometheus.Desc
	stratum              *prometheus.Desc
	systemTimeOffset     *prometheus.Desc
	lastOffset           *prometheus.Desc
	rmsOffset            *prometheus.Desc
	frequencyPPM         *prometheus.Desc
	residualFrequencyPPM *prometheus.Desc
	skewPPM              *prometheus.Desc
	rootDelay            *prometheus.Desc
	rootDispersion       *prometheus.Desc
	updateInterval       *prometheus.Desc
	leapStatus           *prometheus.Desc
	trackingInfo         *prometheus.Desc
	sourcesTotal         *prometheus.Desc
	sourceSelected       *prometheus.Desc
	sourceStratum        *prometheus.Desc
	sourceReachability   *prometheus.Desc
	sourceLastRx         *prometheus.Desc
	sourceOffset         *prometheus.Desc
	sourceOffsetStdDev   *prometheus.Desc
	sourceSamples        *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &chronyCollector{
		subsystem: ChronySubsystem,
	})
}

func (c *chronyCollector) Name() string { return c.subsystem }

func (c *chronyCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	srcLabels := []string{"source", "mode"}

	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the Chrony service is running (1 = running, 0 = stopped/disabled)", nil)
	c.stratum = buildPrometheusDesc(c.subsystem, "stratum",
		"Stratum of the NTP source chrony is currently tracking", nil)
	c.systemTimeOffset = buildPrometheusDesc(c.subsystem, "system_time_offset_seconds",
		"Current system time offset relative to NTP time in seconds (fast = positive, slow = negative)", nil)
	c.lastOffset = buildPrometheusDesc(c.subsystem, "last_offset_seconds",
		"Estimated local offset on the last clock update in seconds", nil)
	c.rmsOffset = buildPrometheusDesc(c.subsystem, "rms_offset_seconds",
		"Long-term average of the offset values in seconds", nil)
	c.frequencyPPM = buildPrometheusDesc(c.subsystem, "frequency_ppm",
		"Rate at which the system clock would be wrong if chrony was not correcting it (ppm)", nil)
	c.residualFrequencyPPM = buildPrometheusDesc(c.subsystem, "residual_frequency_ppm",
		"Residual frequency offset of the NTP source (ppm)", nil)
	c.skewPPM = buildPrometheusDesc(c.subsystem, "skew_ppm",
		"Estimated error bound on the frequency (ppm)", nil)
	c.rootDelay = buildPrometheusDesc(c.subsystem, "root_delay_seconds",
		"Total of the network path delays to the stratum-1 NTP server (seconds)", nil)
	c.rootDispersion = buildPrometheusDesc(c.subsystem, "root_dispersion_seconds",
		"Total dispersion accumulated through all NTP servers back to stratum-1 (seconds)", nil)
	c.updateInterval = buildPrometheusDesc(c.subsystem, "update_interval_seconds",
		"Interval between the last two clock updates (seconds)", nil)
	c.leapStatus = buildPrometheusDesc(c.subsystem, "leap_status",
		"Leap second status (0=Normal, 1=Insert second, 2=Delete second, 3=Not synchronised)", nil)
	c.trackingInfo = buildPrometheusDesc(c.subsystem, "tracking_info",
		"Chrony tracking info label gauge (always 1) - pool-rotation note: source labels churn with pool directives; use instant queries/tables",
		[]string{"reference_id", "reference_name", "leap_status"})
	c.sourcesTotal = buildPrometheusDesc(c.subsystem, "sources",
		"Current number of NTP sources chrony is currently tracking", nil)
	c.sourceSelected = buildPrometheusDesc(c.subsystem, "source_selected",
		"Whether this source is currently selected as the best available (1 = selected)",
		srcLabels)
	c.sourceStratum = buildPrometheusDesc(c.subsystem, "source_stratum",
		"Stratum of this NTP source", srcLabels)
	c.sourceReachability = buildPrometheusDesc(c.subsystem, "source_reachability",
		"Source reachability register (0–255; 255 means all 8 last polls succeeded)", srcLabels)
	c.sourceLastRx = buildPrometheusDesc(c.subsystem, "source_last_rx_seconds",
		"Time since the last packet was received from this source (seconds)", srcLabels)
	c.sourceOffset = buildPrometheusDesc(c.subsystem, "source_offset_seconds",
		"Measured offset of the source (seconds)", srcLabels)
	c.sourceOffsetStdDev = buildPrometheusDesc(c.subsystem, "source_offset_stddev_seconds",
		"Estimated standard deviation of the source offset (seconds)", []string{"source"})
	c.sourceSamples = buildPrometheusDesc(c.subsystem, "source_samples",
		"Number of samples currently held in the regression (sourcestats)", []string{"source"})
}

func (c *chronyCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.serviceRunning, c.stratum, c.systemTimeOffset, c.lastOffset, c.rmsOffset,
		c.frequencyPPM, c.residualFrequencyPPM, c.skewPPM, c.rootDelay, c.rootDispersion,
		c.updateInterval, c.leapStatus, c.trackingInfo, c.sourcesTotal,
		c.sourceSelected, c.sourceStratum, c.sourceReachability, c.sourceLastRx,
		c.sourceOffset, c.sourceOffsetStdDev, c.sourceSamples,
	} {
		ch <- d
	}
}

func (c *chronyCollector) Update(_ context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchChronyStatus()
	if err != nil {
		return err
	}

	// Plugin absent (tracking 404): stay completely silent AND skip the
	// service-status probe — the service endpoint would just 404 too.
	if !data.Present {
		return nil
	}

	// Fetch service status first so it's emitted even when chronyd is stopped.
	status, present, sErr := client.FetchServiceStatusOptional("chronyServiceStatus")
	if sErr != nil {
		c.log.Warn("failed to fetch chrony service status", "err", sErr)
	} else if present {
		running := 0.0
		if status == "running" {
			running = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.serviceRunning, prometheus.GaugeValue,
			running, c.instance)
	}

	// Tracking metrics — only when chronyd is running and has a valid source.
	if data.Tracking.Valid {
		tr := data.Tracking
		ch <- prometheus.MustNewConstMetric(c.stratum, prometheus.GaugeValue, tr.Stratum, c.instance)
		ch <- prometheus.MustNewConstMetric(c.systemTimeOffset, prometheus.GaugeValue, tr.SystemTimeOffsetSeconds, c.instance)
		ch <- prometheus.MustNewConstMetric(c.lastOffset, prometheus.GaugeValue, tr.LastOffsetSeconds, c.instance)
		ch <- prometheus.MustNewConstMetric(c.rmsOffset, prometheus.GaugeValue, tr.RMSOffsetSeconds, c.instance)
		ch <- prometheus.MustNewConstMetric(c.frequencyPPM, prometheus.GaugeValue, tr.FrequencyPPM, c.instance)
		ch <- prometheus.MustNewConstMetric(c.residualFrequencyPPM, prometheus.GaugeValue, tr.ResidualFrequencyPPM, c.instance)
		ch <- prometheus.MustNewConstMetric(c.skewPPM, prometheus.GaugeValue, tr.SkewPPM, c.instance)
		ch <- prometheus.MustNewConstMetric(c.rootDelay, prometheus.GaugeValue, tr.RootDelaySeconds, c.instance)
		ch <- prometheus.MustNewConstMetric(c.rootDispersion, prometheus.GaugeValue, tr.RootDispersionSeconds, c.instance)
		ch <- prometheus.MustNewConstMetric(c.updateInterval, prometheus.GaugeValue, tr.UpdateIntervalSeconds, c.instance)
		ch <- prometheus.MustNewConstMetric(c.leapStatus, prometheus.GaugeValue, tr.LeapStatusValue, c.instance)
		ch <- prometheus.MustNewConstMetric(c.trackingInfo, prometheus.GaugeValue, 1,
			tr.ReferenceID, tr.ReferenceName, tr.LeapStatus, c.instance)
	}

	// Sources total + per-source metrics. Skip entirely when the sources sub-fetch
	// failed, so a transient error is not reported as a real sources=0 that
	// looks like chronyd lost all its NTP sources (#163).
	if data.HasSources {
		ch <- prometheus.MustNewConstMetric(c.sourcesTotal, prometheus.GaugeValue,
			float64(len(data.Sources)), c.instance)

		for _, src := range data.Sources {
			selected := 0.0
			if src.State == "*" {
				selected = 1.0
			}
			ch <- prometheus.MustNewConstMetric(c.sourceSelected, prometheus.GaugeValue,
				selected, src.Name, src.Mode, c.instance)
			ch <- prometheus.MustNewConstMetric(c.sourceStratum, prometheus.GaugeValue,
				src.Stratum, src.Name, src.Mode, c.instance)
			ch <- prometheus.MustNewConstMetric(c.sourceReachability, prometheus.GaugeValue,
				src.Reachability, src.Name, src.Mode, c.instance)
			if src.HasLastRx {
				ch <- prometheus.MustNewConstMetric(c.sourceLastRx, prometheus.GaugeValue,
					src.LastRxSeconds, src.Name, src.Mode, c.instance)
			}
			if src.HasOffset {
				ch <- prometheus.MustNewConstMetric(c.sourceOffset, prometheus.GaugeValue,
					src.OffsetSeconds, src.Name, src.Mode, c.instance)
			}
		}
	}

	// Per-source stats (stddev + samples). Skipped when the sourcestats sub-fetch
	// failed (#163).
	if data.HasSourceStats {
		for _, st := range data.SourceStats {
			if st.HasStdDev {
				ch <- prometheus.MustNewConstMetric(c.sourceOffsetStdDev, prometheus.GaugeValue,
					st.StdDevSeconds, st.Name, c.instance)
			}
			ch <- prometheus.MustNewConstMetric(c.sourceSamples, prometheus.GaugeValue,
				st.Samples, st.Name, c.instance)
		}
	}

	return nil
}
