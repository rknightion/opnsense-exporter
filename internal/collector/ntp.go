package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v4/opnsense"
)

type ntpCollector struct {
	log *slog.Logger

	peerInfo               *prometheus.Desc
	peerStratum            *prometheus.Desc
	peerWhenSeconds        *prometheus.Desc
	peerPollSeconds        *prometheus.Desc
	peerReach              *prometheus.Desc
	peerDelayMilliseconds  *prometheus.Desc
	peerOffsetMilliseconds *prometheus.Desc
	peerJitterMilliseconds *prometheus.Desc
	peersTotal             *prometheus.Desc

	gpsOK         *prometheus.Desc
	gpsSatellites *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &ntpCollector{
		subsystem: NTPSubsystem,
	})
}

func (c *ntpCollector) Name() string {
	return c.subsystem
}

func (c *ntpCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.peerInfo = buildPrometheusDesc(c.subsystem, "peer_info",
		"NTP peer information (value is always 1)",
		[]string{"server", "refid", "type", "status"},
	)
	c.peerStratum = buildPrometheusDesc(c.subsystem, "peer_stratum",
		"Stratum level of the NTP peer",
		[]string{"server"},
	)
	c.peerWhenSeconds = buildPrometheusDesc(c.subsystem, "peer_when_seconds",
		"Seconds since last response from the NTP peer",
		[]string{"server"},
	)
	c.peerPollSeconds = buildPrometheusDesc(c.subsystem, "peer_poll_seconds",
		"Poll interval in seconds for the NTP peer",
		[]string{"server"},
	)
	c.peerReach = buildPrometheusDesc(c.subsystem, "peer_reach",
		"Reachability register of the NTP peer (octal decoded to decimal)",
		[]string{"server"},
	)
	c.peerDelayMilliseconds = buildPrometheusDesc(c.subsystem, "peer_delay_milliseconds",
		"Round-trip delay to the NTP peer in milliseconds",
		[]string{"server"},
	)
	c.peerOffsetMilliseconds = buildPrometheusDesc(c.subsystem, "peer_offset_milliseconds",
		"Clock offset relative to the NTP peer in milliseconds",
		[]string{"server"},
	)
	c.peerJitterMilliseconds = buildPrometheusDesc(c.subsystem, "peer_jitter_milliseconds",
		"Dispersion jitter of the NTP peer in milliseconds",
		[]string{"server"},
	)
	c.peersTotal = buildPrometheusDesc(c.subsystem, "peers_total",
		"Total number of NTP peers",
		nil,
	)
	c.gpsOK = buildPrometheusDesc(c.subsystem, "gps_ok",
		"Whether the last NMEA sentence from a GPS refclock reported a valid fix (1 = ok, 0 = no fix). "+
			"EXPERIMENTAL: derived from OPNsense source, not validated against real GPS hardware (#224). "+
			"Absent entirely when no GPS refclock is attached/reporting.",
		nil,
	)
	c.gpsSatellites = buildPrometheusDesc(c.subsystem, "gps_satellites",
		"Number of satellites used in the last GPS fix ($GPGGA sentences only; absent for sentences that don't carry a satellite count). "+
			"EXPERIMENTAL: derived from OPNsense source, not validated against real GPS hardware (#224).",
		nil,
	)
}

func (c *ntpCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.peerInfo
	ch <- c.peerStratum
	ch <- c.peerWhenSeconds
	ch <- c.peerPollSeconds
	ch <- c.peerReach
	ch <- c.peerDelayMilliseconds
	ch <- c.peerOffsetMilliseconds
	ch <- c.peerJitterMilliseconds
	ch <- c.peersTotal
	ch <- c.gpsOK
	ch <- c.gpsSatellites
}

func (c *ntpCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchNTPStatus()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(
		c.peersTotal,
		prometheus.GaugeValue,
		float64(len(data.Peers)),
		c.instance,
	)

	// Every per-peer metric is keyed on server (peer_info also carries refid/type/
	// status), and two configured associations can reference the same remote, which
	// would emit identical label tuples and fail the whole scrape. Dedupe by server
	// so the first association for a given remote wins (#85).
	seen := make(map[string]bool, len(data.Peers))
	for _, peer := range data.Peers {
		if seen[peer.Server] {
			c.log.Warn("skipping NTP peer with duplicate server label", "server", peer.Server)
			continue
		}
		seen[peer.Server] = true

		ch <- prometheus.MustNewConstMetric(
			c.peerInfo,
			prometheus.GaugeValue,
			1,
			peer.Server,
			peer.RefID,
			peer.Type,
			peer.Status,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.peerStratum,
			prometheus.GaugeValue,
			float64(peer.Stratum),
			peer.Server,
			c.instance,
		)
		// Skip when/poll when the source value was unknown ("-") or unparseable,
		// rather than emitting 0 — which would read as "responded just now" and
		// invert the staleness signal (#89).
		if peer.WhenValid {
			ch <- prometheus.MustNewConstMetric(
				c.peerWhenSeconds,
				prometheus.GaugeValue,
				peer.WhenSeconds,
				peer.Server,
				c.instance,
			)
		}
		if peer.PollValid {
			ch <- prometheus.MustNewConstMetric(
				c.peerPollSeconds,
				prometheus.GaugeValue,
				peer.PollSeconds,
				peer.Server,
				c.instance,
			)
		}
		ch <- prometheus.MustNewConstMetric(
			c.peerReach,
			prometheus.GaugeValue,
			float64(peer.Reach),
			peer.Server,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.peerDelayMilliseconds,
			prometheus.GaugeValue,
			peer.DelayMillis,
			peer.Server,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.peerOffsetMilliseconds,
			prometheus.GaugeValue,
			peer.OffsetMillis,
			peer.Server,
			c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.peerJitterMilliseconds,
			prometheus.GaugeValue,
			peer.JitterMillis,
			peer.Server,
			c.instance,
		)
	}

	gps, gpsErr := client.FetchNTPGPSStatus()
	if gpsErr != nil {
		return gpsErr
	}

	// No GPS refclock reporting a fix: stay completely silent rather than
	// emitting a fake 0 (absent hardware => absent series, #224).
	if gps.Present {
		ch <- prometheus.MustNewConstMetric(
			c.gpsOK,
			prometheus.GaugeValue,
			boolToGauge(gps.OK),
			c.instance,
		)
		if gps.SatellitesValid {
			ch <- prometheus.MustNewConstMetric(
				c.gpsSatellites,
				prometheus.GaugeValue,
				float64(gps.Satellites),
				c.instance,
			)
		}
	}

	return nil
}
