// Package collector implements the NetBird node-local collector.
//
// This collector reports management/signal-plane connectivity, relay
// availability, and (opt-in) per-peer connection type/traffic/latency for the
// os-netbird plugin — the direct analogue of the tailscale collector. See
// opnsense/netbird.go for the full verification status of the underlying
// payload: the aggregate/unenrolled shape is live-verified; per-peer detail
// fields are source-derived only (no netbird enrollment was available, #211).
package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type netbirdCollector struct {
	log *slog.Logger

	managementConnected *prometheus.Desc
	signalConnected     *prometheus.Desc
	relaysTotal         *prometheus.Desc
	relaysAvailable     *prometheus.Desc
	peersTotal          *prometheus.Desc
	peersConnected      *prometheus.Desc
	serviceRunning      *prometheus.Desc
	info                *prometheus.Desc
	daemonState         *prometheus.Desc

	peerConnected     *prometheus.Desc
	peerDirect        *prometheus.Desc
	peerRxBytes       *prometheus.Desc
	peerTxBytes       *prometheus.Desc
	peerLastHandshake *prometheus.Desc
	peerLatency       *prometheus.Desc

	subsystem      string
	instance       string
	detailsEnabled bool
}

func init() {
	collectorInstances = append(collectorInstances, &netbirdCollector{
		subsystem: NetbirdSubsystem,
	})
}

func (c *netbirdCollector) Name() string {
	return c.subsystem
}

// SetDetailsEnabled enables per-peer detail metrics (gated behind
// --exporter.enable-netbird-details).
func (c *netbirdCollector) SetDetailsEnabled(enabled bool) {
	c.detailsEnabled = enabled
}

func (c *netbirdCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	peerLabels := []string{"fqdn"}

	c.managementConnected = buildPrometheusDesc(c.subsystem, "management_connected",
		"Whether this node's netbird daemon has an active connection to the management server (1 = connected, 0 = not)", nil)
	c.signalConnected = buildPrometheusDesc(c.subsystem, "signal_connected",
		"Whether this node's netbird daemon has an active connection to the signal server (1 = connected, 0 = not)", nil)
	c.relaysTotal = buildPrometheusDesc(c.subsystem, "relays_total",
		"Number of relay servers known to this node's netbird daemon", nil)
	c.relaysAvailable = buildPrometheusDesc(c.subsystem, "relays_available",
		"Number of relay servers currently reachable from this node's netbird daemon", nil)
	c.peersTotal = buildPrometheusDesc(c.subsystem, "peers_total",
		"Number of netbird network peers known to this node", nil)
	c.peersConnected = buildPrometheusDesc(c.subsystem, "peers_connected",
		"Number of netbird network peers this node currently has an active WireGuard connection to", nil)
	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the netbird plugin service is running (1 = running, 0 = stopped/disabled)", nil)
	c.info = buildPrometheusDesc(c.subsystem, "info",
		"NetBird node version information (value is always 1; see labels). Only emitted when the daemon reports version data (absent while the daemon itself is down)",
		[]string{"cli_version", "daemon_version"})
	c.daemonState = buildPrometheusDesc(c.subsystem, "daemon_state",
		"Current state of this node's netbird daemon (#455; always 1; exactly one series per scrape). state is drawn from netbird's closed DaemonStatus vocabulary - Idle, Connecting, Connected, NeedsLogin, LoginFailed, SessionExpired - and anything else, including a future upstream state, collapses to unknown. Idle is a normal lazy-connection state, NOT a fault; NeedsLogin/SessionExpired mean the peer needs operator re-authentication. Only emitted when the daemon reported a daemonStatus (absent while the daemon itself is down).",
		[]string{"state"})

	c.peerConnected = buildPrometheusDesc(c.subsystem, "peer_connected",
		"Whether this node currently has an active WireGuard connection to the peer (1 = connected, 0 = not). Only emitted when --exporter.enable-netbird-details is set.",
		peerLabels)
	c.peerDirect = buildPrometheusDesc(c.subsystem, "peer_direct",
		"Whether the connection to the peer uses a direct P2P path (1 = direct, 0 = relayed). Only emitted for peers with an active connection and when --exporter.enable-netbird-details is set.",
		peerLabels)
	c.peerRxBytes = buildPrometheusDesc(c.subsystem, "peer_received_bytes_total",
		"Bytes received from this peer since the netbird daemon started. Only emitted when --exporter.enable-netbird-details is set.",
		peerLabels)
	c.peerTxBytes = buildPrometheusDesc(c.subsystem, "peer_transmitted_bytes_total",
		"Bytes transmitted to this peer since the netbird daemon started. Only emitted when --exporter.enable-netbird-details is set.",
		peerLabels)
	c.peerLastHandshake = buildPrometheusDesc(c.subsystem, "peer_last_handshake_timestamp_seconds",
		"Unix timestamp of the last WireGuard handshake with this peer. Only emitted for peers with an active connection and a recorded handshake, and when --exporter.enable-netbird-details is set.",
		peerLabels)
	c.peerLatency = buildPrometheusDesc(c.subsystem, "peer_latency_seconds",
		"Measured round-trip latency to this peer. Only emitted for peers with an active connection and a recorded latency, and when --exporter.enable-netbird-details is set.",
		peerLabels)
}

func (c *netbirdCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.managementConnected
	ch <- c.signalConnected
	ch <- c.relaysTotal
	ch <- c.relaysAvailable
	ch <- c.peersTotal
	ch <- c.peersConnected
	ch <- c.serviceRunning
	ch <- c.info
	ch <- c.daemonState
	ch <- c.peerConnected
	ch <- c.peerDirect
	ch <- c.peerRxBytes
	ch <- c.peerTxBytes
	ch <- c.peerLastHandshake
	ch <- c.peerLatency
}

func (c *netbirdCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchNetbirdStatus()
	if err != nil {
		return err
	}
	if !data.Present {
		// Plugin not installed — stay completely silent (do not probe the
		// service-status endpoint either; it would 404 every scheduled poll).
		return nil
	}

	mgmtVal := 0.0
	if data.ManagementConnected {
		mgmtVal = 1.0
	}
	ch <- prometheus.MustNewConstMetric(c.managementConnected, prometheus.GaugeValue,
		mgmtVal, c.instance)

	sigVal := 0.0
	if data.SignalConnected {
		sigVal = 1.0
	}
	ch <- prometheus.MustNewConstMetric(c.signalConnected, prometheus.GaugeValue,
		sigVal, c.instance)

	ch <- prometheus.MustNewConstMetric(c.relaysTotal, prometheus.GaugeValue,
		float64(data.RelaysTotal), c.instance)
	ch <- prometheus.MustNewConstMetric(c.relaysAvailable, prometheus.GaugeValue,
		float64(data.RelaysAvailable), c.instance)
	ch <- prometheus.MustNewConstMetric(c.peersTotal, prometheus.GaugeValue,
		float64(data.PeersTotal), c.instance)
	ch <- prometheus.MustNewConstMetric(c.peersConnected, prometheus.GaugeValue,
		float64(data.PeersConnected), c.instance)

	// Only emitted when the daemon actually reported version data — the
	// bare-[] daemon-down fallback carries no version strings, and emitting
	// info with empty label values would be a meaningless series.
	if data.DaemonUp && (data.CliVersion != "" || data.DaemonVersion != "") {
		ch <- prometheus.MustNewConstMetric(c.info, prometheus.GaugeValue,
			1, data.CliVersion, data.DaemonVersion, c.instance)
	}

	// #455: exactly one series for the CURRENT state, so the label stays
	// bounded and a state change never leaves a stale series behind. Absent
	// entirely when daemonStatus itself was empty (DaemonStateValid false) —
	// mirrors firmware's CheckPresent gate rather than fabricating a state.
	if data.DaemonStateValid {
		ch <- prometheus.MustNewConstMetric(c.daemonState, prometheus.GaugeValue,
			1, data.DaemonState, c.instance)
	}

	if c.detailsEnabled {
		for _, p := range data.Peers {
			connVal := 0.0
			if p.Connected {
				connVal = 1.0
			}
			ch <- prometheus.MustNewConstMetric(c.peerConnected, prometheus.GaugeValue,
				connVal, p.FQDN, c.instance)
			ch <- prometheus.MustNewConstMetric(c.peerRxBytes, prometheus.CounterValue,
				p.ReceivedBytes, p.FQDN, c.instance)
			ch <- prometheus.MustNewConstMetric(c.peerTxBytes, prometheus.CounterValue,
				p.TransmittedBytes, p.FQDN, c.instance)
			// Direct/handshake/latency only make sense for an active connection:
			// an idle peer's CLI values are "-"/zero-time/zero, and emitting them
			// would conflate "relayed"/"zero latency" with "not connected at all"
			// (mirrors tailscale.go's peer_direct guard).
			if p.Connected {
				directVal := 0.0
				if p.Direct {
					directVal = 1.0
				}
				ch <- prometheus.MustNewConstMetric(c.peerDirect, prometheus.GaugeValue,
					directVal, p.FQDN, c.instance)
				if p.HasHandshake {
					ch <- prometheus.MustNewConstMetric(c.peerLastHandshake, prometheus.GaugeValue,
						p.LastHandshakeSeconds, p.FQDN, c.instance)
				}
				if p.HasLatency {
					ch <- prometheus.MustNewConstMetric(c.peerLatency, prometheus.GaugeValue,
						p.LatencySeconds, p.FQDN, c.instance)
				}
			}
		}
	}

	status, present, sErr := client.FetchServiceStatusOptional("netbirdServiceStatus")
	if sErr != nil {
		c.log.Warn("failed to fetch netbird service status", "err", sErr)
	} else if present {
		val := 0.0
		if status == "running" {
			val = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.serviceRunning, prometheus.GaugeValue,
			val, c.instance)
	}

	return nil
}
