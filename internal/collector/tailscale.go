// Package collector implements the Tailscale node-local collector.
//
// This collector is complementary to tailscale2otel: it exports only
// node-local signals (per-peer traffic as seen from this node, local
// WireGuard session state derived from handshakes, plugin service state).
// Fleet/control-plane data — including the coordination-server Online flag —
// is deliberately not exported here.
package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v5/opnsense"
)

type tailscaleCollector struct {
	log *slog.Logger

	serviceRunning         *prometheus.Desc
	backendRunning         *prometheus.Desc
	info                   *prometheus.Desc
	peersTotal             *prometheus.Desc
	peersWithActiveSession *prometheus.Desc
	healthWarnings         *prometheus.Desc
	peerSessionActive      *prometheus.Desc
	peerDirect             *prometheus.Desc
	peerRxBytes            *prometheus.Desc
	peerTxBytes            *prometheus.Desc
	peerLastHandshake      *prometheus.Desc
	reauthRequired         *prometheus.Desc
	keyExpiry              *prometheus.Desc

	subsystem      string
	instance       string
	detailsEnabled bool
}

func init() {
	collectorInstances = append(collectorInstances, &tailscaleCollector{
		subsystem: TailscaleSubsystem,
	})
}

func (c *tailscaleCollector) Name() string {
	return c.subsystem
}

// SetDetailsEnabled enables per-peer detail metrics (gated behind
// --exporter.enable-tailscale-peer-details).
func (c *tailscaleCollector) SetDetailsEnabled(enabled bool) {
	c.detailsEnabled = enabled
}

func (c *tailscaleCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	peerLabels := []string{"peer"}

	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the Tailscale plugin service is running (1 = running, 0 = stopped/disabled)", nil)
	c.backendRunning = buildPrometheusDesc(c.subsystem, "backend_running",
		"Whether the tailscaled backend state is Running (1 = Running, 0 = anything else)", nil)
	c.info = buildPrometheusDesc(c.subsystem, "info",
		"Tailscale node information (value is always 1; see labels)",
		[]string{"version", "relay"})
	c.peersTotal = buildPrometheusDesc(c.subsystem, "peers",
		"Current number of tailnet peers known to this node", nil)
	c.peersWithActiveSession = buildPrometheusDesc(c.subsystem, "peers_with_active_session",
		"Number of tailnet peers with an established WireGuard session from this node (derived from local last-handshake presence, not coordination-server online state)", nil)
	c.healthWarnings = buildPrometheusDesc(c.subsystem, "health_warnings",
		"Number of live health warning strings reported by the local tailscaled client (e.g. update available, DERP unreachable, key expiry). The warning text itself is never exported as a label.", nil)
	c.peerSessionActive = buildPrometheusDesc(c.subsystem, "peer_session_active",
		"Whether this node has an established WireGuard session with the peer (1 = a handshake has been recorded since tailscaled start). Node-local; deliberately not the coordination-server online flag. Only emitted when --exporter.enable-tailscale-peer-details is set.",
		peerLabels)
	c.peerDirect = buildPrometheusDesc(c.subsystem, "peer_direct",
		"Whether the established session to the peer uses a direct (non-relayed) path (1 = direct, 0 = DERP-relayed). Only emitted for peers with a WireGuard session and when --exporter.enable-tailscale-peer-details is set.",
		peerLabels)
	c.peerRxBytes = buildPrometheusDesc(c.subsystem, "peer_rx_bytes_total",
		"Bytes received from this peer by this node since tailscaled start. Only emitted when --exporter.enable-tailscale-peer-details is set.",
		peerLabels)
	c.peerTxBytes = buildPrometheusDesc(c.subsystem, "peer_tx_bytes_total",
		"Bytes sent to this peer by this node since tailscaled start. Only emitted when --exporter.enable-tailscale-peer-details is set.",
		peerLabels)
	c.peerLastHandshake = buildPrometheusDesc(c.subsystem, "peer_last_handshake_timestamp_seconds",
		"Unix timestamp of the last WireGuard handshake with this peer from this node. Only emitted when --exporter.enable-tailscale-peer-details is set.",
		peerLabels)

	// #583. PRESENCE ONLY, and that is a hard rule: the AuthURL tailscaled is
	// holding is a one-click credential - anyone who reads it can authorise this
	// node onto the tailnet - so it is never a label value and never a metric
	// value. backend_running already goes to 0 in this state, but it goes to 0
	// for every other reason too; this isolates the one cause that needs a human
	// rather than a restart.
	c.reauthRequired = buildPrometheusDesc(c.subsystem, "reauth_required",
		"Whether tailscaled is parked waiting for an interactive login (1 = it is holding an auth URL). The tunnel stays down until a human completes the login - no restart or retry clears it. Distinct from backend_running, which reads 0 for this and every other reason. The auth URL itself is a credential and is never exported, in a label or anywhere else.",
		nil)
	// Self only. Peer key expiry is fleet inventory and belongs to
	// tailscale2otel; tailscale.go enforces that structurally by declaring
	// KeyExpiry on the Self type alone.
	c.keyExpiry = buildPrometheusDesc(c.subsystem, "key_expiry_timestamp_seconds",
		"Unix timestamp at which THIS node's own Tailscale key expires. When it does the tunnel dies with no other warning, so this is the direct analogue of a certificate expiry gauge. Not emitted at all when the node key does not expire - upstream omits the field entirely then, and a 0 would read as \"expired in 1970\" and page forever on a healthy node. Self only: peer key expiry is fleet inventory covered by tailscale2otel.",
		nil)
}

func (c *tailscaleCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.serviceRunning
	ch <- c.backendRunning
	ch <- c.info
	ch <- c.peersTotal
	ch <- c.peersWithActiveSession
	ch <- c.healthWarnings
	ch <- c.peerSessionActive
	ch <- c.peerDirect
	ch <- c.peerRxBytes
	ch <- c.peerTxBytes
	ch <- c.peerLastHandshake
	ch <- c.reauthRequired
	ch <- c.keyExpiry
}

func (c *tailscaleCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchTailscaleStatus()
	if err != nil {
		return err
	}
	if !data.Present {
		// Plugin not installed — stay completely silent (do not probe the
		// service-status endpoint either; it would 404 every scheduled poll).
		return nil
	}

	backendVal := 0.0
	if data.BackendState == "Running" {
		backendVal = 1.0
	}
	ch <- prometheus.MustNewConstMetric(c.backendRunning, prometheus.GaugeValue,
		backendVal, c.instance)
	ch <- prometheus.MustNewConstMetric(c.info, prometheus.GaugeValue,
		1, data.Version, data.SelfRelay, c.instance)
	ch <- prometheus.MustNewConstMetric(c.peersTotal, prometheus.GaugeValue,
		float64(data.PeersTotal), c.instance)
	ch <- prometheus.MustNewConstMetric(c.peersWithActiveSession, prometheus.GaugeValue,
		float64(data.PeersWithActiveSession), c.instance)
	ch <- prometheus.MustNewConstMetric(c.healthWarnings, prometheus.GaugeValue,
		float64(data.HealthWarnings), c.instance)

	reauthVal := 0.0
	if data.ReauthRequired {
		reauthVal = 1.0
	}
	ch <- prometheus.MustNewConstMetric(c.reauthRequired, prometheus.GaugeValue,
		reauthVal, c.instance)
	// Absent, not zero, when the node key has no expiry.
	if data.HasSelfKeyExpiry {
		ch <- prometheus.MustNewConstMetric(c.keyExpiry, prometheus.GaugeValue,
			data.SelfKeyExpiry, c.instance)
	}

	if c.detailsEnabled {
		for _, p := range data.Peers {
			sessionVal := 0.0
			if p.HasHandshake {
				sessionVal = 1.0
			}
			ch <- prometheus.MustNewConstMetric(c.peerSessionActive, prometheus.GaugeValue,
				sessionVal, p.Name, c.instance)
			ch <- prometheus.MustNewConstMetric(c.peerRxBytes, prometheus.CounterValue,
				p.RxBytes, p.Name, c.instance)
			ch <- prometheus.MustNewConstMetric(c.peerTxBytes, prometheus.CounterValue,
				p.TxBytes, p.Name, c.instance)
			// Direct/relayed and last-handshake only make sense for an
			// established session: emitting peer_direct=0 for idle peers
			// would conflate "relayed" with "no session" (19/30 live peers
			// have no handshake at all).
			if p.HasHandshake {
				directVal := 0.0
				if p.Direct {
					directVal = 1.0
				}
				ch <- prometheus.MustNewConstMetric(c.peerDirect, prometheus.GaugeValue,
					directVal, p.Name, c.instance)
				ch <- prometheus.MustNewConstMetric(c.peerLastHandshake, prometheus.GaugeValue,
					p.LastHandshakeSeconds, p.Name, c.instance)
			}
		}
	}

	status, sErr := client.FetchServiceStatus("tailscaleServiceStatus")
	if sErr != nil {
		c.log.Warn("failed to fetch tailscale service status", "err", sErr)
	} else {
		val := 0.0
		if status == "running" {
			val = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.serviceRunning, prometheus.GaugeValue,
			val, c.instance)
	}
	return nil
}
