package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type frrCollector struct {
	log *slog.Logger

	serviceRunning *prometheus.Desc

	// BGP per-family
	bgpPeersTotal  *prometheus.Desc
	bgpFailedPeers *prometheus.Desc
	bgpRibEntries  *prometheus.Desc

	// BGP per-peer
	bgpPeerUp           *prometheus.Desc
	bgpPeerPrefixesRcvd *prometheus.Desc
	bgpPeerPrefixesSent *prometheus.Desc
	bgpPeerUptimeSec    *prometheus.Desc
	bgpPeerMsgRcvd      *prometheus.Desc
	bgpPeerMsgSent      *prometheus.Desc

	// OSPF summary
	ospfNeighborsTotal *prometheus.Desc

	// OSPF per-neighbor
	ospfNeighborAdjacency *prometheus.Desc

	// OSPF per-area
	ospfAreaIfActive *prometheus.Desc
	ospfAreaNbrFull  *prometheus.Desc
	ospfAreaLSACount *prometheus.Desc
	ospfAreaSPFExec  *prometheus.Desc

	// BFD summary
	bfdPeersTotal *prometheus.Desc

	// BFD per-peer
	bfdPeerUp              *prometheus.Desc
	bfdPeerUptimeSec       *prometheus.Desc
	bfdPeerCtrlIn          *prometheus.Desc
	bfdPeerCtrlOut         *prometheus.Desc
	bfdPeerSessionUpEvents *prometheus.Desc
	bfdPeerSessionDnEvents *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &frrCollector{
		subsystem: FRRSubsystem,
	})
}

func (c *frrCollector) Name() string { return c.subsystem }

func (c *frrCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	afLabels := []string{"af"}
	peerLabels := []string{"peer", "remote_as", "af"}
	peerOnlyLabels := []string{"peer"}
	peerIfLabels := []string{"peer", "interface"}
	nbrLabels := []string{"neighbor_id", "address", "interface"}
	areaLabels := []string{"area"}

	c.serviceRunning = buildPrometheusDesc(c.subsystem, "service_running",
		"Whether the FRR (quagga) service is running (1 = running, 0 = stopped/disabled)", nil)

	// BGP per-family
	c.bgpPeersTotal = buildPrometheusDesc(c.subsystem, "bgp_peers_total",
		"Total number of configured BGP peers for this address family", afLabels)
	c.bgpFailedPeers = buildPrometheusDesc(c.subsystem, "bgp_failed_peers",
		"Number of BGP peers in a failed state for this address family", afLabels)
	c.bgpRibEntries = buildPrometheusDesc(c.subsystem, "bgp_rib_entries",
		"Number of RIB entries for this address family", afLabels)

	// BGP per-peer
	c.bgpPeerUp = buildPrometheusDesc(c.subsystem, "bgp_peer_up",
		"Whether this BGP peer session is established (1 = Established, 0 = otherwise)",
		peerLabels)
	c.bgpPeerPrefixesRcvd = buildPrometheusDesc(c.subsystem, "bgp_peer_prefixes_received",
		"Number of prefixes received from this BGP peer", peerLabels)
	c.bgpPeerPrefixesSent = buildPrometheusDesc(c.subsystem, "bgp_peer_prefixes_sent",
		"Number of prefixes sent to this BGP peer", peerLabels)
	c.bgpPeerUptimeSec = buildPrometheusDesc(c.subsystem, "bgp_peer_uptime_seconds",
		"Uptime of this BGP peer session in seconds", peerLabels)
	c.bgpPeerMsgRcvd = buildPrometheusDesc(c.subsystem, "bgp_peer_messages_received_total",
		"Cumulative BGP messages received from this peer", peerLabels)
	c.bgpPeerMsgSent = buildPrometheusDesc(c.subsystem, "bgp_peer_messages_sent_total",
		"Cumulative BGP messages sent to this peer", peerLabels)

	// OSPF summary
	c.ospfNeighborsTotal = buildPrometheusDesc(c.subsystem, "ospf_neighbors_total",
		"Total number of OSPF neighbors", nil)

	// OSPF per-neighbor
	c.ospfNeighborAdjacency = buildPrometheusDesc(c.subsystem, "ospf_neighbor_adjacency",
		"Whether this OSPF neighbor is in Full adjacency state (1 = Full, 0 = otherwise)",
		nbrLabels)

	// OSPF per-area
	c.ospfAreaIfActive = buildPrometheusDesc(c.subsystem, "ospf_area_interfaces_active",
		"Number of active interfaces in this OSPF area", areaLabels)
	c.ospfAreaNbrFull = buildPrometheusDesc(c.subsystem, "ospf_area_neighbors_full_adjacent",
		"Number of neighbors in Full adjacency state in this OSPF area", areaLabels)
	c.ospfAreaLSACount = buildPrometheusDesc(c.subsystem, "ospf_area_lsa_count",
		"Number of LSAs in this OSPF area", areaLabels)
	c.ospfAreaSPFExec = buildPrometheusDesc(c.subsystem, "ospf_area_spf_executed_total",
		"Cumulative number of SPF calculations executed in this OSPF area", areaLabels)

	// BFD summary
	c.bfdPeersTotal = buildPrometheusDesc(c.subsystem, "bfd_peers_total",
		"Total number of configured BFD peers", nil)

	// BFD per-peer
	c.bfdPeerUp = buildPrometheusDesc(c.subsystem, "bfd_peer_up",
		"Whether this BFD peer session is up (1 = up, 0 = down)", peerIfLabels)
	c.bfdPeerUptimeSec = buildPrometheusDesc(c.subsystem, "bfd_peer_uptime_seconds",
		"Uptime of this BFD peer session in seconds", peerOnlyLabels)
	c.bfdPeerCtrlIn = buildPrometheusDesc(c.subsystem, "bfd_peer_control_packets_received_total",
		"Cumulative BFD control packets received from this peer", peerOnlyLabels)
	c.bfdPeerCtrlOut = buildPrometheusDesc(c.subsystem, "bfd_peer_control_packets_sent_total",
		"Cumulative BFD control packets sent to this peer", peerOnlyLabels)
	c.bfdPeerSessionUpEvents = buildPrometheusDesc(c.subsystem, "bfd_peer_session_up_events_total",
		"Cumulative BFD session-up events for this peer", peerOnlyLabels)
	c.bfdPeerSessionDnEvents = buildPrometheusDesc(c.subsystem, "bfd_peer_session_down_events_total",
		"Cumulative BFD session-down events for this peer", peerOnlyLabels)
}

func (c *frrCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.serviceRunning,
		c.bgpPeersTotal, c.bgpFailedPeers, c.bgpRibEntries,
		c.bgpPeerUp, c.bgpPeerPrefixesRcvd, c.bgpPeerPrefixesSent,
		c.bgpPeerUptimeSec, c.bgpPeerMsgRcvd, c.bgpPeerMsgSent,
		c.ospfNeighborsTotal,
		c.ospfNeighborAdjacency,
		c.ospfAreaIfActive, c.ospfAreaNbrFull, c.ospfAreaLSACount, c.ospfAreaSPFExec,
		c.bfdPeersTotal,
		c.bfdPeerUp, c.bfdPeerUptimeSec,
		c.bfdPeerCtrlIn, c.bfdPeerCtrlOut,
		c.bfdPeerSessionUpEvents, c.bfdPeerSessionDnEvents,
	} {
		ch <- d
	}
}

func (c *frrCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	bgp, bgpErr := client.FetchFRRBGP()
	if bgpErr != nil {
		return bgpErr
	}

	ospf, ospfErr := client.FetchFRROSPF()
	if ospfErr != nil {
		return ospfErr
	}

	bfd, bfdErr := client.FetchFRRBFD()
	if bfdErr != nil {
		return bfdErr
	}

	// Skip-on-absent: if none of the three subsystems are present, the plugin
	// is absent — stay fully silent and do not probe service status (D1).
	if !bgp.Present && !ospf.Present && !bfd.Present {
		return nil
	}

	// Emit BGP metrics.
	if bgp.Present {
		for _, fam := range bgp.Families {
			ch <- prometheus.MustNewConstMetric(c.bgpPeersTotal,
				prometheus.GaugeValue, fam.PeerCount, fam.AF, c.instance)
			ch <- prometheus.MustNewConstMetric(c.bgpFailedPeers,
				prometheus.GaugeValue, fam.FailedPeers, fam.AF, c.instance)
			ch <- prometheus.MustNewConstMetric(c.bgpRibEntries,
				prometheus.GaugeValue, fam.RibCount, fam.AF, c.instance)
		}
		for _, peer := range bgp.Peers {
			ch <- prometheus.MustNewConstMetric(c.bgpPeerUp,
				prometheus.GaugeValue, peer.Up, peer.Peer, peer.RemoteAS, peer.AF, c.instance)
			ch <- prometheus.MustNewConstMetric(c.bgpPeerPrefixesRcvd,
				prometheus.GaugeValue, peer.PrefixesReceived, peer.Peer, peer.RemoteAS, peer.AF, c.instance)
			ch <- prometheus.MustNewConstMetric(c.bgpPeerPrefixesSent,
				prometheus.GaugeValue, peer.PrefixesSent, peer.Peer, peer.RemoteAS, peer.AF, c.instance)
			// Skip uptime metric when 0 (peer not established / no uptime data).
			if peer.UptimeSeconds > 0 {
				ch <- prometheus.MustNewConstMetric(c.bgpPeerUptimeSec,
					prometheus.GaugeValue, peer.UptimeSeconds, peer.Peer, peer.RemoteAS, peer.AF, c.instance)
			}
			ch <- prometheus.MustNewConstMetric(c.bgpPeerMsgRcvd,
				prometheus.CounterValue, peer.MessagesReceived, peer.Peer, peer.RemoteAS, peer.AF, c.instance)
			ch <- prometheus.MustNewConstMetric(c.bgpPeerMsgSent,
				prometheus.CounterValue, peer.MessagesSent, peer.Peer, peer.RemoteAS, peer.AF, c.instance)
		}
	}

	// Emit OSPF metrics.
	if ospf.Present {
		ch <- prometheus.MustNewConstMetric(c.ospfNeighborsTotal,
			prometheus.GaugeValue, float64(len(ospf.Neighbors)), c.instance)
		for _, nbr := range ospf.Neighbors {
			ch <- prometheus.MustNewConstMetric(c.ospfNeighborAdjacency,
				prometheus.GaugeValue, nbr.Adjacent, nbr.NeighborID, nbr.Address, nbr.Interface, c.instance)
		}
		for _, area := range ospf.Areas {
			ch <- prometheus.MustNewConstMetric(c.ospfAreaIfActive,
				prometheus.GaugeValue, area.InterfacesActive, area.Area, c.instance)
			ch <- prometheus.MustNewConstMetric(c.ospfAreaNbrFull,
				prometheus.GaugeValue, area.NeighborsFullAdjacent, area.Area, c.instance)
			ch <- prometheus.MustNewConstMetric(c.ospfAreaLSACount,
				prometheus.GaugeValue, area.LSACount, area.Area, c.instance)
			ch <- prometheus.MustNewConstMetric(c.ospfAreaSPFExec,
				prometheus.CounterValue, area.SPFExecuted, area.Area, c.instance)
		}
	}

	// Emit BFD metrics.
	if bfd.Present {
		ch <- prometheus.MustNewConstMetric(c.bfdPeersTotal,
			prometheus.GaugeValue, float64(len(bfd.Peers)), c.instance)
		for _, peer := range bfd.Peers {
			ch <- prometheus.MustNewConstMetric(c.bfdPeerUp,
				prometheus.GaugeValue, peer.Up, peer.Peer, peer.Interface, c.instance)
			if peer.UptimeSeconds > 0 {
				ch <- prometheus.MustNewConstMetric(c.bfdPeerUptimeSec,
					prometheus.GaugeValue, peer.UptimeSeconds, peer.Peer, c.instance)
			}
			if peer.HasCounters {
				ch <- prometheus.MustNewConstMetric(c.bfdPeerCtrlIn,
					prometheus.CounterValue, peer.ControlIn, peer.Peer, c.instance)
				ch <- prometheus.MustNewConstMetric(c.bfdPeerCtrlOut,
					prometheus.CounterValue, peer.ControlOut, peer.Peer, c.instance)
				ch <- prometheus.MustNewConstMetric(c.bfdPeerSessionUpEvents,
					prometheus.CounterValue, peer.SessionUpEvents, peer.Peer, c.instance)
				ch <- prometheus.MustNewConstMetric(c.bfdPeerSessionDnEvents,
					prometheus.CounterValue, peer.SessionDownEvents, peer.Peer, c.instance)
			}
		}
	}

	// Probe service status only when the plugin appears to be present.
	status, present, sErr := client.FetchServiceStatusOptional("quaggaServiceStatus")
	if sErr != nil {
		c.log.Warn("failed to fetch frr service status", "err", sErr)
	} else if present {
		running := 0.0
		if status == "running" {
			running = 1.0
		}
		ch <- prometheus.MustNewConstMetric(c.serviceRunning,
			prometheus.GaugeValue, running, c.instance)
	}

	return nil
}
