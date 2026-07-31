package collector

import (
	"context"
	"log/slog"
	"strings"

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

	// BGP per-peer session detail (#197)
	bgpPeerConnEstablished  *prometheus.Desc
	bgpPeerConnDropped      *prometheus.Desc
	bgpPeerMessagesByType   *prometheus.Desc
	bgpPeerLastResetSec     *prometheus.Desc
	bgpPeerPrefixesAccepted *prometheus.Desc
	bgpPeerQueueDepth       *prometheus.Desc

	// OSPF summary
	ospfNeighborsTotal *prometheus.Desc

	// OSPF per-neighbor
	ospfNeighborAdjacency *prometheus.Desc

	// OSPF per-neighbor adjacency stability (#582)
	ospfNeighborNSMStateInfo  *prometheus.Desc
	ospfNeighborUptimeSec     *prometheus.Desc
	ospfNeighborDeadTimerSec  *prometheus.Desc
	ospfNeighborLSAQueueDepth *prometheus.Desc

	// OSPF per-area
	ospfAreaIfActive *prometheus.Desc
	ospfAreaNbrFull  *prometheus.Desc
	ospfAreaLSACount *prometheus.Desc
	ospfAreaSPFExec  *prometheus.Desc

	// OSPF instance-level SPF-run timing (#582)
	ospfSPFLastExecutedTimestamp *prometheus.Desc
	ospfSPFLastDurationSec       *prometheus.Desc

	// OSPF per-interface detail (#198)
	ospfInterfaceUp                *prometheus.Desc
	ospfInterfaceCost              *prometheus.Desc
	ospfInterfaceNeighbors         *prometheus.Desc
	ospfInterfaceNeighborsAdjacent *prometheus.Desc
	ospfInterfaceState             *prometheus.Desc

	// OSPFv3 (ospf6) parity (#198)
	ospfv3InterfaceUp         *prometheus.Desc
	ospfv3InterfaceCost       *prometheus.Desc
	ospfv3InterfaceState      *prometheus.Desc
	ospfv3AreaLSACount        *prometheus.Desc
	ospfv3InterfacePendingLSA *prometheus.Desc

	// OSPFv3 SPF-run timing (#582): duration is instance-level, recency is
	// per-area — see the FRROSPFv3Overview field docs in opnsense/frr.go for
	// why these aren't symmetric with each other or with OSPFv2's pair.
	ospfv3SPFLastDurationSec           *prometheus.Desc
	ospfv3AreaSPFLastExecutedTimestamp *prometheus.Desc

	// BFD summary
	bfdPeersTotal *prometheus.Desc

	// BFD per-peer
	bfdPeerUp              *prometheus.Desc
	bfdPeerUptimeSec       *prometheus.Desc
	bfdPeerCtrlIn          *prometheus.Desc
	bfdPeerCtrlOut         *prometheus.Desc
	bfdPeerSessionUpEvents *prometheus.Desc
	bfdPeerSessionDnEvents *prometheus.Desc

	// BFD per-peer diagnostic/RTT/down-duration (#484)
	bfdPeerDiagnosticInfo *prometheus.Desc
	bfdPeerRTTMin         *prometheus.Desc
	bfdPeerRTTAvg         *prometheus.Desc
	bfdPeerRTTMax         *prometheus.Desc
	bfdPeerDowntimeSec    *prometheus.Desc

	// Routing-state volume gauges (#199, opt-in via --exporter.enable-frr-routes)
	routeCount        *prometheus.Desc
	routeNexthopCount *prometheus.Desc
	ospfRouteCount    *prometheus.Desc
	ospfv3RouteCount  *prometheus.Desc
	ospfLSACount      *prometheus.Desc
	ospfv3LSACount    *prometheus.Desc

	routesEnabled bool

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

	// #582: OSPF per-neighbor adjacency-stability label sets, riding the
	// same bootgrid row as nbrLabels above.
	nbrStateLabels := []string{"neighbor_id", "address", "interface", "nsm_state"}
	nbrQueueLabels := []string{"neighbor_id", "address", "interface", "queue"}

	// #197: BGP peer session-detail label sets, deliberately distinct from the
	// peerLabels (peer+remote_as+af) used by the existing per-peer BGP metrics
	// above — these are session-level counters, not per-AF.
	bgpPeerTypeDirectionLabels := []string{"peer", "type", "direction"}
	bgpPeerAFLabels := []string{"peer", "af"}
	bgpPeerDirectionLabels := []string{"peer", "direction"}

	// #198: OSPF/OSPFv3 per-interface label sets, bounded by NIC count.
	ifaceAreaLabels := []string{"interface", "area"}
	ifaceStateLabels := []string{"interface", "state"}
	ifaceQueueLabels := []string{"interface", "queue"}

	// #199 (opt-in): routing-state volume label sets.
	routeLabels := []string{"af", "protocol"}
	routeTypeLabels := []string{"type"}
	ospfLSALabels := []string{"area", "lsa_type"}
	ospfv3LSAScopeLabels := []string{"scope"}

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

	// BGP per-peer session detail (#197)
	c.bgpPeerConnEstablished = buildPrometheusDesc(c.subsystem, "bgp_peer_connections_established_total",
		"Cumulative number of times this BGP peer session has been established (flap counter)",
		peerOnlyLabels)
	c.bgpPeerConnDropped = buildPrometheusDesc(c.subsystem, "bgp_peer_connections_dropped_total",
		"Cumulative number of times this BGP peer session has been dropped (flap counter)",
		peerOnlyLabels)
	c.bgpPeerMessagesByType = buildPrometheusDesc(c.subsystem, "bgp_peer_messages_by_type_total",
		"Cumulative BGP messages exchanged with this peer, by message type and direction",
		bgpPeerTypeDirectionLabels)
	c.bgpPeerLastResetSec = buildPrometheusDesc(c.subsystem, "bgp_peer_last_reset_seconds",
		"Time since this BGP peer session was last reset, in seconds. The reset reason "+
			"(FRR's lastResetDueTo) is logged at debug level rather than carried as a label "+
			"(unbounded free-text value).",
		peerOnlyLabels)
	c.bgpPeerPrefixesAccepted = buildPrometheusDesc(c.subsystem, "bgp_peer_prefixes_accepted",
		"Number of prefixes accepted from this BGP peer after inbound policy, by address family "+
			"(complements the pre-policy opnsense_frr_bgp_peer_prefixes_received)",
		bgpPeerAFLabels)
	c.bgpPeerQueueDepth = buildPrometheusDesc(c.subsystem, "bgp_peer_queue_depth",
		"Current BGP work-queue depth for this peer, by direction (in = inbound, out = outbound)",
		bgpPeerDirectionLabels)

	// OSPF summary
	c.ospfNeighborsTotal = buildPrometheusDesc(c.subsystem, "ospf_neighbors_total",
		"Total number of OSPF neighbors", nil)

	// OSPF per-neighbor
	c.ospfNeighborAdjacency = buildPrometheusDesc(c.subsystem, "ospf_neighbor_adjacency",
		"Whether this OSPF neighbor is in Full adjacency state (1 = Full, 0 = otherwise)",
		nbrLabels)

	// OSPF per-neighbor adjacency stability (#582): the binary adjacency flag
	// above only distinguishes Full from everything else. These fill in what
	// a non-Full neighbor is actually doing (stuck negotiating vs. flapping)
	// and whether its LSA sync queues are draining.
	c.ospfNeighborNSMStateInfo = buildPrometheusDesc(c.subsystem, "ospf_neighbor_nsm_state_info",
		"FRR's raw OSPF neighbor state machine state for this neighbor (value is always 1; use "+
			"the nsm_state label — DependUpon/Deleted/Down/Attempt/Init/2-Way/ExStart/Exchange/"+
			"Loading/Full). Distinct from ospf_neighbor_adjacency: that flag only shows Full vs. "+
			"not, this shows what a non-Full neighbor is stuck at.",
		nbrStateLabels)
	c.ospfNeighborUptimeSec = buildPrometheusDesc(c.subsystem, "ospf_neighbor_uptime_seconds",
		"How long this OSPF neighbor's adjacency has been progressing, in seconds. Absent "+
			"(not zero) while the neighbor's inactivity timer isn't scheduled — FRR doesn't "+
			"report this field for a neighbor that hasn't started forming an adjacency.",
		nbrLabels)
	c.ospfNeighborDeadTimerSec = buildPrometheusDesc(c.subsystem, "ospf_neighbor_dead_timer_seconds",
		"Time remaining before this OSPF neighbor's dead interval expires, in seconds. A value "+
			"repeatedly resetting close to the configured dead interval is healthy; one trending "+
			"toward zero and recovering (rather than resetting cleanly on a fresh hello) is a "+
			"flapping adjacency. Absent (not zero) when FRR reports the timer as \"inactive\" "+
			"(no dead-interval timer currently running for this neighbor).",
		nbrLabels)
	c.ospfNeighborLSAQueueDepth = buildPrometheusDesc(c.subsystem, "ospf_neighbor_lsa_queue_depth",
		"Current LSA synchronization queue depth for this OSPF neighbor, by queue "+
			"(db_summary = database description summary list, ls_request = link-state request "+
			"list, ls_retransmission = link-state retransmission list). Persistently nonzero "+
			"ls_retransmission depth is the classic symptom of a neighbor stuck failing to "+
			"acknowledge LSAs.",
		nbrQueueLabels)

	// OSPF per-area
	c.ospfAreaIfActive = buildPrometheusDesc(c.subsystem, "ospf_area_interfaces_active",
		"Number of active interfaces in this OSPF area", areaLabels)
	c.ospfAreaNbrFull = buildPrometheusDesc(c.subsystem, "ospf_area_neighbors_full_adjacent",
		"Number of neighbors in Full adjacency state in this OSPF area", areaLabels)
	c.ospfAreaLSACount = buildPrometheusDesc(c.subsystem, "ospf_area_lsa_count",
		"Number of LSAs in this OSPF area", areaLabels)
	c.ospfAreaSPFExec = buildPrometheusDesc(c.subsystem, "ospf_area_spf_executed_total",
		"Cumulative number of SPF calculations executed in this OSPF area", areaLabels)

	// OSPF instance-level SPF-run timing (#582): ospf_area_spf_executed_total
	// above is a per-area COUNT of runs, not their cost or recency — a router
	// thrashing SPF (short-interval recalculation storms) is a CPU-cost
	// incident this pair makes visible that the count alone does not.
	c.ospfSPFLastExecutedTimestamp = buildPrometheusDesc(c.subsystem, "ospf_spf_last_executed_timestamp_seconds",
		"Unix timestamp of this OSPF instance's last SPF calculation. Exported as an absolute "+
			"timestamp rather than a \"seconds ago\" reading (FRR re-derives the age fresh on "+
			"every poll; an absolute timestamp lets time()-metric compute current age at query "+
			"time instead of only at last-scrape time). Absent until the instance's first SPF run.",
		nil)
	c.ospfSPFLastDurationSec = buildPrometheusDesc(c.subsystem, "ospf_spf_last_duration_seconds",
		"Wall-clock duration of this OSPF instance's last SPF calculation, in seconds. Absent "+
			"until the instance's first SPF run.",
		nil)

	// OSPF per-interface detail (#198)
	c.ospfInterfaceUp = buildPrometheusDesc(c.subsystem, "ospf_interface_up",
		"Whether this OSPF interface's underlying link is up (1 = up, 0 = down)", ifaceAreaLabels)
	c.ospfInterfaceCost = buildPrometheusDesc(c.subsystem, "ospf_interface_cost",
		"OSPF cost configured on this interface", ifaceAreaLabels)
	c.ospfInterfaceNeighbors = buildPrometheusDesc(c.subsystem, "ospf_interface_neighbors",
		"Number of OSPF neighbors seen on this interface", ifaceAreaLabels)
	c.ospfInterfaceNeighborsAdjacent = buildPrometheusDesc(c.subsystem, "ospf_interface_neighbors_adjacent",
		"Number of OSPF neighbors in Full adjacency on this interface", ifaceAreaLabels)
	c.ospfInterfaceState = buildPrometheusDesc(c.subsystem, "ospf_interface_state",
		"OSPF interface state (enum-style: 1 for the current state, 0 for the others in the "+
			"fixed set DR/BDR/DROther/PointToPoint/Waiting/Down)", ifaceStateLabels)

	// OSPFv3 (ospf6) parity (#198). UNVERIFIED against a live v3 adjacency —
	// see the VERIFICATION banner in opnsense/frr.go.
	c.ospfv3InterfaceUp = buildPrometheusDesc(c.subsystem, "ospfv3_interface_up",
		"Whether this OSPFv3 interface is up (1 = up, 0 = down)", ifaceAreaLabels)
	c.ospfv3InterfaceCost = buildPrometheusDesc(c.subsystem, "ospfv3_interface_cost",
		"OSPFv3 cost configured on this interface", ifaceAreaLabels)
	c.ospfv3InterfaceState = buildPrometheusDesc(c.subsystem, "ospfv3_interface_state",
		"OSPFv3 interface state (enum-style: 1 for the current state, 0 for the others in the "+
			"fixed set DR/BDR/DROther/PointToPoint/Waiting/Down). There is no OSPFv3 neighbor "+
			"endpoint in the quagga plugin API, so interface state is the best available proxy "+
			"for adjacency.", ifaceStateLabels)
	c.ospfv3AreaLSACount = buildPrometheusDesc(c.subsystem, "ospfv3_area_lsa_count",
		"Number of LSAs in this OSPFv3 area (v3 parity with opnsense_frr_ospf_area_lsa_count)",
		areaLabels)
	c.ospfv3InterfacePendingLSA = buildPrometheusDesc(c.subsystem, "ospfv3_interface_pending_lsa",
		"OSPFv3 flooding backlog on this interface: pending LSAs by queue "+
			"(update = LSUpdate, ack = LSAck)", ifaceQueueLabels)

	// OSPFv3 SPF-run timing (#582). Deliberately NOT symmetric with the
	// OSPFv2 pair above: FRR's ospf6d only exposes a numeric "how long did
	// the last SPF take" reading at the INSTANCE level, and a numeric "time
	// since the last SPF ran" reading per AREA — the instance-level
	// "spfLastExecutedMsecs" is a formatted string with no numeric
	// equivalent (see the FRROSPFv3Overview field docs in opnsense/frr.go).
	c.ospfv3SPFLastDurationSec = buildPrometheusDesc(c.subsystem, "ospfv3_spf_last_duration_seconds",
		"Wall-clock duration of this OSPFv3 instance's last SPF calculation, in seconds. "+
			"Absent until the instance's first SPF run.",
		nil)
	c.ospfv3AreaSPFLastExecutedTimestamp = buildPrometheusDesc(c.subsystem, "ospfv3_area_spf_last_executed_timestamp_seconds",
		"Unix timestamp of this OSPFv3 area's last SPF calculation. Exported as an absolute "+
			"timestamp for the same reason as opnsense_frr_ospf_spf_last_executed_timestamp_seconds "+
			"above. Absent until this area's first SPF run.",
		areaLabels)

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

	// BFD per-peer diagnostic/RTT/down-duration (#484)
	c.bfdPeerDiagnosticInfo = buildPrometheusDesc(c.subsystem, "bfd_peer_diagnostic_info",
		"FRR BFD peer diagnostic reason (value is always 1; use labels). diagnostic/"+
			"remote_diagnostic are FRR's diag2str() enum: ok, control detection time expired, "+
			"echo function failed, neighbor signaled session down, forwarding plane reset, "+
			"path down, concatenated path down, administratively down, reverse concatenated "+
			"path down, unknown.",
		[]string{"peer", "diagnostic", "remote_diagnostic"})
	c.bfdPeerRTTMin = buildPrometheusDesc(c.subsystem, "bfd_peer_rtt_min_microseconds",
		"Minimum measured BFD round-trip time for this peer, in microseconds. Reads 0 unless "+
			"both ends support FRR's BFD RTT extension — a legitimate zero, not a fault.",
		peerOnlyLabels)
	c.bfdPeerRTTAvg = buildPrometheusDesc(c.subsystem, "bfd_peer_rtt_avg_microseconds",
		"Average measured BFD round-trip time for this peer, in microseconds. Reads 0 unless "+
			"both ends support FRR's BFD RTT extension — a legitimate zero, not a fault.",
		peerOnlyLabels)
	c.bfdPeerRTTMax = buildPrometheusDesc(c.subsystem, "bfd_peer_rtt_max_microseconds",
		"Maximum measured BFD round-trip time for this peer, in microseconds. Reads 0 unless "+
			"both ends support FRR's BFD RTT extension — a legitimate zero, not a fault.",
		peerOnlyLabels)
	c.bfdPeerDowntimeSec = buildPrometheusDesc(c.subsystem, "bfd_peer_downtime_seconds",
		"Duration this BFD peer session has been down, in seconds. Only emitted while the "+
			"peer is in the down state — absent (not zero) while up, initializing, or "+
			"administratively shut down, matching FRR's mutually exclusive uptime/downtime "+
			"fields.",
		peerOnlyLabels)

	// Routing-state volume gauges (#199, opt-in via --exporter.enable-frr-routes).
	// Aggregates only — never a per-prefix or per-LSA series.
	c.routeCount = buildPrometheusDesc(c.subsystem, "route_count",
		"Number of distinct routed prefixes in the zebra RIB, by address family and protocol. "+
			"Only emitted when --exporter.enable-frr-routes is set.", routeLabels)
	c.routeNexthopCount = buildPrometheusDesc(c.subsystem, "route_nexthop_count",
		"Number of nexthop rows in the zebra RIB (ECMP width), by address family and protocol. "+
			"Only emitted when --exporter.enable-frr-routes is set.", routeLabels)
	c.ospfRouteCount = buildPrometheusDesc(c.subsystem, "ospf_route_count",
		"Number of rows in the OSPF route table, by route type. "+
			"Only emitted when --exporter.enable-frr-routes is set.", routeTypeLabels)
	c.ospfv3RouteCount = buildPrometheusDesc(c.subsystem, "ospfv3_route_count",
		"Number of rows in the OSPFv3 route table, by route type. "+
			"Only emitted when --exporter.enable-frr-routes is set.", routeTypeLabels)
	c.ospfLSACount = buildPrometheusDesc(c.subsystem, "ospf_lsa_count",
		"Number of LSAs in the OSPF LSDB, by area and LSA type. "+
			"Only emitted when --exporter.enable-frr-routes is set.", ospfLSALabels)
	c.ospfv3LSACount = buildPrometheusDesc(c.subsystem, "ospfv3_lsa_count",
		"Number of LSAs in the OSPFv3 LSDB, by flooding scope. "+
			"Only emitted when --exporter.enable-frr-routes is set.", ospfv3LSAScopeLabels)
}

// SetRoutesEnabled controls whether the opt-in routing-state volume gauges
// (#199) are fetched and emitted. Called by WithFRRRoutesEnabled() at wiring
// time.
func (c *frrCollector) SetRoutesEnabled(enabled bool) {
	c.routesEnabled = enabled
}

// frrOSPFEnumStates is the fixed OSPF/OSPFv3 interface-state set used by the
// enum-style ospf_interface_state/ospfv3_interface_state gauges: for each
// interface, exactly one of these series is 1 and the rest are 0.
var frrOSPFEnumStates = []string{"DR", "BDR", "DROther", "PointToPoint", "Waiting", "Down"}

// normalizeFRROSPFState canonicalizes a raw FRR OSPF/OSPFv3 interface state
// string (which may be hyphenated, e.g. "Point-To-Point") against
// frrOSPFEnumStates. Returns "" when the raw value doesn't match any known
// state — all enum series are then emitted as 0 for that interface, which is
// still bounded (interface count x 6).
func normalizeFRROSPFState(raw string) string {
	cleaned := strings.Map(func(r rune) rune {
		if r == '-' || r == ' ' || r == '_' {
			return -1
		}
		return r
	}, raw)
	for _, s := range frrOSPFEnumStates {
		if strings.EqualFold(cleaned, s) {
			return s
		}
	}
	return ""
}

func (c *frrCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.serviceRunning,
		c.bgpPeersTotal, c.bgpFailedPeers, c.bgpRibEntries,
		c.bgpPeerUp, c.bgpPeerPrefixesRcvd, c.bgpPeerPrefixesSent,
		c.bgpPeerUptimeSec, c.bgpPeerMsgRcvd, c.bgpPeerMsgSent,
		c.bgpPeerConnEstablished, c.bgpPeerConnDropped, c.bgpPeerMessagesByType,
		c.bgpPeerLastResetSec, c.bgpPeerPrefixesAccepted, c.bgpPeerQueueDepth,
		c.ospfNeighborsTotal,
		c.ospfNeighborAdjacency,
		c.ospfNeighborNSMStateInfo, c.ospfNeighborUptimeSec, c.ospfNeighborDeadTimerSec,
		c.ospfNeighborLSAQueueDepth,
		c.ospfAreaIfActive, c.ospfAreaNbrFull, c.ospfAreaLSACount, c.ospfAreaSPFExec,
		c.ospfSPFLastExecutedTimestamp, c.ospfSPFLastDurationSec,
		c.ospfInterfaceUp, c.ospfInterfaceCost, c.ospfInterfaceNeighbors,
		c.ospfInterfaceNeighborsAdjacent, c.ospfInterfaceState,
		c.ospfv3InterfaceUp, c.ospfv3InterfaceCost, c.ospfv3InterfaceState,
		c.ospfv3AreaLSACount, c.ospfv3InterfacePendingLSA,
		c.ospfv3SPFLastDurationSec, c.ospfv3AreaSPFLastExecutedTimestamp,
		c.bfdPeersTotal,
		c.bfdPeerUp, c.bfdPeerUptimeSec,
		c.bfdPeerCtrlIn, c.bfdPeerCtrlOut,
		c.bfdPeerSessionUpEvents, c.bfdPeerSessionDnEvents,
		c.bfdPeerDiagnosticInfo, c.bfdPeerRTTMin, c.bfdPeerRTTAvg, c.bfdPeerRTTMax,
		c.bfdPeerDowntimeSec,
		c.routeCount, c.routeNexthopCount, c.ospfRouteCount, c.ospfv3RouteCount,
		c.ospfLSACount, c.ospfv3LSACount,
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

	bgpNeighbors, bgpNeighborsErr := client.FetchFRRBGPNeighbors()
	if bgpNeighborsErr != nil {
		return bgpNeighborsErr
	}

	ospfInterfaces, ospfInterfacesErr := client.FetchFRROSPFInterfaces()
	if ospfInterfacesErr != nil {
		return ospfInterfacesErr
	}

	ospfv3Overview, ospfv3OverviewErr := client.FetchFRROSPFv3Overview()
	if ospfv3OverviewErr != nil {
		return ospfv3OverviewErr
	}

	ospfv3Interfaces, ospfv3InterfacesErr := client.FetchFRROSPFv3Interfaces()
	if ospfv3InterfacesErr != nil {
		return ospfv3InterfacesErr
	}

	// Skip-on-absent: if none of these subsystems are present, the plugin is
	// absent — stay fully silent and do not probe service status (D1).
	if !bgp.Present && !ospf.Present && !bfd.Present &&
		!bgpNeighbors.Present && !ospfInterfaces.Present &&
		!ospfv3Overview.Present && !ospfv3Interfaces.Present {
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

	// Emit BGP peer session-detail metrics (#197).
	if bgpNeighbors.Present {
		for _, peer := range bgpNeighbors.Peers {
			ch <- prometheus.MustNewConstMetric(c.bgpPeerConnEstablished,
				prometheus.CounterValue, peer.ConnectionsEstablished, peer.Peer, c.instance)
			ch <- prometheus.MustNewConstMetric(c.bgpPeerConnDropped,
				prometheus.CounterValue, peer.ConnectionsDropped, peer.Peer, c.instance)
			ch <- prometheus.MustNewConstMetric(c.bgpPeerLastResetSec,
				prometheus.GaugeValue, peer.LastResetSeconds, peer.Peer, c.instance)
			ch <- prometheus.MustNewConstMetric(c.bgpPeerQueueDepth,
				prometheus.GaugeValue, peer.QueueDepthIn, peer.Peer, "in", c.instance)
			ch <- prometheus.MustNewConstMetric(c.bgpPeerQueueDepth,
				prometheus.GaugeValue, peer.QueueDepthOut, peer.Peer, "out", c.instance)
			if peer.LastResetDueTo != "" {
				c.log.Debug("bgp peer last reset reason", "peer", peer.Peer, "due_to", peer.LastResetDueTo)
			}
			for _, m := range peer.Messages {
				ch <- prometheus.MustNewConstMetric(c.bgpPeerMessagesByType,
					prometheus.CounterValue, m.Count, peer.Peer, m.Type, m.Direction, c.instance)
			}
			for _, p := range peer.Prefixes {
				ch <- prometheus.MustNewConstMetric(c.bgpPeerPrefixesAccepted,
					prometheus.GaugeValue, p.Count, peer.Peer, p.AF, c.instance)
			}
		}
	}

	// Emit OSPF metrics.
	if ospf.Present {
		ch <- prometheus.MustNewConstMetric(c.ospfNeighborsTotal,
			prometheus.GaugeValue, float64(len(ospf.Neighbors)), c.instance)
		for _, nbr := range ospf.Neighbors {
			ch <- prometheus.MustNewConstMetric(c.ospfNeighborAdjacency,
				prometheus.GaugeValue, nbr.Adjacent, nbr.NeighborID, nbr.Address, nbr.Interface, c.instance)

			// #582: adjacency-stability metrics riding the same neighbor row.
			ch <- prometheus.MustNewConstMetric(c.ospfNeighborNSMStateInfo,
				prometheus.GaugeValue, 1, nbr.NeighborID, nbr.Address, nbr.Interface, nbr.NSMState, c.instance)
			if nbr.HasUptime {
				ch <- prometheus.MustNewConstMetric(c.ospfNeighborUptimeSec,
					prometheus.GaugeValue, nbr.UptimeSeconds, nbr.NeighborID, nbr.Address, nbr.Interface, c.instance)
			}
			if nbr.HasDeadTimer {
				ch <- prometheus.MustNewConstMetric(c.ospfNeighborDeadTimerSec,
					prometheus.GaugeValue, nbr.DeadTimerSeconds, nbr.NeighborID, nbr.Address, nbr.Interface, c.instance)
			}
			ch <- prometheus.MustNewConstMetric(c.ospfNeighborLSAQueueDepth,
				prometheus.GaugeValue, nbr.DatabaseSummaryQueueDepth,
				nbr.NeighborID, nbr.Address, nbr.Interface, "db_summary", c.instance)
			ch <- prometheus.MustNewConstMetric(c.ospfNeighborLSAQueueDepth,
				prometheus.GaugeValue, nbr.LinkStateRequestQueueDepth,
				nbr.NeighborID, nbr.Address, nbr.Interface, "ls_request", c.instance)
			ch <- prometheus.MustNewConstMetric(c.ospfNeighborLSAQueueDepth,
				prometheus.GaugeValue, nbr.LinkStateRetransmissionQueueDepth,
				nbr.NeighborID, nbr.Address, nbr.Interface, "ls_retransmission", c.instance)
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

		// #582: instance-level SPF-run timing.
		if ospf.HasSPFLastExecuted {
			ch <- prometheus.MustNewConstMetric(c.ospfSPFLastExecutedTimestamp,
				prometheus.GaugeValue, ospf.SPFLastExecutedTimestamp, c.instance)
		}
		if ospf.HasSPFLastDuration {
			ch <- prometheus.MustNewConstMetric(c.ospfSPFLastDurationSec,
				prometheus.GaugeValue, ospf.SPFLastDurationSeconds, c.instance)
		}
	}

	// Emit OSPF per-interface detail metrics (#198).
	if ospfInterfaces.Present {
		for _, iface := range ospfInterfaces.Interfaces {
			ch <- prometheus.MustNewConstMetric(c.ospfInterfaceUp,
				prometheus.GaugeValue, iface.Up, iface.Interface, iface.Area, c.instance)
			ch <- prometheus.MustNewConstMetric(c.ospfInterfaceCost,
				prometheus.GaugeValue, iface.Cost, iface.Interface, iface.Area, c.instance)
			ch <- prometheus.MustNewConstMetric(c.ospfInterfaceNeighbors,
				prometheus.GaugeValue, iface.NbrCount, iface.Interface, iface.Area, c.instance)
			ch <- prometheus.MustNewConstMetric(c.ospfInterfaceNeighborsAdjacent,
				prometheus.GaugeValue, iface.NbrAdjacentCount, iface.Interface, iface.Area, c.instance)
			matched := normalizeFRROSPFState(iface.State)
			for _, state := range frrOSPFEnumStates {
				val := 0.0
				if state == matched {
					val = 1.0
				}
				ch <- prometheus.MustNewConstMetric(c.ospfInterfaceState,
					prometheus.GaugeValue, val, iface.Interface, state, c.instance)
			}
		}
	}

	// Emit OSPFv3 (ospf6) parity metrics (#198).
	if ospfv3Overview.Present {
		for _, area := range ospfv3Overview.Areas {
			ch <- prometheus.MustNewConstMetric(c.ospfv3AreaLSACount,
				prometheus.GaugeValue, area.LSACount, area.Area, c.instance)
			// #582: per-area SPF-run recency (the only level OSPFv3 reports
			// it numerically — see the field docs in opnsense/frr.go).
			if area.HasSPFLastExecuted {
				ch <- prometheus.MustNewConstMetric(c.ospfv3AreaSPFLastExecutedTimestamp,
					prometheus.GaugeValue, area.SPFLastExecutedTimestamp, area.Area, c.instance)
			}
		}
		// #582: instance-level SPF-run duration.
		if ospfv3Overview.HasSPFLastDuration {
			ch <- prometheus.MustNewConstMetric(c.ospfv3SPFLastDurationSec,
				prometheus.GaugeValue, ospfv3Overview.SPFLastDurationSeconds, c.instance)
		}
	}
	if ospfv3Interfaces.Present {
		for _, iface := range ospfv3Interfaces.Interfaces {
			ch <- prometheus.MustNewConstMetric(c.ospfv3InterfaceUp,
				prometheus.GaugeValue, iface.Up, iface.Interface, iface.Area, c.instance)
			ch <- prometheus.MustNewConstMetric(c.ospfv3InterfaceCost,
				prometheus.GaugeValue, iface.Cost, iface.Interface, iface.Area, c.instance)
			ch <- prometheus.MustNewConstMetric(c.ospfv3InterfacePendingLSA,
				prometheus.GaugeValue, iface.PendingLsaUpdate, iface.Interface, "update", c.instance)
			ch <- prometheus.MustNewConstMetric(c.ospfv3InterfacePendingLSA,
				prometheus.GaugeValue, iface.PendingLsaAck, iface.Interface, "ack", c.instance)
			matched := normalizeFRROSPFState(iface.State)
			for _, state := range frrOSPFEnumStates {
				val := 0.0
				if state == matched {
					val = 1.0
				}
				ch <- prometheus.MustNewConstMetric(c.ospfv3InterfaceState,
					prometheus.GaugeValue, val, iface.Interface, state, c.instance)
			}
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
			// diagnostic/remote-diagnostic and RTT are emitted unconditionally by
			// FRR for every peer regardless of session state (bfdd_vty.c:387-389,
			// 433-436), so they're always emitted here too.
			ch <- prometheus.MustNewConstMetric(c.bfdPeerDiagnosticInfo,
				prometheus.GaugeValue, 1, peer.Peer, peer.Diagnostic, peer.RemoteDiagnostic, c.instance)
			ch <- prometheus.MustNewConstMetric(c.bfdPeerRTTMin,
				prometheus.GaugeValue, peer.RTTMinUsec, peer.Peer, c.instance)
			ch <- prometheus.MustNewConstMetric(c.bfdPeerRTTAvg,
				prometheus.GaugeValue, peer.RTTAvgUsec, peer.Peer, c.instance)
			ch <- prometheus.MustNewConstMetric(c.bfdPeerRTTMax,
				prometheus.GaugeValue, peer.RTTMaxUsec, peer.Peer, c.instance)
			// Down-duration: emitted ONLY when FRR actually sent a "downtime" key
			// (peer.HasDowntime, set from frrBFDNeighborEntry.Downtime being
			// non-nil). This must stay a presence check, never peer.DowntimeSeconds
			// > 0 — a peer that went down in the same second as the sample has a
			// legitimate DowntimeSeconds of 0, which is not the same as "no data"
			// (INIT/ADM_DOWN, where HasDowntime is false and the field is skipped
			// entirely — see #484).
			if peer.HasDowntime {
				ch <- prometheus.MustNewConstMetric(c.bfdPeerDowntimeSec,
					prometheus.GaugeValue, peer.DowntimeSeconds, peer.Peer, c.instance)
			}
		}
	}

	// Emit opt-in routing-state volume gauges (#199). Only fetched when
	// enabled: the underlying bootgrid endpoints have no success-body caching
	// and their payload size scales with route-table size.
	if c.routesEnabled {
		routes, routesErr := client.FetchFRRRouteVolumes()
		if routesErr != nil {
			return routesErr
		}
		if routes.Present {
			for _, r := range routes.Routes {
				ch <- prometheus.MustNewConstMetric(c.routeCount,
					prometheus.GaugeValue, r.RouteCount, r.AF, r.Protocol, c.instance)
				ch <- prometheus.MustNewConstMetric(c.routeNexthopCount,
					prometheus.GaugeValue, r.NexthopCount, r.AF, r.Protocol, c.instance)
			}
			for _, r := range routes.OSPFRoutes {
				ch <- prometheus.MustNewConstMetric(c.ospfRouteCount,
					prometheus.GaugeValue, r.Count, r.Type, c.instance)
			}
			for _, r := range routes.OSPFv3Routes {
				ch <- prometheus.MustNewConstMetric(c.ospfv3RouteCount,
					prometheus.GaugeValue, r.Count, r.Type, c.instance)
			}
			for _, l := range routes.OSPFLSA {
				ch <- prometheus.MustNewConstMetric(c.ospfLSACount,
					prometheus.GaugeValue, l.Count, l.Area, l.LSAType, c.instance)
			}
			for _, l := range routes.OSPFv3LSA {
				ch <- prometheus.MustNewConstMetric(c.ospfv3LSACount,
					prometheus.GaugeValue, l.Count, l.Scope, c.instance)
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
