package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

type protocolCollector struct {
	log *slog.Logger

	tcpConnectionCountByState *prometheus.Desc
	tcpSentPackets            *prometheus.Desc
	tcpReceivedPackets        *prometheus.Desc

	arpSentRequests     *prometheus.Desc
	arpReceivedRequests *prometheus.Desc

	icmpCalls           *prometheus.Desc
	icmpSentPackets     *prometheus.Desc
	icmpDroppedByReason *prometheus.Desc

	udpDeliveredPackets  *prometheus.Desc
	udpOutputPackets     *prometheus.Desc
	udpReceivedDatagrams *prometheus.Desc
	udpDroppedByReason   *prometheus.Desc

	// CARP
	carpReceivedPackets *prometheus.Desc
	carpSentPackets     *prometheus.Desc
	carpDroppedByReason *prometheus.Desc

	// Pfsync
	pfsyncReceivedPackets *prometheus.Desc
	pfsyncSentPackets     *prometheus.Desc
	pfsyncDroppedByReason *prometheus.Desc
	pfsyncSendErrors      *prometheus.Desc

	// IP
	ipReceivedPackets    *prometheus.Desc
	ipForwardedPackets   *prometheus.Desc
	ipSentPackets        *prometheus.Desc
	ipDroppedByReason    *prometheus.Desc
	ipFragmentsReceived  *prometheus.Desc
	ipReassembledPackets *prometheus.Desc

	// IPv6 / ICMPv6 (#165) — the ip_*/icmp_* series above are IPv4-only.
	ip6ReceivedPackets    *prometheus.Desc
	ip6ForwardedPackets   *prometheus.Desc
	ip6SentPackets        *prometheus.Desc
	ip6DroppedByReason    *prometheus.Desc
	ip6FragmentsReceived  *prometheus.Desc
	ip6ReassembledPackets *prometheus.Desc
	icmp6Calls            *prometheus.Desc
	icmp6DroppedByReason  *prometheus.Desc

	// Detailed TCP
	tcpConnectionRequests     *prometheus.Desc
	tcpConnectionAccepts      *prometheus.Desc
	tcpConnectionsEstablished *prometheus.Desc
	tcpConnectionsClosed      *prometheus.Desc
	tcpConnectionDrops        *prometheus.Desc
	tcpRetransmitTimeouts     *prometheus.Desc
	tcpKeepaliveTimeouts      *prometheus.Desc
	tcpListenQueueOverflows   *prometheus.Desc
	tcpSyncacheEntries        *prometheus.Desc

	// ARP detailed
	arpSentFailures    *prometheus.Desc
	arpSentReplies     *prometheus.Desc
	arpReceivedReplies *prometheus.Desc
	arpReceivedPackets *prometheus.Desc
	arpDroppedNoEntry  *prometheus.Desc
	arpEntriesTimeout  *prometheus.Desc

	// Expanded TCP metrics
	tcpSentDataBytes           *prometheus.Desc
	tcpRetransmittedPackets    *prometheus.Desc
	tcpRetransmittedBytes      *prometheus.Desc
	tcpReceivedInSequenceBytes *prometheus.Desc
	tcpReceivedDuplicateBytes  *prometheus.Desc
	tcpSegmentsUpdatedRtt      *prometheus.Desc
	tcpBadConnectionAttempts   *prometheus.Desc
	tcpKeepaliveProbes         *prometheus.Desc
	tcpSyncacheDropped         *prometheus.Desc

	// Expanded IP metrics
	ipSentFragments *prometheus.Desc

	// Expanded ARP metrics
	arpDroppedDuplicateAddress *prometheus.Desc

	// TCP ECN send-side / AccECN handshake counters (26.1.11+, #237) — presence-gated.
	tcpEcnPacketsTotal          *prometheus.Desc
	tcpEcnAccEcnHandshakesTotal *prometheus.Desc

	// TCP syncookies (26.7+, #237) — presence-gated.
	tcpSyncookiesTotal *prometheus.Desc

	// TCP received-acks-for-data 3-way split (26.7+, #237) — presence-gated.
	tcpReceivedAcksForDataTotal *prometheus.Desc

	subsystem string
	instance  string
}

func init() {
	collectorInstances = append(collectorInstances, &protocolCollector{
		subsystem: ProtocolSubsystem,
	})
}

func (c *protocolCollector) Name() string {
	return c.subsystem
}

func (c *protocolCollector) Register(namespace, instanceLabel string, log *slog.Logger) {
	c.log = log
	c.instance = instanceLabel
	c.log.Debug("Registering collector", "collector", c.Name())

	c.tcpConnectionCountByState = buildPrometheusDesc(c.subsystem, "tcp_connection_count_by_state",
		"Number of TCP connections by state",
		[]string{"state"},
	)

	c.tcpSentPackets = buildPrometheusDesc(c.subsystem, "tcp_sent_packets_total",
		"Number of sent TCP packets ",
		nil,
	)

	c.tcpReceivedPackets = buildPrometheusDesc(c.subsystem, "tcp_received_packets_total",
		"Number of received TCP packets",
		nil,
	)

	c.arpSentRequests = buildPrometheusDesc(c.subsystem, "arp_sent_requests_total",
		"Number of sent ARP requests",
		nil,
	)

	c.arpReceivedRequests = buildPrometheusDesc(c.subsystem, "arp_received_requests_total",
		"Number of received ARP requests",
		nil,
	)
	c.icmpCalls = buildPrometheusDesc(c.subsystem, "icmp_calls_total",
		"Number of ICMP calls",
		nil,
	)
	c.icmpSentPackets = buildPrometheusDesc(c.subsystem, "icmp_sent_packets_total",
		"Number of sent ICMP packets",
		nil,
	)
	c.icmpDroppedByReason = buildPrometheusDesc(c.subsystem, "icmp_dropped_by_reason_total",
		"Number of dropped ICMP packets by reason",
		[]string{"reason"},
	)
	c.udpDeliveredPackets = buildPrometheusDesc(c.subsystem, "udp_delivered_packets_total",
		"Number of delivered UDP packets",
		nil,
	)

	c.udpOutputPackets = buildPrometheusDesc(c.subsystem, "udp_output_packets_total",
		"Number of output UDP packets",
		nil,
	)

	c.udpReceivedDatagrams = buildPrometheusDesc(c.subsystem, "udp_received_datagrams_total",
		"Number of received UDP datagrams",
		nil,
	)

	c.udpDroppedByReason = buildPrometheusDesc(c.subsystem, "udp_dropped_by_reason_total",
		"Number of dropped UDP packets by reason",
		[]string{"reason"},
	)

	// CARP
	c.carpReceivedPackets = buildPrometheusDesc(c.subsystem, "carp_received_packets_total",
		"Number of received CARP packets",
		[]string{"address_family"},
	)
	c.carpSentPackets = buildPrometheusDesc(c.subsystem, "carp_sent_packets_total",
		"Number of sent CARP packets",
		[]string{"address_family"},
	)
	c.carpDroppedByReason = buildPrometheusDesc(c.subsystem, "carp_dropped_by_reason_total",
		"Number of dropped CARP packets by reason",
		[]string{"reason"},
	)

	// Pfsync
	c.pfsyncReceivedPackets = buildPrometheusDesc(c.subsystem, "pfsync_received_packets_total",
		"Number of received Pfsync packets",
		[]string{"address_family"},
	)
	c.pfsyncSentPackets = buildPrometheusDesc(c.subsystem, "pfsync_sent_packets_total",
		"Number of sent Pfsync packets",
		[]string{"address_family"},
	)
	c.pfsyncDroppedByReason = buildPrometheusDesc(c.subsystem, "pfsync_dropped_by_reason_total",
		"Number of dropped Pfsync packets by reason",
		[]string{"reason"},
	)
	c.pfsyncSendErrors = buildPrometheusDesc(c.subsystem, "pfsync_send_errors_total",
		"Number of Pfsync send errors",
		nil,
	)

	// IP
	c.ipReceivedPackets = buildPrometheusDesc(c.subsystem, "ip_received_packets_total",
		"Number of received IP packets",
		nil,
	)
	c.ipForwardedPackets = buildPrometheusDesc(c.subsystem, "ip_forwarded_packets_total",
		"Number of forwarded IP packets",
		nil,
	)
	c.ipSentPackets = buildPrometheusDesc(c.subsystem, "ip_sent_packets_total",
		"Number of sent IP packets",
		nil,
	)
	c.ipDroppedByReason = buildPrometheusDesc(c.subsystem, "ip_dropped_by_reason_total",
		"Number of dropped IP packets by reason",
		[]string{"reason"},
	)
	c.ipFragmentsReceived = buildPrometheusDesc(c.subsystem, "ip_fragments_received_total",
		"Number of received IP fragments",
		nil,
	)
	c.ipReassembledPackets = buildPrometheusDesc(c.subsystem, "ip_reassembled_packets_total",
		"Number of reassembled IP packets",
		nil,
	)

	// IPv6 (the ip_* series above are IPv4-only; see #165)
	c.ip6ReceivedPackets = buildPrometheusDesc(c.subsystem, "ip6_received_packets_total",
		"Number of received IPv6 packets", nil)
	c.ip6ForwardedPackets = buildPrometheusDesc(c.subsystem, "ip6_forwarded_packets_total",
		"Number of forwarded IPv6 packets", nil)
	c.ip6SentPackets = buildPrometheusDesc(c.subsystem, "ip6_sent_packets_total",
		"Number of sent IPv6 packets", nil)
	c.ip6DroppedByReason = buildPrometheusDesc(c.subsystem, "ip6_dropped_by_reason_total",
		"Number of dropped IPv6 packets by reason", []string{"reason"})
	c.ip6FragmentsReceived = buildPrometheusDesc(c.subsystem, "ip6_fragments_received_total",
		"Number of received IPv6 fragments", nil)
	c.ip6ReassembledPackets = buildPrometheusDesc(c.subsystem, "ip6_reassembled_packets_total",
		"Number of reassembled IPv6 packets", nil)
	c.icmp6Calls = buildPrometheusDesc(c.subsystem, "icmp6_calls_total",
		"Number of ICMPv6 calls", nil)
	c.icmp6DroppedByReason = buildPrometheusDesc(c.subsystem, "icmp6_dropped_by_reason_total",
		"Number of dropped ICMPv6 packets by reason", []string{"reason"})

	// Detailed TCP
	c.tcpConnectionRequests = buildPrometheusDesc(c.subsystem, "tcp_connection_requests_total",
		"Number of TCP connection requests",
		nil,
	)
	c.tcpConnectionAccepts = buildPrometheusDesc(c.subsystem, "tcp_connection_accepts_total",
		"Number of TCP connection accepts",
		nil,
	)
	c.tcpConnectionsEstablished = buildPrometheusDesc(c.subsystem, "tcp_connections_established_total",
		"Number of TCP connections established",
		nil,
	)
	c.tcpConnectionsClosed = buildPrometheusDesc(c.subsystem, "tcp_connections_closed_total",
		"Number of TCP connections closed",
		nil,
	)
	c.tcpConnectionDrops = buildPrometheusDesc(c.subsystem, "tcp_connection_drops_total",
		"Number of TCP connection drops",
		nil,
	)
	c.tcpRetransmitTimeouts = buildPrometheusDesc(c.subsystem, "tcp_retransmit_timeouts_total",
		"Number of TCP retransmit timeouts",
		nil,
	)
	c.tcpKeepaliveTimeouts = buildPrometheusDesc(c.subsystem, "tcp_keepalive_timeouts_total",
		"Number of TCP keepalive timeouts",
		nil,
	)
	c.tcpListenQueueOverflows = buildPrometheusDesc(c.subsystem, "tcp_listen_queue_overflows_total",
		"Number of TCP listen queue overflows",
		nil,
	)
	c.tcpSyncacheEntries = buildPrometheusDesc(c.subsystem, "tcp_syncache_entries_total",
		"Number of TCP syncache entries added",
		nil,
	)

	// ARP detailed
	c.arpSentFailures = buildPrometheusDesc(c.subsystem, "arp_sent_failures_total",
		"Number of ARP sent failures",
		nil,
	)
	c.arpSentReplies = buildPrometheusDesc(c.subsystem, "arp_sent_replies_total",
		"Number of ARP sent replies",
		nil,
	)
	c.arpReceivedReplies = buildPrometheusDesc(c.subsystem, "arp_received_replies_total",
		"Number of ARP received replies",
		nil,
	)
	c.arpReceivedPackets = buildPrometheusDesc(c.subsystem, "arp_received_packets_total",
		"Number of ARP received packets",
		nil,
	)
	c.arpDroppedNoEntry = buildPrometheusDesc(c.subsystem, "arp_dropped_no_entry_total",
		"Number of ARP packets dropped with no entry",
		nil,
	)
	c.arpEntriesTimeout = buildPrometheusDesc(c.subsystem, "arp_entries_timeout_total",
		"Number of ARP entries that timed out",
		nil,
	)

	// Expanded TCP metrics
	c.tcpSentDataBytes = buildPrometheusDesc(c.subsystem, "tcp_sent_data_bytes_total",
		"Total bytes of data sent via TCP",
		nil,
	)
	c.tcpRetransmittedPackets = buildPrometheusDesc(c.subsystem, "tcp_retransmitted_packets_total",
		"Total number of TCP packets retransmitted",
		nil,
	)
	c.tcpRetransmittedBytes = buildPrometheusDesc(c.subsystem, "tcp_retransmitted_bytes_total",
		"Total bytes retransmitted via TCP",
		nil,
	)
	c.tcpReceivedInSequenceBytes = buildPrometheusDesc(c.subsystem, "tcp_received_in_sequence_bytes_total",
		"Total bytes received in sequence via TCP",
		nil,
	)
	c.tcpReceivedDuplicateBytes = buildPrometheusDesc(c.subsystem, "tcp_received_duplicate_bytes_total",
		"Total completely duplicate bytes received via TCP",
		nil,
	)
	c.tcpSegmentsUpdatedRtt = buildPrometheusDesc(c.subsystem, "tcp_segments_updated_rtt_total",
		"Total TCP segments that updated RTT",
		nil,
	)
	c.tcpBadConnectionAttempts = buildPrometheusDesc(c.subsystem, "tcp_bad_connection_attempts_total",
		"Total bad TCP connection attempts",
		nil,
	)
	c.tcpKeepaliveProbes = buildPrometheusDesc(c.subsystem, "tcp_keepalive_probes_total",
		"Total TCP keepalive probes sent",
		nil,
	)
	c.tcpSyncacheDropped = buildPrometheusDesc(c.subsystem, "tcp_syncache_dropped_total",
		"Total TCP syncache entries dropped",
		nil,
	)

	// Expanded IP metrics
	c.ipSentFragments = buildPrometheusDesc(c.subsystem, "ip_sent_fragments_total",
		"Total IP fragments sent",
		nil,
	)

	// Expanded ARP metrics
	c.arpDroppedDuplicateAddress = buildPrometheusDesc(c.subsystem, "arp_dropped_duplicate_address_total",
		"Total ARP packets dropped due to duplicate address",
		nil,
	)

	// TCP ECN packet counters, both directions. "received" is always emitted
	// (resolved across the 26.1.11 ce/ect0/ect1 rename); "sent" (ect0/ect1 only —
	// there is no sent-side CE mark) is only emitted on 26.1.11+ boxes that report it.
	c.tcpEcnPacketsTotal = buildPrometheusDesc(c.subsystem, "tcp_ecn_packets_total",
		"Total TCP packets carrying an ECN mark, by direction and mark. The sent direction is only emitted on OPNsense 26.1.11+.",
		[]string{"direction", "mark"},
	)
	c.tcpEcnAccEcnHandshakesTotal = buildPrometheusDesc(c.subsystem, "tcp_ecn_accecn_handshakes_total",
		"Total TCP AccECN (FreeBSD 15) handshake SYNs by mark. Only emitted on OPNsense 26.1.11+.",
		[]string{"mark"},
	)

	// TCP syncookies (26.7+): replaces the legacy syncache sent-cookies/receivd-cookies
	// pair, which never fed a metric.
	c.tcpSyncookiesTotal = buildPrometheusDesc(c.subsystem, "tcp_syncookies_total",
		"Total TCP SYN cookies by result. Only emitted on OPNsense 26.7+.",
		[]string{"result"},
	)

	// TCP received-acks-for-data 3-way split (26.7+): replaces the legacy
	// received-acks-for-unsent-data aggregate, which never fed a metric.
	c.tcpReceivedAcksForDataTotal = buildPrometheusDesc(c.subsystem, "tcp_received_acks_for_data_total",
		"Total TCP ACKs received for data by reason. Only emitted on OPNsense 26.7+.",
		[]string{"reason"},
	)
}

func (c *protocolCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.tcpConnectionCountByState
	ch <- c.tcpSentPackets
	ch <- c.tcpReceivedPackets
	ch <- c.arpSentRequests
	ch <- c.arpReceivedRequests
	ch <- c.icmpCalls
	ch <- c.icmpSentPackets
	ch <- c.icmpDroppedByReason
	ch <- c.udpDeliveredPackets
	ch <- c.udpOutputPackets
	ch <- c.udpReceivedDatagrams
	ch <- c.udpDroppedByReason

	// CARP
	ch <- c.carpReceivedPackets
	ch <- c.carpSentPackets
	ch <- c.carpDroppedByReason

	// Pfsync
	ch <- c.pfsyncReceivedPackets
	ch <- c.pfsyncSentPackets
	ch <- c.pfsyncDroppedByReason
	ch <- c.pfsyncSendErrors

	// IP
	ch <- c.ipReceivedPackets
	ch <- c.ipForwardedPackets
	ch <- c.ipSentPackets
	ch <- c.ipDroppedByReason
	ch <- c.ipFragmentsReceived
	ch <- c.ipReassembledPackets

	// IPv6 / ICMPv6
	ch <- c.ip6ReceivedPackets
	ch <- c.ip6ForwardedPackets
	ch <- c.ip6SentPackets
	ch <- c.ip6DroppedByReason
	ch <- c.ip6FragmentsReceived
	ch <- c.ip6ReassembledPackets
	ch <- c.icmp6Calls
	ch <- c.icmp6DroppedByReason

	// Detailed TCP
	ch <- c.tcpConnectionRequests
	ch <- c.tcpConnectionAccepts
	ch <- c.tcpConnectionsEstablished
	ch <- c.tcpConnectionsClosed
	ch <- c.tcpConnectionDrops
	ch <- c.tcpRetransmitTimeouts
	ch <- c.tcpKeepaliveTimeouts
	ch <- c.tcpListenQueueOverflows
	ch <- c.tcpSyncacheEntries

	// ARP detailed
	ch <- c.arpSentFailures
	ch <- c.arpSentReplies
	ch <- c.arpReceivedReplies
	ch <- c.arpReceivedPackets
	ch <- c.arpDroppedNoEntry
	ch <- c.arpEntriesTimeout

	// Expanded TCP
	ch <- c.tcpSentDataBytes
	ch <- c.tcpRetransmittedPackets
	ch <- c.tcpRetransmittedBytes
	ch <- c.tcpReceivedInSequenceBytes
	ch <- c.tcpReceivedDuplicateBytes
	ch <- c.tcpSegmentsUpdatedRtt
	ch <- c.tcpBadConnectionAttempts
	ch <- c.tcpKeepaliveProbes
	ch <- c.tcpSyncacheDropped

	// Expanded IP
	ch <- c.ipSentFragments

	// Expanded ARP
	ch <- c.arpDroppedDuplicateAddress

	// TCP ECN / syncookies / acks-for-data (#237)
	ch <- c.tcpEcnPacketsTotal
	ch <- c.tcpEcnAccEcnHandshakesTotal
	ch <- c.tcpSyncookiesTotal
	ch <- c.tcpReceivedAcksForDataTotal
}

func (c *protocolCollector) Update(ctx context.Context, client *opnsense.Client, ch chan<- prometheus.Metric) *opnsense.APICallError {
	data, err := client.FetchProtocolStatistics()
	if err != nil {
		return err
	}
	for state, count := range data.TCPConnectionCountByState {
		ch <- prometheus.MustNewConstMetric(
			c.tcpConnectionCountByState, prometheus.GaugeValue, float64(count), state, c.instance,
		)
	}
	ch <- prometheus.MustNewConstMetric(
		c.tcpSentPackets, prometheus.CounterValue, float64(data.TCPSentPackets), c.instance,
	)

	ch <- prometheus.MustNewConstMetric(
		c.tcpReceivedPackets, prometheus.CounterValue, float64(data.TCPReceivedPackets), c.instance,
	)

	ch <- prometheus.MustNewConstMetric(
		c.arpSentRequests, prometheus.CounterValue, float64(data.ARPSentRequests), c.instance,
	)

	ch <- prometheus.MustNewConstMetric(
		c.arpReceivedRequests, prometheus.CounterValue, float64(data.ARPReceivedRequests), c.instance,
	)

	ch <- prometheus.MustNewConstMetric(
		c.icmpCalls, prometheus.CounterValue, float64(data.ICMPCalls), c.instance,
	)

	ch <- prometheus.MustNewConstMetric(
		c.icmpSentPackets, prometheus.CounterValue, float64(data.ICMPSentPackets), c.instance,
	)
	for reason, count := range data.ICMPDroppedByReason {
		// Cumulative BSD netstat drop counter (reset only on reboot) — CounterValue
		// to match the carp/pfsync/ip drop-reason siblings (#106).
		ch <- prometheus.MustNewConstMetric(
			c.icmpDroppedByReason, prometheus.CounterValue, float64(count), reason, c.instance,
		)
	}
	ch <- prometheus.MustNewConstMetric(
		c.udpDeliveredPackets, prometheus.CounterValue, float64(data.UDPDeliveredPackets), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.udpOutputPackets, prometheus.CounterValue, float64(data.UDPOutputPackets), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.udpReceivedDatagrams, prometheus.CounterValue, float64(data.UDPReceivedDatagrams), c.instance,
	)
	for reason, count := range data.UDPDroppedByReason {
		// Cumulative BSD netstat drop counter (reset only on reboot) — CounterValue
		// to match the carp/pfsync/ip drop-reason siblings (#106).
		ch <- prometheus.MustNewConstMetric(
			c.udpDroppedByReason, prometheus.CounterValue, float64(count), reason, c.instance,
		)
	}

	// CARP
	ch <- prometheus.MustNewConstMetric(
		c.carpReceivedPackets, prometheus.CounterValue, float64(data.CARPReceivedInet), "inet", c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.carpReceivedPackets, prometheus.CounterValue, float64(data.CARPReceivedInet6), "inet6", c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.carpSentPackets, prometheus.CounterValue, float64(data.CARPSentInet), "inet", c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.carpSentPackets, prometheus.CounterValue, float64(data.CARPSentInet6), "inet6", c.instance,
	)
	for reason, count := range data.CARPDroppedByReason {
		ch <- prometheus.MustNewConstMetric(
			c.carpDroppedByReason, prometheus.CounterValue, float64(count), reason, c.instance,
		)
	}

	// Pfsync
	ch <- prometheus.MustNewConstMetric(
		c.pfsyncReceivedPackets, prometheus.CounterValue, float64(data.PfsyncReceivedInet), "inet", c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.pfsyncReceivedPackets, prometheus.CounterValue, float64(data.PfsyncReceivedInet6), "inet6", c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.pfsyncSentPackets, prometheus.CounterValue, float64(data.PfsyncSentInet), "inet", c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.pfsyncSentPackets, prometheus.CounterValue, float64(data.PfsyncSentInet6), "inet6", c.instance,
	)
	for reason, count := range data.PfsyncDroppedByReason {
		ch <- prometheus.MustNewConstMetric(
			c.pfsyncDroppedByReason, prometheus.CounterValue, float64(count), reason, c.instance,
		)
	}
	ch <- prometheus.MustNewConstMetric(
		c.pfsyncSendErrors, prometheus.CounterValue, float64(data.PfsyncSendErrors), c.instance,
	)

	// IP
	ch <- prometheus.MustNewConstMetric(
		c.ipReceivedPackets, prometheus.CounterValue, float64(data.IPReceivedPackets), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.ipForwardedPackets, prometheus.CounterValue, float64(data.IPForwardedPackets), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.ipSentPackets, prometheus.CounterValue, float64(data.IPSentPackets), c.instance,
	)
	for reason, count := range data.IPDroppedByReason {
		ch <- prometheus.MustNewConstMetric(
			c.ipDroppedByReason, prometheus.CounterValue, float64(count), reason, c.instance,
		)
	}
	ch <- prometheus.MustNewConstMetric(
		c.ipFragmentsReceived, prometheus.CounterValue, float64(data.IPReceivedFragments), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.ipReassembledPackets, prometheus.CounterValue, float64(data.IPReassembledPackets), c.instance,
	)

	// IPv6 / ICMPv6 (#165)
	ch <- prometheus.MustNewConstMetric(
		c.ip6ReceivedPackets, prometheus.CounterValue, float64(data.IP6ReceivedPackets), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.ip6ForwardedPackets, prometheus.CounterValue, float64(data.IP6ForwardedPackets), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.ip6SentPackets, prometheus.CounterValue, float64(data.IP6SentPackets), c.instance,
	)
	for reason, count := range data.IP6DroppedByReason {
		ch <- prometheus.MustNewConstMetric(
			c.ip6DroppedByReason, prometheus.CounterValue, float64(count), reason, c.instance,
		)
	}
	ch <- prometheus.MustNewConstMetric(
		c.ip6FragmentsReceived, prometheus.CounterValue, float64(data.IP6ReceivedFragments), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.ip6ReassembledPackets, prometheus.CounterValue, float64(data.IP6ReassembledPackets), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.icmp6Calls, prometheus.CounterValue, float64(data.ICMP6Calls), c.instance,
	)
	for reason, count := range data.ICMP6DroppedByReason {
		ch <- prometheus.MustNewConstMetric(
			c.icmp6DroppedByReason, prometheus.CounterValue, float64(count), reason, c.instance,
		)
	}

	// Detailed TCP
	ch <- prometheus.MustNewConstMetric(
		c.tcpConnectionRequests, prometheus.CounterValue, float64(data.TCPConnectionRequests), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpConnectionAccepts, prometheus.CounterValue, float64(data.TCPConnectionAccepts), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpConnectionsEstablished, prometheus.CounterValue, float64(data.TCPConnectionsEstablished), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpConnectionsClosed, prometheus.CounterValue, float64(data.TCPConnectionsClosed), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpConnectionDrops, prometheus.CounterValue, float64(data.TCPConnectionDrops), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpRetransmitTimeouts, prometheus.CounterValue, float64(data.TCPRetransmitTimeouts), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpKeepaliveTimeouts, prometheus.CounterValue, float64(data.TCPKeepaliveTimeouts), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpListenQueueOverflows, prometheus.CounterValue, float64(data.TCPListenQueueOverflows), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpSyncacheEntries, prometheus.CounterValue, float64(data.TCPSyncacheEntriesAdded), c.instance,
	)

	// ARP detailed
	ch <- prometheus.MustNewConstMetric(
		c.arpSentFailures, prometheus.CounterValue, float64(data.ARPSentFailures), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.arpSentReplies, prometheus.CounterValue, float64(data.ARPSentReplies), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.arpReceivedReplies, prometheus.CounterValue, float64(data.ARPReceivedReplies), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.arpReceivedPackets, prometheus.CounterValue, float64(data.ARPReceivedPackets), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.arpDroppedNoEntry, prometheus.CounterValue, float64(data.ARPDroppedNoEntry), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.arpEntriesTimeout, prometheus.CounterValue, float64(data.ARPEntriesTimeout), c.instance,
	)

	// Expanded TCP metrics
	ch <- prometheus.MustNewConstMetric(
		c.tcpSentDataBytes, prometheus.CounterValue, float64(data.TCPSentDataBytes), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpRetransmittedPackets, prometheus.CounterValue, float64(data.TCPRetransmittedPackets), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpRetransmittedBytes, prometheus.CounterValue, float64(data.TCPRetransmittedBytes), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpReceivedInSequenceBytes, prometheus.CounterValue, float64(data.TCPReceivedInSequenceBytes), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpReceivedDuplicateBytes, prometheus.CounterValue, float64(data.TCPReceivedDuplicateBytes), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpSegmentsUpdatedRtt, prometheus.CounterValue, float64(data.TCPSegmentsUpdatedRtt), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpBadConnectionAttempts, prometheus.CounterValue, float64(data.TCPBadConnectionAttempts), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpKeepaliveProbes, prometheus.CounterValue, float64(data.TCPKeepaliveProbes), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpSyncacheDropped, prometheus.CounterValue, float64(data.TCPSyncacheDropped), c.instance,
	)

	// Expanded IP metrics
	ch <- prometheus.MustNewConstMetric(
		c.ipSentFragments, prometheus.CounterValue, float64(data.IPSentFragments), c.instance,
	)

	// Expanded ARP metrics
	ch <- prometheus.MustNewConstMetric(
		c.arpDroppedDuplicateAddress, prometheus.CounterValue, float64(data.ARPDroppedDuplicateAddress), c.instance,
	)

	// TCP ECN — received direction is resolved across the 26.1.11 rename and always
	// present; sent direction (no CE mark on the send side) is 26.1.11+ only.
	ch <- prometheus.MustNewConstMetric(
		c.tcpEcnPacketsTotal, prometheus.CounterValue, float64(data.TCPEcnCePackets), "received", "ce", c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpEcnPacketsTotal, prometheus.CounterValue, float64(data.TCPEcnEct0Packets), "received", "ect0", c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpEcnPacketsTotal, prometheus.CounterValue, float64(data.TCPEcnEct1Packets), "received", "ect1", c.instance,
	)
	if data.TCPEcnSentPresent {
		ch <- prometheus.MustNewConstMetric(
			c.tcpEcnPacketsTotal, prometheus.CounterValue, float64(data.TCPEcnSentEct0Packets), "sent", "ect0", c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.tcpEcnPacketsTotal, prometheus.CounterValue, float64(data.TCPEcnSentEct1Packets), "sent", "ect1", c.instance,
		)
	}

	// TCP AccECN handshake counters — 26.1.11+ only.
	if data.TCPEcnAccEcnPresent {
		ch <- prometheus.MustNewConstMetric(
			c.tcpEcnAccEcnHandshakesTotal, prometheus.CounterValue, float64(data.TCPEcnAceCeSyn), "ce", c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.tcpEcnAccEcnHandshakesTotal, prometheus.CounterValue, float64(data.TCPEcnAceEct0Syn), "ect0", c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.tcpEcnAccEcnHandshakesTotal, prometheus.CounterValue, float64(data.TCPEcnAceEct1Syn), "ect1", c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.tcpEcnAccEcnHandshakesTotal, prometheus.CounterValue, float64(data.TCPEcnAceNonEctSyn), "nonect", c.instance,
		)
	}

	// TCP syncookies — 26.7+ only (replaces the legacy syncache pair, which never
	// fed a metric).
	if data.TCPSyncookiesPresent {
		ch <- prometheus.MustNewConstMetric(
			c.tcpSyncookiesTotal, prometheus.CounterValue, float64(data.TCPSyncookiesSentCookies), "sent", c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.tcpSyncookiesTotal, prometheus.CounterValue, float64(data.TCPSyncookiesReceivedCookies), "received", c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.tcpSyncookiesTotal, prometheus.CounterValue, float64(data.TCPSyncookiesFailedCookies), "failed", c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.tcpSyncookiesTotal, prometheus.CounterValue, float64(data.TCPSyncookiesSpuriousCookies), "spurious", c.instance,
		)
	}

	// TCP received-acks-for-data 3-way split — 26.7+ only (replaces the legacy
	// received-acks-for-unsent-data aggregate, which never fed a metric).
	if data.TCPReceivedAcksForDataSplitPresent {
		ch <- prometheus.MustNewConstMetric(
			c.tcpReceivedAcksForDataTotal, prometheus.CounterValue, float64(data.TCPReceivedAcksForDataNotYetSent), "not_yet_sent", c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.tcpReceivedAcksForDataTotal, prometheus.CounterValue, float64(data.TCPReceivedAcksForDataNeverBeenSent), "never_been_sent", c.instance,
		)
		ch <- prometheus.MustNewConstMetric(
			c.tcpReceivedAcksForDataTotal, prometheus.CounterValue, float64(data.TCPReceivedAcksForDataBeingTooOld), "being_too_old", c.instance,
		)
	}

	return nil
}
