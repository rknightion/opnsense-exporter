package collector

import (
	"context"
	"log/slog"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/rknightion/opnsense2otel/v5/opnsense"
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
	tcpConnectionRequests      *prometheus.Desc
	tcpConnectionAccepts       *prometheus.Desc
	tcpConnectionsEstablished  *prometheus.Desc
	tcpConnectionsClosed       *prometheus.Desc
	tcpConnectionDrops         *prometheus.Desc
	tcpConnectionDropsByReason *prometheus.Desc
	tcpRetransmitTimeouts      *prometheus.Desc
	tcpKeepaliveTimeouts       *prometheus.Desc
	tcpListenQueueOverflows    *prometheus.Desc
	tcpSyncacheEntries         *prometheus.Desc

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

	// SACK / hostcache / TIME_WAIT / PMTUD / TCP-MD5 (#545). Five sections that
	// were decoded on every scrape and exported by nothing. Present on every
	// release in the support window, so unlike the #237 group above these are
	// unconditional, not presence-gated.
	tcpSackRecoveryEpisodes    *prometheus.Desc
	tcpSackSegmentRetransmits  *prometheus.Desc
	tcpSackRetransmittedBytes  *prometheus.Desc
	tcpSackBlocks              *prometheus.Desc
	tcpSackScoreboardOverflows *prometheus.Desc
	tcpSackLostRetransmissions *prometheus.Desc
	tcpSackTsoChunkRetransmits *prometheus.Desc

	tcpHostcacheEntriesAdded    *prometheus.Desc
	tcpHostcacheBufferOverflows *prometheus.Desc
	tcpHostcacheHits            *prometheus.Desc

	tcpTimeWaitEvents       *prometheus.Desc
	tcpPmtudBlackholeEvents *prometheus.Desc
	tcpSignature            *prometheus.Desc

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
	c.tcpConnectionDropsByReason = buildPrometheusDesc(c.subsystem, "tcp_connection_drops_by_reason_total",
		"Cumulative TCP connections dropped by reason (retransmit_timeout, persist_timeout, "+
			"finwait2_timeout, keepalive). These are kernel-lifetime counters that reset on "+
			"reboot, like the other protocol counters. A reason is only emitted when the box "+
			"reports that wire field; an older box that omits a reason omits its series rather "+
			"than reporting a fabricated zero (#374).",
		[]string{"reason"},
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

	// --- SACK (#545) ---
	// The exporter already has tcp_retransmitted_{packets,bytes}_total, which count
	// ALL retransmission including plain RTO timeouts. The SACK family below is the
	// subset driven by selective ACK, i.e. loss the peer explicitly told us about.
	// The two families overlap and must never be added together.
	c.tcpSackRecoveryEpisodes = buildPrometheusDesc(c.subsystem, "tcp_sack_recovery_episodes_total",
		"Total times TCP entered SACK-based loss recovery. Each episode is one burst of loss the peer "+
			"reported via selective ACK, however many segments it covered — so this counts loss EVENTS "+
			"while tcp_sack_segment_retransmits_total counts their cost. A rising rate here with a flat "+
			"retransmit rate means frequent small losses; the reverse means rare but severe ones.",
		nil,
	)
	c.tcpSackSegmentRetransmits = buildPrometheusDesc(c.subsystem, "tcp_sack_segment_retransmits_total",
		"Total TCP segments retransmitted during SACK recovery. A subset of "+
			"tcp_retransmitted_packets_total (which also counts plain RTO-driven retransmission) — the "+
			"two overlap, so never sum them.",
		nil,
	)
	c.tcpSackRetransmittedBytes = buildPrometheusDesc(c.subsystem, "tcp_sack_retransmitted_bytes_total",
		"Total bytes retransmitted during TCP SACK recovery. A subset of tcp_retransmitted_bytes_total; "+
			"the two overlap, so never sum them. Compare against tcp_sent_data_bytes_total for a "+
			"SACK-driven retransmission ratio — a sustained rise is a direct TCP-health signal on a box "+
			"whose job is forwarding packets.",
		nil,
	)
	c.tcpSackBlocks = buildPrometheusDesc(c.subsystem, "tcp_sack_blocks_total",
		"Total TCP SACK option blocks, by direction. direction=\"received\" is the peer telling us about "+
			"holes in the data WE sent (outbound loss); direction=\"sent\" is us telling the peer about "+
			"holes in the data IT sent (inbound loss). The direction that rises tells you which way the "+
			"lossy path runs, which no other metric on this box distinguishes.",
		[]string{"direction"},
	)
	c.tcpSackScoreboardOverflows = buildPrometheusDesc(c.subsystem, "tcp_sack_scoreboard_overflows_total",
		"Total times the TCP SACK scoreboard overflowed and the kernel stopped tracking individual holes "+
			"in a connection, falling back to coarser recovery. Should be flat at zero; any sustained rise "+
			"means loss severe enough that SACK recovery is degrading rather than helping.",
		nil,
	)
	c.tcpSackLostRetransmissions = buildPrometheusDesc(c.subsystem, "tcp_sack_lost_retransmissions_total",
		"Total TCP retransmissions that were themselves lost, detected during SACK recovery. This is the "+
			"severe case: the path dropped the repair packet too, so recovery stalls until a timeout fires "+
			"and the connection visibly hangs. No other counter on this box distinguishes a lost repair "+
			"from ordinary loss. A subset of tcp_retransmitted_packets_total and of "+
			"tcp_sack_segment_retransmits_total — all three overlap, so never sum them.",
		nil,
	)
	c.tcpSackTsoChunkRetransmits = buildPrometheusDesc(c.subsystem, "tcp_sack_tso_chunk_retransmits_total",
		"Total TCP segments retransmitted as part of a TSO (TCP segmentation offload) chunk during SACK "+
			"recovery, i.e. repairs the NIC re-segmented rather than the kernel. Low signal on its own; it "+
			"exists so the sack section is modelled completely and the split between offloaded and "+
			"kernel-driven repair is visible when tuning TSO. A subset of "+
			"tcp_sack_segment_retransmits_total — the two overlap, so never sum them.",
		nil,
	)

	// --- Host cache (#545) ---
	c.tcpHostcacheEntriesAdded = buildPrometheusDesc(c.subsystem, "tcp_hostcache_entries_added_total",
		"Total entries added to the TCP host cache, which remembers per-peer RTT/ssthresh so a new "+
			"connection to a known peer warm-starts instead of re-probing. The add rate is a proxy for "+
			"distinct-peer churn, not for connection volume: a repeat peer is a cache hit and adds nothing.",
		nil,
	)
	c.tcpHostcacheBufferOverflows = buildPrometheusDesc(c.subsystem, "tcp_hostcache_buffer_overflows_total",
		"Total TCP host cache insertions that overflowed a hash bucket and evicted an existing entry. "+
			"Nonzero means the cache is under churn pressure and the kernel is losing cached path metrics, "+
			"so affected connections restart from defaults and re-probe the path.",
		nil,
	)
	c.tcpHostcacheHits = buildPrometheusDesc(c.subsystem, "tcp_hostcache_hits_total",
		"Total TCP connections that warm-started a path metric from the host cache instead of re-probing "+
			"it, by which metric was reused: \"rtt\" (round-trip time), \"rttvar\" (RTT variance) and "+
			"\"ssthresh\" (slow-start threshold). Despite the name these are NOT part of the "+
			"statistics.tcp.hostcache section — they are top-level counters "+
			"(connections-hostcache-*) and are the hit side of the cache whose insert and eviction rates "+
			"tcp_hostcache_entries_added_total and tcp_hostcache_buffer_overflows_total report. A high hit "+
			"rate is good: it means repeat peers skip re-probing. Hits falling while "+
			"tcp_hostcache_buffer_overflows_total rises means eviction pressure is destroying the cache's "+
			"value. The three are counted independently, so they do not sum to a connection count.",
		[]string{"metric"},
	)

	// --- TIME_WAIT (#545) ---
	c.tcpTimeWaitEvents = buildPrometheusDesc(c.subsystem, "tcp_timewait_events_total",
		"Total TCP TIME_WAIT state events, by kind. \"responds\" = a segment answered from TIME_WAIT "+
			"(usually a retransmitted FIN, normal); \"recycles\" = a TIME_WAIT entry reused early to make "+
			"room, which means state pressure from short-lived connection churn; \"resets\" = an RST issued "+
			"from TIME_WAIT. Only recycles and resets indicate a problem — responds is ordinary close churn.",
		[]string{"event"},
	)

	// --- PMTUD blackhole detection (#545) ---
	c.tcpPmtudBlackholeEvents = buildPrometheusDesc(c.subsystem, "tcp_pmtud_blackhole_events_total",
		"Total TCP path-MTU-discovery blackhole detection events, by kind. A PMTUD blackhole is a path "+
			"that silently drops oversized packets without returning the ICMP \"fragmentation needed\" that "+
			"would let TCP shrink its MSS — the classic cause of \"some sites load, some hang\", and "+
			"invisible from outside the box. \"activated\" = the kernel suspected a blackhole and dropped "+
			"MSS; \"activated_min_mss\" = it fell all the way back to the minimum MSS, so the path is badly "+
			"broken and throughput will suffer; \"failed\" = shrinking the MSS did not fix it. Any sustained "+
			"rise warrants investigating MTU on the upstream path.",
		[]string{"event"},
	)

	// --- TCP-MD5 (#545) ---
	c.tcpSignature = buildPrometheusDesc(c.subsystem, "tcp_signature_total",
		"Total TCP-MD5 (RFC 2385) signature outcomes, by result. In practice TCP-MD5 authenticates BGP "+
			"sessions, so on a box with no MD5-authenticated peer every result is permanently zero and that "+
			"is correct, not a fault. \"good\" is the healthy denominator — its rate falling to zero is how "+
			"an authenticated peer going quiet shows up. \"bad\" means a wrong or rotated key (or spoofing); "+
			"\"make_failed\" is a local failure to generate a signature, i.e. a missing key in the kernel "+
			"keytable; \"not_expected\" and \"not_provided\" are the two halves of an asymmetric "+
			"configuration, where one side is signing and the other is not.",
		[]string{"result"},
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
	ch <- c.tcpConnectionDropsByReason
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

	// SACK / hostcache / TIME_WAIT / PMTUD / TCP-MD5 (#545)
	ch <- c.tcpSackRecoveryEpisodes
	ch <- c.tcpSackSegmentRetransmits
	ch <- c.tcpSackRetransmittedBytes
	ch <- c.tcpSackBlocks
	ch <- c.tcpSackScoreboardOverflows
	ch <- c.tcpSackLostRetransmissions
	ch <- c.tcpSackTsoChunkRetransmits
	ch <- c.tcpHostcacheEntriesAdded
	ch <- c.tcpHostcacheBufferOverflows
	ch <- c.tcpHostcacheHits
	ch <- c.tcpTimeWaitEvents
	ch <- c.tcpPmtudBlackholeEvents
	ch <- c.tcpSignature
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
	// TCP connection drops by reason (#374) — presence-gated per reason at the
	// client layer, so ranging over the map naturally emits a series only for
	// the reasons the box actually reported.
	for reason, count := range data.TCPConnectionDropsByReason {
		ch <- prometheus.MustNewConstMetric(
			c.tcpConnectionDropsByReason, prometheus.CounterValue, float64(count), reason, c.instance,
		)
	}
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

	// SACK / hostcache / TIME_WAIT / PMTUD / TCP-MD5 (#545). Every one of these is
	// a cumulative kernel counter that resets only on reboot, so all are
	// CounterValue. Unconditional: verified present on 26.1, 26.7.1 and 27.1.a, so
	// unlike the #237 group above there is nothing to presence-gate.
	ch <- prometheus.MustNewConstMetric(
		c.tcpSackRecoveryEpisodes, prometheus.CounterValue, float64(data.TCPSackRecoveryEpisodes), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpSackSegmentRetransmits, prometheus.CounterValue, float64(data.TCPSackSegmentRetransmits), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpSackRetransmittedBytes, prometheus.CounterValue, float64(data.TCPSackByteRetransmits), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpSackBlocks, prometheus.CounterValue, float64(data.TCPSackReceivedBlocks), "received", c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpSackBlocks, prometheus.CounterValue, float64(data.TCPSackSentOptionBlocks), "sent", c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpSackScoreboardOverflows, prometheus.CounterValue, float64(data.TCPSackScoreboardOverflows), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpHostcacheEntriesAdded, prometheus.CounterValue, float64(data.TCPHostcacheEntriesAdded), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpSackLostRetransmissions, prometheus.CounterValue, float64(data.TCPSackLostRetransmissions), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpSackTsoChunkRetransmits, prometheus.CounterValue, float64(data.TCPSackTsoChunkRetransmits), c.instance,
	)
	ch <- prometheus.MustNewConstMetric(
		c.tcpHostcacheBufferOverflows, prometheus.CounterValue, float64(data.TCPHostcacheBufferOverflows), c.instance,
	)
	for metric, count := range data.TCPHostcacheHitsByMetric {
		ch <- prometheus.MustNewConstMetric(
			c.tcpHostcacheHits, prometheus.CounterValue, float64(count), metric, c.instance,
		)
	}
	for event, count := range data.TCPTimeWaitByEvent {
		ch <- prometheus.MustNewConstMetric(
			c.tcpTimeWaitEvents, prometheus.CounterValue, float64(count), event, c.instance,
		)
	}
	for event, count := range data.TCPPmtudBlackholeByEvent {
		ch <- prometheus.MustNewConstMetric(
			c.tcpPmtudBlackholeEvents, prometheus.CounterValue, float64(count), event, c.instance,
		)
	}
	for result, count := range data.TCPSignatureByResult {
		ch <- prometheus.MustNewConstMetric(
			c.tcpSignature, prometheus.CounterValue, float64(count), result, c.instance,
		)
	}

	return nil
}
