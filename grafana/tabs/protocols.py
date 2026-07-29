"""
Protocol Stats tab — covers all opnsense_protocol_* metrics plus BPF statistics.

Rows:
  TCP Traffic         — sent/received packets rate ts
  TCP Connection Lifecycle — request/accept/established/closed/drop/bad-attempt rate ts
  TCP Retransmit & Queue — retransmit/keepalive/syncache/listen-queue rate ts;
                         connection drops by reason (stacked rate, #374)
  TCP Bytes           — sent/retransmit/in-seq/dup bytes (Bps) rate ts + RTT segments
  TCP ECN & SYN Cookies (26.1.11+/26.7+) — ECN packets by direction/mark, AccECN
                         handshakes, SYN cookies by result, acks-for-data by reason (#237)
  TCP Connection State (gauge) — statetimeline + piechart of current state distribution
  UDP                 — delivered/output/received rate ts + dropped-by-reason table
  IP                  — received/forwarded/sent/fragment rate ts + dropped-by-reason table
  ARP (Activity)      — sent-req/recv-req/sent-reply/recv-reply/recv-packets rate ts
  ARP (Errors & Aging) — sent-failures/dropped-no-entry/entries-timeout/dropped-dup rate ts
  ICMP                — calls/sent rate ts + dropped-by-reason table
  CARP Protocol       — recv/sent rate ts + dropped-by-reason table
  pfsync Protocol     — recv/sent rate ts + dropped-by-reason table + send-errors ts
  BPF Statistics      — listeners_total stat; per-(process,interface) packet counters rate ts;
                         buffer size gauges ts (always visible — core endpoint)
"""

from builder import Builder, sel, grp, RATE


def build(b: Builder):
    # -------------------------------------------------------------------------
    # TCP — Traffic
    # -------------------------------------------------------------------------
    tcp_traffic = b.ts(
        "TCP Packets (rate)",
        [
            (f"rate({sel('opnsense_protocol_tcp_sent_packets_total')}[{RATE}])",
             "sent"),
            (f"rate({sel('opnsense_protocol_tcp_received_packets_total')}[{RATE}])",
             "received"),
        ],
        unit="pps",
        w=12, h=8,
        desc="Rate of TCP packets sent and received.",
    )

    # TCP — Connection Lifecycle
    tcp_lifecycle = b.ts(
        "TCP Connection Lifecycle (rate)",
        [
            (f"rate({sel('opnsense_protocol_tcp_connection_requests_total')}[{RATE}])",
             "requests"),
            (f"rate({sel('opnsense_protocol_tcp_connection_accepts_total')}[{RATE}])",
             "accepts"),
            (f"rate({sel('opnsense_protocol_tcp_connections_established_total')}[{RATE}])",
             "established"),
            (f"rate({sel('opnsense_protocol_tcp_connections_closed_total')}[{RATE}])",
             "closed"),
            (f"rate({sel('opnsense_protocol_tcp_connection_drops_total')}[{RATE}])",
             "drops"),
            (f"rate({sel('opnsense_protocol_tcp_bad_connection_attempts_total')}[{RATE}])",
             "bad attempts"),
        ],
        unit="connps",
        w=12, h=8,
        desc="Rate of TCP connection lifecycle events.",
    )

    # TCP — Retransmit, Keepalive, Syncache, Listen Queue
    tcp_retransmit = b.ts(
        "TCP Retransmit, Keepalive & Queue (rate)",
        [
            (f"rate({sel('opnsense_protocol_tcp_retransmit_timeouts_total')}[{RATE}])",
             "retransmit timeouts"),
            (f"rate({sel('opnsense_protocol_tcp_keepalive_timeouts_total')}[{RATE}])",
             "keepalive timeouts"),
            (f"rate({sel('opnsense_protocol_tcp_keepalive_probes_total')}[{RATE}])",
             "keepalive probes"),
            (f"rate({sel('opnsense_protocol_tcp_retransmitted_packets_total')}[{RATE}])",
             "retransmitted packets"),
            (f"rate({sel('opnsense_protocol_tcp_listen_queue_overflows_total')}[{RATE}])",
             "listen queue overflows"),
            (f"rate({sel('opnsense_protocol_tcp_syncache_entries_total')}[{RATE}])",
             "syncache entries added"),
            (f"rate({sel('opnsense_protocol_tcp_syncache_dropped_total')}[{RATE}])",
             "syncache dropped"),
        ],
        unit="pps",
        w=12, h=8,
        desc="Rate of TCP retransmits, keepalive events, syncache activity, and listen queue overflows.",
    )

    # TCP — Connection drops split by reason (#374). These are kernel-lifetime
    # counters that reset on reboot, like the aggregate drops/timeouts above.
    # A reason is only present in the API response when the box reports it, so
    # a bar simply does not appear for an unreported reason rather than
    # flat-lining at zero.
    tcp_drops_by_reason = b.ts(
        "TCP Connection Drops by Reason (rate)",
        [
            (f'rate({sel("opnsense_protocol_tcp_connection_drops_by_reason_total")}[{RATE}])',
             "{{reason}}"),
        ],
        unit="connps",
        w=12, h=8,
        stack=True,
        desc="opnsense_protocol_tcp_connection_drops_by_reason_total: cumulative TCP "
             "connections dropped by reason (retransmit_timeout, persist_timeout, "
             "finwait2_timeout, keepalive) — kernel-lifetime counters that reset on reboot. "
             "A reason series only appears when the box reports that wire field, so an "
             "older box simply omits reasons it does not send rather than reporting zero. "
             "Distinguishes WAN loss, stalled applications, state-lifetime cleanup, and "
             "keepalive failure without a packet capture.",
    )

    # TCP — Bytes throughput
    tcp_bytes = b.ts(
        "TCP Throughput (rate)",
        [
            (f"rate({sel('opnsense_protocol_tcp_sent_data_bytes_total')}[{RATE}])",
             "sent"),
            (f"rate({sel('opnsense_protocol_tcp_retransmitted_bytes_total')}[{RATE}])",
             "retransmitted"),
            (f"rate({sel('opnsense_protocol_tcp_received_in_sequence_bytes_total')}[{RATE}])",
             "received in-sequence"),
            (f"rate({sel('opnsense_protocol_tcp_received_duplicate_bytes_total')}[{RATE}])",
             "received duplicate"),
        ],
        unit="Bps",
        w=12, h=8,
        desc="TCP byte throughput (bytes per second). Includes duplicate and retransmitted bytes.",
    )

    # TCP — RTT segments (rate ts)
    tcp_rtt = b.ts(
        "TCP Segments Updated RTT (rate)",
        [
            (f"rate({sel('opnsense_protocol_tcp_segments_updated_rtt_total')}[{RATE}])",
             "segments updating RTT"),
        ],
        unit="ops",
        w=12, h=8,
        desc="Rate of TCP segments that caused an RTT sample update.",
    )

    # TCP — ECN / AccECN / SYN cookies / acks-for-data (#237). All four are
    # presence-gated on the box's OPNsense version — older boxes simply never
    # populate these series, so the panels render empty rather than erroring.
    tcp_ecn = b.ts(
        "TCP ECN Packets (rate)",
        [
            (f"rate({sel('opnsense_protocol_tcp_ecn_packets_total')}[{RATE}])",
             "{{direction}} {{mark}}"),
        ],
        unit="pps",
        w=8, h=8,
        desc="opnsense_protocol_tcp_ecn_packets_total: TCP packets carrying an ECN mark, "
             "by direction (received/sent) and mark (ce/ect0/ect1). The received direction "
             "is resolved across the 26.1.11 key rename; sent is 26.1.11+ only.",
    )
    tcp_accecn = b.ts(
        "TCP AccECN Handshakes (rate, 26.1.11+)",
        [
            (f"rate({sel('opnsense_protocol_tcp_ecn_accecn_handshakes_total')}[{RATE}])",
             "{{mark}}"),
        ],
        unit="ops",
        w=8, h=8,
        desc="opnsense_protocol_tcp_ecn_accecn_handshakes_total: FreeBSD 15 AccECN "
             "handshake SYNs by mark (ce/ect0/ect1/nonect). OPNsense 26.1.11+ only.",
    )
    tcp_syncookies = b.ts(
        "TCP SYN Cookies (rate, 26.7+)",
        [
            (f"rate({sel('opnsense_protocol_tcp_syncookies_total')}[{RATE}])",
             "{{result}}"),
        ],
        unit="ops",
        w=8, h=8,
        desc="opnsense_protocol_tcp_syncookies_total: SYN cookies by result "
             "(sent/received/failed/spurious). Replaces the legacy syncache "
             "sent-cookies/receivd-cookies pair, which never fed a metric. OPNsense 26.7+ only.",
    )
    tcp_acks_for_data = b.ts(
        "TCP Acks For Data (rate, 26.7+)",
        [
            (f"rate({sel('opnsense_protocol_tcp_received_acks_for_data_total')}[{RATE}])",
             "{{reason}}"),
        ],
        unit="ops",
        w=8, h=8,
        desc="opnsense_protocol_tcp_received_acks_for_data_total: ACKs received for data "
             "by reason (not_yet_sent/never_been_sent/being_too_old) — the 26.7 three-way "
             "split of the legacy received-acks-for-unsent-data aggregate, which never fed "
             "a metric. OPNsense 26.7+ only.",
    )

    # TCP — Connection state: statetimeline (gauge — raw)
    tcp_state_tl = b.statetimeline(
        "TCP Connections by State (over time)",
        [
            (sel("opnsense_protocol_tcp_connection_count_by_state", 'state=~".+"'),
             "{{state}}"),
        ],
        mappings={},  # no binary mapping — numeric count displayed as-is
        # A state census is not an up/down flag: the helper's default [red@base, green@1]
        # painted every state with zero connections solid red, so a healthy firewall
        # rendered two-thirds alarm-coloured (#510). One neutral step, no false alarm.
        thresholds=[{"color": "blue", "value": None}],
        unit="short",
        w=16, h=8,
        desc="Number of TCP connections by state (gauge — current value, not rate).",
    )

    # TCP — Connection state: piechart (current distribution)
    tcp_state_pie = b.piechart(
        "TCP Connections by State (now)",
        [
            (sel("opnsense_protocol_tcp_connection_count_by_state", 'state=~".+"'),
             "{{state}}"),
        ],
        unit="short",
        w=8, h=8,
        desc="Current distribution of TCP connections across states (gauge).",
    )

    # -------------------------------------------------------------------------
    # UDP
    # -------------------------------------------------------------------------
    udp_traffic = b.ts(
        "UDP Packets (rate)",
        [
            (f"rate({sel('opnsense_protocol_udp_received_datagrams_total')}[{RATE}])",
             "received datagrams"),
            (f"rate({sel('opnsense_protocol_udp_delivered_packets_total')}[{RATE}])",
             "delivered"),
            (f"rate({sel('opnsense_protocol_udp_output_packets_total')}[{RATE}])",
             "output"),
        ],
        unit="pps",
        w=12, h=8,
        desc="Rate of UDP datagrams received, delivered, and output.",
    )

    udp_drops = b.table(
        "UDP Dropped by Reason",
        [
            f'sort_desc(sum {grp("reason")} (rate({sel("opnsense_protocol_udp_dropped_by_reason_total")}[5m])))',
        ],
        renames={"Value": "Drop rate (5m avg)", "reason": "Reason", "opnsense_instance": "Instance"},
        unit_overrides={"Drop rate (5m avg)": "pps"},
        sort_by="Drop rate (5m avg)",
        w=12, h=8,
        desc="UDP drops broken down by reason (5-minute average rate).",
    )

    # -------------------------------------------------------------------------
    # IP
    # -------------------------------------------------------------------------
    ip_traffic = b.ts(
        "IP Packets (rate)",
        [
            (f"rate({sel('opnsense_protocol_ip_received_packets_total')}[{RATE}])",
             "received"),
            (f"rate({sel('opnsense_protocol_ip_forwarded_packets_total')}[{RATE}])",
             "forwarded"),
            (f"rate({sel('opnsense_protocol_ip_sent_packets_total')}[{RATE}])",
             "sent"),
        ],
        unit="pps",
        w=12, h=8,
        desc="Rate of IP packets received, forwarded, and sent.",
    )

    ip_frags = b.ts(
        "IP Fragmentation (rate)",
        [
            (f"rate({sel('opnsense_protocol_ip_fragments_received_total')}[{RATE}])",
             "fragments received"),
            (f"rate({sel('opnsense_protocol_ip_reassembled_packets_total')}[{RATE}])",
             "reassembled"),
            (f"rate({sel('opnsense_protocol_ip_sent_fragments_total')}[{RATE}])",
             "fragments sent"),
        ],
        unit="pps",
        w=12, h=8,
        desc="Rate of IP fragment reception, reassembly, and transmission.",
    )

    ip_drops = b.table(
        "IP Dropped by Reason",
        [
            f'sort_desc(sum {grp("reason")} (rate({sel("opnsense_protocol_ip_dropped_by_reason_total")}[5m])))',
        ],
        renames={"Value": "Drop rate (5m avg)", "reason": "Reason", "opnsense_instance": "Instance"},
        unit_overrides={"Drop rate (5m avg)": "pps"},
        sort_by="Drop rate (5m avg)",
        w=24, h=8,
        desc="IP drops broken down by reason (5-minute average rate).",
    )

    # -------------------------------------------------------------------------
    # IPv6 / ICMPv6 (#165) — the ip_*/icmp_* panels above are IPv4-only.
    # -------------------------------------------------------------------------
    ip6_traffic = b.ts(
        "IPv6 Packets (rate)",
        [
            (f"rate({sel('opnsense_protocol_ip6_received_packets_total')}[{RATE}])", "received"),
            (f"rate({sel('opnsense_protocol_ip6_forwarded_packets_total')}[{RATE}])", "forwarded"),
            (f"rate({sel('opnsense_protocol_ip6_sent_packets_total')}[{RATE}])", "sent"),
        ],
        unit="pps", w=12, h=8,
        desc="Rate of IPv6 packets received, forwarded, and sent (dual-stack visibility, #165).",
    )
    ip6_frags = b.ts(
        "IPv6 Fragmentation (rate)",
        [
            (f"rate({sel('opnsense_protocol_ip6_fragments_received_total')}[{RATE}])", "fragments received"),
            (f"rate({sel('opnsense_protocol_ip6_reassembled_packets_total')}[{RATE}])", "reassembled"),
        ],
        unit="pps", w=12, h=8,
        desc="Rate of IPv6 fragment reception and reassembly.",
    )
    ip6_drops = b.table(
        "IPv6 Dropped by Reason",
        [f'sort_desc(sum {grp("reason")} (rate({sel("opnsense_protocol_ip6_dropped_by_reason_total")}[5m])))'],
        renames={"Value": "Drop rate (5m avg)", "reason": "Reason", "opnsense_instance": "Instance"},
        unit_overrides={"Drop rate (5m avg)": "pps"},
        sort_by="Drop rate (5m avg)", w=12, h=8,
        desc="IPv6 drops broken down by reason (5-minute average rate).",
    )
    icmp6_traffic = b.ts(
        "ICMPv6 Calls (rate)",
        [(f"rate({sel('opnsense_protocol_icmp6_calls_total')}[{RATE}])", "calls")],
        unit="pps", w=12, h=8, desc="Rate of ICMPv6 calls.",
    )
    icmp6_drops = b.table(
        "ICMPv6 Dropped by Reason",
        [f'sort_desc(sum {grp("reason")} (rate({sel("opnsense_protocol_icmp6_dropped_by_reason_total")}[5m])))'],
        renames={"Value": "Drop rate (5m avg)", "reason": "Reason", "opnsense_instance": "Instance"},
        unit_overrides={"Drop rate (5m avg)": "pps"},
        sort_by="Drop rate (5m avg)", w=12, h=8,
        desc="ICMPv6 drops broken down by reason (5-minute average rate).",
    )

    # -------------------------------------------------------------------------
    # ARP
    # -------------------------------------------------------------------------
    arp_activity = b.ts(
        "ARP Activity (rate)",
        [
            (f"rate({sel('opnsense_protocol_arp_sent_requests_total')}[{RATE}])",
             "sent requests"),
            (f"rate({sel('opnsense_protocol_arp_received_requests_total')}[{RATE}])",
             "received requests"),
            (f"rate({sel('opnsense_protocol_arp_sent_replies_total')}[{RATE}])",
             "sent replies"),
            (f"rate({sel('opnsense_protocol_arp_received_replies_total')}[{RATE}])",
             "received replies"),
            (f"rate({sel('opnsense_protocol_arp_received_packets_total')}[{RATE}])",
             "received packets"),
        ],
        unit="pps",
        w=12, h=8,
        desc="Rate of ARP requests, replies, and packets.",
    )

    arp_errors = b.ts(
        "ARP Errors & Aging (rate)",
        [
            (f"rate({sel('opnsense_protocol_arp_sent_failures_total')}[{RATE}])",
             "send failures"),
            (f"rate({sel('opnsense_protocol_arp_dropped_no_entry_total')}[{RATE}])",
             "dropped (no entry)"),
            (f"rate({sel('opnsense_protocol_arp_entries_timeout_total')}[{RATE}])",
             "entries timed out"),
            (f"rate({sel('opnsense_protocol_arp_dropped_duplicate_address_total')}[{RATE}])",
             "dropped (duplicate addr)"),
        ],
        unit="pps",
        w=12, h=8,
        desc="Rate of ARP errors, drops, and aging events.",
    )

    # -------------------------------------------------------------------------
    # ICMP
    # -------------------------------------------------------------------------
    icmp_traffic = b.ts(
        "ICMP (rate)",
        [
            (f"rate({sel('opnsense_protocol_icmp_calls_total')}[{RATE}])",
             "calls"),
            (f"rate({sel('opnsense_protocol_icmp_sent_packets_total')}[{RATE}])",
             "sent packets"),
        ],
        unit="pps",
        w=12, h=8,
        desc="Rate of ICMP calls and sent packets.",
    )

    icmp_drops = b.table(
        "ICMP Dropped by Reason",
        [
            f'sort_desc(sum {grp("reason")} (rate({sel("opnsense_protocol_icmp_dropped_by_reason_total")}[5m])))',
        ],
        renames={"Value": "Drop rate (5m avg)", "reason": "Reason", "opnsense_instance": "Instance"},
        unit_overrides={"Drop rate (5m avg)": "pps"},
        sort_by="Drop rate (5m avg)",
        w=12, h=8,
        desc="ICMP drops broken down by reason (5-minute average rate).",
    )

    # -------------------------------------------------------------------------
    # CARP (protocol-level stats, distinct from the CARP VIP tab)
    # -------------------------------------------------------------------------
    carp_traffic = b.ts(
        "CARP Packets (rate)",
        [
            (f"rate({sel('opnsense_protocol_carp_received_packets_total')}[{RATE}])",
             "received {{address_family}}"),
            (f"rate({sel('opnsense_protocol_carp_sent_packets_total')}[{RATE}])",
             "sent {{address_family}}"),
        ],
        unit="pps",
        w=12, h=8,
        desc="Rate of CARP packets received and sent, by address family.",
    )

    carp_drops = b.table(
        "CARP Dropped by Reason",
        [
            f'sort_desc(sum {grp("reason")} (rate({sel("opnsense_protocol_carp_dropped_by_reason_total")}[5m])))',
        ],
        renames={"Value": "Drop rate (5m avg)", "reason": "Reason", "opnsense_instance": "Instance"},
        unit_overrides={"Drop rate (5m avg)": "pps"},
        sort_by="Drop rate (5m avg)",
        w=12, h=8,
        desc="CARP drops broken down by reason (5-minute average rate).",
    )

    # -------------------------------------------------------------------------
    # pfsync
    # -------------------------------------------------------------------------
    pfsync_traffic = b.ts(
        "pfsync Packets (rate)",
        [
            (f"rate({sel('opnsense_protocol_pfsync_received_packets_total')}[{RATE}])",
             "received {{address_family}}"),
            (f"rate({sel('opnsense_protocol_pfsync_sent_packets_total')}[{RATE}])",
             "sent {{address_family}}"),
        ],
        unit="pps",
        w=12, h=8,
        desc="Rate of pfsync packets received and sent, by address family.",
    )

    pfsync_errors = b.ts(
        "pfsync Send Errors (rate)",
        [
            (f"rate({sel('opnsense_protocol_pfsync_send_errors_total')}[{RATE}])",
             "send errors"),
        ],
        unit="pps",
        w=8, h=8,
        desc="Rate of pfsync send errors.",
    )

    pfsync_drops = b.table(
        "pfsync Dropped by Reason",
        [
            f'sort_desc(sum {grp("reason")} (rate({sel("opnsense_protocol_pfsync_dropped_by_reason_total")}[5m])))',
        ],
        renames={"Value": "Drop rate (5m avg)", "reason": "Reason", "opnsense_instance": "Instance"},
        unit_overrides={"Drop rate (5m avg)": "pps"},
        sort_by="Drop rate (5m avg)",
        w=16, h=8,
        desc="pfsync drops broken down by reason (5-minute average rate).",
    )

    # -------------------------------------------------------------------------
    # BPF Statistics (core endpoint — always present, no sentinel gate)
    # -------------------------------------------------------------------------
    bpf_listeners = b.stat(
        "BPF Listeners",
        sel("opnsense_bpf_listeners_total"),
        unit="short", w=6, h=4,
        desc=(
            "Total number of BPF listener entries before aggregation. "
            "Aggregated by (process, interface) per D9."
        ),
    )
    bpf_pkts = b.ts(
        "BPF Packet Counters (rate)",
        [
            (f'rate({sel("opnsense_bpf_received_packets_total")}[{RATE}])',
             "{{process}}/{{interface}} received"),
            (f'rate({sel("opnsense_bpf_dropped_packets_total")}[{RATE}])',
             "{{process}}/{{interface}} dropped"),
            (f'rate({sel("opnsense_bpf_matched_packets_total")}[{RATE}])',
             "{{process}}/{{interface}} matched"),
        ],
        unit="pps", w=18, h=8,
        desc=(
            "BPF packet counters (cumulative) per (process, interface) aggregation. "
            "Aggregation sums entries with the same process+interface labels."
        ),
    )
    bpf_buffers = b.ts(
        "BPF Buffer Sizes",
        [
            (sel("opnsense_bpf_store_buffer_bytes"),
             "{{process}}/{{interface}} store"),
            (sel("opnsense_bpf_hold_buffer_bytes"),
             "{{process}}/{{interface}} hold"),
        ],
        unit="bytes", w=24, h=8,
        desc=(
            "BPF store and hold buffer sizes in bytes per (process, interface). "
            "These are gauges — the kernel may resize them dynamically."
        ),
    )

    # -------------------------------------------------------------------------
    # Assemble the tab
    # -------------------------------------------------------------------------
    b.tab("Protocol Stats", [
        b.row("TCP Traffic", [tcp_traffic, tcp_lifecycle]),
        b.row("TCP Retransmit & Queue", [tcp_retransmit, tcp_drops_by_reason, tcp_bytes]),
        b.row("TCP Bytes & RTT", [tcp_rtt, tcp_state_pie]),
        b.row("TCP ECN & SYN Cookies (26.1.11+/26.7+)",
              [tcp_ecn, tcp_accecn, tcp_syncookies, tcp_acks_for_data]),
        b.row("TCP Connection State", [tcp_state_tl]),
        b.row("UDP", [udp_traffic, udp_drops]),
        b.row("IP", [ip_traffic, ip_frags, ip_drops]),
        b.row("IPv6", [ip6_traffic, ip6_frags, ip6_drops]),
        b.row("ARP", [arp_activity, arp_errors]),
        b.row("ICMP", [icmp_traffic, icmp_drops]),
        b.row("ICMPv6", [icmp6_traffic, icmp6_drops]),
        b.row("CARP Protocol", [carp_traffic, carp_drops]),
        b.row("pfsync Protocol", [pfsync_traffic, pfsync_errors, pfsync_drops]),
        b.row("BPF Statistics", [bpf_listeners, bpf_pkts, bpf_buffers]),
    ])
