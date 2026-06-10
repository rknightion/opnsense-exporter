"""
FRR tab — FRR Routing (BGP/OSPF/BFD) metrics via the os-frr (quagga) plugin
(opnsense_frr_*).

Plugin-gated: tab and all rows hidden unless FRR metrics are present.

Counters (bgp_peer_messages_received/sent_total,
bfd_peer_control_packets_received/sent_total,
bfd_peer_session_up/down_events_total, ospf_area_spf_executed_total)
are cumulative -> rate().
Gauges shown raw: service_running, bgp_peers_total, bgp_failed_peers,
bgp_rib_entries, bgp_peer_up, bgp_peer_prefixes_received/sent,
bgp_peer_uptime_seconds, ospf_neighbors_total, ospf_neighbor_adjacency,
ospf_area_*, bfd_peers_total, bfd_peer_up, bfd_peer_uptime_seconds.
"""

from builder import Builder, sel, RATE, RUNSTOP, UPDOWN


def build(b: Builder):
    b.sentinel("has_frr",
               "label_values(opnsense_frr_service_running, __name__)")

    # ------------------------------------------------------------------ #
    # Row 1: FRR Service                                                   #
    # ------------------------------------------------------------------ #
    svc = b.stat(
        "FRR Service",
        sel("opnsense_frr_service_running"),
        mappings=RUNSTOP, color_mode="background",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        w=4, h=4,
        desc="FRR (quagga) routing service state (1 = running, 0 = stopped).",
    )
    bgp_peers = b.stat(
        "BGP Peers",
        sel("opnsense_frr_bgp_peers_total"),
        unit="short", w=4, h=4,
        desc="Total BGP peers configured (by address family).",
    )
    bgp_failed = b.stat(
        "BGP Failed Peers",
        sel("opnsense_frr_bgp_failed_peers"),
        unit="short", w=4, h=4,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "orange", "value": 1},
            {"color": "red", "value": 3},
        ],
        desc="Number of BGP peers in a failed/non-Established state.",
    )
    ospf_neighbors = b.stat(
        "OSPF Neighbors",
        sel("opnsense_frr_ospf_neighbors_total"),
        unit="short", w=4, h=4,
        desc="Total number of OSPF neighbors.",
    )
    bfd_peers = b.stat(
        "BFD Peers",
        sel("opnsense_frr_bfd_peers_total"),
        unit="short", w=4, h=4,
        desc="Total number of configured BFD peers.",
    )
    bgp_rib = b.ts(
        "BGP RIB Entries",
        [(sel("opnsense_frr_bgp_rib_entries"), "{{af}}")],
        unit="short", w=8, h=4,
        desc="BGP RIB (routing information base) entry count by address family.",
    )

    # ------------------------------------------------------------------ #
    # Row 2: BGP Peers                                                     #
    # ------------------------------------------------------------------ #
    bgp_peer_state = b.statetimeline(
        "BGP Peer Status",
        [(sel("opnsense_frr_bgp_peer_up"), "{{peer}} AS{{remote_as}} ({{af}})")],
        UPDOWN, w=24, h=8,
        desc="BGP peer up/down state over time (1 = Established, 0 = not Established).",
    )
    bgp_pfx_recv = b.ts(
        "BGP Prefixes Received",
        [(sel("opnsense_frr_bgp_peer_prefixes_received"), "{{peer}} {{af}}")],
        unit="short", w=12, h=8,
        desc="Number of prefixes received from each BGP peer.",
    )
    bgp_pfx_sent = b.ts(
        "BGP Prefixes Sent",
        [(sel("opnsense_frr_bgp_peer_prefixes_sent"), "{{peer}} {{af}}")],
        unit="short", w=12, h=8,
        desc="Number of prefixes advertised to each BGP peer.",
    )
    bgp_uptime = b.ts(
        "BGP Peer Uptime",
        [(sel("opnsense_frr_bgp_peer_uptime_seconds"), "{{peer}} {{af}}")],
        unit="s", w=12, h=8,
        desc="BGP session uptime in seconds per peer.",
    )
    bgp_msg_rate = b.ts(
        "BGP Message Rate",
        [
            (f'rate({sel("opnsense_frr_bgp_peer_messages_received_total")}[{RATE}])',
             "{{peer}} {{af}} recv"),
            (f'rate({sel("opnsense_frr_bgp_peer_messages_sent_total")}[{RATE}])',
             "{{peer}} {{af}} sent"),
        ],
        unit="short", w=12, h=8,
        desc="BGP UPDATE/KEEPALIVE/NOTIFICATION message rate per peer.",
    )

    # ------------------------------------------------------------------ #
    # Row 3: OSPF                                                          #
    # ------------------------------------------------------------------ #
    ospf_adj = b.statetimeline(
        "OSPF Neighbor Adjacency",
        [(sel("opnsense_frr_ospf_neighbor_adjacency"),
          "{{neighbor_id}} via {{interface}}")],
        UPDOWN, w=24, h=8,
        desc="OSPF neighbor adjacency state over time (1 = Full, 0 = not Full).",
    )
    ospf_area_ifaces = b.ts(
        "OSPF Area Active Interfaces",
        [(sel("opnsense_frr_ospf_area_interfaces_active"), "area {{area}}")],
        unit="short", w=8, h=8,
        desc="Number of active interfaces per OSPF area.",
    )
    ospf_area_full = b.ts(
        "OSPF Area Full-Adjacent Neighbors",
        [(sel("opnsense_frr_ospf_area_neighbors_full_adjacent"), "area {{area}}")],
        unit="short", w=8, h=8,
        desc="Number of fully-adjacent (Full state) neighbors per OSPF area.",
    )
    ospf_lsa = b.ts(
        "OSPF Area LSA Count",
        [(sel("opnsense_frr_ospf_area_lsa_count"), "area {{area}}")],
        unit="short", w=8, h=8,
        desc="Number of LSAs in the LSDB per OSPF area.",
    )
    ospf_spf = b.ts(
        "OSPF SPF Execution Rate",
        [(f'rate({sel("opnsense_frr_ospf_area_spf_executed_total")}[{RATE}])',
          "area {{area}}")],
        unit="short", w=24, h=8,
        desc="OSPF SPF (shortest path first) execution rate per area.",
    )

    # ------------------------------------------------------------------ #
    # Row 4: BFD                                                           #
    # ------------------------------------------------------------------ #
    bfd_state = b.statetimeline(
        "BFD Peer Status",
        [(sel("opnsense_frr_bfd_peer_up"), "{{peer}} ({{interface}})")],
        UPDOWN, w=24, h=8,
        desc="BFD peer up/down state over time (1 = up, 0 = down).",
    )
    bfd_uptime = b.ts(
        "BFD Peer Uptime",
        [(sel("opnsense_frr_bfd_peer_uptime_seconds"), "{{peer}}")],
        unit="s", w=12, h=8,
        desc="BFD session uptime in seconds per peer.",
    )
    bfd_pkt_rate = b.ts(
        "BFD Control Packet Rate",
        [
            (f'rate({sel("opnsense_frr_bfd_peer_control_packets_received_total")}[{RATE}])',
             "{{peer}} recv"),
            (f'rate({sel("opnsense_frr_bfd_peer_control_packets_sent_total")}[{RATE}])',
             "{{peer}} sent"),
        ],
        unit="short", w=12, h=8,
        desc="BFD control packet receive/send rates per peer.",
    )
    bfd_events = b.ts(
        "BFD Session Up/Down Events",
        [
            (f'rate({sel("opnsense_frr_bfd_peer_session_up_events_total")}[{RATE}])',
             "{{peer}} up events"),
            (f'rate({sel("opnsense_frr_bfd_peer_session_down_events_total")}[{RATE}])',
             "{{peer}} down events"),
        ],
        unit="short", w=24, h=8,
        desc="BFD session state-change event rates per peer.",
    )

    b.tab("FRR Routing", [
        b.row("FRR Service & Summary",
              [svc, bgp_peers, bgp_failed, ospf_neighbors, bfd_peers, bgp_rib],
              present="has_frr"),
        b.row("BGP Peers",
              [bgp_peer_state, bgp_pfx_recv, bgp_pfx_sent,
               bgp_uptime, bgp_msg_rate],
              present="has_frr"),
        b.row("OSPF",
              [ospf_adj, ospf_area_ifaces, ospf_area_full,
               ospf_lsa, ospf_spf],
              present="has_frr"),
        b.row("BFD",
              [bfd_state, bfd_uptime, bfd_pkt_rate, bfd_events],
              present="has_frr"),
    ])
