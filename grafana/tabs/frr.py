"""
FRR tab — FRR Routing (BGP/OSPF/BFD) metrics via the os-frr (quagga) plugin
(opnsense_frr_*).

Plugin-gated: tab and all rows hidden unless FRR metrics are present.

Counters (bgp_peer_messages_received/sent_total,
bfd_peer_control_packets_received/sent_total,
bfd_peer_session_up/down_events_total, ospf_area_spf_executed_total,
bgp_peer_connections_established/dropped_total, bgp_peer_messages_by_type_total)
are cumulative -> rate().
Gauges shown raw: service_running, bgp_peers, bgp_failed_peers,
bgp_rib_entries, bgp_peer_up, bgp_peer_prefixes_received/sent,
bgp_peer_uptime_seconds, ospf_neighbors, ospf_neighbor_adjacency,
ospf_area_*, bfd_peers, bfd_peer_up, bfd_peer_uptime_seconds,
bfd_peer_downtime_seconds, bfd_peer_rtt_min/avg/max_microseconds,
bgp_peer_last_reset_seconds, bgp_peer_prefixes_accepted, bgp_peer_queue_depth,
ospf_interface_up/cost/neighbors/neighbors_adjacent, ospfv3_interface_up/cost,
ospfv3_area_lsa_count, ospfv3_interface_pending_lsa, and (opt-in) route_count,
route_nexthop_count, bgp_route_count, bgp_path_count, ospf/ospfv3_route_count,
ospf/ospfv3_lsa_count. BFD summary peers are shown as a bounded status count
and an identity table.

ospf_interface_state/ospfv3_interface_state are enum-style gauges: one series
per (interface, state) with exactly one state at value 1 per interface. Shown
as an instant table filtered to the active row (value == 1), not a
statetimeline.

bfd_peer_diagnostic_info is an info metric (value always 1) carrying FRR's
diag2str() down-reason enum as labels (diagnostic/remote_diagnostic) — shown
as a table, not charted. bfd_peer_downtime_seconds is the Down-state
counterpart of bfd_peer_uptime_seconds: FRR emits the two as mutually
exclusive fields (#484), so a peer that is up/initializing/administratively
shut down has NO downtime series at all — do not treat a missing series on
this panel as zero downtime. bfd_peer_rtt_min/avg/max_microseconds read 0
unless both BFD peers support FRR's RTT extension, which is a legitimate
zero, not a fault signal.

The routing-state volume gauges are opt-in (--exporter.enable-frr-routes).
Zebra/OSPF panels use the has_frr_routes sentinel; BGP route-table panels use
has_frr_bgp_routes because either endpoint family can be present independently.

OSPF neighbor adjacency stability (#582): ospf_neighbor_nsm_state_info is an
info metric (value always 1) carrying FRR's raw NSM state name as a label —
shown as a table, same pattern as bfd_peer_diagnostic_info. Distinct from
ospf_neighbor_adjacency above: that flag only shows Full vs. not-Full, this
shows what a non-Full neighbor is stuck at (ExStart/Exchange/Loading = a
negotiation problem, Init/Attempt = it never got that far). ospf_neighbor_
uptime_seconds/dead_timer_seconds are presence-gated — FRR omits both for a
neighbor whose inactivity timer isn't scheduled, so an absent series there
means "no reading", not zero. ospf_neighbor_lsa_queue_depth is always
emitted (0 is a legitimate empty-queue reading); a persistently nonzero
ls_retransmission depth is the classic neighbor-sync-stuck symptom the
issue asks this dashboard to surface.

OSPF/OSPFv3 SPF-run timing (#582): ospf_spf_last_duration_seconds and
ospfv3_spf_last_duration_seconds are genuine duration gauges (how long the
last SPF run took), shown raw. ospf_spf_last_executed_timestamp_seconds and
ospfv3_area_spf_last_executed_timestamp_seconds are absolute-timestamp
gauges (unix seconds of the last SPF run) — shown as `time() - metric`
("SPF age"), the same pattern already used for freshness metrics elsewhere
in this dashboard (e.g. clamav signature-db age, crowdsec heartbeat age).
NOTE: OSPFv3's SPF-age reading is PER AREA, not instance-level like OSPFv2's
— FRR's ospf6d only reports a numeric "time since last run" per area; its
instance-level sibling of the same name is a formatted string with no
numeric equivalent (see the FRROSPFv3Overview field docs in opnsense/frr.go).
Both *_timestamp_seconds metrics still need an ANNOTATIONS/NOT_ANNOTATED
entry in annotations.py per AUTHORING.md rule 9 — not added here, see the
#582 implementation report.
"""

from builder import Builder, sel, RATE, RUNSTOP, UPDOWN


def build(b: Builder):
    b.sentinel("has_frr", metric="opnsense_frr_service_running")
    b.sentinel("has_frr_routes", metric="opnsense_frr_route_count")
    b.sentinel("has_frr_bgp_routes", metric="opnsense_frr_bgp_route_count")

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
        sel("opnsense_frr_bgp_peers"),
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
        sel("opnsense_frr_ospf_neighbors"),
        unit="short", w=4, h=4,
        desc="Total number of OSPF neighbors.",
    )
    bfd_peers = b.stat(
        "BFD Peers",
        sel("opnsense_frr_bfd_peers"),
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
        unit="ops", w=12, h=8,
        desc="BGP UPDATE/KEEPALIVE/NOTIFICATION message rate per peer.",
    )

    # ------------------------------------------------------------------ #
    # Row 2b: BGP Peer Session Detail (flaps, per-message-type, per-AF)    #
    # ------------------------------------------------------------------ #
    bgp_conn_flaps = b.ts(
        "BGP Peer Connection Flap Rate",
        [
            (f'rate({sel("opnsense_frr_bgp_peer_connections_established_total")}[{RATE}])',
             "{{peer}} established"),
            (f'rate({sel("opnsense_frr_bgp_peer_connections_dropped_total")}[{RATE}])',
             "{{peer}} dropped"),
        ],
        unit="ops", w=12, h=8,
        desc="Rate of BGP session establish/drop events per peer — the canonical flap counters.",
    )
    bgp_last_reset = b.ts(
        "BGP Peer Time Since Last Reset",
        [(sel("opnsense_frr_bgp_peer_last_reset_seconds"), "{{peer}}")],
        unit="s", w=12, h=8,
        desc="Time since this BGP peer session was last reset. A recent drop to a low value "+
             "indicates a reset even if the session has since re-established.",
    )
    bgp_msg_by_type_rate = b.ts(
        "BGP Message Rate by Type",
        [(f'rate({sel("opnsense_frr_bgp_peer_messages_by_type_total")}[{RATE}])',
          "{{peer}} {{type}} {{direction}}")],
        unit="ops", w=12, h=8,
        desc="Per-message-type BGP rate per peer (open/update/keepalive/notification/"+
             "route_refresh/capability) — separates UPDATE churn from KEEPALIVE noise.",
    )
    bgp_pfx_accepted = b.ts(
        "BGP Prefixes Accepted (post-policy)",
        [(sel("opnsense_frr_bgp_peer_prefixes_accepted"), "{{peer}} {{af}}")],
        unit="short", w=12, h=8,
        desc="Number of prefixes accepted from each BGP peer after inbound policy "+
             "(complements the pre-policy BGP Prefixes Received panel above).",
    )
    bgp_queue_depth = b.ts(
        "BGP Peer Work-Queue Depth",
        [(sel("opnsense_frr_bgp_peer_queue_depth"), "{{peer}} {{direction}}")],
        unit="short", w=24, h=8,
        desc="Current BGP in/out work-queue depth per peer — a persistently non-zero value "+
             "indicates the peer is falling behind processing updates.",
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
        unit="ops", w=24, h=8,
        desc="OSPF SPF (shortest path first) execution rate per area.",
    )

    # ------------------------------------------------------------------ #
    # Row 3a2: OSPF Neighbor Adjacency Stability (#582)                    #
    # ------------------------------------------------------------------ #
    ospf_nbr_nsm_state = b.table(
        "OSPF Neighbor State (NSM)",
        [sel("opnsense_frr_ospf_neighbor_nsm_state_info")],
        w=24, h=6,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "neighbor_id": "Neighbor",
            "address": "Address",
            "interface": "Interface",
            "nsm_state": "State",
            "opnsense_instance": "Instance",
        },
        sort_by="Neighbor",
        desc="FRR's raw OSPF neighbor state machine state (info metric — value is always 1; "+
             "use the State label). Distinct from the Adjacency panel above: that flag only "+
             "shows Full vs. not, this shows what a non-Full neighbor is stuck at "+
             "(ExStart/Exchange/Loading = negotiation trouble, Init/Attempt = never got that far).",
    )
    ospf_nbr_uptime = b.ts(
        "OSPF Neighbor Adjacency Uptime",
        [(sel("opnsense_frr_ospf_neighbor_uptime_seconds"), "{{neighbor_id}} via {{interface}}")],
        unit="s", w=12, h=8,
        desc="How long each OSPF neighbor's adjacency has been progressing. Absent (not zero) "+
             "for a neighbor whose inactivity timer isn't scheduled yet.",
    )
    ospf_nbr_dead_timer = b.ts(
        "OSPF Neighbor Dead Timer",
        [(sel("opnsense_frr_ospf_neighbor_dead_timer_seconds"), "{{neighbor_id}} via {{interface}}")],
        unit="s", w=12, h=8,
        desc="Time remaining before each OSPF neighbor's dead interval expires. Repeatedly "+
             "resetting close to the configured interval is healthy; a value trending toward "+
             "zero and recovering (rather than resetting cleanly on a fresh hello) is a "+
             "flapping adjacency. Absent (not zero) when FRR reports the timer as inactive.",
    )
    ospf_nbr_lsa_queue = b.ts(
        "OSPF Neighbor LSA Queue Depth",
        [(sel("opnsense_frr_ospf_neighbor_lsa_queue_depth"), "{{neighbor_id}} {{queue}}")],
        unit="short", w=24, h=8,
        desc="Per-neighbor LSA synchronization queue depth (db_summary/ls_request/"+
             "ls_retransmission). A persistently nonzero ls_retransmission depth is the "+
             "classic symptom of a neighbor stuck failing to acknowledge LSAs.",
    )

    # ------------------------------------------------------------------ #
    # Row 3b: OSPF Interface Detail                                       #
    # ------------------------------------------------------------------ #
    ospf_iface_up = b.statetimeline(
        "OSPF Interface Link Status",
        [(sel("opnsense_frr_ospf_interface_up"), "{{interface}} (area {{area}})")],
        UPDOWN, w=12, h=8,
        desc="OSPF interface underlying link state over time (ifUp).",
    )
    ospf_iface_cost = b.ts(
        "OSPF Interface Cost",
        [(sel("opnsense_frr_ospf_interface_cost"), "{{interface}} (area {{area}})")],
        unit="short", w=6, h=8,
        desc="OSPF cost configured per interface.",
    )
    ospf_iface_nbrs = b.ts(
        "OSPF Interface Neighbors",
        [
            (sel("opnsense_frr_ospf_interface_neighbors"), "{{interface}} total"),
            (sel("opnsense_frr_ospf_interface_neighbors_adjacent"), "{{interface}} adjacent"),
        ],
        unit="short", w=6, h=8,
        desc="OSPF neighbor and Full-adjacency counts per interface.",
    )
    ospf_iface_state = b.table(
        "OSPF Interface State (DR/BDR election)",
        [f'{sel("opnsense_frr_ospf_interface_state")} == 1'],
        w=24, h=6,
        excludes=["Value", "__name__", "job", "instance"],
        renames={"interface": "Interface", "state": "State"},
        desc="Current OSPF interface state (DR/BDR/DROther/PointToPoint/Waiting/Down) — one "+
             "row per interface, the active state only.",
    )

    # ------------------------------------------------------------------ #
    # Row 3c: OSPFv3 (ospf6) Parity — UNVERIFIED against a live v3         #
    # adjacency; see opnsense/frr.go's VERIFICATION banner. There is no    #
    # OSPFv3 neighbor endpoint, so interface state is the adjacency proxy. #
    # ------------------------------------------------------------------ #
    ospfv3_iface_up = b.statetimeline(
        "OSPFv3 Interface Status",
        [(sel("opnsense_frr_ospfv3_interface_up"), "{{interface}} (area {{area}})")],
        UPDOWN, w=12, h=8,
        desc="OSPFv3 (ospf6) interface up/down state over time. No OSPFv3 neighbor endpoint "+
             "exists in the quagga plugin API, so interface state is the best available "+
             "adjacency proxy.",
    )
    ospfv3_iface_cost = b.ts(
        "OSPFv3 Interface Cost",
        [(sel("opnsense_frr_ospfv3_interface_cost"), "{{interface}} (area {{area}})")],
        unit="short", w=6, h=8,
        desc="OSPFv3 cost configured per interface.",
    )
    ospfv3_area_lsa = b.ts(
        "OSPFv3 Area LSA Count",
        [(sel("opnsense_frr_ospfv3_area_lsa_count"), "area {{area}}")],
        unit="short", w=6, h=8,
        desc="Number of LSAs in the OSPFv3 LSDB per area (v3 parity with OSPF Area LSA Count).",
    )
    ospfv3_iface_state = b.table(
        "OSPFv3 Interface State (DR/BDR election)",
        [f'{sel("opnsense_frr_ospfv3_interface_state")} == 1'],
        w=12, h=6,
        excludes=["Value", "__name__", "job", "instance"],
        renames={"interface": "Interface", "state": "State"},
        desc="Current OSPFv3 interface state — one row per interface, the active state only.",
    )
    ospfv3_pending_lsa = b.ts(
        "OSPFv3 Interface Pending LSA (Flooding Backlog)",
        [(sel("opnsense_frr_ospfv3_interface_pending_lsa"), "{{interface}} {{queue}}")],
        unit="short", w=12, h=8,
        desc="Pending LSUpdate/LSAck queue depth per OSPFv3 interface — a growing backlog "+
             "indicates an LSA flooding problem.",
    )

    # ------------------------------------------------------------------ #
    # Row 3c2: OSPF/OSPFv3 SPF-Run Timing (#582)                          #
    # ------------------------------------------------------------------ #
    ospf_spf_age = b.ts(
        "OSPF SPF Age (Time Since Last Run)",
        [(f'time() - {sel("opnsense_frr_ospf_spf_last_executed_timestamp_seconds")}', "instance")],
        unit="s", w=12, h=8,
        desc="Seconds since this OSPF instance's last SPF calculation. The already-charted "+
             "SPF Execution Rate above is a COUNT of runs, not their recency or cost — a "+
             "router thrashing SPF (short-interval recalculation storms) shows up here as "+
             "this value repeatedly dropping close to zero.",
    )
    ospf_spf_duration = b.ts(
        "OSPF SPF Last Run Duration",
        [(sel("opnsense_frr_ospf_spf_last_duration_seconds"), "instance")],
        unit="s", w=12, h=8,
        desc="Wall-clock duration of this OSPF instance's last SPF calculation — the CPU-cost "+
             "half of the SPF story that a run count alone cannot show.",
    )
    ospfv3_spf_duration = b.ts(
        "OSPFv3 SPF Last Run Duration",
        [(sel("opnsense_frr_ospfv3_spf_last_duration_seconds"), "instance")],
        unit="s", w=12, h=8,
        desc="Wall-clock duration of this OSPFv3 instance's last SPF calculation.",
    )
    ospfv3_area_spf_age = b.ts(
        "OSPFv3 Area SPF Age (Time Since Last Run)",
        [(f'time() - {sel("opnsense_frr_ospfv3_area_spf_last_executed_timestamp_seconds")}',
          "area {{area}}")],
        unit="s", w=12, h=8,
        desc="Seconds since each OSPFv3 area last ran SPF. Per-area, not instance-level: "+
             "FRR's ospf6d only reports SPF recency numerically at the area scope (its "+
             "instance-level sibling is a formatted string with no numeric equivalent).",
    )

    # ------------------------------------------------------------------ #
    # Row 3d: Routing-State Volume (opt-in, --exporter.enable-frr-routes)  #
    # ------------------------------------------------------------------ #
    route_count = b.ts(
        "Zebra RIB Route Count",
        [(sel("opnsense_frr_route_count"), "{{af}} {{protocol}}")],
        unit="short", w=12, h=8,
        desc="Number of distinct routed prefixes in the zebra RIB, by address family and "+
             "protocol — trend signal for redistribution accidents or route leaks.",
    )
    route_nexthop_count = b.ts(
        "Zebra RIB Nexthop Count (ECMP Width)",
        [(sel("opnsense_frr_route_nexthop_count"), "{{af}} {{protocol}}")],
        unit="short", w=12, h=8,
        desc="Number of nexthop rows in the zebra RIB, by address family and protocol — "+
             "diverges from Route Count when ECMP is active.",
    )
    ospf_route_count = b.ts(
        "OSPF Route Table Count",
        [(sel("opnsense_frr_ospf_route_count"), "{{type}}")],
        unit="short", w=12, h=8,
        desc="Number of rows in the OSPF route table, by route type (N/R/N E2/...).",
    )
    ospfv3_route_count = b.ts(
        "OSPFv3 Route Table Count",
        [(sel("opnsense_frr_ospfv3_route_count"), "{{type}}")],
        unit="short", w=12, h=8,
        desc="Number of rows in the OSPFv3 route table, by route type.",
    )
    ospf_lsa_count = b.ts(
        "OSPF LSDB Count",
        [(sel("opnsense_frr_ospf_lsa_count"), "area {{area}} {{lsa_type}}")],
        unit="short", w=12, h=8,
        desc="Number of LSAs in the OSPF LSDB, by area and LSA type — catches LSA storms.",
    )
    ospfv3_lsa_count = b.ts(
        "OSPFv3 LSDB Count",
        [(sel("opnsense_frr_ospfv3_lsa_count"), "{{scope}}")],
        unit="short", w=12, h=8,
        desc="Number of LSAs in the OSPFv3 LSDB, by flooding scope.",
    )
    bgp_route_count = b.ts(
        "BGP Route Table Count",
        [(sel("opnsense_frr_bgp_route_count"), "{{af}}")],
        unit="short", w=12, h=8,
        desc="Number of distinct prefixes in the BGP route table, by address family.",
    )
    bgp_path_count = b.ts(
        "BGP Path Count",
        [(sel("opnsense_frr_bgp_path_count"), "{{af}}")],
        unit="short", w=12, h=8,
        desc="Number of BGP paths in the route table, by address family.",
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
        unit="ops", w=12, h=8,
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
        unit="ops", w=24, h=8,
        desc="BFD session state-change event rates per peer.",
    )

    # ------------------------------------------------------------------ #
    # Row 4b: BFD Diagnostic / RTT / Down-Duration (#484)                  #
    # ------------------------------------------------------------------ #
    bfd_diagnostic = b.table(
        "BFD Peer Diagnostic",
        [sel("opnsense_frr_bfd_peer_diagnostic_info")],
        w=24, h=6,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "peer": "Peer",
            "diagnostic": "Diagnostic",
            "remote_diagnostic": "Remote Diagnostic",
            "opnsense_instance": "Instance",
        },
        sort_by="Peer",
        desc="FRR's diag2str() down-reason enum per BFD peer (info metric — value is always "+
             "1; use labels). Distinct from the up/down state already shown above: this is "+
             "WHY a session last went down (e.g. \"control detection time expired\", "+
             "\"neighbor signaled session down\"), not whether it currently is.",
    )
    bfd_rtt = b.ts(
        "BFD Peer Round-Trip Time",
        [
            (sel("opnsense_frr_bfd_peer_rtt_min_microseconds"), "{{peer}} min"),
            (sel("opnsense_frr_bfd_peer_rtt_avg_microseconds"), "{{peer}} avg"),
            (sel("opnsense_frr_bfd_peer_rtt_max_microseconds"), "{{peer}} max"),
        ],
        unit="µs", w=12, h=8,
        desc="Measured BFD round-trip time per peer (FRR's RTT extension). Reads 0 unless "+
             "BOTH ends of the session support the extension — a legitimate zero, not a "+
             "fault indicator.",
    )
    bfd_downtime = b.ts(
        "BFD Peer Down-Duration",
        [(sel("opnsense_frr_bfd_peer_downtime_seconds"), "{{peer}}")],
        unit="s", w=12, h=8,
        desc="Duration a BFD peer session has been down. Only present while the peer is "+
             "actually in the down state — FRR emits uptime and downtime as mutually "+
             "exclusive fields, so a peer that is up, initializing, or administratively "+
             "shut down has NO series here at all (absent, not zero).",
    )
    bfd_summary_peers = b.ts(
        "BFD Summary Peers by Status",
        [(sel("opnsense_frr_bfd_summary_peers"), "{{status}}")],
        unit="short", w=12, h=8,
        desc="Bounded count of BFD summary peers grouped by the status reported by FRR.",
    )
    bfd_summary_peer_info = b.table(
        "BFD Summary Peer Identity",
        [sel("opnsense_frr_bfd_summary_peer_info")],
        w=24, h=6,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "id": "ID",
            "local": "Local",
            "peer": "Peer",
            "status": "Status",
            "opnsense_instance": "Instance",
        },
        sort_by="Peer",
        desc="Current BFD summary sessions with bounded identity and status labels.",
    )

    # Split into sibling leaves (#619): 51 panels in one tab is a tab people
    # scroll past. The existing rows are regrouped and nothing else changes — no row
    # split, merged, renamed or reordered within its group, no panel moved between
    # rows — so this reads as a move.
    b.tab("FRR Routing", [
        b.row("FRR Service & Summary",
              [svc, bgp_peers, bgp_failed, ospf_neighbors, bfd_peers, bgp_rib],
              present="has_frr"),
        b.row("BGP Peers",
              [bgp_peer_state, bgp_pfx_recv, bgp_pfx_sent,
               bgp_uptime, bgp_msg_rate],
              present="has_frr"),
        b.row("BGP Peer Session Detail",
              [bgp_conn_flaps, bgp_last_reset, bgp_msg_by_type_rate,
               bgp_pfx_accepted, bgp_queue_depth],
              present="has_frr"),
        b.row("BFD",
              [bfd_state, bfd_uptime, bfd_pkt_rate, bfd_events,
               bfd_diagnostic, bfd_rtt, bfd_downtime],
              present="has_frr"),
        b.row("BFD Summary",
              [bfd_summary_peers, bfd_summary_peer_info],
              present="has_frr"),
    ])
    b.tab("FRR - OSPF", [
        b.row("OSPF",
              [ospf_adj, ospf_area_ifaces, ospf_area_full,
               ospf_lsa, ospf_spf],
              present="has_frr"),
        b.row("OSPF Neighbor Adjacency Stability",
              [ospf_nbr_nsm_state, ospf_nbr_uptime, ospf_nbr_dead_timer, ospf_nbr_lsa_queue],
              present="has_frr"),
        b.row("OSPF Interface Detail",
              [ospf_iface_up, ospf_iface_cost, ospf_iface_nbrs, ospf_iface_state],
              present="has_frr"),
        b.row("OSPFv3 (ospf6) Parity",
              [ospfv3_iface_up, ospfv3_iface_cost, ospfv3_area_lsa,
               ospfv3_iface_state, ospfv3_pending_lsa],
              present="has_frr"),
        b.row("OSPF/OSPFv3 SPF-Run Timing",
              [ospf_spf_age, ospf_spf_duration, ospfv3_spf_duration, ospfv3_area_spf_age],
              present="has_frr"),
        b.row("Routing-State Volume (opt-in: --exporter.enable-frr-routes)",
              [route_count, route_nexthop_count, ospf_route_count,
               ospfv3_route_count, ospf_lsa_count, ospfv3_lsa_count],
              present="has_frr_routes"),
        b.row("BGP Route-Table Volume (opt-in: --exporter.enable-frr-routes)",
              [bgp_route_count, bgp_path_count],
              present="has_frr_bgp_routes"),
    ])
