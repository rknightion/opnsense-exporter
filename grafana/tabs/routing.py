"""
Routing & Neighbors tab — ARP table, NDP, LLDP, Host Discovery, and Network
Diagnostics metrics.

Rows:
  1. ARP table          — entry count stat, count by interface bargauge, detail table
  2. NDP (IPv6 Neighbors) — entry count stat, count by interface bargauge, detail table
  3. LLDP Neighbors (gated) — neighbor count by local interface bargauge, detail table
  4. Host Discovery     — hosts/hosts_recent by interface+source bargauges
  5. NetISR (gated)     — dispatch/queue/handle/drop rate ts, queue length/watermark/limit ts
  6. Sockets & Routes (gated) — sockets_active bargauge, sockets_unix_total stat,
                                routes_total bargauge
  7. pfsync (gated)     — pfsync_nodes_total stat, pfsync_node_info table

LLDP is placed here rather than the Interfaces tab: it is a neighbor-discovery table
conceptually alongside ARP/NDP (a topology sensor — alert when a port stops seeing its
expected switch/port), not an interface-throughput metric (#216). Host Discovery
(the core hostwatch persistent inventory, #223) joins them for the same reason: it is
a neighbor/host-visibility signal, not throughput — and its "arp-ndp" fallback source
(hostwatch disabled) is a live read of the same ARP/NDP tables shown above it.

Coverage:
  opnsense_arp_table_entries
  opnsense_ndp_entries
  opnsense_lldp_neighbors
  opnsense_lldp_neighbor_info
  opnsense_hostdiscovery_hosts
  opnsense_hostdiscovery_hosts_recent
  opnsense_network_diag_netisr_dispatched_total
  opnsense_network_diag_netisr_hybrid_dispatched_total
  opnsense_network_diag_netisr_queued_total
  opnsense_network_diag_netisr_handled_total
  opnsense_network_diag_netisr_queue_drops_total
  opnsense_network_diag_netisr_queue_length
  opnsense_network_diag_netisr_queue_watermark
  opnsense_network_diag_netisr_queue_limit
  opnsense_network_diag_netisr_protocol_info
  opnsense_network_diag_netisr_active_workstreams
  opnsense_network_diag_netisr_workstreams_at_limit
  opnsense_network_diag_netisr_queue_imbalance_ratio
  opnsense_network_diag_netisr_drop_concentration_ratio
  opnsense_network_diag_netisr_cpu_dispatched_total
  opnsense_network_diag_netisr_cpu_hybrid_dispatched_total
  opnsense_network_diag_netisr_cpu_queued_total
  opnsense_network_diag_netisr_cpu_handled_total
  opnsense_network_diag_netisr_cpu_queue_drops_total
  opnsense_network_diag_netisr_cpu_queue_length
  opnsense_network_diag_netisr_cpu_queue_watermark
  opnsense_network_diag_sockets_active
  opnsense_network_diag_sockets_unix
  opnsense_network_diag_routes
  opnsense_network_diag_interface_routes
  opnsense_network_diag_routes_by_flags
  opnsense_network_diag_default_route_present
  opnsense_network_diag_default_route_info
  opnsense_network_diag_pfsync_nodes
  opnsense_network_diag_pfsync_node_info
"""

from builder import Builder, sel, grp, RATE
from tabs import log_events


def build(b: Builder):
    # ---- Sentinels -------------------------------------------------------
    b.sentinel("has_network_diag", metric="opnsense_network_diag_sockets_unix")
    # opnsense_lldp_neighbors/neighbor_info are only emitted when at least one
    # neighbor has been seen (os-lldpd present but quiet emits nothing at all),
    # so this sentinel doubles as "plugin present AND has neighbors right now".
    b.sentinel("has_lldp", metric="opnsense_lldp_neighbors")

    # ======================================================================
    # Row 1 – ARP table
    # ======================================================================
    arp_count = b.stat(
        "ARP Entries",
        sel("opnsense_arp_table_table_entries"),
        unit="short",
        w=4, h=4,
        instant=True,
        graph="none",
        desc="Total number of ARP table entries currently known (low-cardinality aggregate, always emitted).",
    )
    arp_by_iface = b.bargauge(
        "ARP Entries by Interface",
        [(f'count {grp("interface_description")}({sel("opnsense_arp_table_entries")})',
          "{{interface_description}}")],
        unit="short",
        w=8, h=8,
        orient="horizontal",
        instant=True,
        desc="ARP entry count grouped by interface. Requires --exporter.enable-arp-details (#125).",
    )
    arp_table = b.table(
        "ARP Table Detail",
        [sel("opnsense_arp_table_entries")],
        w=24, h=12,
        excludes=["Value", "__name__", "job", "instance", "env"],
        renames={
            "ip": "IP",
            "mac": "MAC",
            "hostname": "Hostname",
            "interface_description": "Interface",
            "type": "Type",
            "expired": "Expired",
            "permanent": "Permanent", "opnsense_instance": "Instance"},
        sort_by="Interface",
        desc="Full ARP table — all entries with their IP, MAC, hostname, interface, and flags.",
    )

    # ======================================================================
    # Row 2 – NDP (IPv6 neighbors)
    # ======================================================================
    ndp_count = b.stat(
        "NDP Entries",
        sel("opnsense_ndp_table_entries"),
        unit="short",
        w=4, h=4,
        instant=True,
        graph="none",
        desc="Total number of NDP (IPv6 neighbor) entries currently known (low-cardinality aggregate, always emitted).",
    )
    ndp_by_iface = b.bargauge(
        "NDP Entries by Interface",
        [(f'count {grp("interface_description")}({sel("opnsense_ndp_entries")})',
          "{{interface_description}}")],
        unit="short",
        w=8, h=8,
        orient="horizontal",
        instant=True,
        desc="NDP entry count grouped by interface. Requires --exporter.enable-ndp-details (#125).",
    )
    ndp_table = b.table(
        "NDP Table Detail",
        [sel("opnsense_ndp_entries")],
        w=24, h=12,
        excludes=["Value", "__name__", "job", "instance", "env"],
        renames={
            "ip": "IP",
            "mac": "MAC",
            "interface_description": "Interface",
            "type": "Type", "opnsense_instance": "Instance"},
        sort_by="Interface",
        desc="Full NDP (IPv6 neighbor discovery) table — all entries with IP, MAC, interface, and type.",
    )

    # ======================================================================
    # Row 3 – LLDP Neighbors (gated: has_lldp)
    # ======================================================================
    lldp_by_iface = b.bargauge(
        "LLDP Neighbors by Local Interface",
        [(sel("opnsense_lldp_neighbors"), "{{interface}}")],
        unit="short",
        w=8, h=8,
        orient="horizontal",
        instant=True,
        desc="Number of LLDP neighbors currently seen on each local interface. A port that "
             "normally reports 1 dropping to 0 indicates miscabling or a switch/port change; "
             "requires the os-lldpd plugin.",
    )
    lldp_table = b.table(
        "LLDP Neighbor Detail",
        [sel("opnsense_lldp_neighbor_info")],
        w=24, h=12,
        excludes=["Value", "__name__", "job", "instance", "env"],
        renames={
            "interface": "Local Interface",
            "chassis_name": "Neighbor",
            "port_id": "Neighbor Port ID",
            "port_descr": "Neighbor Port Description", "opnsense_instance": "Instance"},
        sort_by="Local Interface",
        desc="Full LLDP neighbor table — local interface paired with the remote device's "
             "SysName, PortID, and PortDescr. A topology sensor: alert on an expected "
             "(interface, neighbor) pairing going missing.",
    )

    # ======================================================================
    # Row 4 – Host Discovery (core hostwatch inventory, #223)
    # ======================================================================
    # Never gated: this is a core, default-on collector (like ARP/NDP above),
    # not an opt-in/plugin feature. Series legend carries both interface and
    # source so the "arp-ndp" fallback (hostwatch disabled) is distinguishable
    # from "discovery" (hostwatch enabled) rather than silently merged.
    hostdiscovery_by_iface = b.bargauge(
        "Discovered Hosts by Interface",
        [(sel("opnsense_hostdiscovery_hosts"), "{{interface}} ({{source}})")],
        unit="short",
        w=12, h=8,
        orient="horizontal",
        instant=True,
        desc="Number of hosts in the discovered-host inventory per interface. source=discovery "
             "means the hostwatch daemon is enabled (persistent inventory, survives reboots and "
             "cache expiry); source=arp-ndp means it is disabled and this is a live ARP/NDP-table "
             "fallback (see the ARP/NDP rows above) with no history.",
    )
    hostdiscovery_recent_by_iface = b.bargauge(
        "Recently Seen Hosts (15m) by Interface",
        [(sel("opnsense_hostdiscovery_hosts_recent"), "{{interface}} ({{source}})")],
        unit="short",
        w=12, h=8,
        orient="horizontal",
        instant=True,
        desc="Subset of the discovered-host inventory last seen within 15 minutes, per interface. "
             "Always 0 for source=arp-ndp, which carries no last_seen timestamp to judge recency "
             "from. A sustained drop signals hosts going quiet on that interface.",
    )

    # ======================================================================
    # Row 5 – NetISR (gated: has_network_diag)
    # ======================================================================
    netisr_dispatch_ts = b.ts(
        "NetISR Dispatches & Handled (rate)",
        [
            (f'rate({sel("opnsense_network_diag_netisr_dispatched_total")}[{RATE}])',
             "{{protocol}} dispatched"),
            (f'rate({sel("opnsense_network_diag_netisr_hybrid_dispatched_total")}[{RATE}])',
             "{{protocol}} hybrid dispatched"),
            (f'rate({sel("opnsense_network_diag_netisr_handled_total")}[{RATE}])',
             "{{protocol}} handled"),
        ],
        unit="pps",
        w=12, h=8,
        desc="Network ISR dispatch and handled rates by protocol.",
    )
    netisr_queue_ts = b.ts(
        "NetISR Queued & Drops (rate)",
        [
            (f'rate({sel("opnsense_network_diag_netisr_queued_total")}[{RATE}])',
             "{{protocol}} queued"),
            (f'rate({sel("opnsense_network_diag_netisr_queue_drops_total")}[{RATE}])',
             "{{protocol}} drops"),
        ],
        unit="pps",
        w=12, h=8,
        desc="NetISR packets queued and dropped per second by protocol.",
    )
    netisr_len_ts = b.ts(
        "NetISR Queue Length / Watermark / Limit",
        [
            (sel("opnsense_network_diag_netisr_queue_length"),
             "{{protocol}} length"),
            (sel("opnsense_network_diag_netisr_queue_watermark"),
             "{{protocol}} watermark"),
            (sel("opnsense_network_diag_netisr_queue_limit"),
             "{{protocol}} limit"),
        ],
        unit="short",
        w=24, h=8,
        desc="Current queue length, high-watermark, and configured limit per protocol.",
    )

    # ======================================================================
    # Row 5b – NetISR per-workstream distribution (gated: has_network_diag)
    #
    # The row above shows netisr collapsed to protocol. That view cannot tell a
    # firewall dropping every packet on one saturated workstream apart from one
    # that is uniformly overloaded, and the two have opposite remedies (CPU
    # affinity vs queue size). This row is where that distinction lives.
    # ======================================================================
    netisr_workstreams_ts = b.ts(
        "NetISR Active Workstreams vs At Limit",
        [
            (sel("opnsense_network_diag_netisr_active_workstreams"),
             "{{protocol}} active"),
            (sel("opnsense_network_diag_netisr_workstreams_at_limit"),
             "{{protocol}} at limit"),
        ],
        unit="short",
        w=12, h=8,
        desc="How many netisr workstreams carry work for each protocol, and how many have hit "
             "their configured queue limit. A protocol with a 'cpu' or 'flow' policy that shows "
             "only one active workstream on a multi-core box is not spreading load. Protocols "
             "with a 'source' policy are single-lane by design - check the policy table before "
             "reading one active workstream as a fault.",
    )
    netisr_ratios_ts = b.ts(
        "NetISR Queue Imbalance & Drop Concentration",
        [
            (sel("opnsense_network_diag_netisr_queue_imbalance_ratio"),
             "{{protocol}} imbalance"),
            (sel("opnsense_network_diag_netisr_drop_concentration_ratio"),
             "{{protocol}} drop concentration"),
        ],
        unit="short",
        w=12, h=8,
        desc="Imbalance = busiest workstream's watermark divided by the mean across active "
             "workstreams; 1.0 is perfectly even and higher means skew. Drop concentration = the "
             "share of all drops landing on a single workstream; 1.0 means every drop hit one "
             "lane, which points at CPU affinity rather than queue size. Both read 0 when the "
             "measure is undefined (fewer than two active workstreams, or no drops at all) - "
             "zero here means 'not applicable', not 'healthy'.",
    )
    netisr_percpu_queue_ts = b.ts(
        "NetISR Per-CPU Queue Length & Watermark",
        [
            (sel("opnsense_network_diag_netisr_cpu_queue_watermark"),
             "{{protocol}} cpu{{cpu}} watermark"),
            (sel("opnsense_network_diag_netisr_cpu_queue_length"),
             "{{protocol}} cpu{{cpu}} length"),
        ],
        unit="short",
        w=12, h=8,
        desc="Per-workstream queue depth. Watermark is a since-boot high-water mark and never "
             "decays, so it records the worst moment since the last reboot rather than current "
             "state; length is instantaneous. A watermark sitting exactly on the protocol's "
             "queue limit is the signature of a saturated lane.",
    )
    netisr_percpu_drops_ts = b.ts(
        "NetISR Per-CPU Queue Drops (rate)",
        [
            (f'rate({sel("opnsense_network_diag_netisr_cpu_queue_drops_total")}[{RATE}])',
             "{{protocol}} cpu{{cpu}}"),
        ],
        unit="pps",
        w=12, h=8,
        desc="Packets dropped per second by netisr, per protocol per workstream. This is the "
             "panel that names the CPU - if one series is nonzero while its siblings sit at "
             "zero, raising net.isr.maxqlen treats the symptom and leaves the imbalance.",
    )
    netisr_percpu_work_ts = b.ts(
        "NetISR Per-CPU Throughput (rate)",
        [
            (f'rate({sel("opnsense_network_diag_netisr_cpu_handled_total")}[{RATE}])',
             "{{protocol}} cpu{{cpu}} handled"),
            (f'rate({sel("opnsense_network_diag_netisr_cpu_queued_total")}[{RATE}])',
             "{{protocol}} cpu{{cpu}} queued"),
            (f'rate({sel("opnsense_network_diag_netisr_cpu_dispatched_total")}[{RATE}])',
             "{{protocol}} cpu{{cpu}} dispatched"),
            (f'rate({sel("opnsense_network_diag_netisr_cpu_hybrid_dispatched_total")}[{RATE}])',
             "{{protocol}} cpu{{cpu}} hybrid"),
        ],
        unit="pps",
        w=12, h=8,
        desc="Per-workstream packet throughput. Idle workstreams are emitted as flat zero on "
             "purpose - 'eight of twelve CPUs never receive netisr work' is the finding, and "
             "suppressing the empty series would hide it.",
    )
    netisr_policy_table = b.table(
        "NetISR Protocol Policy",
        [sel("opnsense_network_diag_netisr_protocol_info")],
        w=24, h=8,
        excludes=["Value", "__name__", "job", "instance", "env"],
        renames={
            "protocol": "Protocol", "protocol_id": "ID", "policy": "Policy",
            "policy_type": "Policy Type", "flags": "Flags",
            "opnsense_instance": "Instance"},
        sort_by="Protocol",
        desc="How FreeBSD distributes each protocol's work. Policy type 'cpu' and 'flow' fan out "
             "across workstreams; 'source' is single-lane by design, so igmp, rtsock and arp "
             "showing one active workstream is correct and must not be alerted on.",
    )

    # ======================================================================
    # Row 6 – Sockets & Routes (gated: has_network_diag)
    # ======================================================================
    sockets_active_bg = b.bargauge(
        "Active Sockets by Type",
        [(sel("opnsense_network_diag_sockets_active"), "{{type}}")],
        unit="short",
        w=8, h=8,
        orient="horizontal",
        instant=True,
        desc="Number of active sockets broken down by socket type.",
    )
    sockets_unix_stat = b.stat(
        "Unix Domain Sockets",
        sel("opnsense_network_diag_sockets_unix"),
        unit="short",
        w=4, h=4,
        instant=True,
        graph="none",
        desc="Total number of active Unix domain sockets (instantaneous count, not a counter).",
    )
    default_route_stat = b.ts(
        "Default Route Present",
        [(sel("opnsense_network_diag_default_route_present"), "{{proto}}")],
        unit="short", w=12, h=8,
        desc="1 when a default route exists for the address family, 0 when it does not. Emitted for "
             "a FIXED ipv4/ipv6 set every scrape rather than only when a route exists - the one case "
             "worth alerting on is the route GOING AWAY, and an absent series cannot be alerted on. "
             "Losing the default route is a total-outage condition that had no signal before this.",
    )
    default_route_table = b.table(
        "Default Route Detail",
        [sel("opnsense_network_diag_default_route_info")],
        w=12, h=8,
        excludes=["Value", "__name__", "job", "instance", "env"],
        renames={
            "proto": "Family", "device": "Device", "interface": "Interface",
            "gateway": "Gateway", "opnsense_instance": "Instance"},
        sort_by="Family",
        desc="Which gateway and interface currently carry the default route. `gateway` is a label "
             "HERE and nowhere else in this family: there are only ever one or two of these series, "
             "and a default gateway changing is itself the event worth seeing. Per-route destination "
             "is deliberately never a label - 52 of the 76 routes on the prod box are transient UHS "
             "host routes and would churn.",
    )
    routes_by_iface = b.bargauge(
        "Routes by Interface",
        [(sel("opnsense_network_diag_interface_routes"), "{{interface}} ({{proto}})")],
        unit="short", w=12, h=8, orient="horizontal", instant=True,
        desc="Routing-table entries per interface and address family. Answers which interface a "
             "route count belongs to, which the protocol-only total cannot.",
    )
    routes_by_flags = b.bargauge(
        "Routes by Flags",
        [(sel("opnsense_network_diag_routes_by_flags"), "{{flags}} ({{proto}})")],
        unit="short", w=12, h=8, orient="horizontal", instant=True,
        desc="Routing entries grouped by their BSD route flags (U up, G gateway, H host, S static, "
             "and so on). A sudden growth in host routes usually means a VPN or peer-discovery "
             "process is churning entries.",
    )
    routes_bg = b.bargauge(
        "Routing Table Entries by Protocol",
        [(sel("opnsense_network_diag_routes"), "{{proto}}")],
        unit="short",
        w=12, h=8,
        orient="horizontal",
        instant=True,
        desc="Number of routing table entries per address-family protocol (instantaneous count).",
    )

    # ======================================================================
    # Row 7 – pfsync (gated: has_network_diag)
    # ======================================================================
    pfsync_nodes_stat = b.stat(
        "pfsync Cluster Nodes",
        sel("opnsense_network_diag_pfsync_nodes"),
        unit="short",
        w=4, h=4,
        instant=True,
        graph="none",
        desc="Total number of pfsync cluster nodes (instantaneous count).",
    )
    pfsync_node_table = b.table(
        "pfsync Node Info",
        [sel("opnsense_network_diag_pfsync_node_info")],
        w=20, h=8,
        excludes=["Value", "__name__", "job", "instance", "env"],
        renames={
            "creatorid": "Creator ID",
            "is_local": "Local", "opnsense_instance": "Instance"},
        sort_by="Creator ID",
        desc="pfsync node detail — creator ID and whether the node is local.",
    )

    # ======================================================================
    # Assemble tab
    # ======================================================================
    b.tab("Routing & Neighbors", [
        b.row("ARP Table", [arp_count, arp_by_iface, arp_table]),
        b.row("NDP (IPv6 Neighbors)", [ndp_count, ndp_by_iface, ndp_table]),
        # #536: a MAC flap faster than the poll interval is invisible in the table
        # above - only the kernel sees it, and only as a log line.
        log_events.arp_moves_row(b),
        b.row("LLDP Neighbors", [lldp_by_iface, lldp_table], present="has_lldp"),
        b.row("Host Discovery", [hostdiscovery_by_iface, hostdiscovery_recent_by_iface]),
        b.row("NetISR (Network Interrupt Subsystem)", [netisr_dispatch_ts, netisr_queue_ts, netisr_len_ts],
              present="has_network_diag"),
        b.row("NetISR Per-CPU Distribution", [
            netisr_workstreams_ts, netisr_ratios_ts,
            netisr_percpu_queue_ts, netisr_percpu_drops_ts,
            netisr_percpu_work_ts, netisr_policy_table],
              present="has_network_diag"),
        b.row("Sockets & Routes", [sockets_active_bg, sockets_unix_stat, routes_bg],
              present="has_network_diag"),
        b.row("Routing Table Detail", [
            default_route_stat, default_route_table, routes_by_iface, routes_by_flags],
              present="has_network_diag"),
        b.row("pfsync", [pfsync_nodes_stat, pfsync_node_table],
              present="has_network_diag"),
    ])
