"""
Routing & Neighbors tab — ARP table, NDP, LLDP, and Network Diagnostics metrics.

Rows:
  1. ARP table          — entry count stat, count by interface bargauge, detail table
  2. NDP (IPv6 Neighbors) — entry count stat, count by interface bargauge, detail table
  3. LLDP Neighbors (gated) — neighbor count by local interface bargauge, detail table
  4. NetISR (gated)     — dispatch/queue/handle/drop rate ts, queue length/watermark/limit ts
  5. Sockets & Routes (gated) — sockets_active bargauge, sockets_unix_total stat,
                                routes_total bargauge
  6. pfsync (gated)     — pfsync_nodes_total stat, pfsync_node_info table

LLDP is placed here rather than the Interfaces tab: it is a neighbor-discovery table
conceptually alongside ARP/NDP (a topology sensor — alert when a port stops seeing its
expected switch/port), not an interface-throughput metric (#216).

Coverage:
  opnsense_arp_table_entries
  opnsense_ndp_entries
  opnsense_lldp_neighbors
  opnsense_lldp_neighbor_info
  opnsense_network_diag_netisr_dispatched_total
  opnsense_network_diag_netisr_hybrid_dispatched_total
  opnsense_network_diag_netisr_queued_total
  opnsense_network_diag_netisr_handled_total
  opnsense_network_diag_netisr_queue_drops_total
  opnsense_network_diag_netisr_queue_length
  opnsense_network_diag_netisr_queue_watermark
  opnsense_network_diag_netisr_queue_limit
  opnsense_network_diag_sockets_active
  opnsense_network_diag_sockets_unix_total
  opnsense_network_diag_routes_total
  opnsense_network_diag_pfsync_nodes_total
  opnsense_network_diag_pfsync_node_info
"""

from builder import Builder, sel, RATE


def build(b: Builder):
    # ---- Sentinels -------------------------------------------------------
    b.sentinel("has_network_diag",
               "label_values(opnsense_network_diag_sockets_unix_total, __name__)")
    # opnsense_lldp_neighbors/neighbor_info are only emitted when at least one
    # neighbor has been seen (os-lldpd present but quiet emits nothing at all),
    # so this sentinel doubles as "plugin present AND has neighbors right now".
    b.sentinel("has_lldp", "label_values(opnsense_lldp_neighbors, __name__)")

    # ======================================================================
    # Row 1 – ARP table
    # ======================================================================
    arp_count = b.stat(
        "ARP Entries",
        sel("opnsense_arp_table_entries_total"),
        unit="short",
        w=4, h=4,
        instant=True,
        graph="none",
        desc="Total number of ARP table entries currently known (low-cardinality aggregate, always emitted).",
    )
    arp_by_iface = b.bargauge(
        "ARP Entries by Interface",
        [(f'count by (interface_description)({sel("opnsense_arp_table_entries")})',
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
        excludes=["Value", "__name__", "job", "instance", "env", "opnsense_instance"],
        renames={
            "ip": "IP",
            "mac": "MAC",
            "hostname": "Hostname",
            "interface_description": "Interface",
            "type": "Type",
            "expired": "Expired",
            "permanent": "Permanent",
        },
        sort_by="Interface",
        desc="Full ARP table — all entries with their IP, MAC, hostname, interface, and flags.",
    )

    # ======================================================================
    # Row 2 – NDP (IPv6 neighbors)
    # ======================================================================
    ndp_count = b.stat(
        "NDP Entries",
        sel("opnsense_ndp_entries_total"),
        unit="short",
        w=4, h=4,
        instant=True,
        graph="none",
        desc="Total number of NDP (IPv6 neighbor) entries currently known (low-cardinality aggregate, always emitted).",
    )
    ndp_by_iface = b.bargauge(
        "NDP Entries by Interface",
        [(f'count by (interface_description)({sel("opnsense_ndp_entries")})',
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
        excludes=["Value", "__name__", "job", "instance", "env", "opnsense_instance"],
        renames={
            "ip": "IP",
            "mac": "MAC",
            "interface_description": "Interface",
            "type": "Type",
        },
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
        excludes=["Value", "__name__", "job", "instance", "env", "opnsense_instance"],
        renames={
            "interface": "Local Interface",
            "chassis_name": "Neighbor",
            "port_id": "Neighbor Port ID",
            "port_descr": "Neighbor Port Description",
        },
        sort_by="Local Interface",
        desc="Full LLDP neighbor table — local interface paired with the remote device's "
             "SysName, PortID, and PortDescr. A topology sensor: alert on an expected "
             "(interface, neighbor) pairing going missing.",
    )

    # ======================================================================
    # Row 4 – NetISR (gated: has_network_diag)
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
    # Row 5 – Sockets & Routes (gated: has_network_diag)
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
        sel("opnsense_network_diag_sockets_unix_total"),
        unit="short",
        w=4, h=4,
        instant=True,
        graph="none",
        desc="Total number of active Unix domain sockets (instantaneous count, not a counter).",
    )
    routes_bg = b.bargauge(
        "Routing Table Entries by Protocol",
        [(sel("opnsense_network_diag_routes_total"), "{{proto}}")],
        unit="short",
        w=12, h=8,
        orient="horizontal",
        instant=True,
        desc="Number of routing table entries per address-family protocol (instantaneous count).",
    )

    # ======================================================================
    # Row 6 – pfsync (gated: has_network_diag)
    # ======================================================================
    pfsync_nodes_stat = b.stat(
        "pfsync Cluster Nodes",
        sel("opnsense_network_diag_pfsync_nodes_total"),
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
        excludes=["Value", "__name__", "job", "instance", "env", "opnsense_instance"],
        renames={
            "creatorid": "Creator ID",
            "is_local": "Local",
        },
        sort_by="Creator ID",
        desc="pfsync node detail — creator ID and whether the node is local.",
    )

    # ======================================================================
    # Assemble tab
    # ======================================================================
    b.tab("Routing & Neighbors", [
        b.row("ARP Table", [arp_count, arp_by_iface, arp_table]),
        b.row("NDP (IPv6 Neighbors)", [ndp_count, ndp_by_iface, ndp_table]),
        b.row("LLDP Neighbors", [lldp_by_iface, lldp_table], present="has_lldp"),
        b.row("NetISR (Network Interrupt Subsystem)", [netisr_dispatch_ts, netisr_queue_ts, netisr_len_ts],
              present="has_network_diag"),
        b.row("Sockets & Routes", [sockets_active_bg, sockets_unix_stat, routes_bg],
              present="has_network_diag"),
        b.row("pfsync", [pfsync_nodes_stat, pfsync_node_table],
              present="has_network_diag"),
    ])
