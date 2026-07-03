"""
VPN tab — covers all WireGuard, OpenVPN, and IPsec metrics.

No tab-level gate (the tab always shows if VPN collectors are enabled).
Rows gate individually by feature presence.

Rows:
  1. VPN Services          (always visible): WireGuard service stat, IPsec service stat,
                            OpenVPN instances-enabled count stat.
  2. WireGuard Interfaces  gated has_wireguard_ifaces: statetimeline UPDOWN
  3. WireGuard Peers       gated has_wireguard_peers: peer status statetimeline,
                            RX/TX rate ts, last-handshake table, handshake age stat
  4. OpenVPN               gated has_openvpn: session count ts, per-instance sessions ts,
                            instances table, per-session details table (opt-in metric)
  5. IPsec Tunnels         gated has_ipsec_tunnels: phase1 statetimeline + ts,
                            phase2 tables + ts
  6. IPsec Pools           gated has_ipsec_pools: mode-cfg pool utilization
"""

from builder import Builder, sel, epoch_ms, RATE, RUNSTOP, UPDOWN


# Custom peer-status mapping: 0=Down, 1=Up, 2=Unknown
_WG_PEER = {"0": ("Down", "red"), "1": ("Up", "green"), "2": ("Unknown", "orange"),
            "3": ("Stale", "yellow")}


def build(b: Builder):
    # ---- Sentinels ---------------------------------------------------------
    b.sentinel("has_wireguard",
               "label_values(opnsense_wireguard_service_running, __name__)")
    b.sentinel("has_wireguard_ifaces",
               "label_values(opnsense_wireguard_interfaces_status, __name__)")
    b.sentinel("has_wireguard_peers",
               "label_values(opnsense_wireguard_peer_status, __name__)")
    b.sentinel("has_openvpn",
               "label_values(opnsense_openvpn_instances, __name__)")
    b.sentinel("has_ipsec",
               "label_values(opnsense_ipsec_service_running, __name__)")
    b.sentinel("has_ipsec_tunnels",
               "label_values(opnsense_ipsec_phase1_status, __name__)")
    b.sentinel("has_ipsec_pools",
               "label_values(opnsense_ipsec_pool_size, __name__)")

    # ================================================================
    # Row 1: VPN Services (always visible)
    # ================================================================
    wg_svc = b.stat(
        "WireGuard Service",
        sel("opnsense_wireguard_service_running"),
        mappings=RUNSTOP, color_mode="background",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        w=4, h=4,
        desc="WireGuard service state (1 = running, 0 = stopped).",
    )
    ipsec_svc = b.stat(
        "IPsec Service",
        sel("opnsense_ipsec_service_running"),
        mappings=RUNSTOP, color_mode="background",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        w=4, h=4,
        desc="IPsec (strongSwan) service state (1 = running, 0 = stopped).",
    )
    # No opnsense_openvpn_service_running metric; summarise as enabled-instance count.
    ovpn_count = b.stat(
        "OpenVPN Instances Enabled",
        f'count({sel("opnsense_openvpn_instances")} == 1)',
        unit="short", w=4, h=4,
        desc=(
            "Number of OpenVPN instances currently enabled. "
            "Derived from opnsense_openvpn_instances == 1."
        ),
    )

    # ================================================================
    # Row 2: WireGuard Interfaces
    # ================================================================
    wg_iface_state = b.statetimeline(
        "WireGuard Interface Status",
        [(sel("opnsense_wireguard_interfaces_status"),
          "{{device_name}} ({{device}}) {{device_type}}")],
        UPDOWN, w=24, h=8,
        desc="1 = Up (green), 0 = Down (red). One row per WireGuard interface.",
    )

    # ================================================================
    # Row 3: WireGuard Peers
    # ================================================================
    wg_peer_state = b.statetimeline(
        "WireGuard Peer Status",
        [(sel("opnsense_wireguard_peer_status"),
          "{{peer_name}} ({{device_name}})")],
        _WG_PEER, w=24, h=8,
        desc="Peer reachability over time: Up / Down / Unknown / Stale.",
    )
    wg_rx = b.ts(
        "WireGuard Peer RX",
        [(f'rate({sel("opnsense_wireguard_peer_received_bytes_total")}[{RATE}])',
          "{{peer_name}} rx")],
        unit="Bps", w=12, h=8,
        desc="Bytes received per second by each WireGuard peer.",
    )
    wg_tx = b.ts(
        "WireGuard Peer TX",
        [(f'rate({sel("opnsense_wireguard_peer_transmitted_bytes_total")}[{RATE}])',
          "{{peer_name}} tx")],
        unit="Bps", w=12, h=8,
        desc="Bytes transmitted per second by each WireGuard peer.",
    )
    wg_handshake_table = b.table(
        "WireGuard Last Handshake",
        [epoch_ms(sel("opnsense_wireguard_peer_last_handshake_seconds"))],
        w=16, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "peer_name": "Peer",
            "device_name": "Interface",
            "device": "Device",
            "device_type": "Type",
            "Value": "Last Handshake",
        },
        unit_overrides={"Last Handshake": "dateTimeAsIso"},
        sort_by="Peer",
        desc="Unix timestamp of each peer's last successful handshake, displayed as ISO datetime.",
    )
    wg_handshake_age = b.stat(
        "Handshake Age (max)",
        f'max({sel("opnsense_wireguard_peer_handshake_age_seconds")})',
        unit="s", w=8, h=8,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "orange", "value": 90},
            {"color": "red", "value": 180},
        ],
        color_mode="background",
        desc=(
            "Maximum seconds since any peer's last handshake. "
            "WireGuard re-keys every ~180 s; red > 180 s suggests a stale peer."
        ),
    )

    # ================================================================
    # Row 4: OpenVPN
    # ================================================================
    ovpn_sessions_total = b.ts(
        "OpenVPN Sessions",
        [(sel("opnsense_openvpn_sessions_total"), "sessions")],
        unit="short", w=12, h=8,
        desc="Total number of active OpenVPN sessions over time.",
    )
    ovpn_sessions_by_instance = b.ts(
        "OpenVPN Sessions by Instance",
        [(sel("opnsense_openvpn_sessions_by_instance"), "{{description}}")],
        unit="short", w=12, h=8,
        desc="Number of active OpenVPN sessions per server/client instance.",
    )
    ovpn_instances = b.table(
        "OpenVPN Instances",
        [sel("opnsense_openvpn_instances")],
        w=12, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "uuid": "UUID",
            "role": "Role",
            "description": "Description",
            "device_type": "Device Type",
            "Value": "Enabled",
        },
        sort_by="Role",
        desc="All configured OpenVPN instances. Value: 1 = enabled, 0 = disabled.",
    )
    ovpn_sessions = b.table(
        "OpenVPN Sessions",
        [sel("opnsense_openvpn_sessions")],
        w=12, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "description": "Instance",
            "real_address": "Real Address",
            "virtual_address": "Virtual Address",
            "username": "Username",
            "Value": "OK",
        },
        sort_by="Instance",
        desc=(
            "Per-session OpenVPN details (username, virtual address). "
            "Value: 1 = ok, 0 = not ok. Only populated when the exporter runs "
            "with --exporter.enable-openvpn-details."
        ),
    )

    # ================================================================
    # Row 5: IPsec Tunnels — Phase 1
    # ================================================================
    ipsec_p1_state = b.statetimeline(
        "IPsec Phase 1 Status",
        [(sel("opnsense_ipsec_phase1_status"),
          "{{name}} — {{description}}")],
        UPDOWN, w=24, h=8,
        desc="Phase 1 (IKE SA) connection status over time. 1 = connected, 0 = down.",
    )
    ipsec_p1_install = b.ts(
        "IPsec Phase 1 Install Time",
        [(sel("opnsense_ipsec_phase1_install_time"),
          "{{name}}")],
        unit="s", w=8, h=8,
        desc="Age (seconds) since the IKE SA was established.",
    )
    ipsec_p1_bytes = b.ts(
        "IPsec Phase 1 Throughput",
        [
            (f'rate({sel("opnsense_ipsec_phase1_bytes_in")}[{RATE}])',
             "{{name}} in"),
            (f'rate({sel("opnsense_ipsec_phase1_bytes_out")}[{RATE}])',
             "{{name}} out"),
        ],
        unit="Bps", w=8, h=8,
        desc="Phase 1 bytes in/out per second.",
    )
    ipsec_p1_pkts = b.ts(
        "IPsec Phase 1 Packets",
        [
            (f'rate({sel("opnsense_ipsec_phase1_packets_in")}[{RATE}])',
             "{{name}} in"),
            (f'rate({sel("opnsense_ipsec_phase1_packets_out")}[{RATE}])',
             "{{name}} out"),
        ],
        unit="pps", w=8, h=8,
        desc="Phase 1 packets in/out per second.",
    )

    # IPsec Phase 2 tables + timeseries
    ipsec_p2_install = b.table(
        "IPsec Phase 2 Install Time",
        [sel("opnsense_ipsec_phase2_install_time")],
        w=24, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "description": "Description",
            "name": "Name",
            "phase1_name": "Phase 1",
            "Value": "Install Age (s)",
        },
        unit_overrides={"Install Age (s)": "s"},
        sort_by="Phase 1",
        desc="Age (seconds) since each Child SA was installed.",
    )
    ipsec_p2_throughput = b.ts(
        "IPsec Phase 2 Throughput",
        [
            (f'rate({sel("opnsense_ipsec_phase2_bytes_in")}[{RATE}])',
             "{{name}} in"),
            (f'rate({sel("opnsense_ipsec_phase2_bytes_out")}[{RATE}])',
             "{{name}} out"),
        ],
        unit="Bps", w=12, h=8,
        desc="Phase 2 (Child SA) bytes in/out per second.",
    )
    ipsec_p2_pkts = b.ts(
        "IPsec Phase 2 Packets",
        [
            (f'rate({sel("opnsense_ipsec_phase2_packets_in")}[{RATE}])',
             "{{name}} in"),
            (f'rate({sel("opnsense_ipsec_phase2_packets_out")}[{RATE}])',
             "{{name}} out"),
        ],
        unit="pps", w=12, h=8,
        desc="Phase 2 (Child SA) packets in/out per second.",
    )
    ipsec_p2_times = b.table(
        "IPsec Phase 2 Rekey & Lifetime",
        [
            sel("opnsense_ipsec_phase2_rekey_time"),
            sel("opnsense_ipsec_phase2_life_time"),
        ],
        w=24, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "description": "Description",
            "name": "Name",
            "phase1_name": "Phase 1",
            "Value #A": "Rekey Time (s)",
            "Value #B": "Life Time (s)",
        },
        unit_overrides={
            "Value #A": "s",
            "Value #B": "s",
        },
        sort_by="Name",
        desc="Rekey and lifetime values for each Phase 2 (Child SA) tunnel.",
    )

    # ================================================================
    # Row 6: IPsec Pools (mode-cfg address pool utilization)
    # ================================================================
    pool_online = b.ts(
        "IPsec Pool Leases Online",
        [(sel("opnsense_ipsec_pool_leases_online"), "{{pool}} ({{net}})")],
        unit="short", w=8, h=8,
        desc="Number of mode-cfg leases currently online per pool.",
    )
    pool_offline = b.ts(
        "IPsec Pool Leases Offline",
        [(sel("opnsense_ipsec_pool_leases_offline"), "{{pool}} ({{net}})")],
        unit="short", w=8, h=8,
        desc="Number of mode-cfg leases currently offline per pool.",
    )
    pool_size = b.bargauge(
        "IPsec Pool Size",
        [(sel("opnsense_ipsec_pool_size"), "{{pool}} {{net}}")],
        unit="short", w=8, h=8, orient="horizontal",
        desc="Total address space size of each mode-cfg pool.",
    )

    # ================================================================
    # Tab assembly
    # ================================================================
    b.tab("VPN", [
        b.row("VPN Services",
              [wg_svc, ipsec_svc, ovpn_count]),
        b.row("WireGuard Interfaces",
              [wg_iface_state],
              present="has_wireguard_ifaces"),
        b.row("WireGuard Peers",
              [wg_peer_state, wg_rx, wg_tx,
               wg_handshake_table, wg_handshake_age],
              present="has_wireguard_peers"),
        b.row("OpenVPN",
              [ovpn_sessions_total, ovpn_sessions_by_instance,
               ovpn_instances, ovpn_sessions],
              present="has_openvpn"),
        b.row("IPsec Phase 1",
              [ipsec_p1_state, ipsec_p1_install, ipsec_p1_bytes, ipsec_p1_pkts],
              present="has_ipsec_tunnels"),
        b.row("IPsec Phase 2",
              [ipsec_p2_install, ipsec_p2_throughput, ipsec_p2_pkts, ipsec_p2_times],
              present="has_ipsec_tunnels"),
        b.row("IPsec Mode-CFG Pools",
              [pool_online, pool_offline, pool_size],
              present="has_ipsec_pools"),
    ])
