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
                            instances table, per-session details table (opt-in metric),
                            instance traffic ts (always-on), per-session traffic ts +
                            connected-since table (opt-in, --exporter.enable-openvpn-details)
  5. IPsec Tunnels         gated has_ipsec_tunnels: phase1 statetimeline + ts,
                            phase2 tables + ts
  6. IPsec Pools           gated has_ipsec_pools: mode-cfg pool utilization
"""

from builder import Builder, sel, grp, epoch_ms, RATE, RUNSTOP, UPDOWN
from tabs import log_events


# Custom peer-status mapping: 0=Down, 1=Up, 2=Unknown
_WG_PEER = {"0": ("Down", "red"), "1": ("Up", "green"), "2": ("Unknown", "orange"),
            "3": ("Stale", "yellow")}


def build(b: Builder):
    # ---- Sentinels ---------------------------------------------------------
    b.sentinel("has_wireguard", metric="opnsense_wireguard_service_running")
    b.sentinel("has_wireguard_ifaces", metric="opnsense_wireguard_interfaces_status")
    b.sentinel("has_wireguard_peers", metric="opnsense_wireguard_peer_status")
    b.sentinel("has_openvpn", metric="opnsense_openvpn_instances")
    b.sentinel("has_ipsec", metric="opnsense_ipsec_service_running")
    b.sentinel("has_ipsec_tunnels", metric="opnsense_ipsec_phase1_status")
    b.sentinel("has_ipsec_pools", metric="opnsense_ipsec_pool_size")
    b.sentinel("has_ipsec_sad", metric="opnsense_ipsec_sad_entries")

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
        desc=("Number of OpenVPN instances currently enabled. "
            "Derived from opnsense_openvpn_instances == 1."
             "Fleet total: this is a deliberate sum across every selected firewall (#468) — with two boxes picked, the number is both boxes' together."),
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
        f'max {grp()} ({sel("opnsense_wireguard_peer_handshake_age_seconds")})',
        unit="s", w=8, h=8, legend="{{opnsense_instance}}",
        thresholds=[
            {"color": "green", "value": None},
            {"color": "orange", "value": 90},
            {"color": "red", "value": 180},
        ],
        color_mode="background",
        desc=(
            "Maximum seconds since any peer's last handshake, per firewall. "
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
        [
            sel("opnsense_openvpn_instances"),
            sel("opnsense_openvpn_instance_max_clients"),
        ],
        w=12, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "uuid": "UUID",
            "role": "Role",
            "description": "Description",
            "device_type": "Device Type",
            "Value #A": "Enabled",
            "Value #B": "Max Clients",
        },
        sort_by="Role",
        desc=(
            "All configured OpenVPN instances. Enabled: 1 = enabled, 0 = disabled. "
            "Max Clients is the configured concurrent-client cap (server instances "
            "only); blank means no cap is configured (unlimited), not a cap of zero."
        ),
    )
    # #584: the utilization/headroom signal the raw maxclients gauge exists to
    # feed -- nothing warned an operator before a capped server started
    # refusing connections at the limit. Joined on description (both series
    # share the OpenVPN instance's description/uuid/role/device_type label
    # set); an uncapped or client-role instance has no max_clients series and
    # so contributes no line here, not a fabricated 0% or divide-by-zero.
    ovpn_utilization = b.ts(
        "OpenVPN Utilization",
        [(f'100 * {sel("opnsense_openvpn_sessions_by_instance")} '
          f'/ on(description, opnsense_instance) '
          f'{sel("opnsense_openvpn_instance_max_clients")}',
          "{{description}}")],
        unit="percent", w=12, h=8,
        desc=(
            "Live session count as a percentage of the configured concurrent-client "
            "cap, per OpenVPN server instance. Only plotted for instances with a "
            "cap actually configured (see OpenVPN Instances table above)."
        ),
    )
    # NOT "OpenVPN Sessions" (#649): the timeseries above already owns that title on
    # this same tab, so two panels a screen apart answered to one name. Cross-tab
    # duplicates are fine — the tab disambiguates them, and alert deep-linking already
    # demands a tab qualifier for any repeated title — but a same-tab collision has
    # nothing to disambiguate it. This one counts sessions, that one lists them.
    ovpn_sessions = b.table(
        "OpenVPN Session Details",
        [sel("opnsense_openvpn_sessions")],
        w=12, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "description": "Instance",
            "real_address": "Real Address",
            "virtual_address": "Virtual Address",
            "virtual_ipv6_address": "Virtual IPv6 Address",
            "username": "Username",
            "Value": "OK",
        },
        sort_by="Instance",
        desc=(
            "Per-session OpenVPN details (username, virtual address). "
            "'Virtual IPv6 Address' is populated only for dual-stack or "
            "IPv6-only tunnels; empty for v4-only sessions. "
            "Value: 1 = ok, 0 = not ok. Only populated when the exporter runs "
            "with --exporter.enable-openvpn-details."
        ),
    )
    ovpn_instance_traffic = b.ts(
        "OpenVPN Instance Traffic",
        [
            (f'rate({sel("opnsense_openvpn_instance_received_bytes_total")}[{RATE}])',
             "{{description}} rx"),
            (f'rate({sel("opnsense_openvpn_instance_transmitted_bytes_total")}[{RATE}])',
             "{{description}} tx"),
        ],
        unit="Bps", w=12, h=8,
        desc=(
            "Bytes received/transmitted per second, summed across all active "
            "sessions on each OpenVPN instance. Always populated (no identity label)."
        ),
    )
    ovpn_session_traffic = b.ts(
        "OpenVPN Session Traffic",
        [
            (f'rate({sel("opnsense_openvpn_session_received_bytes_total")}[{RATE}])',
             "{{username}} rx"),
            (f'rate({sel("opnsense_openvpn_session_transmitted_bytes_total")}[{RATE}])',
             "{{username}} tx"),
        ],
        unit="Bps", w=12, h=8,
        desc=(
            "Bytes received/transmitted per second for each connected OpenVPN "
            "session. The 'username' series label prefers the client's TLS "
            "common name when present, else the OpenVPN username. Only "
            "populated when the exporter runs with --exporter.enable-openvpn-details."
        ),
    )
    ovpn_connected_since = b.table(
        "OpenVPN Session Connected Since",
        [epoch_ms(sel("opnsense_openvpn_session_connected_since_timestamp_seconds"))],
        w=24, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "description": "Instance",
            "real_address": "Real Address",
            "virtual_address": "Virtual Address",
            "virtual_ipv6_address": "Virtual IPv6 Address",
            "username": "Identity",
            "Value": "Connected Since",
        },
        unit_overrides={"Connected Since": "dateTimeAsIso"},
        sort_by="Instance",
        desc=(
            "Unix timestamp of when each OpenVPN session connected, displayed "
            "as ISO datetime. Only populated when the exporter runs with "
            "--exporter.enable-openvpn-details."
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
            (f'rate({sel("opnsense_ipsec_phase1_bytes_in_total")}[{RATE}])',
             "{{name}} in"),
            (f'rate({sel("opnsense_ipsec_phase1_bytes_out_total")}[{RATE}])',
             "{{name}} out"),
        ],
        unit="Bps", w=8, h=8,
        desc="Phase 1 bytes in/out per second.",
    )
    ipsec_p1_pkts = b.ts(
        "IPsec Phase 1 Packets",
        [
            (f'rate({sel("opnsense_ipsec_phase1_packets_in_total")}[{RATE}])',
             "{{name}} in"),
            (f'rate({sel("opnsense_ipsec_phase1_packets_out_total")}[{RATE}])',
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
            (f'rate({sel("opnsense_ipsec_phase2_bytes_in_total")}[{RATE}])',
             "{{name}} in"),
            (f'rate({sel("opnsense_ipsec_phase2_bytes_out_total")}[{RATE}])',
             "{{name}} out"),
        ],
        unit="Bps", w=12, h=8,
        desc="Phase 2 (Child SA) bytes in/out per second.",
    )
    ipsec_p2_pkts = b.ts(
        "IPsec Phase 2 Packets",
        [
            (f'rate({sel("opnsense_ipsec_phase2_packets_in_total")}[{RATE}])',
             "{{name}} in"),
            (f'rate({sel("opnsense_ipsec_phase2_packets_out_total")}[{RATE}])',
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
    # #578: Connected only exists at phase1 (IKE SA) level -- a tunnel with
    # phase1 up and one dead child SA reads fully healthy without this panel.
    ipsec_p2_established = b.statetimeline(
        "IPsec Phase 2 (Child SA) Established",
        [(sel("opnsense_ipsec_phase2_established"),
          "{{name}} — {{description}}")],
        UPDOWN, w=24, h=8,
        desc=(
            "Whether each phase2 child SA is fully installed (1) vs down or "
            "transitional -- rekeying, deleting, etc. (0). Check this alongside "
            "IPsec Phase 1 Status above: phase1 can show connected while a "
            "single child SA has failed or never installed."
        ),
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
    lease_online = b.table(
        "IPsec Mode-CFG Leases",
        [sel("opnsense_ipsec_lease_online")],
        w=24, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "pool": "Pool",
            "user": "User",
            "Value": "Online",
        },
        sort_by="Pool",
        desc=(
            "Per-user IPsec mode-cfg lease online state (1 = online, 0 = offline). "
            "Only populated when the exporter runs with "
            "--exporter.enable-ipsec-lease-details (the 'user' label is unbounded "
            "road-warrior identity)."
        ),
    )

    # ================================================================
    # Row 7: IPsec Kernel (SAD/SPD) & Config
    # ================================================================
    # Kernel view (setkey) complements the vici phase1/phase2 metrics: it catches
    # "tunnel up but no SA/policy installed" and exposes rekey-health timers.
    sad_entries = b.ts(
        "IPsec Kernel SAs Installed",
        [(sel("opnsense_ipsec_sad_entries"), "{{satype}}")],
        unit="short", w=8, h=8,
        desc=(
            "Number of installed kernel security associations (setkey -D), by "
            "satype. Zero while phase1 claims connected signals a broken tunnel."
        ),
    )
    spd_policies = b.ts(
        "IPsec Kernel Policies Installed",
        [(sel("opnsense_ipsec_spd_policies"), "{{direction}}")],
        unit="short", w=8, h=8,
        desc=(
            "Number of installed kernel security policies (setkey -DP), by "
            "direction (in/out/fwd)."
        ),
    )
    sad_nat = b.statetimeline(
        "IPsec NAT-Traversal",
        [(sel("opnsense_ipsec_sad_nat_traversal"), "IKE {{ikeid}}")],
        {"0": ("No NAT-T", "green"), "1": ("NAT-T", "blue")},
        w=8, h=8,
        desc="Whether the IKE SA's kernel SAs are NAT-traversed. 1 = NAT-T detected.",
    )
    sa_age = b.ts(
        "IPsec SA Age vs Rekey Lifetime",
        [
            (sel("opnsense_ipsec_sa_age_seconds"), "reqid {{reqid}} age"),
            (sel("opnsense_ipsec_sa_lifetime_soft_seconds"), "reqid {{reqid}} soft"),
            (sel("opnsense_ipsec_sa_lifetime_hard_seconds"), "reqid {{reqid}} hard"),
        ],
        unit="s", w=16, h=8,
        desc=(
            "Kernel SA age (oldest SA per reqid/child-SA group) against its soft "
            "(rekey) and hard expiry lifetimes. Age approaching the soft lifetime "
            "is the time-to-rekey signal."
        ),
    )
    # #578: the byte-count rekey trigger's own explanatory ratio -- the already
    # exported phase1/phase2 bytes-in/out carry no limits, so "is this tunnel
    # rekeying every 90s because it keeps hitting its byte quota" was previously
    # unanswerable. RAW values (not rate()) on purpose: this is a level-vs-
    # threshold comparison like sa_age above, not a throughput view (throughput
    # already has its own panel: IPsec Phase 2 Throughput). A soft/hard series
    # absent for a given reqid means that limit is unconfigured (0 = unlimited
    # in setkey/strongSwan's own convention, never exported as a fabricated
    # zero) -- not a scrape gap.
    sa_bytes = b.ts(
        "IPsec SA Bytes vs Rekey Limits",
        [
            (sel("opnsense_ipsec_sa_bytes_current_total"), "reqid {{reqid}} current"),
            (sel("opnsense_ipsec_sa_bytes_soft_limit"), "reqid {{reqid}} soft"),
            (sel("opnsense_ipsec_sa_bytes_hard_limit"), "reqid {{reqid}} hard"),
        ],
        unit="bytes", w=12, h=8,
        desc=(
            "Kernel SA cumulative byte usage (most-utilized SA per reqid/child-SA "
            "group) against its configured soft (rekey) and hard byte-count "
            "limits. Current repeatedly climbing straight back up to soft right "
            "after a rekey is the 'IPsec is up but throughput is garbage' "
            "pattern -- a byte-count lifetime configured too small for the "
            "tunnel's real traffic. Missing soft/hard series for a reqid means "
            "no byte-count limit is configured for that child SA."
        ),
    )
    # Packet-count ("allocations") equivalent of the byte-count panel above --
    # some child SAs are configured with a packet-count rekey margin instead of,
    # or alongside, a byte-count one, and would otherwise rekey constantly with
    # no explanation available on this dashboard.
    sa_allocated = b.ts(
        "IPsec SA Packet Allocations vs Rekey Limits",
        [
            (sel("opnsense_ipsec_sa_allocated_current_total"), "reqid {{reqid}} current"),
            (sel("opnsense_ipsec_sa_allocated_soft_limit"), "reqid {{reqid}} soft"),
            (sel("opnsense_ipsec_sa_allocated_hard_limit"), "reqid {{reqid}} hard"),
        ],
        unit="short", w=12, h=8,
        desc=(
            "Kernel SA cumulative packet usage (most-utilized SA per reqid/"
            "child-SA group) against its configured soft (rekey) and hard "
            "packet-count limits. Missing soft/hard series for a reqid means no "
            "packet-count limit is configured for that child SA."
        ),
    )
    config_flags = b.statetimeline(
        "IPsec Config State",
        [
            (sel("opnsense_ipsec_legacy_enabled"), "enabled"),
            (sel("opnsense_ipsec_config_dirty"), "uncommitted changes"),
        ],
        {"0": ("No", "green"), "1": ("Yes", "yellow")},
        # enabled is GOOD at 1: a working IPsec install was painting yellow for its whole
        # history and going green when IPsec was switched off (#511).
        series_mappings={"enabled": {"0": ("No", "red"), "1": ("Yes", "green")}},
        w=8, h=8,
        desc=(
            "IPsec enabled flag and the pending-config (dirty) flag. "
            "Dirty = 1 means a staged IPsec change has not been applied."
        ),
    )

    # ================================================================
    # Tab assembly
    # ================================================================
    b.tab("VPN", [
        b.autogrid_row("VPN Services",
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
               ovpn_instances, ovpn_utilization, ovpn_sessions,
               ovpn_instance_traffic, ovpn_session_traffic, ovpn_connected_since],
              present="has_openvpn"),
        # #523: the transitions behind every state panel above, moved here from the
        # retired Observability domain. A tunnel that is up but flapping looks healthy
        # on the state gauges and obvious here, which is the whole reason to co-locate.
        #
        # It stays on THIS leaf rather than following the IPsec rows next door (#619):
        # has_log_events_vpn covers every tunnel type, so filing it under IPsec would
        # bury WireGuard and OpenVPN lifecycle behind an IPsec tab.
        log_events.vpn_row(b),
    ])
    # Split out of "VPN" (#619): 39 panels in one tab, of which 20 were IPsec. Rows
    # are regrouped and otherwise untouched.
    b.tab("VPN - IPsec", [
        b.row("IPsec Phase 1",
              [ipsec_p1_state, ipsec_p1_install, ipsec_p1_bytes, ipsec_p1_pkts],
              present="has_ipsec_tunnels"),
        b.row("IPsec Phase 2",
              [ipsec_p2_install, ipsec_p2_throughput, ipsec_p2_pkts, ipsec_p2_times,
               ipsec_p2_established],
              present="has_ipsec_tunnels"),
        b.row("IPsec Mode-CFG Pools",
              [pool_online, pool_offline, pool_size, lease_online],
              present="has_ipsec_pools"),
        b.row("IPsec Kernel (SAD/SPD)",
              [sad_entries, spd_policies, sad_nat, sa_age, sa_bytes, sa_allocated],
              present="has_ipsec_sad"),
        b.row("IPsec Config State",
              [config_flags],
              present="has_ipsec"),
    ], present="has_ipsec")
