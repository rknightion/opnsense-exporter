"""
Tab module: Firewall & PF

Covers:
 - Firewall traffic (pass/block packets and bytes) by interface
 - PF state table and source tracking gauges
 - PF counters, limit counters, memory limits, timeouts
 - Firewall rules (top 20, gated behind has_firewall_rules sentinel)
 - GeoIP alias-database freshness (always on)
 - NAT rule inventory counts (opt-in detail flag, #221)
"""

from builder import Builder, sel, epoch_ms, RATE

# The pf-traffic and netflow metrics label `interface` with the kernel DEVICE name
# (igb0, ixl0_vlan25, pppoe0), NOT the configured description that the $interface
# variable enumerates (LAN, IOT, ...). Those label-spaces are disjoint, so these
# panels must filter on the device-space $device variable, not $interface (#98).
DEV = 'interface=~"$device"'


def build(b: Builder):
    # ── Sentinel for firewall rules rows ──────────────────────────────────
    b.sentinel("has_firewall_rules", metric="opnsense_firewall_rule_rules_total")
    # ── Sentinel for the opt-in NAT rule inventory row (#221) ─────────────
    b.sentinel("has_firewall_nat_counts", metric="opnsense_firewall_nat_rules")

    # ══════════════════════════════════════════════════════════════════════
    # ROW 1 — Traffic pass/block packets (pps) by interface
    # ══════════════════════════════════════════════════════════════════════
    pkt_pass_in = b.ts(
        "Inbound Pass Packets/s",
        [
            (f'rate({sel("opnsense_firewall_in_ipv4_pass_packets_total", DEV)}[{RATE}])',
             "{{interface}} IPv4 pass-in"),
            (f'rate({sel("opnsense_firewall_in_ipv6_pass_packets_total", DEV)}[{RATE}])',
             "{{interface}} IPv6 pass-in"),
        ],
        unit="pps", w=12, h=8,
        desc="Rate of inbound IPv4/IPv6 packets permitted by the firewall, per interface.",
    )

    pkt_block_in = b.ts(
        "Inbound Block Packets/s",
        [
            (f'rate({sel("opnsense_firewall_in_ipv4_block_packets_total", DEV)}[{RATE}])',
             "{{interface}} IPv4 block-in"),
            (f'rate({sel("opnsense_firewall_in_ipv6_block_packets_total", DEV)}[{RATE}])',
             "{{interface}} IPv6 block-in"),
        ],
        unit="pps", w=12, h=8,
        desc="Rate of inbound IPv4/IPv6 packets blocked by the firewall, per interface.",
    )

    pkt_pass_out = b.ts(
        "Outbound Pass Packets/s",
        [
            (f'rate({sel("opnsense_firewall_out_ipv4_pass_packets_total", DEV)}[{RATE}])',
             "{{interface}} IPv4 pass-out"),
            (f'rate({sel("opnsense_firewall_out_ipv6_pass_packets_total", DEV)}[{RATE}])',
             "{{interface}} IPv6 pass-out"),
        ],
        unit="pps", w=12, h=8,
        desc="Rate of outbound IPv4/IPv6 packets permitted by the firewall, per interface.",
    )

    pkt_block_out = b.ts(
        "Outbound Block Packets/s",
        [
            (f'rate({sel("opnsense_firewall_out_ipv4_block_packets_total", DEV)}[{RATE}])',
             "{{interface}} IPv4 block-out"),
            (f'rate({sel("opnsense_firewall_out_ipv6_block_packets_total", DEV)}[{RATE}])',
             "{{interface}} IPv6 block-out"),
        ],
        unit="pps", w=12, h=8,
        desc="Rate of outbound IPv4/IPv6 packets blocked by the firewall, per interface.",
    )

    # ══════════════════════════════════════════════════════════════════════
    # ROW 2 — Traffic pass/block throughput (bytes/s) by interface
    # ══════════════════════════════════════════════════════════════════════
    bw_pass_in = b.ts(
        "Inbound Pass Throughput",
        [
            (f'rate({sel("opnsense_firewall_in_ipv4_pass_bytes_total", DEV)}[{RATE}])',
             "{{interface}} IPv4 pass-in"),
            (f'rate({sel("opnsense_firewall_in_ipv6_pass_bytes_total", DEV)}[{RATE}])',
             "{{interface}} IPv6 pass-in"),
        ],
        unit="Bps", w=12, h=8,
        desc="Rate of inbound bytes permitted by the firewall, per interface.",
    )

    bw_block_in = b.ts(
        "Inbound Block Throughput",
        [
            (f'rate({sel("opnsense_firewall_in_ipv4_block_bytes_total", DEV)}[{RATE}])',
             "{{interface}} IPv4 block-in"),
            (f'rate({sel("opnsense_firewall_in_ipv6_block_bytes_total", DEV)}[{RATE}])',
             "{{interface}} IPv6 block-in"),
        ],
        unit="Bps", w=12, h=8,
        desc="Rate of inbound bytes blocked by the firewall, per interface.",
    )

    bw_pass_out = b.ts(
        "Outbound Pass Throughput",
        [
            (f'rate({sel("opnsense_firewall_out_ipv4_pass_bytes_total", DEV)}[{RATE}])',
             "{{interface}} IPv4 pass-out"),
            (f'rate({sel("opnsense_firewall_out_ipv6_pass_bytes_total", DEV)}[{RATE}])',
             "{{interface}} IPv6 pass-out"),
        ],
        unit="Bps", w=12, h=8,
        desc="Rate of outbound bytes permitted by the firewall, per interface.",
    )

    bw_block_out = b.ts(
        "Outbound Block Throughput",
        [
            (f'rate({sel("opnsense_firewall_out_ipv4_block_bytes_total", DEV)}[{RATE}])',
             "{{interface}} IPv4 block-out"),
            (f'rate({sel("opnsense_firewall_out_ipv6_block_bytes_total", DEV)}[{RATE}])',
             "{{interface}} IPv6 block-out"),
        ],
        unit="Bps", w=12, h=8,
        desc="Rate of outbound bytes blocked by the firewall, per interface.",
    )

    # ══════════════════════════════════════════════════════════════════════
    # ROW 3 — Interface hits & PF state table
    # ══════════════════════════════════════════════════════════════════════
    iface_hits = b.ts(
        "Recent Firewall Log Entries per Interface",
        [
            (sel("opnsense_firewall_interface_log_entries_recent", "interface=~\"$interface\""),
             "{{interface}}"),
        ],
        unit="short", w=12, h=8,
        desc="Firewall log entries per interface in the most recent ~5000-record log window. "
             "This is a sliding-window gauge (not a counter): plotted directly, never rate()d. "
             "interface=\"other\" aggregates interfaces beyond the top 10.",
    )

    pf_states_gauge = b.gauge(
        "PF States Used %",
        f'100 * {sel("opnsense_firewall_pf_states_current")} / '
        f'clamp_min({sel("opnsense_firewall_pf_states_limit")}, 1)',
        unit="percent", mn=0, mx=100, w=6, h=8,
        desc="Current PF states as a percentage of the configured limit.",
        thresholds=[
            {"color": "green", "value": None},
            {"color": "yellow", "value": 70},
            {"color": "red", "value": 90},
        ],
    )

    pf_states_ts = b.ts(
        "PF States (absolute)",
        [
            (sel("opnsense_firewall_pf_states_current"), "current states"),
            (sel("opnsense_firewall_pf_states_limit"), "limit"),
        ],
        unit="short", w=6, h=8,
        desc="Absolute current and limit values for active PF state table entries.",
    )

    # ══════════════════════════════════════════════════════════════════════
    # ROW 4 — PF state table (pf_stats)
    # ══════════════════════════════════════════════════════════════════════
    pf_entries = b.ts(
        "PF State Table Entries",
        [
            (sel("opnsense_pf_stats_state_table_entries"), "state table entries"),
            (sel("opnsense_pf_stats_source_tracking_entries"), "source tracking entries"),
        ],
        unit="short", w=12, h=8,
        desc="Current entries in the PF state table and source tracking table.",
    )

    pf_state_ops = b.ts(
        "PF State Table Operations/s",
        [
            (f'rate({sel("opnsense_pf_stats_state_table_searches_total")}[{RATE}])', "searches"),
            (f'rate({sel("opnsense_pf_stats_state_table_inserts_total")}[{RATE}])', "inserts"),
            (f'rate({sel("opnsense_pf_stats_state_table_removals_total")}[{RATE}])', "removals"),
        ],
        unit="ops", w=12, h=8,
        desc="Rate of PF state table operations: searches, inserts, and removals.",
    )

    # ══════════════════════════════════════════════════════════════════════
    # ROW 5 — PF counters
    # ══════════════════════════════════════════════════════════════════════
    pf_counters_ts = b.ts(
        "PF Counters (rate)",
        [
            (f'rate({sel("opnsense_pf_stats_counter_total")}[{RATE}])', "{{counter}}"),
        ],
        unit="ops", w=16, h=8,
        desc="Per-counter rate of PF statistics (match, bad-offset, fragment, etc.).",
    )

    pf_counters_tbl = b.table(
        "PF Counters (total)",
        [f'sort_desc(sum by (counter) ({sel("opnsense_pf_stats_counter_total")}))'],
        renames={"counter": "Counter", "Value": "Total"},
        excludes=["opnsense_instance", "Time"],
        sort_by="Total", sort_desc=True,
        w=8, h=8,
        desc="Cumulative totals for all named PF counters.",
    )

    pf_limit_tbl = b.table(
        "PF Limit Counters",
        [f'sort_desc(sum by (counter) ({sel("opnsense_pf_stats_limit_counter_total")}))'],
        renames={"counter": "Counter", "Value": "Total"},
        excludes=["opnsense_instance", "Time"],
        sort_by="Total", sort_desc=True,
        w=24, h=8,
        desc="Cumulative totals for PF limit counters (memory, state-limit, etc.).",
    )

    # ══════════════════════════════════════════════════════════════════════
    # ROW 6 — PF memory & timeouts
    # ══════════════════════════════════════════════════════════════════════
    pf_memory = b.bargauge(
        "PF Memory Limits by Pool",
        [
            (sel("opnsense_pf_stats_memory_limit"), "{{pool}}"),
        ],
        unit="short", orient="horizontal", w=12, h=8,
        desc="PF memory pool limits by pool name.",
    )

    pf_timeouts = b.table(
        "PF Timeouts",
        [sel("opnsense_pf_stats_timeout_seconds")],
        renames={"name": "Timeout Name", "Value": "Seconds"},
        excludes=["opnsense_instance", "Time"],
        sort_by="Timeout Name", sort_desc=False,
        w=12, h=8,
        desc="PF timeout values in seconds, by name.",
    )

    # ══════════════════════════════════════════════════════════════════════
    # ROW 7 — Firewall rules (top 20), gated on has_firewall_rules
    # ══════════════════════════════════════════════════════════════════════
    fw_rules_count = b.stat(
        "Firewall Rules Total",
        sel("opnsense_firewall_rule_rules_total"),
        unit="short", w=4, h=4,
        desc="Total number of firewall rules with statistics (instantaneous count, not a rate).",
    )

    rules_configured = b.piechart(
        "Configured Rules (enabled vs disabled)",
        [(sel("opnsense_firewall_rule_configured_rules"), "enabled={{enabled}}")],
        unit="short", w=4, h=6,
    )

    fw_rule_evals = b.table(
        "Top 20 Rules — Evaluations/s",
        [
            f'topk(20, sum by (description, action, interface, direction)'
            f'(rate({sel("opnsense_firewall_rule_evaluations_total")}[{RATE}])))',
        ],
        renames={"description": "Rule", "action": "Action",
                 "interface": "Interface", "direction": "Direction", "Value": "Evals/s"},
        excludes=["opnsense_instance", "Time"],
        sort_by="Evals/s", sort_desc=True,
        w=24, h=10,
        desc="Top 20 rules by evaluation rate. UUID labels are dropped to reduce cardinality.",
    )

    fw_rule_pkts = b.table(
        "Top 20 Rules — Packets/s",
        [
            f'topk(20, sum by (description, action, interface, direction)'
            f'(rate({sel("opnsense_firewall_rule_packets_total")}[{RATE}])))',
        ],
        renames={"description": "Rule", "action": "Action",
                 "interface": "Interface", "direction": "Direction", "Value": "Pkts/s"},
        excludes=["opnsense_instance", "Time"],
        sort_by="Pkts/s", sort_desc=True,
        w=12, h=10,
        desc="Top 20 rules by matched packet rate.",
    )

    fw_rule_bytes = b.table(
        "Top 20 Rules — Bytes/s",
        [
            f'topk(20, sum by (description, action, interface, direction)'
            f'(rate({sel("opnsense_firewall_rule_bytes_total")}[{RATE}])))',
        ],
        renames={"description": "Rule", "action": "Action",
                 "interface": "Interface", "direction": "Direction", "Value": "Bps"},
        excludes=["opnsense_instance", "Time"],
        unit_overrides={"Bps": "Bps"},
        sort_by="Bps", sort_desc=True,
        w=12, h=10,
        desc="Top 20 rules by matched byte rate.",
    )

    fw_rule_states = b.table(
        "Top 20 Rules — Active States",
        [
            f'topk(20, sum by (description, action, interface, direction)'
            f'({sel("opnsense_firewall_rule_states")}))',
        ],
        renames={"description": "Rule", "action": "Action",
                 "interface": "Interface", "direction": "Direction", "Value": "States"},
        excludes=["opnsense_instance", "Time"],
        sort_by="States", sort_desc=True,
        w=12, h=10,
        desc="Top 20 rules by current active state count.",
    )

    fw_rule_pf = b.table(
        "Top 20 Rules — PF Rules Generated",
        [
            f'topk(20, sum by (description, action, interface, direction)'
            f'({sel("opnsense_firewall_rule_pf_rules")}))',
        ],
        renames={"description": "Rule", "action": "Action",
                 "interface": "Interface", "direction": "Direction", "Value": "PF Rules"},
        excludes=["opnsense_instance", "Time"],
        sort_by="PF Rules", sort_desc=True,
        w=12, h=10,
        desc="Top 20 rules by number of PF rules generated.",
    )

    # ══════════════════════════════════════════════════════════════════════
    # GeoIP alias-database freshness (#221) — always on, cheap/cached
    # ══════════════════════════════════════════════════════════════════════
    geoip_usages = b.stat(
        "GeoIP Alias Usages",
        sel("opnsense_firewall_geoip_alias_usages"),
        unit="short", w=6, h=4,
        desc="Number of configured firewall aliases of type GeoIP, regardless of whether the GeoIP database itself has ever downloaded.",
    )
    geoip_addresses = b.stat(
        "GeoIP Addresses Loaded",
        sel("opnsense_firewall_geoip_addresses"),
        unit="short", w=6, h=4,
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        desc="Number of GeoIP addresses/networks currently loaded from the downloaded database. 0 until a MaxMind/ipinfo key is configured and a download has succeeded.",
    )
    geoip_files = b.stat(
        "GeoIP Table Files",
        sel("opnsense_firewall_geoip_files"),
        unit="short", w=6, h=4,
        desc="Number of per-country GeoIP alias table files currently written. 0 until a MaxMind/ipinfo key is configured and a download has succeeded.",
    )
    geoip_age = b.stat(
        "GeoIP Database Age",
        f"(time() - {sel('opnsense_firewall_geoip_last_update_timestamp_seconds')}) / 3600",
        unit="short", w=6, h=4,
        thresholds=[{"color": "green", "value": None},
                    {"color": "orange", "value": 24},
                    {"color": "red", "value": 168}],
        desc=(
            "Hours since the GeoIP database last downloaded successfully. Absent "
            "entirely until the first successful download. A large or growing "
            "value indicates an expired MaxMind license key or a failed download — "
            "GeoIP aliases silently stop matching any traffic once the database "
            "stops updating."
        ),
    )
    geoip_last_update = b.table(
        "GeoIP Database Last Update",
        [epoch_ms(sel("opnsense_firewall_geoip_last_update_timestamp_seconds"))],
        w=24, h=4,
        excludes=["__name__", "job", "instance", "Value"],
        renames={"opnsense_instance": "Instance", "Value #A": "Last Update"},
        unit_overrides={"Last Update": "dateTimeAsIso"},
        desc="Timestamp of the last successful GeoIP database download, per instance.",
    )

    # ══════════════════════════════════════════════════════════════════════
    # NAT rule inventory counts (#221) — opt-in detail flag
    # (--exporter.enable-firewall-nat-counts)
    # ══════════════════════════════════════════════════════════════════════
    nat_rules = b.bargauge(
        "NAT Rules by Type",
        [(f'sum by (type, enabled) ({sel("opnsense_firewall_nat_rules")})',
          "{{type}} enabled={{enabled}}")],
        unit="short", w=12, h=8,
        desc=(
            "MVC-managed NAT rule counts by type (source_nat, d_nat, one_to_one, "
            "npt) and enabled state. Rules created before an admin migrated to the "
            "MVC-managed NAT backend are not counted; NAT rules have no pf hit/byte "
            "statistics upstream, so this is inventory only."
        ),
    )
    nat_rules_table = b.table(
        "NAT Rules — Detail",
        [f'{sel("opnsense_firewall_nat_rules")}'],
        w=12, h=8,
        excludes=["__name__", "job", "instance"],
        renames={"type": "Type", "enabled": "Enabled",
                 "opnsense_instance": "Instance", "Value": "Rules"},
        sort_by="Type",
        desc="NAT rule counts by type and enabled state, one row per (type, enabled) pair.",
    )

    # ══════════════════════════════════════════════════════════════════════
    # Assemble tab
    # ══════════════════════════════════════════════════════════════════════
    b.tab("Firewall & PF", [
        b.row("Traffic — Inbound Pass/Block (packets/s)",
              [pkt_pass_in, pkt_block_in]),
        b.row("Traffic — Outbound Pass/Block (packets/s)",
              [pkt_pass_out, pkt_block_out]),
        b.row("Traffic — Pass/Block Throughput (inbound)",
              [bw_pass_in, bw_block_in]),
        b.row("Traffic — Pass/Block Throughput (outbound)",
              [bw_pass_out, bw_block_out]),
        b.row("Interface Hits & PF State Table",
              [iface_hits, pf_states_gauge, pf_states_ts]),
        b.row("PF State Table (pf-stats)",
              [pf_entries, pf_state_ops]),
        b.row("PF Counters",
              [pf_counters_ts, pf_counters_tbl, pf_limit_tbl]),
        b.row("PF Memory & Timeouts",
              [pf_memory, pf_timeouts]),
        b.row("Firewall Rules (top 20)",
              [fw_rules_count, rules_configured, fw_rule_evals,
               fw_rule_pkts, fw_rule_bytes,
               fw_rule_states, fw_rule_pf],
              present="has_firewall_rules"),
        b.row("GeoIP Alias-Database Freshness",
              [geoip_usages, geoip_addresses, geoip_files, geoip_age, geoip_last_update]),
        b.row("NAT Rule Inventory (details flag)",
              [nat_rules, nat_rules_table],
              present="has_firewall_nat_counts"),
    ])
