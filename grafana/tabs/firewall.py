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

from builder import Builder, sel, grp, epoch_ms, RATE
from uids import focus_device, focus_interface, to_tab
from tabs import log_events

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
    # Default-off API fallback; keep its sampled boards hidden unless enabled.
    b.sentinel("has_pftop", metric="opnsense_pftop_cardinality_keys")

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
        # Already explicit before #467 — it merely happened to match the triple
        # gauge() used to inject, so nothing here changes. Meaning: PF drops new
        # connections outright once the state table is full, so 90% of the
        # configured limit is a real cliff rather than a stylistic choice.
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

    pf_iface_refs = b.ts(
        "PF State References by Interface",
        [
            (sel("opnsense_firewall_pf_interface_references"),
             "{{interface}}{{skipped}}"),
        ],
        unit="short", w=12, h=8,
        desc=(
            "PF state-table references held per interface — the only per-interface breakdown of "
            "state usage the API exposes, and the answer to 'which interface is consuming the "
            "state table', which otherwise needs a shell on the box. A gauge, not a counter: "
            "plot it directly, never rate() it. skipped=\"true\" marks an interface on pf's skip "
            "list, which pf does not filter at all. The API's aggregate 'all' key is deliberately "
            "not emitted — sum() these instead, or every total counts twice."
        ),
    )

    # #580: a reset marker for the pf pass/block counters (rows 1-2 above). Without
    # it, a `pfctl -z`/filter reload shows up on those rate() panels as an
    # unexplained negative delta or plateau. Table, not a timeseries: the value
    # only changes on a reset, so a line chart would render as a flat step
    # function that tells the reader nothing a "when" table doesn't say better —
    # same reasoning as the GeoIP "Database Last Update" table below.
    pf_counters_cleared = b.table(
        "PF Counters Reset (Cleared) — by Interface",
        [epoch_ms(sel("opnsense_firewall_pf_counters_cleared_timestamp_seconds"))],
        w=12, h=8,
        excludes=["__name__", "job", "instance"],
        renames={"interface": "Interface", "opnsense_instance": "Instance", "Value": "Counters Reset At"},
        unit_overrides={"Counters Reset At": "dateTimeAsIso"},
        desc=(
            "When pf's own pass/block packet and byte counters (the traffic panels above) were "
            "last reset for each interface — a `pfctl -z` or a filter/rule reload. OPNsense reports "
            "this with no timezone marker at all, so it is decoded assuming UTC and can be off by "
            "the firewall's real UTC offset; read it as 'a reset happened', not a to-the-minute "
            "clock. A rate()/increase() query spanning a reset already reads a bogus negative delta "
            "or spurious plateau on the traffic panels above — use this table to explain that away "
            "rather than chase it as a real traffic drop. Absent entirely for an interface the box "
            "has never reported a parseable reset time for."
        ),
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
        [f'sort_desc(sum {grp("counter")} ({sel("opnsense_pf_stats_counter_total")}))'],
        renames={"counter": "Counter", "Value": "Total", "opnsense_instance": "Instance"},
        excludes=["Time"],
        sort_by="Total", sort_desc=True,
        w=8, h=8,
        desc="Cumulative totals for all named PF counters.",
    )

    pf_limit_tbl = b.table(
        "PF Limit Counters",
        [f'sort_desc(sum {grp("counter")} ({sel("opnsense_pf_stats_limit_counter_total")}))'],
        renames={"counter": "Counter", "Value": "Total", "opnsense_instance": "Instance"},
        excludes=["Time"],
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
        renames={"name": "Timeout Name", "Value": "Seconds", "opnsense_instance": "Instance"},
        excludes=["Time"],
        sort_by="Timeout Name", sort_desc=False,
        w=12, h=8,
        desc="PF timeout values in seconds, by name.",
    )

    # ══════════════════════════════════════════════════════════════════════
    # ROW 7 — opt-in pfTop API fallback
    # ══════════════════════════════════════════════════════════════════════
    pftop_states = b.table(
        "pfTop State Board",
        [
            f'sort_desc({sel("opnsense_pftop_state_bytes")})',
            sel("opnsense_pftop_state_packets"),
            sel("opnsense_pftop_state_records"),
        ],
        excludes=["Time", "job", "instance"],
        w=24, h=10,
        desc=(
            "The current deterministic top-100 PF state identities. Bytes and packets are "
            "current per-state gauges, not process-lifetime counters; duplicate endpoint rows "
            "are folded before ranking."
        ),
    )

    pftop_talkers = b.table(
        "pfTop Traffic-Sample Talkers",
        [f'sort_desc({sel("opnsense_pftop_talker_rate_bits")})'],
        excludes=["Time", "job", "instance"],
        w=24, h=10,
        desc=(
            "The current deterministic top-100 host/interface identities from OPNsense's "
            "two-second iftop sample, split into in, out and total directions. This sampled "
            "diagnostic is not a replacement for NetFlow traffic accounting."
        ),
    )

    pftop_overflow = b.table(
        "pfTop Overflow Accounting",
        [
            sel("opnsense_pftop_state_overflow_bytes"),
            sel("opnsense_pftop_state_overflow_packets"),
            sel("opnsense_pftop_state_overflow_records"),
            sel("opnsense_pftop_talker_overflow_rate_bits"),
            sel("opnsense_pftop_talker_overflow_records"),
        ],
        excludes=["Time", "job", "instance"],
        w=16, h=8,
        desc=(
            "Current-snapshot values outside the named top-100 boards or refused by the "
            "five-minute identity inventories. Named values plus overflow account for the "
            "successful endpoint response, not all firewall traffic."
        ),
    )

    pftop_cardinality = b.table(
        "pfTop Cardinality Guard",
        [
            sel("opnsense_pftop_cardinality_keys"),
            sel("opnsense_pftop_cardinality_capped_total"),
        ],
        excludes=["Time", "job", "instance"],
        w=8, h=8,
        desc=(
            "Live five-minute inventory keys and cumulative novel identities refused at the "
            "100-key state or talker cap. The complete collector ceiling is 611 series per target."
        ),
    )

    # ══════════════════════════════════════════════════════════════════════
    # ROW 8 — Firewall rules (top 20), gated on has_firewall_rules
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
            f'topk {grp()} (20, sum {grp("description", "action", "interface", "direction")}'
            f'(rate({sel("opnsense_firewall_rule_evaluations_total")}[{RATE}])))',
        ],
        renames={"description": "Rule", "action": "Action",
                 "interface": "Interface", "direction": "Direction", "Value": "Evals/s", "opnsense_instance": "Instance"},
        excludes=["Time"],
        sort_by="Evals/s", sort_desc=True,
        w=24, h=10,
        desc="Top 20 rules by evaluation rate. UUID labels are dropped to reduce cardinality.",
    )

    fw_rule_pkts = b.table(
        "Top 20 Rules — Packets/s",
        [
            f'topk {grp()} (20, sum {grp("description", "action", "interface", "direction")}'
            f'(rate({sel("opnsense_firewall_rule_packets_total")}[{RATE}])))',
        ],
        renames={"description": "Rule", "action": "Action",
                 "interface": "Interface", "direction": "Direction", "Value": "Pkts/s", "opnsense_instance": "Instance"},
        excludes=["Time"],
        sort_by="Pkts/s", sort_desc=True,
        w=12, h=10,
        desc="Top 20 rules by matched packet rate.",
    )

    fw_rule_bytes = b.table(
        "Top 20 Rules — Bytes/s",
        [
            f'topk {grp()} (20, sum {grp("description", "action", "interface", "direction")}'
            f'(rate({sel("opnsense_firewall_rule_bytes_total")}[{RATE}])))',
        ],
        renames={"description": "Rule", "action": "Action",
                 "interface": "Interface", "direction": "Direction", "Value": "Bps", "opnsense_instance": "Instance"},
        excludes=["Time"],
        unit_overrides={"Bps": "Bps"},
        sort_by="Bps", sort_desc=True,
        w=12, h=10,
        desc="Top 20 rules by matched byte rate.",
    )

    fw_rule_states = b.table(
        "Top 20 Rules — Active States",
        [
            f'topk {grp()} (20, sum {grp("description", "action", "interface", "direction")}'
            f'({sel("opnsense_firewall_rule_states")}))',
        ],
        renames={"description": "Rule", "action": "Action",
                 "interface": "Interface", "direction": "Direction", "Value": "States", "opnsense_instance": "Instance"},
        excludes=["Time"],
        sort_by="States", sort_desc=True,
        w=12, h=10,
        desc="Top 20 rules by current active state count.",
    )

    fw_rule_pf = b.table(
        "Top 20 Rules — PF Rules Generated",
        [
            f'topk {grp()} (20, sum {grp("description", "action", "interface", "direction")}'
            f'({sel("opnsense_firewall_rule_pf_rules")}))',
        ],
        renames={"description": "Rule", "action": "Action",
                 "interface": "Interface", "direction": "Direction", "Value": "PF Rules", "opnsense_instance": "Instance"},
        excludes=["Time"],
        sort_by="PF Rules", sort_desc=True,
        w=12, h=10,
        desc="Top 20 rules by number of PF rules generated.",
    )

    # #558: the "protocol" label added to the per-rule metrics is the grouping
    # dimension the free-text description/uuid labels above cannot provide —
    # a bounded (tcp/udp/icmp/any/...) breakdown of rule hits.
    fw_rule_proto = b.piechart(
        "Rule Hits by Protocol",
        [(f'sum {grp("protocol")} (rate({sel("opnsense_firewall_rule_packets_total")}[{RATE}]))',
          "{{protocol}}")],
        unit="pps",
        w=8, h=10,
        desc="opnsense_firewall_rule_packets_total matched-packet rate grouped by the rule's "
             "configured protocol (tcp/udp/icmp/esp/any/...). A rule with no search-result match "
             "(the 'system' rows) or an empty protocol value reports as 'unknown' rather than an "
             "empty label.",
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
        unit="h", w=6, h=4,
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
        excludes=["__name__", "job", "instance"],
        renames={"opnsense_instance": "Instance", "Value": "Last Update"},
        unit_overrides={"Last Update": "dateTimeAsIso"},
        desc="Timestamp of the last successful GeoIP database download, per instance.",
    )

    # ══════════════════════════════════════════════════════════════════════
    # NAT rule inventory counts (#221) — opt-in detail flag
    # (--exporter.enable-firewall-nat-counts)
    # ══════════════════════════════════════════════════════════════════════
    nat_rules = b.bargauge(
        "NAT Rules by Type",
        [(f'sum {grp("type", "enabled")} ({sel("opnsense_firewall_nat_rules")})',
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

    migration_rules = b.stat(
        "Legacy Firewall Rules",
        sel("opnsense_firewall_migration_legacy_rules"),
        unit="short", w=12, h=4,
        desc=(
            "Rules still waiting for OPNsense's 26.7 MVC migration. The panel is empty "
            "on releases that do not expose the migration API."
        ),
    )
    migration_outbound = b.stat(
        "Legacy Outbound NAT Rules",
        sel("opnsense_firewall_migration_legacy_outbound_nat_rules"),
        unit="short", w=12, h=4,
        desc=(
            "Outbound NAT rules still waiting for OPNsense's 26.7 MVC migration. "
            "Zero means the migration debt is clear; no data means the API is absent."
        ),
    )

    # ══════════════════════════════════════════════════════════════════════
    # Assemble tab
    # ══════════════════════════════════════════════════════════════════════
    # ---- drilldowns (#419) ------------------------------------------------
    # The pf families label `interface` with the kernel DEVICE name, so the field
    # link sets $device — NOT $interface. Getting that backwards would silently
    # navigate to a selection that matches nothing, which is precisely the #98 trap
    # this module's DEV constant exists for. The log-entries panel is the one panel
    # here in description space, so it gets the other one.
    for panel in (pkt_pass_in, pkt_block_in, pkt_pass_out, pkt_block_out,
                  bw_pass_in, bw_block_in, bw_pass_out, bw_block_out):
        b.field_links(panel, [focus_device("interface")])
    b.field_links(iface_hits, [focus_interface()])
    for panel in (pkt_pass_in, pkt_block_out):
        b.panel_links(panel, [
            to_tab("Interface counters for this selection", "Network", "Interfaces"),
        ])
    # #523 dropped the "Firewall log events (per rule, per action)" links from
    # pkt_block_in and iface_hits. Those events are now two rows further down THIS tab
    # rather than on a separate Log-derived Events tab, so the link would navigate the
    # reader to the page they are already on.

    # Split into sibling leaves (#619): 38 panels in one tab is a tab people
    # scroll past. The existing rows are regrouped and nothing else changes — no row
    # split, merged, renamed or reordered within its group, no panel moved between
    # rows — so this reads as a move.
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
              [iface_hits, pf_states_gauge, pf_states_ts, pf_iface_refs, pf_counters_cleared]),
        b.row("PF State Table (pf-stats)",
              [pf_entries, pf_state_ops]),
        b.row("PF Counters",
              [pf_counters_ts, pf_counters_tbl, pf_limit_tbl]),
        b.row("PF Memory & Timeouts",
              [pf_memory, pf_timeouts]),
        b.row("pfTop API Fallback (sampled top 100)",
              [pftop_states, pftop_talkers, pftop_overflow, pftop_cardinality],
              present="has_pftop"),
    ])
    b.tab("Firewall Rules & NAT", [
        b.row("Firewall Rules (top 20)",
              [fw_rules_count, rules_configured, fw_rule_evals,
               fw_rule_pkts, fw_rule_bytes,
               fw_rule_states, fw_rule_pf, fw_rule_proto],
              present="has_firewall_rules"),
        b.row("GeoIP Alias-Database Freshness",
              [geoip_usages, geoip_addresses, geoip_files, geoip_age, geoip_last_update]),
        b.row("NAT Rule Inventory (details flag)",
              [nat_rules, nat_rules_table],
              present="has_firewall_nat_counts"),
        b.row("26.7 Migration Debt", [migration_rules, migration_outbound]),
        # #523: the filterlog and UPnP/NAT-PMP event rows used to sit on a separate
        # Log-derived Events tab under an Observability domain. They describe the same
        # subject as everything above — what pf did, and what state NAT is in — so they
        # belong here, one scroll from the counters they explain.
        log_events.firewall_row(b),
        log_events.upnp_row(b),
    ])
