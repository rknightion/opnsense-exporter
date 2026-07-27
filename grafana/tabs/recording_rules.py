"""Precomputed operational signals emitted by the bundled recording rules."""

from builder import Builder, sel


def build(b: Builder):
    # Every bundled recording rule preserves opnsense_instance (each either
    # aggregates `by (opnsense_instance, ...)` or is a binary op over metrics that
    # carry it), so the derived series are scoped exactly like the raw ones.
    b.sentinel("has_recording_rules", name_regex="instance:opnsense_.+")
    b.sentinel("has_recording_gateway_loss", metric="instance:opnsense_gateway_loss:ratio")
    b.sentinel("has_recording_ipsec", metric="instance:opnsense_ipsec_tunnels_down:count")
    b.sentinel("has_recording_wireguard", metric="instance:opnsense_wireguard_peers_down:count")
    b.sentinel("has_recording_unbound", metric="instance:opnsense_unbound_queries:rate5m")
    b.sentinel("has_recording_zenarmor", metric="instance:opnsense_zenarmor_block:ratio5m")
    b.sentinel("has_recording_haproxy", metric="instance:opnsense_haproxy_5xx:ratio5m")
    b.sentinel("has_recording_ids", metric="instance:opnsense_ids_alerts:active")
    b.sentinel("has_recording_flow", metric="instance:opnsense_flow_bytes:rate5m")

    memory = b.gauge(
        "Memory Utilization",
        sel("instance:opnsense_system_mem:utilization"),
        unit="percentunit",
        desc="Physical-memory utilization precomputed by the bundled recording rule.",
        w=6,
        h=6,
        mx=1,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "orange", "value": 0.8},
            {"color": "red", "value": 0.9},
        ],
    )
    pf_states = b.gauge(
        "PF State Utilization",
        sel("instance:opnsense_pf_state:utilization"),
        unit="percentunit",
        desc="Current PF state-table occupancy as a fraction of its configured limit.",
        w=6,
        h=6,
        mx=1,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "orange", "value": 0.8},
            {"color": "red", "value": 0.9},
        ],
    )
    pressure_trend = b.ts(
        "Resource Pressure Trend",
        [
            (sel("instance:opnsense_system_mem:utilization"), "Memory"),
            (sel("instance:opnsense_pf_state:utilization"), "PF states"),
        ],
        unit="percentunit",
        desc="Precomputed memory and PF state-table utilization over the selected period.",
        w=12,
        h=6,
    )

    interface_traffic = b.ts(
        "Interface Traffic (5m rate)",
        [
            (
                sel("instance:opnsense_interface_rx_bits:rate5m"),
                "RX {{interface}}",
            ),
            (
                sel("instance:opnsense_interface_tx_bits:rate5m"),
                "TX {{interface}}",
            ),
        ],
        unit="bps",
        desc="Per-interface receive and transmit throughput computed over five minutes.",
        w=16,
        h=8,
    )
    firewall_blocks = b.ts(
        "Firewall Blocks (5m rate)",
        [
            (
                sel("instance:opnsense_firewall_block_packets:rate5m"),
                "{{interface}}",
            )
        ],
        unit="pps",
        desc="IPv4 and IPv6 packets blocked in either direction, grouped by interface.",
        w=8,
        h=8,
    )

    gateway_loss = b.bargauge(
        "Gateway Packet Loss",
        [
            (
                sel("instance:opnsense_gateway_loss:ratio"),
                "{{name}}",
            )
        ],
        unit="percentunit",
        desc="Current packet-loss ratio for each monitored gateway.",
        w=8,
        h=7,
        mx=1,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "orange", "value": 0.05},
            {"color": "red", "value": 0.2},
        ],
    )
    ipsec_down = b.stat(
        "IPsec Tunnels Down",
        sel("instance:opnsense_ipsec_tunnels_down:count"),
        desc="Number of configured IPsec phase-one tunnels currently down.",
        w=8,
        h=7,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "red", "value": 1},
        ],
    )
    wireguard_down = b.stat(
        "WireGuard Peers Down",
        sel("instance:opnsense_wireguard_peers_down:count"),
        desc="Number of monitored WireGuard peers currently down.",
        w=8,
        h=7,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "red", "value": 1},
        ],
    )

    unbound_cache = b.gauge(
        "Unbound Cache Hit Ratio",
        sel("instance:opnsense_unbound_cache:hit_ratio"),
        unit="percentunit",
        desc="Share of Unbound DNS lookups served from cache over five minutes.",
        w=12,
        h=6,
        mx=1,
        thresholds=[
            {"color": "red", "value": None},
            {"color": "orange", "value": 0.8},
            {"color": "green", "value": 0.95},
        ],
    )
    unbound_queries = b.stat(
        "Unbound Query Rate",
        sel("instance:opnsense_unbound_queries:rate5m"),
        unit="reqps",
        desc="DNS queries per second averaged over five minutes.",
        w=12,
        h=6,
        thresholds=[{"color": "blue", "value": None}],
    )
    zenarmor_blocks = b.gauge(
        "Zenarmor Block Ratio",
        sel("instance:opnsense_zenarmor_block:ratio5m"),
        unit="percentunit",
        desc="Share of Zenarmor log events with a block action over five minutes; "
        "informational, not a health threshold.",
        w=8,
        h=6,
        mx=1,
        thresholds=[{"color": "blue", "value": None}],
    )
    haproxy_5xx = b.bargauge(
        "HAProxy 5xx Ratio",
        [(sel("instance:opnsense_haproxy_5xx:ratio5m"), "{{backend}}")],
        unit="percentunit",
        desc="Share of HAProxy requests returning server errors, grouped by backend.",
        w=12,
        h=6,
        mx=1,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "orange", "value": 0.01},
            {"color": "red", "value": 0.05},
        ],
    )
    ids_alerts = b.stat(
        "Active IDS Blocks",
        sel("instance:opnsense_ids_alerts:active"),
        unit="short",
        desc="Blocked IDS alerts retained in the exporter's active recent-alert window.",
        w=8,
        h=6,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "orange", "value": 1},
            {"color": "red", "value": 50},
        ],
    )

    flow_bytes = b.ts(
        "Flow Volume (5m rate)",
        [
            (
                sel("instance:opnsense_flow_bytes:rate5m"),
                "{{interface}} {{direction}}",
            )
        ],
        unit="Bps",
        desc="Per-interface flow throughput by direction, precomputed over five minutes. The rule "
        'pins source="netflow" deliberately: the flow family carries two independent measurements '
        "of the same traffic (Zenarmor and NetFlow) and #346 decision 3 forbids summing them, so "
        "this series is safe to build on without every query having to remember the source filter.",
        w=24,
        h=8,
    )

    b.tab(
        "Recording rules",
        [
            b.row("Resource Pressure", [memory, pf_states, pressure_trend]),
            b.row("Traffic", [interface_traffic, firewall_blocks]),
            b.row(
                "Gateway Health",
                [gateway_loss],
                present="has_recording_gateway_loss",
            ),
            b.row("IPsec Health", [ipsec_down], present="has_recording_ipsec"),
            b.row(
                "WireGuard Health",
                [wireguard_down],
                present="has_recording_wireguard",
            ),
            b.row(
                "Unbound DNS",
                [unbound_cache, unbound_queries],
                present="has_recording_unbound",
            ),
            b.row(
                "Zenarmor",
                [zenarmor_blocks],
                present="has_recording_zenarmor",
            ),
            b.row(
                "HAProxy",
                [haproxy_5xx],
                present="has_recording_haproxy",
            ),
            b.row(
                "IDS / IPS",
                [ids_alerts],
                present="has_recording_ids",
            ),
            b.row(
                "Flow Volume",
                [flow_bytes],
                present="has_recording_flow",
            ),
        ],
        present="has_recording_rules",
    )
