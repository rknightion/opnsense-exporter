"""Precomputed operational signals emitted by the bundled recording rules."""

from builder import Builder, sel


def build(b: Builder):
    b.sentinel(
        "has_recording_rules",
        'label_values({__name__=~"instance:opnsense_.+"}, __name__)',
    )
    b.sentinel(
        "has_recording_gateway_loss",
        "label_values(instance:opnsense_gateway_loss:ratio, __name__)",
    )
    b.sentinel(
        "has_recording_ipsec",
        "label_values(instance:opnsense_ipsec_tunnels_down:count, __name__)",
    )
    b.sentinel(
        "has_recording_wireguard",
        "label_values(instance:opnsense_wireguard_peers_down:count, __name__)",
    )
    b.sentinel(
        "has_recording_unbound",
        "label_values(instance:opnsense_unbound_queries:rate5m, __name__)",
    )
    b.sentinel(
        "has_recording_zenarmor",
        "label_values(instance:opnsense_zenarmor_block:ratio5m, __name__)",
    )
    b.sentinel(
        "has_recording_haproxy",
        "label_values(instance:opnsense_haproxy_5xx:ratio5m, __name__)",
    )
    b.sentinel(
        "has_recording_ids",
        "label_values(instance:opnsense_ids_alerts:active, __name__)",
    )

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
        ],
        present="has_recording_rules",
    )
