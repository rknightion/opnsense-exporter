"""
Gateways & WAN tab — all 17 opnsense_gateways_* metrics.

Rows:
  1. Status & Latency   — status statetimeline + RTT timeseries + RTT thresholds table
  2. Packet Loss        — loss_percentage ts + loss thresholds table
  3. Gateway Inventory  — gateways_info table + monitor_info table + flags table
  4. Probe Config       — probe interval/period/timeout table + priority table
"""

from builder import Builder, sel, GW_STATUS


def build(b: Builder):
    # ---- Row 1: Status & Latency ------------------------------------------
    gw_status = b.statetimeline(
        "Gateway Status",
        [(sel("opnsense_gateways_status"), "{{name}} ({{address}})")],
        GW_STATUS, w=24, h=8,
        desc="0=Offline, 1=Online, 2=Unknown, 3=Pending, 4=Packetloss, 5=Latency, 6=Offline (forced). Label default_gateway is included in series.",
    )
    rtt = b.ts(
        "Gateway RTT",
        [
            (sel("opnsense_gateways_rtt_milliseconds"), "{{name}} RTT"),
            (sel("opnsense_gateways_rttd_milliseconds"), "{{name}} stddev"),
        ],
        unit="ms", w=12, h=8,
        desc="Average RTT and RTT standard deviation (RTTd) in milliseconds.",
    )
    rtt_thresholds = b.table(
        "RTT Thresholds",
        [
            sel("opnsense_gateways_rtt_low_milliseconds"),
            sel("opnsense_gateways_rtt_high_milliseconds"),
        ],
        w=12, h=8,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "name": "Gateway",
            "address": "Address",
            "Value #A": "RTT Low (ms)",
            "Value #B": "RTT High (ms)",
        },
        unit_overrides={
            "Value #A": "ms",
            "Value #B": "ms",
        },
        sort_by="Gateway",
        desc="Configured low/high RTT alarm thresholds per gateway.",
    )

    # ---- Row 2: Packet Loss -----------------------------------------------
    loss = b.ts(
        "Packet Loss %",
        [(sel("opnsense_gateways_loss_percentage"), "{{name}} loss")],
        unit="percent", w=12, h=8,
        desc="Current packet loss percentage per gateway.",
    )
    loss_thresholds = b.table(
        "Loss Thresholds",
        [
            sel("opnsense_gateways_loss_low_percentage"),
            sel("opnsense_gateways_loss_high_percentage"),
        ],
        w=12, h=8,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "name": "Gateway",
            "address": "Address",
            "Value #A": "Loss Low (%)",
            "Value #B": "Loss High (%)",
        },
        unit_overrides={
            "Value #A": "percent",
            "Value #B": "percent",
        },
        sort_by="Gateway",
        desc="Configured low/high packet-loss alarm thresholds per gateway.",
    )

    # ---- Row 3: Gateway Inventory -----------------------------------------
    gw_info = b.table(
        "Gateway Info",
        [sel("opnsense_gateways_info")],
        w=24, h=10,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "name": "Name",
            "description": "Description",
            "device": "Device",
            "protocol": "Protocol",
            "enabled": "Enabled",
            "weight": "Weight",
            "interface": "Interface",
            "upstream": "Upstream",
        },
        sort_by="Name",
        desc="Static gateway configuration (info metric — value is always 1).",
    )
    monitor_info = b.table(
        "Gateway Monitor Info",
        [sel("opnsense_gateways_monitor_info")],
        w=24, h=8,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "name": "Name",
            "enabled": "Enabled",
            "no_route": "No Route",
            "address": "Monitor Address",
        },
        sort_by="Name",
        desc="Gateway monitoring configuration (info metric — value is always 1).",
    )
    flags = b.table(
        "Gateway Flags (force_down / virtual / dynamic / priority)",
        [
            sel("opnsense_gateways_force_down"),
            sel("opnsense_gateways_virtual"),
            sel("opnsense_gateways_dynamic"),
            sel("opnsense_gateways_priority"),
        ],
        w=24, h=10,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "name": "Name",
            "address": "Address",
            "Value #A": "Force Down",
            "Value #B": "Virtual",
            "Value #C": "Dynamic",
            "Value #D": "Priority",
        },
        sort_by="Name",
        desc="Per-gateway boolean flags and routing priority (lower value = higher priority).",
    )

    # ---- Row 4: Probe Config ----------------------------------------------
    probe_cfg = b.table(
        "Probe Configuration",
        [
            sel("opnsense_gateways_probe_interval_seconds"),
            sel("opnsense_gateways_probe_period_seconds"),
            sel("opnsense_gateways_probe_timeout_seconds"),
        ],
        w=24, h=8,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "name": "Gateway",
            "address": "Address",
            "Value #A": "Interval (s)",
            "Value #B": "Period (s)",
            "Value #C": "Timeout (s)",
        },
        unit_overrides={
            "Value #A": "s",
            "Value #B": "s",
            "Value #C": "s",
        },
        sort_by="Gateway",
        desc="ICMP probe timing configuration per gateway.",
    )

    b.tab("Gateways & WAN", [
        b.row("Status & Latency", [gw_status, rtt, rtt_thresholds]),
        b.row("Packet Loss", [loss, loss_thresholds]),
        b.row("Gateway Inventory", [gw_info, monitor_info, flags]),
        b.row("Probe Config", [probe_cfg]),
    ])
