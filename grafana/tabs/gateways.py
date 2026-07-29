"""
Gateways & WAN tab — all 17 opnsense_gateways_* metrics.

Rows:
  1. Status & Alarm Events — current state plus dpinger alarm transition rate
  2. Latency            — RTT timeseries + RTT thresholds table
  3. Packet Loss        — loss_percentage ts + loss thresholds table
  4. Gateway Inventory  — gateways_info table + monitor_info table + flags table
  5. Probe Config       — probe interval/period/timeout table + priority table
"""

from builder import Builder, RATE, sel, GW_STATUS
from uids import to_tab


def build(b: Builder):
    # ---- Row 1: Status & Latency ------------------------------------------
    gw_status = b.statetimeline(
        "Gateway Status",
        [(sel("opnsense_gateways_status"), "{{name}} ({{address}})")],
        GW_STATUS, w=12, h=8,
        desc="0=Offline, 1=Online, 2=Unknown, 3=Pending, 4=Packetloss, 5=Latency, 6=Offline (forced). Label default_gateway is included in series.",
    )
    gateway_alarm_events = sel(
        "opnsense_log_events_gateway_total", 'event=~"alarm_started|alarm_cleared"'
    )
    gateway_alarms = b.ts(
        "Gateway Alarm Events",
        [(f'sum by (opnsense_instance, gateway, event) '
          f'(rate({gateway_alarm_events}[{RATE}]))',
          "{{gateway}} {{event}}")],
        unit="ops", w=12, h=8,
        desc="Rate of dpinger gateway alarm transitions. alarm_started marks none -> down; alarm_cleared marks down -> none. "
             "This complements the current Gateway Status timeline; it is absent until syslog shipping sees a matching dpinger line.",
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

    # ---- drilldowns (#419) ------------------------------------------------
    # A gateway name is not a dashboard variable, so there is no field link to make
    # here: the useful jump is sideways, to the place that says WHY a gateway changed
    # state. It carries the instance and window, which is the whole point — a raw
    # syslog stream read at the wrong window is worse than no link.
    #
    # #523 removed the two "Gateway alarm events (log-derived)" links. They pointed at
    # the retired Log-derived Events tab for a panel this tab has carried itself since
    # the dpinger counter landed — Gateway Alarm Events is in row one, beside Gateway
    # Status. A link to a panel already on screen is navigation that costs a click and
    # returns the reader to where they started.
    b.panel_links(gw_status, [
        to_tab("Raw syslog for this window", "Services", "Syslog", loki=True),
    ])
    b.panel_links(rtt, [
        to_tab("Interface counters for this window", "Network", "Interfaces"),
    ])

    b.tab("Gateways & WAN", [
        b.row("Status & Alarm Events", [gw_status, gateway_alarms]),
        b.row("Latency", [rtt, rtt_thresholds]),
        b.row("Packet Loss", [loss, loss_thresholds]),
        b.row("Gateway Inventory", [gw_info, monitor_info, flags]),
        b.row("Probe Config", [probe_cfg]),
    ])
