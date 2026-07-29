"""
Interfaces tab — all opnsense_interfaces_* metrics, plus the opnsense_vnstat_*
persistent traffic-accounting family (#215), which is interface-shaped enough
to live here rather than its own tab.

Rows:
  1. Throughput        — rx/tx bytes as bps (rate*8), tx shown as negative-Y
  2. Packets & Errors  — rx/tx packets (pps), multicasts (rate), input/output errors (rate), collisions (rate)
  3. Queues            — send_queue_length, send_queue_max_length, send_queue_drops (rate), input_queue_drops (rate)
  4. Link state & rates— link_state statetimeline + info table (mtu, line_rate, device, type)
  5. Admin State & Identity — admin_up statetimeline + info table (media/VLAN/link type)
  6. LAGG (Link Aggregation) — protocol/hash + active ports/flapping + per-port active/LACP state (#214)
  7. Bridge Membership — member table (#214)
  8. SFP / Optics (DOM) — transceiver identity + Digital Optical Monitoring: temperature,
     voltage, per-lane RX power (dBm AND mW, #456 — corrected/added the two units for the
     same reading; the old single dBm panel had been showing the mW value) /TX bias. DOM
     panels are hardware-dependent — a copper RJ45 SFP reports identity only, never DOM,
     so those panels legitimately show "No data" on such interfaces (absent series, not
     zero) (#214)
  9. Diagnostics — unknown-protocol packet rate, and the attach/statistics-reset
     marker expressed as an age (system uptime minus the marker). The age panel
     explains simultaneous resets across every per-interface counter: it distinguishes
     an interface recreation/explicit stats reset from a real traffic drop or an
     exporter bug. No default alert on either metric (#375).
  10. Vnstat Traffic Accounting — persistent (survives-reboot) day/month/total byte
     counts per interface, sourced from vnstat's own on-disk DB rather than the live
     interface counters above. Opt-in collector (--exporter.enable-vnstat); row is
     gated on a presence sentinel so it disappears entirely when disabled/absent (#215).

Two new label spaces introduced in #214, both DEVICE-space (kernel device name, same
space as the existing device label on admin_up/info) — NOT the description-space
$interface variable:
  - lagg_info/lagg_active_ports/lagg_flapping_total: device = the lagg(4) interface itself
  - lagg_port_active/_collecting/_distributing: device = owning lagg, member = physical port
  - bridge_member: device = owning bridge(4), member = attached interface
  - sfp_*: device = the interface owning the SFP cage

vnstat's "interface" label (#215) is ALSO device-space (vnstat's interface_list returns
kernel device names like vtnet1, not OPNsense's configured description) — filter with
$device, not $interface, same as the LAGG/bridge/SFP rows above.
"""

from builder import Builder, sel, RATE, UPDOWN, LINK_STATE
from uids import focus_interface, to_tab


def build(b: Builder):
    iface = 'interface=~"$interface"'
    # vnstat's interface label is device-space (vtnet1, not a configured description) —
    # same reasoning as the LAGG/bridge/SFP rows above and firewall.py's DEV constant (#98).
    vnstat_iface = 'interface=~"$device"'

    b.sentinel("has_lagg", metric="opnsense_interfaces_lagg_info")
    b.sentinel("has_bridge", metric="opnsense_interfaces_bridge_member")
    b.sentinel("has_sfp", metric="opnsense_interfaces_sfp_info")
    b.sentinel("has_vnstat", metric="opnsense_vnstat_bytes_total")

    # ---- Row 1: Throughput ------------------------------------------------
    rx_bps = b.ts(
        "Interface RX Throughput",
        [(f'rate({sel("opnsense_interfaces_received_bytes_total", iface)}[{RATE}]) * 8',
          "{{interface}} rx")],
        unit="bps", w=12, h=8,
        desc="Bytes received per second × 8 = bits per second.",
    )
    tx_bps = b.ts(
        "Interface TX Throughput",
        [(f'rate({sel("opnsense_interfaces_transmitted_bytes_total", iface)}[{RATE}]) * 8',
          "{{interface}} tx")],
        unit="bps", w=12, h=8,
        desc="Bytes transmitted per second × 8 = bits per second. Shown as negative-Y by convention.",
        overrides=[{
            "matcher": {"id": "byRegexp", "options": ".*"},
            "properties": [{"id": "custom.transform", "value": "negative-Y"}],
        }],
    )

    # ---- Row 2: Packets & Errors ------------------------------------------
    rx_pkts = b.ts(
        "Packets RX",
        [(f'rate({sel("opnsense_interfaces_received_packets_total", iface)}[{RATE}])',
          "{{interface}} rx")],
        unit="pps", w=12, h=8,
        desc="Packets received per second.",
    )
    tx_pkts = b.ts(
        "Packets TX",
        [(f'rate({sel("opnsense_interfaces_transmitted_packets_total", iface)}[{RATE}])',
          "{{interface}} tx")],
        unit="pps", w=12, h=8,
        desc="Packets transmitted per second.",
    )
    multicasts = b.ts(
        "Multicast Traffic",
        [
            (f'rate({sel("opnsense_interfaces_received_multicasts_total", iface)}[{RATE}])',
             "{{interface}} rx mcast"),
            (f'rate({sel("opnsense_interfaces_transmitted_multicasts_total", iface)}[{RATE}])',
             "{{interface}} tx mcast"),
        ],
        unit="pps", w=12, h=8,
        desc="Multicast packets per second.",
    )
    errors = b.ts(
        "Interface Errors",
        [
            (f'rate({sel("opnsense_interfaces_input_errors_total", iface)}[{RATE}])',
             "{{interface}} input errors"),
            (f'rate({sel("opnsense_interfaces_output_errors_total", iface)}[{RATE}])',
             "{{interface}} output errors"),
        ],
        unit="ops", w=8, h=8,
        desc="Input and output errors per second.",
    )
    collisions = b.ts(
        "Collisions",
        [(f'rate({sel("opnsense_interfaces_collisions_total", iface)}[{RATE}])',
          "{{interface}}")],
        unit="ops", w=4, h=8,
        desc="Collision events per second.",
    )

    # ---- Row 3: Queues ----------------------------------------------------
    queue_len = b.ts(
        "Send Queue Length",
        [
            (sel("opnsense_interfaces_send_queue_length", iface),
             "{{interface}} current"),
            (sel("opnsense_interfaces_send_queue_max_length", iface),
             "{{interface}} max"),
        ],
        unit="short", w=12, h=8,
        desc="Current and maximum send queue length (instantaneous gauges).",
    )
    queue_drops = b.ts(
        "Queue Drops",
        [
            (f'rate({sel("opnsense_interfaces_send_queue_drops_total", iface)}[{RATE}])',
             "{{interface}} send queue drops"),
            (f'rate({sel("opnsense_interfaces_input_queue_drops_total", iface)}[{RATE}])',
             "{{interface}} input queue drops"),
        ],
        unit="ops", w=12, h=8,
        desc="Send-queue and input-queue drops per second.",
    )

    # ---- Row 4: Link state & rates ----------------------------------------
    link_state = b.statetimeline(
        "Link State",
        [(sel("opnsense_interfaces_link_state", iface), "{{interface}}")],
        LINK_STATE, w=24, h=8,
        desc="1 = Up (green), 0 = Down (red), 2 = Unknown (yellow). Unknown is "
             "reported by the kernel for carrier-less pseudo-devices (PPPoE, "
             "tun/tailscale) and is not a fault - alert on Down (0), not not-Up.",
    )
    iface_info = b.table(
        "Interface Info (MTU / Line Rate / Device / Type)",
        [
            sel("opnsense_interfaces_mtu_bytes", iface),
            sel("opnsense_interfaces_line_rate_bits", iface),
        ],
        w=24, h=10,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "interface": "Interface",
            "device": "Device",
            "type": "Type",
            "Value #A": "MTU",
            "Value #B": "Line Rate (bps)",
        },
        unit_overrides={
            "Value #A": "bytes",
            "Value #B": "bps",
        },
        sort_by="Interface",
        desc="Static per-interface properties: MTU, negotiated line rate, OS device name, and type.",
    )

    # ---- Row 5: Admin state & identity -------------------------------------
    admin_state = b.statetimeline(
        "Admin Status",
        [(sel("opnsense_interfaces_admin_up", iface), "{{interface}} ({{device}})")],
        UPDOWN, w=24, h=6,
        desc="opnsense_interfaces_admin_up: 1 = administratively up (ifconfig UP flag), "
             "0 = admin down. Admin up + Link State down = no carrier.",
    )
    iface_identity = b.table(
        "Interface Identity (media / VLAN / link type)",
        [sel("opnsense_interfaces_info", iface)],
        w=24, h=10,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "interface": "Interface",
            "device": "Device",
            "identifier": "Identifier",
            "media": "Media",
            "link_type": "Link Type",
            "vlan_tag": "VLAN Tag",
            "vlan_parent": "VLAN Parent",
            "physical": "Physical",
        },
        sort_by="Interface",
        desc="opnsense_interfaces_info: interface identity from the overview API "
             "(media/duplex, link type, VLAN topology).",
    )

    # ---- Row 6: LAGG (link aggregation) ------------------------------------
    # device/member here are the DEVICE-space kernel names (lagg0, ix0, ...) —
    # the same space as admin_up/info's device label, NOT $interface (#98).
    lagg_info = b.table(
        "LAGG Protocol / Hash",
        [sel("opnsense_interfaces_lagg_info")],
        w=12, h=8,
        excludes=["Value", "__name__", "job", "instance"],
        renames={"device": "LAGG Device", "protocol": "Protocol", "hash": "Hash"},
        sort_by="LAGG Device",
        desc="opnsense_interfaces_lagg_info: laggproto/lagghash configuration for each "
             "LAGG interface. Only present for interfaces that are themselves a lagg(4) device.",
    )
    lagg_active_ports = b.ts(
        "LAGG Active Ports",
        [(sel("opnsense_interfaces_lagg_active_ports"), "{{device}}")],
        unit="short", w=6, h=8,
        desc="Number of member ports currently active/carrying traffic. Only emitted when "
             "the box reports a lagg statistics block for the device.",
    )
    lagg_flapping = b.ts(
        "LAGG Port Flapping",
        [(f'rate({sel("opnsense_interfaces_lagg_flapping_total")}[{RATE}])', "{{device}}")],
        unit="ops", w=6, h=8,
        desc="Rate of LAGG active-port membership change (flap) events — a healthy LAGG "
             "should sit at 0; sustained flapping indicates a failing member link.",
    )
    lagg_port_state = b.table(
        "LAGG Member Port State",
        [
            sel("opnsense_interfaces_lagg_port_active"),
            sel("opnsense_interfaces_lagg_port_collecting"),
            sel("opnsense_interfaces_lagg_port_distributing"),
        ],
        w=24, h=10,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "device": "LAGG Device", "member": "Member Port",
            "Value #A": "Active", "Value #B": "Collecting (LACP)", "Value #C": "Distributing (LACP)",
        },
        sort_by="LAGG Device",
        desc="Per-member-port active/LACP negotiation state. Collecting/Distributing are "
             "LACP-only — a failover/loadbalance LAGG's member never reports them (blank, "
             "not 0). A LAGG that dropped from N active ports to fewer keeps passing traffic "
             "with no other metric moving — watch this table plus LAGG Active Ports.",
    )

    # ---- Row 7: Bridge membership ------------------------------------------
    bridge_members = b.table(
        "Bridge Membership",
        [sel("opnsense_interfaces_bridge_member")],
        w=24, h=8,
        excludes=["Value", "__name__", "job", "instance"],
        renames={"device": "Bridge Device", "member": "Member Interface"},
        sort_by="Bridge Device",
        desc="opnsense_interfaces_bridge_member: which interfaces are attached to each "
             "bridge(4) interface.",
    )

    # ---- Row 8: SFP / Optics (DOM) ------------------------------------------
    sfp_info = b.table(
        "SFP Transceiver Identity",
        [sel("opnsense_interfaces_sfp_info")],
        w=24, h=8,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "device": "Device", "vendor": "Vendor",
            "part_number": "Part Number", "serial_number": "Serial Number",
        },
        sort_by="Device",
        desc="opnsense_interfaces_sfp_info: transceiver identity for any plugged SFP/SFP+ "
             "module, optical or copper. Digital Optical Monitoring (DOM) panels below only "
             "populate for transceivers that support DOM — a copper RJ45 SFP shows identity "
             "here but no series below (absent, not zero).",
    )
    sfp_temperature = b.ts(
        "SFP Temperature",
        [(sel("opnsense_interfaces_sfp_temperature_celsius"), "{{device}}")],
        # Industrial-temp modules (-40 to +85) legitimately read sub-zero in an unheated
        # cabinet; same clipping as the dBm panel, narrower blast radius (#512).
        unit="celsius", min0=False, w=12, h=8,
        desc="Digital Optical Monitoring module temperature. Only present for DOM-capable "
             "transceivers — a rising trend or an out-of-spec reading is an early warning "
             "sign for a dying optic.",
    )
    sfp_voltage = b.ts(
        "SFP Supply Voltage",
        [(sel("opnsense_interfaces_sfp_voltage_volts"), "{{device}}")],
        unit="volt", w=12, h=8,
        desc="Digital Optical Monitoring module supply voltage. Only present for DOM-capable "
             "transceivers.",
    )
    sfp_rx_power_dbm = b.ts(
        "SFP Lane RX Power (dBm)",
        [(sel("opnsense_interfaces_sfp_lane_rx_power_dbm"), "{{device}} lane {{lane}}")],
        # dBm optical RX power is essentially always negative (-3 to -20 typical), so the
        # min0 default drew an empty plot with the real readings below the axis (#512).
        unit="dBm", min0=False, w=12, h=8,
        desc="opnsense_interfaces_sfp_lane_rx_power_dbm: per-lane received optical power, "
             "logarithmic (dBm) scale. Only present for DOM-capable transceivers; a falling "
             "trend indicates a degrading link or fiber. See also the milliwatts panel for "
             "the linear reading of the same measurement. NOTE (#456): before this release "
             "this series erroneously published the milliwatt reading under this dBm-named "
             "metric — expect a one-time step change to the correct (and much "
             "smaller-magnitude, often negative) dBm figure after upgrading.",
    )
    sfp_rx_power_mw = b.ts(
        "SFP Lane RX Power (mW)",
        [(sel("opnsense_interfaces_sfp_lane_rx_power_milliwatts"), "{{device}} lane {{lane}}")],
        unit="mwatt", w=12, h=8,
        desc="opnsense_interfaces_sfp_lane_rx_power_milliwatts: per-lane received optical "
             "power, linear (mW) scale — added in #456 alongside the corrected dBm series. "
             "Only present for DOM-capable transceivers.",
    )
    sfp_tx_bias = b.ts(
        "SFP Lane TX Bias Current",
        [(sel("opnsense_interfaces_sfp_lane_tx_bias_milliamps"), "{{device}} lane {{lane}}")],
        unit="mA", w=12, h=8,
        desc="Per-lane laser bias current. Only present for DOM-capable transceivers; a "
             "rising trend at constant output power is a classic laser end-of-life signal.",
    )

    # ---- Row 9: Diagnostics (#375) ------------------------------------------
    # Both panels are diagnostic, not alerting: no default alert rule for either
    # metric (there is no live non-zero baseline yet to threshold against).
    unknown_protocol_packets = b.ts(
        "Unknown Protocol Packets",
        [(f'rate({sel("opnsense_interfaces_unknown_protocol_packets_total", iface)}[{RATE}])',
          "{{interface}}")],
        unit="pps", w=12, h=8,
        desc="opnsense_interfaces_unknown_protocol_packets_total: rate of packets delivered "
             "to this interface that the network stack could not classify (kernel "
             "\"packets for unknown protocol\" counter). Sustained non-zero traffic here is "
             "worth investigating - it never reaches a normal protocol handler.",
    )
    attach_or_reset_age = b.ts(
        "Interface Attach / Stats Reset Age",
        [(f'{sel("opnsense_system_uptime_seconds")} - on(opnsense_instance) group_right() '
          f'{sel("opnsense_interfaces_attach_or_statistics_reset_uptime_seconds", iface)}',
          "{{interface}} ({{device}})")],
        unit="s", w=12, h=8,
        desc="opnsense_system_uptime_seconds - opnsense_interfaces_attach_or_statistics_reset_uptime_seconds: "
             "how long ago this interface was attached OR had its statistics explicitly reset - the "
             "kernel marker cannot distinguish the two. Only emitted when the box reports the marker. "
             "A sudden drop toward 0 across every counter on one interface, paired with this age "
             "resetting too, means the interface was recreated or its stats were reset - not a real "
             "traffic drop or an exporter bug.",
    )

    # ---- Row 10: Vnstat traffic accounting (#215) ---------------------------
    # bytes_total is a genuine counter (cumulative since vnstat's DB was created,
    # resets only on `vnstat --resetdb`), but it is intentionally NOT rate()'d here:
    # the point of vnstat's figures is the accumulated total itself (ISP data-cap
    # tracking), not a throughput trend — the Throughput row above already covers
    # live bps from the interface counters. current_day/current_month are gauges
    # (they reset daily/monthly in vnstat's own bookkeeping) and are shown raw for
    # the same reason: operators read these as "how much so far", not a rate.
    # #464: renamed from total_bytes -> bytes_total (Prometheus `_<unit>_total`
    # convention). "total" always meant "cumulative since DB creation", not
    # "rx+tx combined" — direction is still its own label, untouched by this rename.
    vnstat_total = b.ts(
        "Vnstat Total Traffic (Since DB Creation)",
        [
            (sel("opnsense_vnstat_bytes_total", f'{vnstat_iface},direction="rx"'), "{{interface}} rx"),
            (sel("opnsense_vnstat_bytes_total", f'{vnstat_iface},direction="tx"'), "{{interface}} tx"),
        ],
        unit="bytes", w=24, h=8,
        desc="opnsense_vnstat_bytes_total: cumulative bytes recorded by vnstat since this "
             "interface's persistent database was created. Survives reboots and exporter "
             "restarts — a drop to 0 means an admin ran `vnstat --resetdb`, not data loss.",
    )
    vnstat_day = b.ts(
        "Vnstat Current Day Traffic",
        [
            (sel("opnsense_vnstat_current_day_bytes", f'{vnstat_iface},direction="rx"'), "{{interface}} rx"),
            (sel("opnsense_vnstat_current_day_bytes", f'{vnstat_iface},direction="tx"'), "{{interface}} tx"),
        ],
        unit="bytes", w=12, h=8,
        desc="opnsense_vnstat_current_day_bytes: bytes recorded by vnstat so far today. "
             "Resets to 0 at local midnight in vnstat's own bookkeeping (gauge, not counter).",
    )
    vnstat_month = b.ts(
        "Vnstat Current Month Traffic",
        [
            (sel("opnsense_vnstat_current_month_bytes", f'{vnstat_iface},direction="rx"'), "{{interface}} rx"),
            (sel("opnsense_vnstat_current_month_bytes", f'{vnstat_iface},direction="tx"'), "{{interface}} tx"),
        ],
        unit="bytes", w=12, h=8,
        desc="opnsense_vnstat_current_month_bytes: bytes recorded by vnstat so far this "
             "month — the figure to alert on against an ISP data cap. Resets monthly "
             "(gauge, not counter).",
    )

    # ---- drilldowns (#419) ------------------------------------------------
    # These four panels are per-description-interface (`$interface`: LAN, IOT), so a
    # clicked series can re-scope the whole dashboard to that one interface. The
    # cross-tab links answer the two questions this tab cannot: what the firewall did
    # with that traffic, and what the flow records say it was.
    for panel in (rx_bps, tx_bps, errors, link_state):
        b.field_links(panel, [focus_interface()])
    for panel in (rx_bps, tx_bps):
        b.panel_links(panel, [
            to_tab("Firewall traffic for this selection", "Security", "Firewall & PF"),
            to_tab("Flow volume for this selection", "Observability", "Flow Volume"),
        ])
    b.panel_links(errors, [
        to_tab("Interface reset / attach events", "Observability", "Log-derived Events"),
    ])
    b.panel_links(link_state, [
        to_tab("Gateway state over the same window", "Network", "Gateways & WAN"),
    ])

    b.tab("Interfaces", [
        b.row("Throughput", [rx_bps, tx_bps]),
        b.row("Packets & Errors", [rx_pkts, tx_pkts, multicasts, errors, collisions]),
        b.row("Queues", [queue_len, queue_drops]),
        b.row("Link State & Rates", [link_state, iface_info]),
        b.row("Admin State & Identity", [admin_state, iface_identity]),
        b.row("LAGG (Link Aggregation)",
              [lagg_info, lagg_active_ports, lagg_flapping, lagg_port_state],
              present="has_lagg"),
        b.row("Bridge Membership", [bridge_members], present="has_bridge"),
        b.row("SFP / Optics (DOM)",
              [sfp_info, sfp_temperature, sfp_voltage, sfp_rx_power_dbm, sfp_rx_power_mw, sfp_tx_bias],
              present="has_sfp"),
        b.row("Diagnostics", [unknown_protocol_packets, attach_or_reset_age]),
        b.row("Vnstat Traffic Accounting", [vnstat_day, vnstat_month, vnstat_total],
              present="has_vnstat"),
    ])
