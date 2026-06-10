"""
Interfaces tab — all 16 opnsense_interfaces_* metrics.

Rows:
  1. Throughput        — rx/tx bytes as bps (rate*8), tx shown as negative-Y
  2. Packets & Errors  — rx/tx packets (pps), multicasts (rate), input/output errors (rate), collisions (rate)
  3. Queues            — send_queue_length, send_queue_max_length, send_queue_drops (rate), input_queue_drops (rate)
  4. Link state & rates— link_state statetimeline + info table (mtu, line_rate, device, type)
"""

from builder import Builder, sel, RATE, UPDOWN


def build(b: Builder):
    iface = 'interface=~"$interface"'

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
        unit="short", w=8, h=8,
        desc="Input and output errors per second.",
    )
    collisions = b.ts(
        "Collisions",
        [(f'rate({sel("opnsense_interfaces_collisions_total", iface)}[{RATE}])',
          "{{interface}}")],
        unit="short", w=4, h=8,
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
        unit="short", w=12, h=8,
        desc="Send-queue and input-queue drops per second.",
    )

    # ---- Row 4: Link state & rates ----------------------------------------
    link_state = b.statetimeline(
        "Link State",
        [(sel("opnsense_interfaces_link_state", iface), "{{interface}}")],
        UPDOWN, w=24, h=8,
        desc="1 = Up (green), 0 = Down (red).",
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
            "opnsense_interfaces_mtu_bytes": "MTU (bytes)",
            "opnsense_interfaces_line_rate_bits": "Line Rate (bps)",
        },
        unit_overrides={
            "MTU (bytes)": "bytes",
            "Line Rate (bps)": "bps",
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

    b.tab("Interfaces", [
        b.row("Throughput", [rx_bps, tx_bps]),
        b.row("Packets & Errors", [rx_pkts, tx_pkts, multicasts, errors, collisions]),
        b.row("Queues", [queue_len, queue_drops]),
        b.row("Link State & Rates", [link_state, iface_info]),
        b.row("Admin State & Identity", [admin_state, iface_identity]),
    ])
