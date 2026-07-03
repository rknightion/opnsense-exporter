"""
NetFlow tab — all 7 opnsense_netflow_* metrics.

Tab is gated on has_netflow (sentinel: label_values(opnsense_netflow_active, __name__)).

Rows:
  1. NetFlow Status     — enabled stat, local_collection_enabled stat, active stat,
                          collectors_count stat
  2. NetFlow Cache      — cache_packets_total rate ts, cache_source_ip_addresses ts,
                          cache_destination_ip_addresses ts

Coverage:
  opnsense_netflow_enabled
  opnsense_netflow_local_collection_enabled
  opnsense_netflow_active
  opnsense_netflow_collectors_count
  opnsense_netflow_cache_packets_total
  opnsense_netflow_cache_source_ip_addresses
  opnsense_netflow_cache_destination_ip_addresses
"""

from builder import Builder, sel, RATE, ENABLED


# Custom mapping for netflow_active: 0=Inactive/red, 1=Active/green
_ACTIVE = {"0": ("Inactive", "red"), "1": ("Active", "green")}


def build(b: Builder):
    # ---- Sentinel --------------------------------------------------------
    b.sentinel("has_netflow",
               "label_values(opnsense_netflow_active, __name__)")

    # ======================================================================
    # Row 1 – NetFlow Status
    # ======================================================================
    nf_enabled = b.stat(
        "NetFlow Capture",
        sel("opnsense_netflow_enabled"),
        unit="short",
        w=6, h=4,
        mappings=ENABLED,
        color_mode="background",
        graph="none",
        instant=True,
        desc="Whether NetFlow packet capture is enabled (1=Enabled, 0=Disabled).",
    )
    nf_local = b.stat(
        "Local Collection",
        sel("opnsense_netflow_local_collection_enabled"),
        unit="short",
        w=6, h=4,
        mappings=ENABLED,
        color_mode="background",
        graph="none",
        instant=True,
        desc="Whether local NetFlow collection is enabled (1=Enabled, 0=Disabled).",
    )
    nf_active = b.stat(
        "NetFlow Service",
        sel("opnsense_netflow_active"),
        unit="short",
        w=6, h=4,
        mappings=_ACTIVE,
        color_mode="background",
        graph="none",
        instant=True,
        desc="Whether the NetFlow service is currently active (1=Active, 0=Inactive).",
    )
    nf_collectors = b.stat(
        "Collectors",
        sel("opnsense_netflow_collectors_count"),
        unit="short",
        w=6, h=4,
        graph="none",
        instant=True,
        desc="Number of active NetFlow collector destinations configured.",
    )

    # ======================================================================
    # Row 2 – NetFlow Cache
    # ======================================================================
    # NetFlow cache metrics label `interface` with the kernel DEVICE name (pppoe0,
    # ixl0_vlan25), not the configured description — so filter on $device, not the
    # description-space $interface variable (#98).
    iface = 'interface=~"$device"'
    nf_packets_ts = b.ts(
        "Cache Packets (rate)",
        [(f'rate({sel("opnsense_netflow_cache_packets_total", iface)}[{RATE}])',
          "{{interface}}")],
        unit="pps",
        w=8, h=8,
        desc="NetFlow cache packets observed per second by interface.",
    )
    nf_src_ips_ts = b.ts(
        "Unique Source IPs in Cache",
        [(sel("opnsense_netflow_cache_source_ip_addresses", iface),
          "{{interface}}")],
        unit="short",
        w=8, h=8,
        desc="Number of unique source IP addresses currently tracked in the NetFlow cache by interface.",
    )
    nf_dst_ips_ts = b.ts(
        "Unique Destination IPs in Cache",
        [(sel("opnsense_netflow_cache_destination_ip_addresses", iface),
          "{{interface}}")],
        unit="short",
        w=8, h=8,
        desc="Number of unique destination IP addresses currently tracked in the NetFlow cache by interface.",
    )

    # ======================================================================
    # Assemble tab (gated on has_netflow)
    # ======================================================================
    b.tab("NetFlow", [
        b.row("NetFlow Status", [nf_enabled, nf_local, nf_active, nf_collectors]),
        b.row("NetFlow Cache", [nf_packets_ts, nf_src_ips_ts, nf_dst_ips_ts]),
    ], present="has_netflow")
