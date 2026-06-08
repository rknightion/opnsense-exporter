"""
DHCP tab — covers all dnsmasq, Kea DHCPv4/v6, and ISC DHCPv4 metrics.

The host may run at most one DHCP backend at a time; each row is gated on a
presence sentinel so unused backends stay hidden. Detail lease tables live in
separate sub-rows gated on their own sentinels (they are opt-in via
--exporter.enable-*-details flags and high-cardinality).

Rows:
  Dnsmasq:
    1. dnsmasq summary       — gated has_dnsmasq: leases_total/*_reserved_total/*_dynamic_total
                               (stats RAW), leases_by_interface (bargauge), service_running (stat)
    2. dnsmasq lease details — gated has_dnsmasq_details: lease_info table
  Kea:
    3. Kea summary           — gated has_kea: DHCPv4 + DHCPv6 totals/reserved/dynamic + by_iface
    4. Kea DHCPv4 details    — gated has_kea4_details: kea_dhcp4_lease_info table
    5. Kea DHCPv6 details    — gated has_kea6_details: kea_dhcp6_lease_info table
  ISC DHCPv4:
    6. ISC DHCPv4 summary    — gated has_dhcpv4_isc: leases totals + by_iface
    7. ISC DHCPv4 details    — gated has_dhcpv4_details: dhcpv4_lease_info table
"""

from builder import Builder, sel, RUNSTOP


def build(b: Builder):
    # ---- Sentinels ---------------------------------------------------------
    b.sentinel("has_dnsmasq",
               "query_result(opnsense_dnsmasq_leases_total > 0)")
    b.sentinel("has_dnsmasq_details",
               "label_values(opnsense_dnsmasq_lease_info, __name__)")
    b.sentinel("has_kea",
               "query_result((opnsense_kea_dhcp4_leases_total + opnsense_kea_dhcp6_leases_total) > 0)")
    b.sentinel("has_kea4_details",
               "label_values(opnsense_kea_dhcp4_lease_info, __name__)")
    b.sentinel("has_kea6_details",
               "label_values(opnsense_kea_dhcp6_lease_info, __name__)")
    b.sentinel("has_dhcpv4_isc",
               "query_result(opnsense_dhcpv4_leases_total > 0)")
    b.sentinel("has_dhcpv4_details",
               "label_values(opnsense_dhcpv4_lease_info, __name__)")

    # ================================================================
    # DNSMASQ — Row 1: summary
    # ================================================================
    dnsmasq_total = b.stat(
        "Dnsmasq Leases",
        sel("opnsense_dnsmasq_leases_total"),
        unit="short", w=4, h=4,
        desc="Total DHCP leases currently tracked by dnsmasq (instantaneous count).",
    )
    dnsmasq_reserved = b.stat(
        "Reserved (Static)",
        sel("opnsense_dnsmasq_leases_reserved_total"),
        unit="short", w=4, h=4,
        desc="Static/reserved DHCP leases (instantaneous count).",
    )
    dnsmasq_dynamic = b.stat(
        "Dynamic",
        sel("opnsense_dnsmasq_leases_dynamic_total"),
        unit="short", w=4, h=4,
        desc="Dynamic DHCP leases (instantaneous count).",
    )
    dnsmasq_by_iface = b.bargauge(
        "Leases by Interface",
        [(sel("opnsense_dnsmasq_leases_by_interface"), "{{interface}}")],
        unit="short", w=8, h=4, orient="horizontal",
        desc="Number of dnsmasq leases active on each interface.",
    )
    dnsmasq_svc = b.stat(
        "Dnsmasq Service",
        sel("opnsense_dnsmasq_service_running"),
        mappings=RUNSTOP, color_mode="background",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        w=4, h=4,
        desc="1 = running, 0 = stopped/disabled.",
    )

    # ================================================================
    # DNSMASQ — Row 2: lease detail table (opt-in, high-cardinality)
    # ================================================================
    dnsmasq_lease_table = b.table(
        "Dnsmasq Lease Details",
        [sel("opnsense_dnsmasq_lease_info")],
        w=24, h=10,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "address": "IP Address",
            "hostname": "Hostname",
            "hwaddr": "MAC Address",
            "interface": "Interface",
        },
        unit_overrides={"Value": "dateTimeAsIso"},
        sort_by="Interface",
        desc=(
            "Per-lease detail. Value = expire timestamp (shown as ISO date). "
            "Only emitted when --exporter.enable-dnsmasq-details is set. "
            "Filter by interface with the $interface variable."
        ),
    )

    # ================================================================
    # KEA — Row 3: summary (DHCPv4 + DHCPv6)
    # ================================================================
    kea4_total = b.stat(
        "Kea DHCPv4 Leases",
        sel("opnsense_kea_dhcp4_leases_total"),
        unit="short", w=4, h=4,
        desc="Total Kea DHCPv4 leases (instantaneous count).",
    )
    kea4_reserved = b.stat(
        "Kea DHCPv4 Reserved",
        sel("opnsense_kea_dhcp4_leases_reserved_total"),
        unit="short", w=4, h=4,
        desc="Reserved (static) Kea DHCPv4 leases.",
    )
    kea4_dynamic = b.stat(
        "Kea DHCPv4 Dynamic",
        sel("opnsense_kea_dhcp4_leases_dynamic_total"),
        unit="short", w=4, h=4,
        desc="Dynamic Kea DHCPv4 leases.",
    )
    kea4_by_iface = b.bargauge(
        "Kea DHCPv4 Leases by Interface",
        [(sel("opnsense_kea_dhcp4_leases_by_interface"), "{{interface}}")],
        unit="short", w=12, h=4, orient="horizontal",
        desc="Kea DHCPv4 leases active per interface.",
    )
    kea6_total = b.stat(
        "Kea DHCPv6 Leases",
        sel("opnsense_kea_dhcp6_leases_total"),
        unit="short", w=4, h=4,
        desc="Total Kea DHCPv6 leases (instantaneous count).",
    )
    kea6_reserved = b.stat(
        "Kea DHCPv6 Reserved",
        sel("opnsense_kea_dhcp6_leases_reserved_total"),
        unit="short", w=4, h=4,
        desc="Reserved (static) Kea DHCPv6 leases.",
    )
    kea6_dynamic = b.stat(
        "Kea DHCPv6 Dynamic",
        sel("opnsense_kea_dhcp6_leases_dynamic_total"),
        unit="short", w=4, h=4,
        desc="Dynamic Kea DHCPv6 leases.",
    )
    kea6_by_iface = b.bargauge(
        "Kea DHCPv6 Leases by Interface",
        [(sel("opnsense_kea_dhcp6_leases_by_interface"), "{{interface}}")],
        unit="short", w=12, h=4, orient="horizontal",
        desc="Kea DHCPv6 leases active per interface.",
    )

    # ================================================================
    # KEA — Row 4: Kea DHCPv4 lease detail table
    # ================================================================
    kea4_lease_table = b.table(
        "Kea DHCPv4 Lease Details",
        [sel("opnsense_kea_dhcp4_lease_info")],
        w=24, h=10,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "address": "IP Address",
            "hostname": "Hostname",
            "hwaddr": "MAC Address",
            "interface": "Interface",
        },
        unit_overrides={"Value": "dateTimeAsIso"},
        sort_by="Interface",
        desc=(
            "Per-lease DHCPv4 detail. Value = expire timestamp (ISO date). "
            "Only emitted with --exporter.enable-kea-details."
        ),
    )

    # ================================================================
    # KEA — Row 5: Kea DHCPv6 lease detail table
    # ================================================================
    kea6_lease_table = b.table(
        "Kea DHCPv6 Lease Details",
        [sel("opnsense_kea_dhcp6_lease_info")],
        w=24, h=10,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "address": "IPv6 Address",
            "hostname": "Hostname",
            "hwaddr": "DUID / MAC",
            "interface": "Interface",
        },
        unit_overrides={"Value": "dateTimeAsIso"},
        sort_by="Interface",
        desc=(
            "Per-lease DHCPv6 detail. Value = expire timestamp (ISO date). "
            "Only emitted with --exporter.enable-kea-details."
        ),
    )

    # ================================================================
    # ISC DHCPv4 — Row 6: summary
    # ================================================================
    dhcpv4_total = b.stat(
        "ISC DHCPv4 Leases",
        sel("opnsense_dhcpv4_leases_total"),
        unit="short", w=4, h=4,
        desc="Total ISC DHCPv4 leases (instantaneous count).",
    )
    dhcpv4_reserved = b.stat(
        "ISC DHCPv4 Reserved",
        sel("opnsense_dhcpv4_leases_reserved_total"),
        unit="short", w=4, h=4,
        desc="Reserved (static) ISC DHCPv4 leases.",
    )
    dhcpv4_dynamic = b.stat(
        "ISC DHCPv4 Dynamic",
        sel("opnsense_dhcpv4_leases_dynamic_total"),
        unit="short", w=4, h=4,
        desc="Dynamic ISC DHCPv4 leases.",
    )
    dhcpv4_by_iface = b.bargauge(
        "ISC DHCPv4 Leases by Interface",
        [(sel("opnsense_dhcpv4_leases_by_interface"), "{{interface}}")],
        unit="short", w=12, h=4, orient="horizontal",
        desc="ISC DHCPv4 leases active per interface.",
    )

    # ================================================================
    # ISC DHCPv4 — Row 7: lease detail table
    # ================================================================
    dhcpv4_lease_table = b.table(
        "ISC DHCPv4 Lease Details",
        [sel("opnsense_dhcpv4_lease_info")],
        w=24, h=10,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "address": "IP Address",
            "hostname": "Hostname",
            "mac": "MAC Address",
            "interface": "Interface",
            "type": "Type",
            "state": "State",
            "status": "Status",
        },
        sort_by="Interface",
        desc=(
            "Per-lease ISC DHCPv4 detail (value is always 1; use label columns). "
            "Only emitted with --exporter.enable-dhcpv4-details."
        ),
    )

    # ================================================================
    # Tab assembly
    # ================================================================
    b.tab("DHCP", [
        b.row("Dnsmasq DHCP",
              [dnsmasq_total, dnsmasq_reserved, dnsmasq_dynamic,
               dnsmasq_by_iface, dnsmasq_svc],
              present="has_dnsmasq"),
        b.row("Dnsmasq Lease Details",
              [dnsmasq_lease_table],
              present="has_dnsmasq_details"),
        b.row("Kea DHCP",
              [kea4_total, kea4_reserved, kea4_dynamic, kea4_by_iface,
               kea6_total, kea6_reserved, kea6_dynamic, kea6_by_iface],
              present="has_kea"),
        b.row("Kea DHCPv4 Lease Details",
              [kea4_lease_table],
              present="has_kea4_details"),
        b.row("Kea DHCPv6 Lease Details",
              [kea6_lease_table],
              present="has_kea6_details"),
        b.row("ISC DHCPv4",
              [dhcpv4_total, dhcpv4_reserved, dhcpv4_dynamic, dhcpv4_by_iface],
              present="has_dhcpv4_isc"),
        b.row("ISC DHCPv4 Lease Details",
              [dhcpv4_lease_table],
              present="has_dhcpv4_details"),
    ])
