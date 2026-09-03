"""
DHCP tab — covers all dnsmasq, Kea DHCPv4/v6, ISC DHCPv4, and ISC DHCPv6 metrics.

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
    3. Kea summary           — gated has_kea: DHCPv4 + DHCPv6 totals/reserved/dynamic + by_iface,
                               by_state, DHCPv6 by_type, pool size/used/utilization by subnet
    4. Kea DHCPv4 details    — gated has_kea4_details: kea_dhcp4_lease_info table
    5. Kea DHCPv6 details    — gated has_kea6_details: kea_dhcp6_lease_info table
    5b. Kea DHCPv6 PD pools  — gated has_kea_pd_pools: prefix-delegation pool capacity (#208)
    5c. Leases nearing expiry — combined dnsmasq/Kea view, gated on detail metrics
  ISC DHCPv4:
    6. ISC DHCPv4 summary    — gated has_dhcpv4_isc: leases totals + by_iface
    7. ISC DHCPv4 details    — gated has_dhcpv4_details: dhcpv4_lease_info table
  ISC DHCPv6:
    8. ISC DHCPv6 summary    — gated has_dhcpv6_isc: leases totals + by_iface + PD prefixes
    9. ISC DHCPv6 details    — gated has_dhcpv6_details: dhcpv6_lease_info table
"""

from builder import Builder, sel, epoch_ms, RUNSTOP
from tabs import log_events


def build(b: Builder):
    # ---- Sentinels ---------------------------------------------------------
    # Gate each backend row on PRESENCE, not lease count. A `leases_total > 0` filter conflates
    # "backend absent" with "backend up but idle": a running-but-idle backend emits leases_total=0
    # and its row would vanish — hiding the very service-health stat meant to answer "is it up?"
    # (#114). label_values(metric, __name__) is non-empty whenever the series exists, regardless of
    # value, so the row shows for a live backend even at 0 leases (or when the service is stopped).
    # dnsmasq/kea expose service_running; the ISC v4/v6 collectors emit nothing when their plugin is
    # absent (Present-gated, #87), so their always-emitted leases_total is a valid presence signal.
    b.sentinel("has_dnsmasq", metric="opnsense_dnsmasq_service_running")
    b.sentinel("has_dnsmasq_details", metric="opnsense_dnsmasq_lease_info")
    b.sentinel("has_kea", metric="opnsense_kea_service_running")
    b.sentinel("has_kea4_details", metric="opnsense_kea_dhcp4_lease_info")
    b.sentinel("has_kea6_details", metric="opnsense_kea_dhcp6_lease_info")
    b.sentinel("has_kea_pd_pools", metric="opnsense_kea_dhcp6_pd_pool_size")
    b.sentinel("has_dhcpv4_isc", metric="opnsense_dhcpv4_leases_total")
    b.sentinel("has_dhcpv4_details", metric="opnsense_dhcpv4_lease_info")
    b.sentinel("has_dhcpv6_isc", metric="opnsense_dhcpv6_leases_total")
    b.sentinel("has_dhcpv6_details", metric="opnsense_dhcpv6_lease_info")

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

    dnsmasq_pool = b.bargauge(
        "Dnsmasq Pool Size by Interface",
        [(sel("opnsense_dnsmasq_pool_size"), "{{interface}}")],
        unit="short", w=8, h=8, orient="horizontal",
        desc="Configured address pool size per interface (sum of range sizes).",
    )
    dnsmasq_util = b.ts(
        "Dnsmasq Pool Utilization %",
        [(f'100 * {sel("opnsense_dnsmasq_leases_by_interface")} '
          f'/ on(interface, opnsense_instance) '
          f'{sel("opnsense_dnsmasq_pool_size")}',
          "{{interface}}")],
        unit="percent", w=8, h=8,
        desc="DHCP pool utilization per interface (leases / pool size).",
    )

    # ================================================================
    # DNSMASQ — Row 2: lease detail table (opt-in, high-cardinality)
    # ================================================================
    dnsmasq_lease_table = b.table(
        "Dnsmasq Lease Details",
        [epoch_ms(sel("opnsense_dnsmasq_lease_info"))],
        w=24, h=10,
        excludes=["__name__", "job", "instance"],
        renames={
            "address": "IP Address",
            "hostname": "Hostname",
            "hwaddr": "MAC Address",
            "interface": "Interface",
            "device": "Device",
            "vendor": "Vendor",
            "Value": "Expires",
        },
        unit_overrides={"Expires": "dateTimeAsIso"},
        sort_by="Interface",
        desc=(
            "Per-lease detail. The Expires column shows the lease expiry as an ISO date. "
            "Device is the raw logical interface id (only Device, not Interface, joins "
            "against the interfaces metrics on VLANs/bridges); Vendor is an offline IEEE OUI "
            "lookup (empty when the OUI is unknown), mirroring the Kea lease tables below. "
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
    kea4_by_state = b.bargauge(
        "Kea DHCPv4 Leases by State",
        [(sel("opnsense_kea_dhcp4_leases_by_state"), "{{state}}")],
        unit="short", w=12, h=4, orient="horizontal",
        desc=(
            "Kea DHCPv4 leases by lease state. declined/expired-reclaimed indicate address "
            "conflicts or DHCPDECLINE activity worth investigating."
        ),
    )
    kea6_by_state = b.bargauge(
        "Kea DHCPv6 Leases by State",
        [(sel("opnsense_kea_dhcp6_leases_by_state"), "{{state}}")],
        unit="short", w=12, h=4, orient="horizontal",
        desc=(
            "Kea DHCPv6 leases by lease state. declined/expired-reclaimed indicate address "
            "conflicts or DHCPDECLINE activity worth investigating."
        ),
    )
    kea6_by_type = b.bargauge(
        "Kea DHCPv6 Leases by Type",
        [(sel("opnsense_kea_dhcp6_leases_by_type"), "{{type}}")],
        unit="short", w=12, h=4, orient="horizontal",
        desc=(
            "Kea DHCPv6 leases by lease type: IA_NA (address) vs IA_PD (prefix delegation)."
        ),
    )

    kea_pool_stats = b.bargauge(
        "Kea Lease Pool Accounting (server-reported)",
        [(sel("opnsense_kea_dhcp4_lease_pool_stats"), "v4 {{pool_state}}"),
         (sel("opnsense_kea_dhcp6_lease_pool_stats"), "v6 {{pool_state}}")],
        unit="short", w=12, h=4, orient="horizontal",
        desc=(
            "Kea's OWN pool accounting, as reported by the server, rather than a count of the "
            "lease rows we decoded. The two answer different questions and are both worth having: "
            "a row count says what the exporter could see, this says what Kea believes it has "
            "handed out. active climbing toward total is the pool-exhaustion signal — and it is "
            "authoritative in a way a row count is not, because a truncated or filtered lease "
            "query silently lowers the row count without changing what Kea thinks. A persistent "
            "gap between this and the by-state panels above means the two views disagree, which "
            "is worth chasing rather than averaging."
        ),
    )

    kea_svc = b.stat(
        "Kea Service",
        sel("opnsense_kea_service_running"),
        mappings=RUNSTOP, color_mode="background",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        w=4, h=4,
        desc="1 = running, 0 = stopped/disabled.",
    )
    kea4_pool = b.bargauge(
        "DHCPv4 Pool Size by Subnet",
        [(sel("opnsense_kea_dhcp4_pool_size"), "{{subnet}} ({{interface}})")],
        unit="short", w=8, h=8, orient="horizontal",
        desc="Configured DHCPv4 address pool size per subnet.",
    )
    kea6_pool = b.bargauge(
        "DHCPv6 Pool Size by Subnet",
        [(sel("opnsense_kea_dhcp6_pool_size"), "{{subnet}} ({{interface}})")],
        unit="short", w=8, h=8, orient="horizontal",
        desc="Configured DHCPv6 address pool size per subnet.",
    )
    kea_util = b.ts(
        "Kea Pool Utilization % by Interface",
        [(f'100 * {sel("opnsense_kea_dhcp4_leases_by_interface")} '
          f'/ on(interface, opnsense_instance) group_left() '
          f'sum by(interface, opnsense_instance)({sel("opnsense_kea_dhcp4_pool_size")})',
          "v4 {{interface}}"),
         (f'100 * {sel("opnsense_kea_dhcp6_leases_by_interface")} '
          f'/ on(interface, opnsense_instance) group_left() '
          f'sum by(interface, opnsense_instance)({sel("opnsense_kea_dhcp6_pool_size")})',
          "v6 {{interface}}")],
        unit="percent", w=8, h=8,
        desc="Kea DHCP pool utilization per interface (leases / pool size).",
    )
    kea4_pool_used = b.bargauge(
        "DHCPv4 Pool Used by Subnet",
        [(sel("opnsense_kea_dhcp4_pool_used"), "{{subnet}}")],
        unit="short", w=8, h=8, orient="horizontal",
        desc=(
            "Client-side CIDR match: number of current Kea DHCPv4 leases whose address falls "
            "within each configured subnet's pool."
        ),
    )
    kea6_pool_used = b.bargauge(
        "DHCPv6 Pool Used by Subnet",
        [(sel("opnsense_kea_dhcp6_pool_used"), "{{subnet}}")],
        unit="short", w=8, h=8, orient="horizontal",
        desc=(
            "Client-side CIDR match: number of current Kea DHCPv6 address (non-PD) leases whose "
            "address falls within each configured subnet's pool."
        ),
    )
    kea_subnet_util = b.ts(
        "Kea Pool Utilization % by Subnet",
        [(f'100 * {sel("opnsense_kea_dhcp4_pool_used")} '
          f'/ on(subnet, opnsense_instance) '
          f'{sel("opnsense_kea_dhcp4_pool_size")}',
          "v4 {{subnet}}"),
         (f'100 * {sel("opnsense_kea_dhcp6_pool_used")} '
          f'/ on(subnet, opnsense_instance) '
          f'{sel("opnsense_kea_dhcp6_pool_size")}',
          "v6 {{subnet}}")],
        unit="percent", w=8, h=8,
        desc=(
            "Per-subnet Kea DHCP pool utilization (leases matched into the subnet's CIDR / "
            "configured pool size). Finer-grained than the per-interface panel above when a "
            "single interface hosts several Kea subnets."
        ),
    )
    kea_reservations = b.bargauge(
        "Configured Kea Reservations by Subnet",
        [(sel("opnsense_kea_dhcp4_reservations_configured"), "v4 {{subnet}}"),
         (sel("opnsense_kea_dhcp6_reservations_configured"), "v6 {{subnet}}")],
        unit="short", w=12, h=4, orient="horizontal",
        desc=(
            "Complete configured reservation inventory from Kea's DHCPv4 and DHCPv6 "
            "searchReservation endpoints. Unlike lease-row reserved counts, this includes "
            "reservations no client has claimed. No reservation identity is emitted."
        ),
    )

    # ================================================================
    # KEA — Row 4: Kea DHCPv4 lease detail table
    # ================================================================
    kea4_lease_table = b.table(
        "Kea DHCPv4 Lease Details",
        [epoch_ms(sel("opnsense_kea_dhcp4_lease_info"))],
        w=24, h=10,
        excludes=["__name__", "job", "instance"],
        renames={
            "address": "IP Address",
            "hostname": "Hostname",
            "hwaddr": "MAC Address",
            "interface": "Interface",
            "vendor": "Vendor",
            "valid_lifetime": "Valid Lifetime (s)",
            "client_id": "Client ID",
            "Value": "Expires",
        },
        unit_overrides={"Expires": "dateTimeAsIso"},
        sort_by="Interface",
        desc=(
            "Per-lease DHCPv4 detail. The Expires column shows the lease expiry as an ISO date. "
            "Vendor is an offline IEEE OUI lookup (empty when the OUI is unknown, e.g. MAC "
            "randomisation); Client ID is the raw DHCPv4 option 61 identifier (empty when the "
            "client never sent one); Valid Lifetime is Kea's granted lease duration in seconds. "
            "Only emitted with --exporter.enable-kea-details."
        ),
    )

    # ================================================================
    # KEA — Row 5: Kea DHCPv6 lease detail table
    # ================================================================
    kea6_lease_table = b.table(
        "Kea DHCPv6 Lease Details",
        [epoch_ms(sel("opnsense_kea_dhcp6_lease_info"))],
        w=24, h=10,
        excludes=["__name__", "job", "instance"],
        renames={
            "address": "IPv6 Address",
            "hostname": "Hostname",
            "hwaddr": "DUID / MAC",
            "interface": "Interface",
            "vendor": "Vendor",
            "valid_lifetime": "Valid Lifetime (s)",
            # #584: the delegated block size on an IA_PD lease. Deliberately v6-only —
            # on dhcp4_lease_info it would always read 128 and mean nothing.
            "prefix_len": "Prefix Length",
            "Value": "Expires",
        },
        unit_overrides={"Expires": "dateTimeAsIso"},
        sort_by="Interface",
        desc=(
            "Per-lease DHCPv6 detail. The Expires column shows the lease expiry as an ISO date. "
            "Vendor is an offline IEEE OUI lookup (empty when the OUI is unknown, e.g. MAC "
            "randomisation); Valid Lifetime is Kea's granted lease duration in seconds. No "
            "Client ID column: DHCPv6 has no option-61 concept (Kea's lease6 records carry no "
            "client-id field at all), so this metric never emits that label. "
            "Only emitted with --exporter.enable-kea-details."
        ),
    )

    # ================================================================
    # KEA — Row 5b: DHCPv6 prefix-delegation pool capacity (#208)
    # ================================================================
    kea6_pd_pool = b.bargauge(
        "Kea DHCPv6 PD Pool Capacity",
        [(sel("opnsense_kea_dhcp6_pd_pool_size"), "{{subnet}} ({{prefix}})")],
        unit="short", w=24, h=8, orient="horizontal",
        desc=(
            "Delegable-prefix capacity of each configured DHCPv6 prefix-delegation pool "
            "(2^(delegated_len-prefix_len)). Compare against the IA_PD series of "
            "\"Kea DHCPv6 Leases by Type\" above to gauge PD exhaustion."
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
            "device": "Device",
            "type": "Type",
            "state": "State",
            "status": "Status",
        },
        sort_by="Interface",
        desc=(
            "Per-lease ISC DHCPv4 detail (value is always 1; use label columns). Device is the "
            "raw logical interface id (only Device, not Interface, joins against the interfaces "
            "metrics on VLANs/bridges). "
            "Only emitted with --exporter.enable-dhcpv4-details."
        ),
    )

    # ================================================================
    # ISC DHCPv6 — Row 8: summary
    # ================================================================
    dhcpv6_total = b.stat(
        "ISC DHCPv6 Leases",
        sel("opnsense_dhcpv6_leases_total"),
        unit="short", w=4, h=4,
        desc="Total ISC DHCPv6 leases (instantaneous count).",
    )
    dhcpv6_reserved = b.stat(
        "ISC DHCPv6 Reserved",
        sel("opnsense_dhcpv6_leases_reserved_total"),
        unit="short", w=4, h=4,
        desc="Reserved (static) ISC DHCPv6 leases.",
    )
    dhcpv6_dynamic = b.stat(
        "ISC DHCPv6 Dynamic",
        sel("opnsense_dhcpv6_leases_dynamic_total"),
        unit="short", w=4, h=4,
        desc="Dynamic ISC DHCPv6 leases.",
    )
    dhcpv6_by_iface = b.bargauge(
        "ISC DHCPv6 Leases by Interface",
        [(sel("opnsense_dhcpv6_leases_by_interface"), "{{interface}}")],
        unit="short", w=12, h=4, orient="horizontal",
        desc="ISC DHCPv6 leases active per interface.",
    )
    dhcpv6_pd_total = b.stat(
        "PD Prefixes Total",
        sel("opnsense_dhcpv6_pd_prefixes_total"),
        unit="short", w=4, h=4,
        desc="Total number of delegated prefixes (pd_prefixes_total — instantaneous count).",
    )
    dhcpv6_pd_active = b.stat(
        "PD Prefixes Active",
        sel("opnsense_dhcpv6_pd_prefixes_active"),
        unit="short", w=4, h=4,
        desc="Active (state=active) delegated prefixes.",
    )

    # ================================================================
    # ISC DHCPv6 — Row 9: lease detail table
    # ================================================================
    dhcpv6_lease_table = b.table(
        "ISC DHCPv6 Lease Details",
        [sel("opnsense_dhcpv6_lease_info")],
        w=24, h=10,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "address": "IPv6 Address",
            "mac": "MAC Address",
            "duid": "DUID",
            "if_descr": "Interface",
            "device": "Device",
            "state": "State",
            "status": "Status",
            "type": "Type",
        },
        sort_by="Interface",
        desc=(
            "Per-lease ISC DHCPv6 detail (value is always 1; use label columns). Device is the "
            "raw logical interface id (only Device, not Interface, joins against the interfaces "
            "metrics on VLANs/bridges). "
            "Only emitted with --exporter.enable-dhcpv6-details."
        ),
    )

    # Lease-info values are absolute expiry timestamps in seconds, not counters.
    # Normalize the backend label before unioning the vectors so operators can see
    # which detail collector supplied each row. ISC lease_info is deliberately not
    # included: its value is always 1 and carries no expiry timestamp.
    lease_days_by_backend = [
        f'label_replace(({sel("opnsense_dnsmasq_lease_info")} - time()) / 86400, '
        '"backend", "dnsmasq", "address", ".*")',
        f'label_replace(({sel("opnsense_kea_dhcp4_lease_info")} - time()) / 86400, '
        '"backend", "kea4", "address", ".*")',
        f'label_replace(({sel("opnsense_kea_dhcp6_lease_info")} - time()) / 86400, '
        '"backend", "kea6", "address", ".*")',
    ]
    lease_days = " or ".join(lease_days_by_backend)
    lease_near_expiry_expr = f"(({lease_days}) >= 0) and (({lease_days}) < 1)"
    leases_near_expiry = b.table(
        "Leases Nearing Expiry (<24h)",
        [lease_near_expiry_expr],
        w=24, h=10,
        excludes=["__name__", "job", "instance"],
        renames={
            "address": "IP Address",
            "hostname": "Hostname",
            "hwaddr": "MAC / DUID",
            "interface": "Interface",
            "device": "Device",
            "vendor": "Vendor",
            "valid_lifetime": "Valid Lifetime (s)",
            "client_id": "Client ID",
            "prefix_len": "Prefix Length",
            "backend": "Backend",
            "Value": "Days Left",
            "opnsense_instance": "Instance",
        },
        unit_overrides={"Days Left": "d"},
        sort_by="Days Left", sort_desc=False,
        desc=(
            "Upcoming dnsmasq and Kea leases with 0 to under 1 day remaining, "
            "sorted soonest first. The backend label identifies which detail "
            "collector supplied the row. Only emitted when the corresponding "
            "detail metrics are enabled."
        ),
    )

    # ================================================================
    # Tab assembly
    # ================================================================
    # Split into sibling leaves (#619): 51 panels in one tab is a tab people
    # scroll past. The existing rows are regrouped and nothing else changes — no row
    # split, merged, renamed or reordered within its group, no panel moved between
    # rows — so this reads as a move.
    b.tab("DHCP", [
        b.row("Dnsmasq DHCP",
              [dnsmasq_total, dnsmasq_reserved, dnsmasq_dynamic,
               dnsmasq_by_iface, dnsmasq_svc, dnsmasq_pool, dnsmasq_util],
              present="has_dnsmasq"),
        b.row("Dnsmasq Lease Details",
              [dnsmasq_lease_table],
              present="has_dnsmasq_details"),
        b.row("Kea DHCP",
              [kea4_total, kea4_reserved, kea4_dynamic, kea4_by_iface,
               kea6_total, kea6_reserved, kea6_dynamic, kea6_by_iface,
               kea4_by_state, kea6_by_state, kea6_by_type, kea_pool_stats,
               kea_svc, kea4_pool, kea6_pool, kea_util,
               kea4_pool_used, kea6_pool_used, kea_subnet_util],
              present="has_kea"),
        b.row("Kea Reservation Inventory",
              [kea_reservations],
              present="has_kea"),
        b.row("Kea DHCPv4 Lease Details",
              [kea4_lease_table],
              present="has_kea4_details"),
        b.row("Kea DHCPv6 Lease Details",
              [kea6_lease_table],
              present="has_kea6_details"),
        b.row("Leases Nearing Expiry",
              [leases_near_expiry],
              present=["has_dnsmasq_details", "has_kea4_details", "has_kea6_details"]),
        b.row("Kea DHCPv6 Prefix Delegation",
              [kea6_pd_pool],
              present="has_kea_pd_pools"),
    ])
    b.tab("DHCP - ISC & Client", [
        b.row("ISC DHCPv4",
              [dhcpv4_total, dhcpv4_reserved, dhcpv4_dynamic, dhcpv4_by_iface],
              present="has_dhcpv4_isc"),
        b.row("ISC DHCPv4 Lease Details",
              [dhcpv4_lease_table],
              present="has_dhcpv4_details"),
        b.row("ISC DHCPv6",
              [dhcpv6_total, dhcpv6_reserved, dhcpv6_dynamic, dhcpv6_by_iface,
               dhcpv6_pd_total, dhcpv6_pd_active],
              present="has_dhcpv6_isc"),
        b.row("ISC DHCPv6 Lease Details",
              [dhcpv6_lease_table],
              present="has_dhcpv6_details"),
        # #523: lease EVENTS, as opposed to the lease inventories above. Backend-
        # independent, so it stays populated across a Kea/dnsmasq/ISC migration that
        # blanks whichever backend rows the box stopped using.
        log_events.dhcp_row(b),
        # #541: the lease this box HOLDS on its WAN, as opposed to the ones it hands
        # out. A healthy DHCP server can still lose its own upstream address.
        log_events.dhcp_client_row(b),
        # #546: the v6 twin — the WAN DHCPv6 client and the delegated prefix. Separate
        # from the row above because a v4 and a v6 uplink fail independently.
        log_events.dhcp6_client_row(b),
    ])
