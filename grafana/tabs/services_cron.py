"""
Services, Cron & DynDNS tab for the opnsense2otel dashboard.

Covers all metrics across four rows:

  Row 1 — Services (always visible):
    • services_status statetimeline + table
    • services_running_total stat (RAW)
    • services_stopped_total stat (RAW, orange > 0)

  Row 2 — Cron (always visible):
    • cron_job_status table (ENABLED mapping on value)

  Row 3 — Agent plugin services: one status panel per independently optional plugin

  Row 4 — DynDNS (gated has_dyndns):
    • dyndns_accounts_total stat (RAW)
    • dyndns_account_enabled table (ENABLED)
    • dyndns_account_last_update_timestamp_seconds table (dateTimeAsIso)
    • dyndns_account_info table
    • dyndns_service_running stat (RUNSTOP)
"""

from builder import Builder, sel, epoch_ms, RUNSTOP


def build(b: Builder):
    b.sentinel("has_dyndns", metric="opnsense_dyndns_accounts_total")

    # =====================================================================
    # Row 1: Services
    # =====================================================================

    # State timeline: one lane per service (~30 series)
    svc_timeline = b.statetimeline(
        "Service Status",
        [(sel("opnsense_services_status"), "{{name}} — {{description}}")],
        RUNSTOP,
        w=24, h=10,
        desc="Running/stopped state over time for all OPNsense services.",
    )

    # Detail table showing current service status
    svc_table = b.table(
        "Service Status (current)",
        [sel("opnsense_services_status")],
        w=16, h=10,
        excludes=["__name__", "job", "instance"],
        renames={
            "name": "Service",
            "description": "Description",
            "Value": "Status",
            "opnsense_instance": "Instance",
        },
        sort_by="Service",
        desc="Current service status (1 = running, 0 = stopped).",
    )

    # Running total — instantaneous gauge (RAW per AUTHORING.md)
    svc_running = b.stat(
        "Services Running",
        sel("opnsense_services_running_total"),
        unit="short",
        w=4, h=4,
        thresholds=[{"color": "green", "value": None}],
        color_mode="value",
        desc="Number of services currently running.",
    )

    # Stopped total — instantaneous gauge, alert if > 0
    svc_stopped = b.stat(
        "Services Stopped",
        sel("opnsense_services_stopped_total"),
        unit="short",
        w=4, h=4,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "orange", "value": 1},
        ],
        color_mode="background",
        desc="Number of services currently stopped. Orange = at least one service is down.",
    )

    row_services = b.row(
        "Services",
        [svc_timeline, svc_table, svc_running, svc_stopped],
    )

    # =====================================================================
    # Row 2: Cron
    # =====================================================================

    # Cron job status table (1 = enabled, 0 = disabled)
    cron_table = b.table(
        "Cron Jobs",
        [sel("opnsense_cron_job_status")],
        w=24, h=10,
        excludes=["__name__", "job", "instance"],
        renames={
            "schedule": "Schedule",
            "description": "Description",
            "command": "Command",
            "origin": "Origin",
            "Value": "Enabled",
            "opnsense_instance": "Instance",
        },
        sort_by="Description",
        desc="Cron job configuration and enabled state (1 = enabled, 0 = disabled).",
    )

    row_cron = b.row(
        "Cron",
        [cron_table],
    )

    # =====================================================================
    # Row 3: independently optional agent-family plugin services
    # =====================================================================
    agent_plugin_services = [
        b.stat("Beats", sel("opnsense_beats_service_running"), mappings=RUNSTOP,
               color_mode="background", w=4, h=4,
               desc="Whether the optional Beats plugin service is running."),
        b.stat("Collectd", sel("opnsense_collectd_service_running"), mappings=RUNSTOP,
               color_mode="background", w=4, h=4,
               desc="Whether the optional collectd plugin service is running."),
        b.stat("Munin Node", sel("opnsense_munin_node_service_running"), mappings=RUNSTOP,
               color_mode="background", w=4, h=4,
               desc="Whether the optional Munin Node plugin service is running."),
        b.stat("Net-SNMP", sel("opnsense_net_snmp_service_running"), mappings=RUNSTOP,
               color_mode="background", w=4, h=4,
               desc="Whether the optional Net-SNMP plugin service is running."),
        b.stat("Netdata", sel("opnsense_netdata_service_running"), mappings=RUNSTOP,
               color_mode="background", w=4, h=4,
               desc="Whether the optional Netdata plugin service is running."),
        b.stat("Node Exporter", sel("opnsense_node_exporter_service_running"), mappings=RUNSTOP,
               color_mode="background", w=4, h=4,
               desc="Whether the optional node_exporter plugin service is running."),
        b.stat("NRPE", sel("opnsense_nrpe_service_running"), mappings=RUNSTOP,
               color_mode="background", w=4, h=4,
               desc="Whether the optional NRPE plugin service is running."),
        b.stat("Puppet Agent", sel("opnsense_puppet_agent_service_running"), mappings=RUNSTOP,
               color_mode="background", w=4, h=4,
               desc="Whether the optional Puppet Agent plugin service is running."),
        b.stat("QEMU Guest Agent", sel("opnsense_qemu_guest_agent_service_running"), mappings=RUNSTOP,
               color_mode="background", w=4, h=4,
               desc="Whether the optional QEMU Guest Agent plugin service is running."),
        b.stat("Telegraf", sel("opnsense_telegraf_service_running"), mappings=RUNSTOP,
               color_mode="background", w=4, h=4,
               desc="Whether the optional Telegraf plugin service is running."),
        b.stat("Wazuh Agent", sel("opnsense_wazuh_agent_service_running"), mappings=RUNSTOP,
               color_mode="background", w=4, h=4,
               desc="Whether the optional Wazuh Agent plugin service is running."),
        b.stat("Zabbix Agent", sel("opnsense_zabbix_agent_service_running"), mappings=RUNSTOP,
               color_mode="background", w=4, h=4,
               desc="Whether the optional Zabbix Agent plugin service is running."),
        b.stat("Zabbix Proxy", sel("opnsense_zabbix_proxy_service_running"), mappings=RUNSTOP,
               color_mode="background", w=4, h=4,
               desc="Whether the optional Zabbix Proxy plugin service is running."),
    ]
    row_agent_plugins = b.autogrid_row("Agent Plugin Services", agent_plugin_services)

    # =====================================================================
    # Row 3: DynDNS (gated)
    # =====================================================================

    # Total accounts stat (instantaneous — RAW per AUTHORING.md)
    dyndns_total = b.stat(
        "DynDNS Accounts",
        sel("opnsense_dyndns_accounts_total"),
        unit="short",
        w=4, h=4,
        thresholds=[{"color": "blue", "value": None}],
        desc="Total number of configured DynDNS accounts.",
    )

    # Service running stat
    dyndns_svc = b.stat(
        "DynDNS Service",
        sel("opnsense_dyndns_service_running"),
        mappings=RUNSTOP,
        color_mode="background",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        w=4, h=4,
        desc="Whether the DynDNS service is running (1 = running, 0 = stopped).",
    )

    # Enabled table (1 = enabled, 0 = disabled)
    dyndns_enabled = b.table(
        "DynDNS Account Enabled",
        [sel("opnsense_dyndns_account_enabled")],
        w=16, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "description": "Description",
            "service": "Service",
            "hostnames": "Hostnames",
            "interface": "Interface",
            "Value": "Enabled",
            "opnsense_instance": "Instance",
        },
        sort_by="Description",
        desc="Whether each DynDNS account is enabled (1 = enabled, 0 = disabled).",
    )

    # Last successful IP update timestamp
    dyndns_last_update = b.table(
        "DynDNS Last Update",
        [epoch_ms(sel("opnsense_dyndns_account_last_update_timestamp_seconds"))],
        w=24, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "description": "Description",
            "service": "Service",
            "hostnames": "Hostnames",
            "Value": "Last Update",
            "opnsense_instance": "Instance",
        },
        unit_overrides={"Last Update": "dateTimeAsIso"},
        sort_by="Description",
        desc="Unix timestamp of the last successful DynDNS IP update for each account.",
    )

    # Account info table (info metric, value always 1)
    dyndns_info = b.table(
        "DynDNS Account Info",
        [sel("opnsense_dyndns_account_info")],
        w=24, h=8,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "description": "Description",
            "service": "Service",
            "hostnames": "Hostnames",
            "zone": "Zone",
            "interface": "Interface",
            "current_ip": "Current IP",
            "opnsense_instance": "Instance",
        },
        sort_by="Description",
        desc="DynDNS account details including current IP address (info metric).",
    )

    row_dyndns = b.row(
        "DynDNS",
        [dyndns_total, dyndns_svc, dyndns_enabled, dyndns_last_update, dyndns_info],
        present="has_dyndns",
    )

    # =====================================================================
    # Assemble the tab
    # =====================================================================
    b.tab(
        "Services, Cron & DynDNS",
        [row_services, row_cron, row_agent_plugins, row_dyndns],
    )
