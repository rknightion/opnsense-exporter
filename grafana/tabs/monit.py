"""
Monit tab — Monit service/resource monitoring metrics (opnsense_monit_*).

Plugin-gated: tab hidden unless monit metrics are present.

All metrics are gauges (instantaneous values, no _total counters).
"""

from builder import Builder, sel, RUNSTOP, OKERR, UPDOWN, MONITORED


def build(b: Builder):
    b.sentinel("has_monit", metric="opnsense_monit_status_ok")

    # ------------------------------------------------------------------ #
    # Row 1: Monit Overview                                                #
    # ------------------------------------------------------------------ #
    svc = b.stat(
        "Monit Service",
        sel("opnsense_monit_service_running"),
        mappings=RUNSTOP, color_mode="background",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        w=4, h=4,
        desc="Monit service state (1 = running, 0 = stopped).",
    )
    status_ok = b.stat(
        "Monit Status Reachable",
        sel("opnsense_monit_status_ok"),
        mappings=OKERR, color_mode="background",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        w=4, h=4,
        desc=(
            "1 when the monit httpd is reachable and returned a valid status XML. "
            "0 when monit is unreachable or returned an error payload."
        ),
    )
    checks_total = b.stat(
        "Checks Configured",
        sel("opnsense_monit_checks_total"),
        unit="short", w=4, h=4,
        desc="Total number of configured monit checks.",
    )
    checks_ok = b.stat(
        "Checks OK",
        f'sum({sel("opnsense_monit_check_status")})',
        unit="short", w=4, h=4,
        thresholds=[
            {"color": "red", "value": None},
            {"color": "green", "value": 1},
        ],
        desc=("Number of monit checks currently in OK state (status field == 0)."
             "Fleet total: this is a deliberate sum across every selected firewall (#468) — with two boxes picked, the number is both boxes' together."),
    )
    checks_monitored = b.stat(
        "Checks Monitored",
        f'sum({sel("opnsense_monit_check_monitored")})',
        unit="short", w=4, h=4,
        desc=("Number of monit checks actively being monitored (monitor != 0)."
             "Fleet total: this is a deliberate sum across every selected firewall (#468) — with two boxes picked, the number is both boxes' together."),
    )

    # ------------------------------------------------------------------ #
    # Row 2: Check Status Detail                                           #
    # ------------------------------------------------------------------ #
    check_status_timeline = b.statetimeline(
        "Check Status Over Time",
        [(sel("opnsense_monit_check_status"), "{{name}} ({{type}})")],
        UPDOWN, w=24, h=8,
        desc=(
            "Monit check status over time per check. "
            "1 = OK (monit status field == 0), 0 = failed/error."
        ),
    )
    check_monitored_timeline = b.statetimeline(
        "Check Monitored State",
        [(sel("opnsense_monit_check_monitored"), "{{name}} ({{type}})")],
        MONITORED, w=24, h=8,
        desc=(
            "Whether each check is actively monitored over time. "
            "1 = monitored (monitor != 0), 0 = unmonitored."
        ),
    )
    checks_table = b.table(
        "Check Details",
        [
            sel("opnsense_monit_check_status"),
            sel("opnsense_monit_check_monitored"),
        ],
        w=24, h=10,
        excludes=["__name__", "job", "instance"],
        renames={
            "name": "Check Name",
            "type": "Type",
            "Value #A": "Status OK",
            "Value #B": "Monitored",
        },
        sort_by="Check Name",
        desc="Current status and monitored state for all configured monit checks.",
    )

    # ------------------------------------------------------------------ #
    # Row 3: Filesystem Check Resources (#219)                             #
    # ------------------------------------------------------------------ #
    fs_usage_ts = b.ts(
        "Filesystem Usage",
        [
            (sel("opnsense_monit_filesystem_usage_percent"), "{{name}} block"),
            (sel("opnsense_monit_filesystem_inode_usage_percent"), "{{name}} inode"),
        ],
        unit="percent", w=24, h=8,
        desc=(
            "opnsense_monit_filesystem_usage_percent / "
            "opnsense_monit_filesystem_inode_usage_percent: block (space) and inode usage "
            "percent for each monit filesystem check. The only disk-usage-percent source in "
            "the exporter besides the health subsystem gauge."
        ),
    )

    # ------------------------------------------------------------------ #
    # Row 4: Process Check Resources (#219)                                #
    # ------------------------------------------------------------------ #
    process_cpu_ts = b.ts(
        "Process CPU Usage",
        [(sel("opnsense_monit_process_cpu_percent"), "{{name}}")],
        unit="percent", w=12, h=8,
        desc=(
            "opnsense_monit_process_cpu_percent: CPU usage percent for each monit process "
            "check. Absent until monit's second poll cycle computes a rate (monit reports -1 "
            "beforehand; the exporter treats that sentinel as no data)."
        ),
    )
    process_mem_ts = b.ts(
        "Process Memory Usage",
        [(sel("opnsense_monit_process_memory_bytes"), "{{name}}")],
        unit="bytes", w=12, h=8,
        desc="opnsense_monit_process_memory_bytes: resident memory usage for each monit process check.",
    )
    process_uptime_ts = b.ts(
        "Process Uptime",
        [(sel("opnsense_monit_process_uptime_seconds"), "{{name}}")],
        unit="s", w=12, h=8,
        desc="opnsense_monit_process_uptime_seconds: uptime for each monit process check.",
    )
    process_threads_ts = b.ts(
        "Process Threads",
        [(sel("opnsense_monit_process_threads"), "{{name}}")],
        unit="short", w=12, h=8,
        desc="opnsense_monit_process_threads: thread count for each monit process check.",
    )

    # ------------------------------------------------------------------ #
    # Row 5: Host Check Resources (#219)                                   #
    # ------------------------------------------------------------------ #
    host_icmp_ts = b.ts(
        "Host ICMP Response Time",
        [(sel("opnsense_monit_host_icmp_response_seconds"), "{{name}}")],
        unit="s", w=12, h=8,
        desc="opnsense_monit_host_icmp_response_seconds: ICMP ping response time for each monit host check.",
    )
    host_port_ts = b.ts(
        "Host Port Response Time",
        [(sel("opnsense_monit_port_response_seconds"), "{{name}} :{{port}} ({{protocol}})")],
        unit="s", w=12, h=8,
        desc=(
            "opnsense_monit_port_response_seconds: connection response time for each monit "
            "host check's port/connection test."
        ),
    )

    # ------------------------------------------------------------------ #
    # Row 6: System Check Resources (#219)                                 #
    # ------------------------------------------------------------------ #
    system_load_ts = b.ts(
        "System Check Load Average",
        [(sel("opnsense_monit_system_load"), "{{name}} {{period}}")],
        unit="short", w=12, h=8,
        desc="opnsense_monit_system_load: load average (period=1m/5m/15m) for each monit system check.",
    )
    system_cpu_ts = b.ts(
        "System Check CPU Usage",
        [(sel("opnsense_monit_system_cpu_percent"), "{{name}} {{mode}}")],
        unit="percent", w=12, h=8,
        desc=(
            "opnsense_monit_system_cpu_percent: CPU usage percent by mode for each monit "
            "system check. Reported modes are platform-dependent (OPNsense/FreeBSD reports "
            "user/system/nice/hardirq)."
        ),
    )
    system_mem_swap_ts = b.ts(
        "System Check Memory & Swap",
        [
            (sel("opnsense_monit_system_memory_percent"), "{{name}} memory"),
            (sel("opnsense_monit_system_swap_percent"), "{{name}} swap"),
        ],
        unit="percent", w=24, h=8,
        desc=(
            "opnsense_monit_system_memory_percent / opnsense_monit_system_swap_percent: "
            "memory and swap usage percent for each monit system check."
        ),
    )

    b.tab("Monit", [
        b.row("Monit Overview",
              [svc, status_ok, checks_total, checks_ok, checks_monitored],
              present="has_monit"),
        b.row("Check Status Detail",
              [check_status_timeline, check_monitored_timeline, checks_table],
              present="has_monit"),
        b.row("Filesystem Check Resources",
              [fs_usage_ts],
              present="has_monit"),
        b.row("Process Check Resources",
              [process_cpu_ts, process_mem_ts, process_uptime_ts, process_threads_ts],
              present="has_monit"),
        b.row("Host Check Resources",
              [host_icmp_ts, host_port_ts],
              present="has_monit"),
        b.row("System Check Resources",
              [system_load_ts, system_cpu_ts, system_mem_swap_ts],
              present="has_monit"),
    ])
