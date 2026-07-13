"""
System & Resources tab for the OPNsense Exporter dashboard.

Covers:
  - System subsystem (12 metrics)
  - General health: opnsense_system_subsystem_status_code (per-subsystem health-check detail)
  - Activity subsystem (9 metrics)
  - Mbuf subsystem (14 metrics)
  - Temperature subsystem (1 metric) — gated by has_temperature sentinel
  - SMART subsystem (4 metrics) — gated by has_smart sentinel
  - Firmware subsystem (6 metrics)
"""

from builder import Builder, sel, epoch_ms, RATE, YESNO

# opnsense_system_subsystem_status_code value -> (display text, colour). OPNsense's
# SystemStatusCode enum: 2=OK, 1=NOTICE, 0=WARNING, -1=ERROR. OK is included for
# completeness even though OPNsense never reports an OK subsystem (only unhealthy ones
# appear in the payload — see collector.go's AllSubsystems doc).
_SUBSYS_STATUS = {
    "-1": ("Error", "red"),
    "0": ("Warning", "orange"),
    "1": ("Notice", "yellow"),
    "2": ("OK", "green"),
}


def build(b: Builder):
    # ---- sentinels ----------------------------------------------------------
    b.sentinel("has_temperature", "label_values(opnsense_temperature_celsius, __name__)")
    b.sentinel("has_smart", "label_values(opnsense_smart_device_health, __name__)")

    # =========================================================================
    # Row: Host Info
    # =========================================================================
    info_tbl = b.table(
        "System Info",
        [sel("opnsense_system_info")],
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "hostname": "Hostname",
            "opnsense_version": "OPNsense",
            "freebsd_version": "FreeBSD",
            "openssl_version": "OpenSSL",
            "cpu_model": "CPU Model",
            "cpu_cores": "Cores",
            "cpu_threads": "Threads",
            "opnsense_instance": "Instance",
        },
        w=24,
        h=6,
        desc="opnsense_system_info: system identification labels (value is always 1).",
    )

    uptime = b.stat(
        "Uptime",
        sel("opnsense_system_uptime_seconds"),
        unit="s",
        w=4,
        h=4,
        graph="none",
        desc="opnsense_system_uptime_seconds: seconds since boot.",
    )

    load1 = b.stat(
        "Load Avg 1m",
        sel("opnsense_system_load_average", 'interval="1"'),
        decimals=2,
        w=4,
        h=4,
        graph="area",
        desc="opnsense_system_load_average{interval=\"1\"}: 1-minute load average.",
    )

    load5 = b.stat(
        "Load Avg 5m",
        sel("opnsense_system_load_average", 'interval="5"'),
        decimals=2,
        w=4,
        h=4,
        graph="area",
        desc="opnsense_system_load_average{interval=\"5\"}: 5-minute load average.",
    )

    load15 = b.stat(
        "Load Avg 15m",
        sel("opnsense_system_load_average", 'interval="15"'),
        decimals=2,
        w=4,
        h=4,
        graph="area",
        desc="opnsense_system_load_average{interval=\"15\"}: 15-minute load average.",
    )

    config_change = b.stat(
        "Config Last Changed",
        epoch_ms(sel("opnsense_system_config_last_change")),
        unit="dateTimeAsIso",
        w=8,
        h=4,
        graph="none",
        instant=True,
        desc="opnsense_system_config_last_change: Unix timestamp of last configuration change.",
    )

    row_host = b.row("Host", [info_tbl, uptime, load1, load5, load15, config_change])

    # =========================================================================
    # Row: Subsystem Health (#218 — every health-check subsystem, not just
    # firewall/crashreporter: disk space, root lock, plugin config overrides, ...)
    # =========================================================================
    subsys_unhealthy_count = b.stat(
        "Unhealthy Subsystems",
        f'count({sel("opnsense_system_subsystem_status_code")} < 2) or vector(0)',
        thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}],
        color_mode="background",
        w=4,
        h=6,
        desc="Count of health-check subsystems currently NOT OK (opnsense_system_subsystem_status_code < 2). "
             "0 when every subsystem is healthy — OPNsense omits healthy subsystems from the payload.",
    )

    subsys_timeline = b.statetimeline(
        "Subsystem Status",
        [(sel("opnsense_system_subsystem_status_code"), "{{subsystem}}")],
        _SUBSYS_STATUS,
        w=20,
        h=6,
        desc="opnsense_system_subsystem_status_code: per-subsystem SystemStatusCode (disk space, root lock, "
             "crash reporter, firewall, plugin config overrides, ...). A subsystem's series is present only "
             "while unhealthy; its absence from the panel means it is OK.",
    )

    row_subsystem_health = b.row("Subsystem Health", [subsys_unhealthy_count, subsys_timeline])

    # =========================================================================
    # Row: Memory & Swap
    # =========================================================================
    mem_pct = b.gauge(
        "Memory Used %",
        f'100 * {sel("opnsense_system_memory_used_bytes")} / '
        f'clamp_min({sel("opnsense_system_memory_total_bytes")}, 1)',
        unit="percent",
        mx=100,
        w=4,
        h=6,
        desc="Derived: used / total memory × 100.",
    )

    mem_ts = b.ts(
        "Memory Over Time",
        [
            (sel("opnsense_system_memory_total_bytes"), "Total"),
            (sel("opnsense_system_memory_used_bytes"), "Used"),
            (sel("opnsense_system_memory_arc_bytes"), "ARC"),
        ],
        unit="bytes",
        w=12,
        h=6,
        desc="opnsense_system_memory_*_bytes: physical memory breakdown.",
    )

    swap_ts = b.ts(
        "Swap Over Time",
        [
            (sel("opnsense_system_swap_total_bytes"), "Total {{device}}"),
            (sel("opnsense_system_swap_used_bytes"), "Used {{device}}"),
        ],
        unit="bytes",
        w=8,
        h=6,
        desc="opnsense_system_swap_*_bytes: swap utilisation per device.",
    )

    row_mem = b.row("Memory & Swap", [mem_pct, mem_ts, swap_ts])

    # =========================================================================
    # Row: CPU & Threads
    # =========================================================================
    cpu_ts = b.ts(
        "CPU Usage",
        [
            (sel("opnsense_activity_cpu_user_percent"), "User"),
            (sel("opnsense_activity_cpu_nice_percent"), "Nice"),
            (sel("opnsense_activity_cpu_system_percent"), "System"),
            (sel("opnsense_activity_cpu_interrupt_percent"), "Interrupt"),
            (sel("opnsense_activity_cpu_idle_percent"), "Idle"),
        ],
        unit="percent",
        stack=True,
        w=12,
        h=8,
        desc="CPU time breakdown across user, nice, system, interrupt, idle.",
    )

    threads_total = b.stat(
        "Threads Total",
        sel("opnsense_activity_threads_total"),
        w=3,
        h=4,
        desc="opnsense_activity_threads_total: instantaneous total thread count (RAW, not rate).",
    )

    threads_running = b.stat(
        "Threads Running",
        sel("opnsense_activity_threads_running"),
        w=3,
        h=4,
        thresholds=[{"color": "green", "value": None}, {"color": "yellow", "value": 4}, {"color": "red", "value": 16}],
        desc="opnsense_activity_threads_running: number of threads actively running.",
    )

    threads_sleeping = b.stat(
        "Threads Sleeping",
        sel("opnsense_activity_threads_sleeping"),
        w=3,
        h=4,
        desc="opnsense_activity_threads_sleeping: number of threads sleeping.",
    )

    threads_waiting = b.stat(
        "Threads Waiting",
        sel("opnsense_activity_threads_waiting"),
        w=3,
        h=4,
        desc="opnsense_activity_threads_waiting: number of threads waiting on I/O or locks.",
    )

    row_cpu = b.row("CPU & Threads", [cpu_ts, threads_total, threads_running, threads_sleeping, threads_waiting])

    # =========================================================================
    # Row: Disk
    # =========================================================================
    disk_tbl = b.table(
        "Disk Usage",
        [
            sel("opnsense_system_disk_total_bytes"),
            sel("opnsense_system_disk_used_bytes"),
            sel("opnsense_system_disk_usage_ratio"),
        ],
        excludes=["Value", "__name__", "job", "instance", "opnsense_instance"],
        renames={
            "device": "Device",
            "type": "Type",
            "mountpoint": "Mountpoint",
            "Value #A": "Total",
            "Value #B": "Used",
            "Value #C": "Usage Ratio",
        },
        unit_overrides={
            "Total": "bytes",
            "Used": "bytes",
            "Usage Ratio": "percentunit",
        },
        sort_by="Mountpoint",
        sort_desc=False,
        w=16,
        h=8,
        desc="Disk space per device/mountpoint.",
    )

    disk_bar = b.bargauge(
        "Disk Usage % by Mountpoint",
        [
            (
                f'100 * {sel("opnsense_system_disk_usage_ratio")}',
                "{{mountpoint}}",
            )
        ],
        unit="percent",
        orient="horizontal",
        mx=100,
        w=8,
        h=8,
        desc="Disk fill % per mountpoint (100 × opnsense_system_disk_usage_ratio).",
    )

    row_disk = b.row("Disk", [disk_tbl, disk_bar])

    # =========================================================================
    # Row: Firmware
    # =========================================================================
    fw_info = b.table(
        "Firmware Info",
        [sel("opnsense_firmware_info")],
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "os_version": "OS Version",
            "product_version": "Product Version",
            "product_id": "Product ID",
            "product_abi": "ABI",
            "opnsense_instance": "Instance",
        },
        w=12,
        h=5,
        desc="opnsense_firmware_info: firmware metadata labels.",
    )

    fw_needs_reboot = b.stat(
        "Needs Reboot",
        sel("opnsense_firmware_needs_reboot"),
        mappings=YESNO,
        color_mode="background",
        thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}],
        w=3,
        h=4,
        desc="opnsense_firmware_needs_reboot: 1 if a reboot is required.",
    )

    fw_upgrade_reboot = b.stat(
        "Upgrade Needs Reboot",
        sel("opnsense_firmware_upgrade_needs_reboot"),
        mappings=YESNO,
        color_mode="background",
        thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}],
        w=3,
        h=4,
        desc="opnsense_firmware_upgrade_needs_reboot: 1 if pending upgrade requires reboot.",
    )

    fw_last_check = b.stat(
        "Last Firmware Check",
        epoch_ms(sel("opnsense_firmware_last_check_timestamp_seconds")),
        unit="dateTimeAsIso",
        w=6,
        h=4,
        graph="none",
        instant=True,
        desc="opnsense_firmware_last_check_timestamp_seconds: Unix timestamp of last update check.",
    )

    fw_new_pkgs = b.stat(
        "New Packages",
        sel("opnsense_firmware_new_packages_count"),
        thresholds=[{"color": "green", "value": None}, {"color": "yellow", "value": 1}],
        color_mode="background",
        w=3,
        h=4,
        desc="opnsense_firmware_new_packages_count: count of newly available packages.",
    )

    fw_upgrade_pkgs = b.stat(
        "Upgrade Packages",
        sel("opnsense_firmware_upgrade_packages_count"),
        thresholds=[{"color": "green", "value": None}, {"color": "yellow", "value": 1}],
        color_mode="background",
        w=3,
        h=4,
        desc="opnsense_firmware_upgrade_packages_count: count of packages with available upgrades.",
    )

    row_firmware = b.row("Firmware", [fw_info, fw_needs_reboot, fw_upgrade_reboot, fw_last_check, fw_new_pkgs, fw_upgrade_pkgs])

    # =========================================================================
    # Row: Firmware Packages (gated — requires --exporter.enable-firmware-package-details)
    # =========================================================================
    b.sentinel("has_firmware_details",
               "label_values(opnsense_firmware_plugin_installed, __name__)")
    fw_pending_updates = b.table(
        "Pending Package Updates",
        [sel("opnsense_firmware_package_update_available")],
        w=12, h=8,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "name": "Package",
            "installed_version": "Installed",
            "new_version": "Available",
        },
        sort_by="Package",
        desc="opnsense_firmware_package_update_available: one row per package with a pending update. Requires --exporter.enable-firmware-package-details.",
    )
    fw_plugins = b.table(
        "Installed Plugins",
        [sel("opnsense_firmware_plugin_installed")],
        w=12, h=8,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "name": "Plugin",
            "version": "Version",
        },
        sort_by="Plugin",
        desc="opnsense_firmware_plugin_installed: installed os-* plugin inventory. Requires --exporter.enable-firmware-package-details.",
    )
    row_firmware_details = b.row("Firmware Packages", [fw_pending_updates, fw_plugins],
                                 present="has_firmware_details")

    # =========================================================================
    # Row: Temperature (gated)
    # =========================================================================
    temp_ts = b.ts(
        "Temperature",
        [
            (sel("opnsense_temperature_celsius"), "{{device}} ({{type}})"),
        ],
        unit="celsius",
        w=16,
        h=8,
        desc="opnsense_temperature_celsius: sensor temperature per device.",
    )

    temp_max = b.stat(
        "Max Temperature",
        f'max({sel("opnsense_temperature_celsius")})',
        unit="celsius",
        w=8,
        h=8,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "yellow", "value": 70},
            {"color": "red", "value": 85},
        ],
        color_mode="value",
        desc="Maximum temperature across all sensors.",
    )

    row_temp = b.row("Temperature", [temp_ts, temp_max], present="has_temperature")

    # =========================================================================
    # Row: SMART (gated)
    # =========================================================================
    smart_total = b.stat(
        "SMART Devices",
        sel("opnsense_smart_devices_total"),
        w=4,
        h=4,
        desc="opnsense_smart_devices_total: number of SMART-monitored devices.",
    )

    smart_health = b.statetimeline(
        "Drive Health",
        [
            (
                sel("opnsense_smart_device_health"),
                "{{device}} ({{model}} / {{serial}})",
            )
        ],
        mappings={"0": ("Failed", "red"), "1": ("Passed", "green")},
        w=20,
        h=6,
        desc="opnsense_smart_device_health: 1=passed, 0=failed overall SMART assessment.",
    )

    smart_temp = b.ts(
        "Drive Temperature",
        [
            (sel("opnsense_smart_device_temperature_celsius"), "{{device}}"),
        ],
        unit="celsius",
        w=12,
        h=7,
        desc="opnsense_smart_device_temperature_celsius: drive temperature per device.",
    )

    smart_hours = b.ts(
        "Drive Power-On Hours",
        [
            (sel("opnsense_smart_device_power_on_hours"), "{{device}}"),
        ],
        unit="h",
        w=12,
        h=7,
        desc="opnsense_smart_device_power_on_hours: total powered-on hours per device.",
    )

    row_smart = b.row("SMART", [smart_total, smart_health, smart_temp, smart_hours], present="has_smart")

    # =========================================================================
    # Row: SMART Attributes & NVMe (gated)
    # =========================================================================
    # NOTE: with multiple exprs the merge transformation names the value
    # columns "Value #A".."Value #D" (by refId, in exprs order) — rename
    # THOSE, not the metric names.
    smart_attr_table = b.table(
        "SMART Attributes (SATA)",
        [
            sel("opnsense_smart_attribute_value"),      # -> Value #A
            sel("opnsense_smart_attribute_worst"),      # -> Value #B
            sel("opnsense_smart_attribute_threshold"),  # -> Value #C
            sel("opnsense_smart_attribute_raw"),        # -> Value #D
        ],
        w=16, h=10,
        excludes=["__name__", "job", "instance"],
        renames={
            "device": "Device",
            "attribute_id": "ID",
            "attribute_name": "Attribute",
            "Value #A": "Value",
            "Value #B": "Worst",
            "Value #C": "Threshold",
            "Value #D": "Raw",
        },
        sort_by="Device",
        desc="opnsense_smart_attribute_value/worst/threshold/raw per SATA SMART attribute. "
             "Raw values of IDs 5/187/197/198 indicate failing media when non-zero.",
    )
    smart_attr_critical = b.ts(
        "Critical Attribute Raw Values",
        [(sel("opnsense_smart_attribute_raw",
              'attribute_id=~"5|187|197|198|199"'),
          "{{device}} {{attribute_name}}")],
        unit="short", w=8, h=10,
        desc="opnsense_smart_attribute_raw for reallocated/uncorrectable/pending/"
             "offline-uncorrectable/CRC error counters. Any sustained rise is a failing disk.",
    )

    nvme_spare = b.gauge(
        "NVMe Available Spare",
        sel("opnsense_smart_nvme_available_spare_percent"),
        unit="percent", w=4, h=6,
        thresholds=[
            {"color": "red", "value": None},
            {"color": "yellow", "value": 10},
            {"color": "green", "value": 50},
        ],
    )
    nvme_used = b.gauge(
        "NVMe Life Used",
        sel("opnsense_smart_nvme_percentage_used"),
        unit="percent", w=4, h=6, mx=120,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "yellow", "value": 80},
            {"color": "red", "value": 100},
        ],
    )
    nvme_errors = b.ts(
        "NVMe Errors & Unsafe Shutdowns",
        [
            (f'rate({sel("opnsense_smart_nvme_media_errors_total")}[{RATE}])',
             "{{device}} media errors/s"),
            (f'rate({sel("opnsense_smart_nvme_unsafe_shutdowns_total")}[{RATE}])',
             "{{device}} unsafe shutdowns/s"),
        ],
        unit="short", w=8, h=6,
        desc="Rates of opnsense_smart_nvme_media_errors_total and "
             "opnsense_smart_nvme_unsafe_shutdowns_total.",
    )
    nvme_throughput = b.ts(
        "NVMe Data Units Read/Written",
        [
            (f'rate({sel("opnsense_smart_nvme_data_units_read_total")}[{RATE}]) * 512000',
             "{{device}} read B/s"),
            (f'rate({sel("opnsense_smart_nvme_data_units_written_total")}[{RATE}]) * 512000',
             "{{device}} written B/s"),
        ],
        unit="Bps", w=8, h=6,
        desc="1 data unit = 1000 x 512 bytes, hence x 512000 for bytes/s.",
    )

    row_smart_detail = b.row(
        "SMART Attributes & NVMe",
        [smart_attr_table, smart_attr_critical, nvme_spare, nvme_used, nvme_errors, nvme_throughput],
        present="has_smart",
    )

    # =========================================================================
    # Row: mbuf
    # =========================================================================
    mbuf_ts = b.ts(
        "mbuf Counts",
        [
            (sel("opnsense_mbuf_current"), "Current"),
            (sel("opnsense_mbuf_cache"), "Cache"),
            (sel("opnsense_mbuf_total"), "Total"),
        ],
        unit="short",
        w=12,
        h=8,
        desc="opnsense_mbuf current/cache/total: instantaneous mbuf counts (RAW).",
    )

    mbuf_cluster_ts = b.ts(
        "mbuf Cluster Counts",
        [
            (sel("opnsense_mbuf_cluster_current"), "Current"),
            (sel("opnsense_mbuf_cluster_cache"), "Cache"),
            (sel("opnsense_mbuf_cluster_total"), "Total"),
            (sel("opnsense_mbuf_cluster_max"), "Max"),
        ],
        unit="short",
        w=12,
        h=8,
        desc="opnsense_mbuf_cluster_*: instantaneous cluster counts (all RAW per AUTHORING exception list).",
    )

    mbuf_bytes_ts = b.ts(
        "mbuf Memory",
        [
            (sel("opnsense_mbuf_bytes_in_use"), "In Use"),
            (sel("opnsense_mbuf_bytes_total"), "Total"),
        ],
        unit="bytes",
        w=12,
        h=7,
        desc="opnsense_mbuf_bytes_*: mbuf memory in bytes (RAW).",
    )

    mbuf_failures_ts = b.ts(
        "mbuf Failures (rate)",
        [
            (f'rate({sel("opnsense_mbuf_failures_total")}[{RATE}])', "{{type}} failures"),
        ],
        unit="ops",
        w=6,
        h=7,
        desc="opnsense_mbuf_failures_total: rate of mbuf allocation failures by type.",
    )

    mbuf_sleeps_ts = b.ts(
        "mbuf Sleeps (rate)",
        [
            (f'rate({sel("opnsense_mbuf_sleeps_total")}[{RATE}])', "{{type}} sleeps"),
        ],
        unit="ops",
        w=6,
        h=7,
        desc="opnsense_mbuf_sleeps_total: rate of mbuf allocation sleeps by type.",
    )

    mbuf_sendfile_ts = b.ts(
        "sendfile Activity (rate)",
        [
            (f'rate({sel("opnsense_mbuf_sendfile_syscalls_total")}[{RATE}])', "Syscalls"),
            (f'rate({sel("opnsense_mbuf_sendfile_io_total")}[{RATE}])', "I/O ops"),
            (f'rate({sel("opnsense_mbuf_sendfile_pages_sent_total")}[{RATE}])', "Pages sent"),
        ],
        unit="ops",
        w=12,
        h=7,
        desc="opnsense_mbuf_sendfile_*_total: sendfile throughput rates.",
    )

    row_mbuf = b.row("mbuf", [
        mbuf_ts,
        mbuf_cluster_ts,
        mbuf_bytes_ts,
        mbuf_failures_ts,
        mbuf_sleeps_ts,
        mbuf_sendfile_ts,
    ])

    # =========================================================================
    # Assemble tab
    # =========================================================================
    b.tab("System & Resources", [
        row_host,
        row_subsystem_health,
        row_mem,
        row_cpu,
        row_disk,
        row_firmware,
        row_firmware_details,
        row_temp,
        row_smart,
        row_smart_detail,
        row_mbuf,
    ])
