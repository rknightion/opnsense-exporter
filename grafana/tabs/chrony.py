"""
Chrony tab — covers all opnsense_chrony_* metrics.

Gated on the presence of opnsense_chrony_stratum so the tab only shows
when the chrony plugin is installed and scraping.

Note on label churn: with a `pool` directive chrony rotates resolved
servers over time, so the `source` label set churns. Per-source panels
use instant-query tables rather than long-range per-source timeseries
to handle this gracefully.

Rows:
  1. Service & Sync      — service_running stat, stratum stat, leap_status stat
  2. Tracking            — system_time_offset, last_offset, rms_offset, frequency gauges/ts;
                           update_interval, root_delay/dispersion; tracking_info table
  3. Sources             — sources_total stat; source selected/stratum/reachability/last_rx table;
                           offset timeseries
  4. Source Statistics   — source_offset_stddev, source_samples table
"""

from builder import Builder, sel, RUNSTOP


# Leap status mapping: 0=Normal, 1=Insert, 2=Delete, 3=Not synchronised
_LEAP = {
    "0": ("Normal", "green"),
    "1": ("Insert second", "yellow"),
    "2": ("Delete second", "yellow"),
    "3": ("Not synchronised", "red"),
}


def build(b: Builder):
    # ---- Sentinels ---------------------------------------------------------
    b.sentinel("has_chrony",
               "label_values(opnsense_chrony_stratum, __name__)")

    # ================================================================
    # Row 1: Service & Sync
    # ================================================================
    svc = b.stat(
        "Chrony Service",
        sel("opnsense_chrony_service_running"),
        mappings=RUNSTOP, color_mode="background",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        w=4, h=4,
        desc="1 = chrony service is running, 0 = stopped/disabled.",
    )
    stratum = b.stat(
        "Stratum",
        sel("opnsense_chrony_stratum"),
        unit="short", w=4, h=4,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "yellow", "value": 4},
            {"color": "red", "value": 8},
        ],
        color_mode="background",
        desc=(
            "Current NTP stratum. Lower is better (1 = GPS/atomic, "
            "16 = unsynchronised)."
        ),
    )
    leap = b.stat(
        "Leap Status",
        sel("opnsense_chrony_leap_status"),
        mappings=_LEAP, color_mode="background",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 0}],
        w=4, h=4,
        desc=(
            "chronyc Leap Status: 0=Normal, 1=Insert second, "
            "2=Delete second, 3=Not synchronised."
        ),
    )
    sources_total = b.stat(
        "Sources",
        sel("opnsense_chrony_sources_total"),
        unit="short", w=4, h=4,
        desc="Total number of NTP sources configured in chrony.",
    )

    # ================================================================
    # Row 2: Tracking
    # ================================================================
    tracking_info = b.table(
        "Chrony Tracking Info",
        [sel("opnsense_chrony_tracking_info")],
        w=12, h=4,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "reference_id": "Reference ID",
            "reference_name": "Reference Name",
            "leap_status": "Leap Status",
        },
        sort_by="Reference Name",
        desc="Current chrony reference info (value always 1).",
    )
    sys_offset = b.ts(
        "System Time Offset",
        [(sel("opnsense_chrony_system_time_offset_seconds"), "offset (fast=+, slow=−)"),
         (sel("opnsense_chrony_last_offset_seconds"), "last offset"),
         (sel("opnsense_chrony_rms_offset_seconds"), "RMS offset")],
        unit="s", w=12, h=8,
        desc=(
            "System clock offset from NTP time. Negative = slow; "
            "rms_offset is the long-term root-mean-square."
        ),
    )
    freq_ts = b.ts(
        "Frequency Error (ppm)",
        [(sel("opnsense_chrony_frequency_ppm"), "frequency"),
         (sel("opnsense_chrony_residual_frequency_ppm"), "residual"),
         (sel("opnsense_chrony_skew_ppm"), "skew")],
        unit="ppm", w=12, h=8,
        desc="chrony frequency error metrics in parts per million.",
    )
    root_ts = b.ts(
        "Root Delay & Dispersion",
        [(sel("opnsense_chrony_root_delay_seconds"), "root delay"),
         (sel("opnsense_chrony_root_dispersion_seconds"), "root dispersion")],
        unit="s", w=12, h=8,
        desc=(
            "Root delay = total round-trip to the reference clock. "
            "Root dispersion = accumulated error from the reference."
        ),
    )
    update_interval = b.ts(
        "Tracking Update Interval",
        [(sel("opnsense_chrony_update_interval_seconds"), "update interval")],
        unit="s", w=12, h=8,
        desc="Interval between the last two clock updates.",
    )

    # ================================================================
    # Row 3: Sources
    # ================================================================
    source_table = b.table(
        "Source Status",
        [
            sel("opnsense_chrony_source_selected"),
            sel("opnsense_chrony_source_stratum"),
            sel("opnsense_chrony_source_reachability"),
            sel("opnsense_chrony_source_last_rx_seconds"),
        ],
        w=24, h=10,
        excludes=["__name__", "job", "instance"],
        renames={
            "source": "Source",
            "mode": "Mode",
            "opnsense_chrony_source_selected": "Selected",
            "opnsense_chrony_source_stratum": "Stratum",
            "opnsense_chrony_source_reachability": "Reachability",
            "opnsense_chrony_source_last_rx_seconds": "Last RX (s)",
        },
        unit_overrides={"Last RX (s)": "s"},
        sort_by="Source",
        desc=(
            "Per-source NTP status. Selected=1 means this is the active reference. "
            "Reachability is an 8-bit shift register (255=fully reachable). "
            "Last RX = seconds since the last valid packet was received."
        ),
    )
    source_offset = b.ts(
        "Source Offset",
        [(sel("opnsense_chrony_source_offset_seconds"), "{{source}}")],
        unit="s", w=24, h=8,
        desc=(
            "Measured time offset from each NTP source. "
            "Note: source label set may churn with a pool directive."
        ),
    )

    # ================================================================
    # Row 4: Source Statistics
    # ================================================================
    source_stats_table = b.table(
        "Source Statistics",
        [
            sel("opnsense_chrony_source_offset_stddev_seconds"),
            sel("opnsense_chrony_source_samples"),
        ],
        w=24, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "source": "Source",
            "opnsense_chrony_source_offset_stddev_seconds": "Offset Std Dev (s)",
            "opnsense_chrony_source_samples": "Samples",
        },
        unit_overrides={"Offset Std Dev (s)": "s"},
        sort_by="Source",
        desc=(
            "Per-source regression statistics from chronyc sourcestats. "
            "Std Dev measures dispersion of recent offset samples."
        ),
    )

    # ================================================================
    # Tab assembly
    # ================================================================
    b.tab("Chrony", [
        b.row("Service & Sync",
              [svc, stratum, leap, sources_total],
              present="has_chrony"),
        b.row("Tracking",
              [tracking_info, sys_offset, freq_ts, root_ts, update_interval],
              present="has_chrony"),
        b.row("Sources",
              [source_table, source_offset],
              present="has_chrony"),
        b.row("Source Statistics",
              [source_stats_table],
              present="has_chrony"),
    ])
