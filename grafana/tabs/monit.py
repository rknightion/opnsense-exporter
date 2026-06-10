"""
Monit tab — Monit service/resource monitoring metrics (opnsense_monit_*).

Plugin-gated: tab hidden unless monit metrics are present.

All metrics are gauges (instantaneous values, no _total counters).
"""

from builder import Builder, sel, RUNSTOP, OKERR, UPDOWN


def build(b: Builder):
    b.sentinel("has_monit",
               "label_values(opnsense_monit_status_ok, __name__)")

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
        desc="Number of monit checks currently in OK state (status field == 0).",
    )
    checks_monitored = b.stat(
        "Checks Monitored",
        f'sum({sel("opnsense_monit_check_monitored")})',
        unit="short", w=4, h=4,
        desc="Number of monit checks actively being monitored (monitor != 0).",
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
        UPDOWN, w=24, h=8,
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
            "opnsense_monit_check_status": "Status OK",
            "opnsense_monit_check_monitored": "Monitored",
        },
        sort_by="Check Name",
        desc="Current status and monitored state for all configured monit checks.",
    )

    b.tab("Monit", [
        b.row("Monit Overview",
              [svc, status_ok, checks_total, checks_ok, checks_monitored],
              present="has_monit"),
        b.row("Check Status Detail",
              [check_status_timeline, check_monitored_timeline, checks_table],
              present="has_monit"),
    ])
