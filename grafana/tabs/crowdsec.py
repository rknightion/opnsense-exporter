"""
CrowdSec tab — CrowdSec IPS/IDS metrics via os-crowdsec plugin (opnsense_crowdsec_*).

Plugin-gated: tab hidden unless crowdsec metrics are present.

Counts (alerts_total, decisions_total, bouncers_total, machines_total) are
instantaneous gauges — show raw, never rate().
bouncer_last_pull_timestamp_seconds / machine_last_heartbeat_timestamp_seconds
are unix timestamps — shown as age: time() - <ts>.
"""

from builder import Builder, sel, RUNSTOP


def build(b: Builder):
    b.sentinel("has_crowdsec",
               "label_values(opnsense_crowdsec_service_running, __name__)")

    # ------------------------------------------------------------------ #
    # Row 1: CrowdSec Overview                                             #
    # ------------------------------------------------------------------ #
    svc = b.stat(
        "CrowdSec Service",
        sel("opnsense_crowdsec_service_running"),
        mappings=RUNSTOP, color_mode="background",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        w=4, h=4,
        desc="CrowdSec service state (1 = running, 0 = stopped).",
    )
    alerts = b.stat(
        "Active Alerts",
        sel("opnsense_crowdsec_alerts_total"),
        unit="short", w=4, h=4,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "orange", "value": 1},
            {"color": "red", "value": 100},
        ],
        color_mode="background",
        desc="Total number of active CrowdSec alerts.",
    )
    decisions = b.stat(
        "Active Decisions",
        sel("opnsense_crowdsec_decisions_total"),
        unit="short", w=4, h=4,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "orange", "value": 1},
        ],
        color_mode="background",
        desc="Total number of active CrowdSec decisions (bans/captchas etc.).",
    )
    bouncers = b.stat(
        "Bouncers",
        sel("opnsense_crowdsec_bouncers_total"),
        unit="short", w=4, h=4,
        desc="Total number of registered CrowdSec bouncers.",
    )
    machines = b.stat(
        "Machines",
        sel("opnsense_crowdsec_machines_total"),
        unit="short", w=4, h=4,
        desc="Total number of registered CrowdSec machines.",
    )

    # ------------------------------------------------------------------ #
    # Row 2: Bouncer Details                                               #
    # ------------------------------------------------------------------ #
    bouncer_valid_ts = b.statetimeline(
        "Bouncer Valid State",
        [(sel("opnsense_crowdsec_bouncer_valid"), "{{name}} ({{type}})")],
        {"0": ("Invalid", "red"), "1": ("Valid", "green")},
        w=24, h=6,
        desc="Whether each bouncer is in a valid state over time.",
    )
    bouncer_table = b.table(
        "Bouncer Details",
        [
            sel("opnsense_crowdsec_bouncer_valid"),
            f'time() - {sel("opnsense_crowdsec_bouncer_last_pull_timestamp_seconds")}',
        ],
        w=24, h=10,
        excludes=["__name__", "job", "instance"],
        renames={
            "name": "Bouncer",
            "type": "Type",
            "opnsense_crowdsec_bouncer_valid": "Valid",
            "Value #B": "Last Pull Age (s)",
        },
        sort_by="Bouncer",
        desc=(
            "Per-bouncer validity and age since last pull. "
            "Last Pull Age is seconds since the bouncer last contacted the LAPI."
        ),
    )

    # ------------------------------------------------------------------ #
    # Row 3: Machine Details                                               #
    # ------------------------------------------------------------------ #
    machine_validated_ts = b.statetimeline(
        "Machine Validated State",
        [(sel("opnsense_crowdsec_machine_validated"), "{{name}}")],
        {"0": ("Unvalidated", "orange"), "1": ("Validated", "green")},
        w=24, h=6,
        desc="Whether each machine is validated over time.",
    )
    machine_table = b.table(
        "Machine Details",
        [
            sel("opnsense_crowdsec_machine_validated"),
            f'time() - {sel("opnsense_crowdsec_machine_last_heartbeat_timestamp_seconds")}',
        ],
        w=24, h=10,
        excludes=["__name__", "job", "instance"],
        renames={
            "name": "Machine",
            "opnsense_crowdsec_machine_validated": "Validated",
            "Value #B": "Last Heartbeat Age (s)",
        },
        sort_by="Machine",
        desc=(
            "Per-machine validation status and age since last heartbeat. "
            "Last Heartbeat Age is seconds since the machine last checked in."
        ),
    )

    b.tab("CrowdSec", [
        b.row("CrowdSec Overview",
              [svc, alerts, decisions, bouncers, machines],
              present="has_crowdsec"),
        b.row("Bouncer Details",
              [bouncer_valid_ts, bouncer_table],
              present="has_crowdsec"),
        b.row("Machine Details",
              [machine_validated_ts, machine_table],
              present="has_crowdsec"),
    ])
