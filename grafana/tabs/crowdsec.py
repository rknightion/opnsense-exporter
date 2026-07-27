"""
CrowdSec tab — CrowdSec IPS/IDS metrics via os-crowdsec plugin (opnsense_crowdsec_*).

Plugin-gated: tab hidden unless crowdsec metrics are present.

Counts (alerts_total, decisions_total, bouncers_total, machines_total) are
instantaneous gauges — show raw, never rate().
bouncer_last_pull_timestamp_seconds / machine_last_heartbeat_timestamp_seconds
are unix timestamps — shown as age: time() - <ts>.

hub_items (component, status) is an aggregated instantaneous gauge — never
rate(), never per-item name labels (a collection pulls in 50-200
scenarios/parsers). version_info is an info metric (value always 1) — table
only, per AUTHORING.md rule 7.
"""

from builder import Builder, sel, RUNSTOP


def build(b: Builder):
    b.sentinel("has_crowdsec", metric="opnsense_crowdsec_service_running")
    b.sentinel("has_crowdsec_hub_items", metric="opnsense_crowdsec_hub_items")
    b.sentinel("has_crowdsec_version", metric="opnsense_crowdsec_version_info")

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
            "Value #A": "Valid",
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
            "Value #A": "Validated",
            "Value #B": "Last Heartbeat Age (s)",
        },
        sort_by="Machine",
        desc=(
            "Per-machine validation status and age since last heartbeat. "
            "Last Heartbeat Age is seconds since the machine last checked in."
        ),
    )

    # ------------------------------------------------------------------ #
    # Row 4: Hub Component Health (#205)                                   #
    # ------------------------------------------------------------------ #
    hub_tainted_sel = sel("opnsense_crowdsec_hub_items", 'status=~".*tainted.*"')
    hub_outdated_sel = sel("opnsense_crowdsec_hub_items", 'status=~".*outdated.*"')
    hub_tainted = b.stat(
        "Tainted Hub Items",
        "sum(" + hub_tainted_sel + ") or vector(0)",
        unit="short", w=4, h=4,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "red", "value": 1},
        ],
        color_mode="background",
        desc='Total installed hub items (any component) whose status includes "tainted" — locally modified since install.',
    )
    hub_outdated = b.stat(
        "Outdated Hub Items",
        "sum(" + hub_outdated_sel + ") or vector(0)",
        unit="short", w=4, h=4,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "orange", "value": 1},
        ],
        color_mode="background",
        desc='Total installed hub items (any component) whose status includes "outdated" — a newer hub version is available.',
    )
    hub_items_table = b.table(
        "Hub Component Health",
        [sel("opnsense_crowdsec_hub_items")],
        w=24, h=10,
        excludes=["__name__", "job", "instance"],
        renames={
            "component": "Component",
            "status": "Status",
            "Value": "Count",
        },
        sort_by="Component",
        desc=(
            "Installed hub item counts per component (collection/scenario/parser/"
            "postoverflow/appsec_config/appsec_rule) and status. Aggregated only — "
            "never per-item name, since a single collection can pull in 50-200 "
            "scenarios/parsers."
        ),
    )

    # ------------------------------------------------------------------ #
    # Row 5: Engine Version (#205)                                         #
    # ------------------------------------------------------------------ #
    version_table = b.table(
        "Engine Version",
        [sel("opnsense_crowdsec_version_info")],
        w=24, h=4,
        excludes=["Value", "__name__", "job", "instance"],
        renames={"version": "Engine Version"},
        desc="CrowdSec engine (cscli) version, parsed from cscli version's raw text output.",
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
        b.row("Hub Component Health",
              [hub_tainted, hub_outdated, hub_items_table],
              present="has_crowdsec_hub_items"),
        b.row("Engine Version",
              [version_table],
              present="has_crowdsec_version"),
    ])
