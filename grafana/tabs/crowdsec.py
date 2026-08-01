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

## The Loki row (#591 item 5)

Every metric above is a COUNT. `opnsense_crowdsec_alerts_total` says forty things
were flagged and cannot say what or whom, because scenario and the banned address
are unbounded and must never be metric labels. The `crowdsec` log lane
(`--logs.crowdsec.enabled`, internal/logship/crowdsec.go) already ships both, plus
decision_type, country, as and duration, one record per new alert and per new
decision — and until #591 nothing read it. So the counters said how many; nothing
said which.

**Select on `opnsense_source`, never on `opnsense_subsystem`.** This lane builds its
attributes without `logship.AttrSubsystem`, so its records carry no subsystem label.
Note the near-miss: the SYSLOG receiver maps a `crowdsec` program name to
subsystem `ids` (internal/logship/syslog/registry.go), which is a different stream
carrying different records. `tests/test_loki_scoping.py` pins both ends.
"""

from builder import Builder, sel, loki_sel, loki_grp, RUNSTOP

CROWDSEC_STREAM = loki_sel('opnsense_source="crowdsec"')


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
        desc=('Total installed hub items (any component) whose status includes "tainted" '
              '— locally modified since install. ' + "Fleet total: this is a deliberate sum across every selected firewall (#468) — with two boxes picked, the number is both boxes' together."),
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
        desc=('Total installed hub items (any component) whose status includes "outdated" '
              '— a newer hub version is available. ' + "Fleet total: this is a deliberate sum across every selected firewall (#468) — with two boxes picked, the number is both boxes' together."),
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

    # ------------------------------------------------------------------ #
    # Row 6: Alert & Decision Records (Loki, --logs.crowdsec.enabled)      #
    # ------------------------------------------------------------------ #
    b.loki_sentinel("has_crowdsec_logs", matchers='opnsense_source="crowdsec"',
                    label="opnsense_source")

    cs_decisions_rate = b.loki_ts(
        "New Records/s by Decision Type",
        [(f'sum {loki_grp("decision_type")} (rate({CROWDSEC_STREAM} [$__auto]))',
          "{{decision_type}}")],
        unit="ops",
        desc="Newly observed CrowdSec records per second from the `crowdsec` log stream, split "
             "by enforcement type (ban / captcha / throttle). The series with an EMPTY "
             "decision_type is the alert records: an alert is an observation with no disposition "
             "of its own, so the lane deliberately leaves the key unset on it — alerts and "
             "decisions are separate LAPI objects with independent id cursors. Read this against "
             "Active Decisions above, which is a current TOTAL that falls as bans expire; this "
             "is the arrival rate and never falls.",
    )
    cs_scenarios = b.loki_table(
        "Top Scenarios",
        [f'topk {loki_grp()} (200, sum {loki_grp("scenario")} (count_over_time({CROWDSEC_STREAM} '
         '| scenario!="" [$__range])))'],
        field_title="Scenario",
        desc="Which CrowdSec scenarios fired, over the selected range. The scenario name is "
             "structured metadata on the record and is deliberately not a metric label, so this "
             "is the only place the estate can say WHAT the alert count above is made of. Counts "
             "alert and decision records together — a scenario that produced a ban appears in "
             "both, which is the normal path rather than double counting.",
    )
    cs_values = b.loki_table(
        "Top Flagged Addresses",
        [f'topk {loki_grp()} (200, sum {loki_grp("value")} (count_over_time({CROWDSEC_STREAM} '
         '| value!="" [$__range])))'],
        field_title="Flagged Value",
        # Deliberately NOT window-pinned, unlike the unbounded-label tables on the
        # Zenarmor and DNS tabs. This lane emits one record per NEW alert or decision
        # at a 60s poll floor, not one per connection, so a range wide enough to
        # approach Loki's series ceiling would take weeks rather than hours. If it
        # ever does return a query error, pin time_from rather than lowering topk —
        # the ceiling is enforced on a query intermediate, so the rank depth is not
        # the lever.
        desc="The scope values CrowdSec acted on — an address for a scope:ip decision, which is "
             "the overwhelmingly common case. High cardinality by nature, which is why it is "
             "structured metadata and never a label. Counts alert and decision records together, "
             "so an address alerted on and then banned appears twice; the decision-type panel "
             "beside this separates the two.",
    )
    cs_raw_logs = b.logs(
        "Raw CrowdSec Records",
        CROWDSEC_STREAM,
        desc="Unfiltered `crowdsec` log stream (--logs.crowdsec.enabled). Each body is a compact "
             "JSON object whose `kind` is either alert or decision; structured metadata carries "
             "scenario, value, country, as, and — on decisions only — decision_type and "
             "duration. This is the only path these records take: the CrowdSec plugin registers "
             "no syslog scope, so alerts live solely in the LAPI. On a cold start the lane ships "
             "every currently-active alert and decision once, so the first window after enabling "
             "it shows existing state rather than only new events.",
        w=24,
    )

    b.tab("CrowdSec", [
        b.autogrid_row("CrowdSec Overview",
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
        # Collapsed (#422): range queries over a log stream cost round-trips on every
        # cold load, and this row is the drill-down an operator opens after the
        # counters above raised a question.
        b.row("Alert & Decision Records",
              [cs_decisions_rate, cs_scenarios, cs_values, cs_raw_logs],
              present="has_crowdsec_logs", collapse=True),
    ])
