"""
Captive Portal tab — Captive Portal session metrics (opnsense_captiveportal_*).

Plugin-gated: tab hidden unless captive portal reports at least one zone
(query_result(opnsense_captiveportal_zones_total > 0)).

All metrics are gauges (instantaneous counts — never rate()).
  service_running        — service up/down
  zones_total            — number of configured zones
  sessions_total         — aggregate session count across all zones
  zone_sessions          — per-zone session count (labels: zone_id, zone_description)
"""

from builder import Builder, sel, RUNSTOP


def build(b: Builder):
    b.sentinel("has_captiveportal",
               "query_result(opnsense_captiveportal_zones_total > 0)")

    # ------------------------------------------------------------------ #
    # Row 1: Captive Portal Overview                                       #
    # ------------------------------------------------------------------ #
    svc = b.stat(
        "Captive Portal Service",
        sel("opnsense_captiveportal_service_running"),
        mappings=RUNSTOP, color_mode="background",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        w=4, h=4,
        desc="Captive portal service state (1 = running, 0 = stopped).",
    )
    zones_total = b.stat(
        "Zones Configured",
        sel("opnsense_captiveportal_zones_total"),
        unit="short", w=4, h=4,
        desc="Total number of configured captive portal zones.",
    )
    sessions_total = b.stat(
        "Total Sessions",
        sel("opnsense_captiveportal_sessions_total"),
        unit="short", w=4, h=4,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "yellow", "value": 50},
            {"color": "orange", "value": 200},
        ],
        desc="Total active sessions across all captive portal zones.",
    )

    # ------------------------------------------------------------------ #
    # Row 2: Per-Zone Sessions                                             #
    # ------------------------------------------------------------------ #
    zone_sessions_ts = b.ts(
        "Sessions per Zone",
        [(sel("opnsense_captiveportal_zone_sessions"),
          "{{zone_description}} (zone {{zone_id}})")],
        unit="short", w=16, h=8,
        desc="Active session count per captive portal zone over time.",
    )
    zone_sessions_table = b.table(
        "Zone Session Counts",
        [sel("opnsense_captiveportal_zone_sessions")],
        w=8, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "zone_id": "Zone ID",
            "zone_description": "Zone",
            "Value": "Sessions",
        },
        sort_by="Sessions",
        desc="Current session count per captive portal zone.",
    )

    b.tab("Captive Portal", [
        b.row("Captive Portal Overview",
              [svc, zones_total, sessions_total],
              present="has_captiveportal"),
        b.row("Per-Zone Sessions",
              [zone_sessions_ts, zone_sessions_table],
              present="has_captiveportal"),
    ])
