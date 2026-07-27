"""
Captive Portal tab — Captive Portal session + voucher metrics
(opnsense_captiveportal_*).

Plugin-gated: tab hidden unless captive portal reports at least one zone
(query_result(opnsense_captiveportal_zones_total > 0)).

All metrics are gauges (instantaneous counts — never rate()).
  service_running                    — service up/down
  zones_total                        — number of configured zones
  sessions_total                     — aggregate session count across all zones
  zone_sessions                      — per-zone session count (labels: zone_id, zone_description)
  vouchers                           — voucher count per (provider, group, state) (#207)
  voucher_group_next_expiry_seconds  — earliest hard-expiry epoch among a group's
                                        unused/valid vouchers (#207; only emitted for
                                        groups where at least one voucher has a hard
                                        expiry cutoff set — most don't)

Vouchers row is separately gated (has_captiveportal_vouchers): a box can have the
captive portal module configured with zero voucher-type auth servers, in which case
the vouchers metric family is never emitted at all.

SENSITIVITY (tracker #227): the voucher code itself (the API's "username" field) is
never modeled by the exporter and therefore never appears in any label here.
"""

from builder import Builder, sel, RUNSTOP


def build(b: Builder):
    # Existence, not `opnsense_captiveportal_zones_total > 0` (#414 / #114).
    #
    # THE RULE: use existence when the series only appears if the feature is
    # deployed; use a value test only when the series is emitted unconditionally.
    #
    # This collector returns early on a zones-endpoint 404, i.e. when the plugin is
    # not installed (internal/collector/captiveportal.go), so the series exists ONLY
    # on a box that has captive portal deployed. Existence therefore IS the
    # feature-presence signal, and the old `> 0` was a value-gate layered on top of
    # it — exactly the #114 shape that hid a live-but-idle DHCP backend along with
    # the health stat meant to answer "is it up?". A Captive Portal tab reading
    # "0 zones" on a box with the plugin installed is honest; hiding it misreports
    # what is deployed. Contrast opnsense_carp_vips_total in carp.py, which every
    # box emits and which therefore still needs the value test.
    b.sentinel("has_captiveportal", metric="opnsense_captiveportal_zones_total")
    b.sentinel("has_captiveportal_vouchers", metric="opnsense_captiveportal_vouchers")

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

    # ------------------------------------------------------------------ #
    # Row 3: Voucher Inventory                                             #
    # ------------------------------------------------------------------ #
    unused_stat = b.stat(
        "Unused Vouchers",
        f"sum({sel('opnsense_captiveportal_vouchers', 'state=\"unused\"')})",
        unit="short", w=4, h=4,
        thresholds=[
            {"color": "red", "value": None},
            {"color": "yellow", "value": 1},
            {"color": "green", "value": 10},
        ],
        desc=("Total unused (not yet redeemed) vouchers across every provider/group. "
             "A low or falling count is a run-out signal for guest network access."
             "Fleet total: this is a deliberate sum across every selected firewall (#468) — with two boxes picked, the number is both boxes' together."),
    )
    valid_stat = b.stat(
        "Valid (Active) Vouchers",
        f"sum({sel('opnsense_captiveportal_vouchers', 'state=\"valid\"')})",
        unit="short", w=4, h=4,
        desc=("Total vouchers currently redeemed and within their validity window."
             "Fleet total: this is a deliberate sum across every selected firewall (#468) — with two boxes picked, the number is both boxes' together."),
    )
    expired_stat = b.stat(
        "Expired Vouchers",
        f"sum({sel('opnsense_captiveportal_vouchers', 'state=\"expired\"')})",
        unit="short", w=4, h=4,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "yellow", "value": 50},
            {"color": "orange", "value": 200},
        ],
        desc=("Total expired vouchers across every provider/group — "
             "a large or growing count suggests the group needs cleanup."
             "Fleet total: this is a deliberate sum across every selected firewall (#468) — with two boxes picked, the number is both boxes' together."),
    )
    voucher_table = b.table(
        "Vouchers by Provider / Group / State",
        [sel("opnsense_captiveportal_vouchers")],
        w=12, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "provider": "Provider",
            "group": "Group",
            "state": "State",
            "Value": "Count",
            "opnsense_instance": "Instance",
        },
        sort_by="Count",
        sort_desc=True,
        desc="Current voucher count for every (provider, group, state) combination.",
    )
    voucher_expiry_table = b.table(
        "Voucher Group Next Hard Expiry",
        [f"({sel('opnsense_captiveportal_voucher_group_next_expiry_seconds')} - time()) / 3600"],
        w=24, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "provider": "Provider",
            "group": "Group",
            "Value": "Hours Left",
            "opnsense_instance": "Instance",
        },
        unit_overrides={"Hours Left": "h"},
        sort_by="Hours Left",
        sort_desc=False,
        desc="Hours remaining until each voucher group's earliest hard expiry "
             "cutoff (only shown for groups where at least one voucher has an "
             "absolute expiry deadline set — most vouchers rely on validity/first-use "
             "instead and never populate this). Negative = already past that cutoff.",
    )

    b.tab("Captive Portal", [
        b.row("Captive Portal Overview",
              [svc, zones_total, sessions_total],
              present="has_captiveportal"),
        b.row("Per-Zone Sessions",
              [zone_sessions_ts, zone_sessions_table],
              present="has_captiveportal"),
        b.row("Voucher Inventory",
              [unused_stat, valid_stat, expired_stat, voucher_table],
              present="has_captiveportal_vouchers"),
        b.row("Voucher Expiry",
              [voucher_expiry_table],
              present="has_captiveportal_vouchers"),
    ])
