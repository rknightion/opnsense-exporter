"""
Tab module: CARP / HA

Covers the seven CARP metrics:
 - opnsense_carp_demotion   (stat)
 - opnsense_carp_allow      (stat, Yes/No coloured mapping)
 - opnsense_carp_maintenance_mode (stat, YESNO)
 - opnsense_carp_vips_total (stat, raw count)
 - opnsense_carp_vip_status       (statetimeline, per VIP)
 - opnsense_carp_vip_advbase_seconds (table)
 - opnsense_carp_vip_advskew      (table)

The tab itself is gated on has_carp; the VIP detail row is additionally gated
on has_carp_vips.
"""

from builder import Builder, sel, YESNO


# Custom mappings for CARP allow and VIP status.
_CARP_ALLOW = {
    "0": ("No", "red"),
    "1": ("Yes", "green"),
}

_VIP_STATUS = {
    "0":  ("BACKUP",  "blue"),
    "1":  ("MASTER",  "green"),
    "2":  ("INIT",    "orange"),
    "-1": ("Unknown", "red"),
}


def build(b: Builder):
    # ── Sentinels ─────────────────────────────────────────────────────────
    b.sentinel("has_carp", metric="opnsense_carp_allow")
    # Scoped, but the `> 0` comparison STAYS (#414). DO NOT "fix" this to plain
    # existence for consistency with the other sentinels — it is the deliberate
    # exception, and the reason is the metric's emission behaviour, not a preference.
    #
    # THE RULE: use existence when the series only appears if the feature is
    # deployed; use a value test only when the series is emitted unconditionally.
    #
    # CARP status is CORE, not a plugin, so internal/collector/carp.go emits
    # vips_total on every readable box — including as a literal 0 when no VIPs are
    # configured. Existence therefore conveys nothing about whether the feature is
    # in use, which makes `> 0` not a value-gate bolted onto a presence test but the
    # only presence test available. #414's "presence tests remain based on series
    # existence" is about not regressing #114; it is not a mandate to convert a
    # metric every box emits. Contrast opnsense_captiveportal_zones_total in
    # captiveportal.py, which is plugin-gated and so uses existence.
    b.sentinel("has_carp_vips", metric="opnsense_carp_vips_total", nonzero=True)

    # ══════════════════════════════════════════════════════════════════════
    # ROW 1 — CARP global state
    # ══════════════════════════════════════════════════════════════════════
    demotion = b.stat(
        "CARP Demotion Level",
        sel("opnsense_carp_demotion"),
        unit="short", w=6, h=4,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "yellow", "value": 1},
            {"color": "red", "value": 10},
        ],
        color_mode="value",
        desc="CARP demotion level; 0 = normal priority, higher values reduce election preference.",
    )

    allow = b.stat(
        "CARP Allowed",
        sel("opnsense_carp_allow"),
        unit="short", w=6, h=4,
        mappings=_CARP_ALLOW,
        color_mode="background",
        desc="Whether CARP is globally allowed on this node (1 = allowed).",
    )

    maintenance = b.stat(
        "CARP Maintenance Mode",
        sel("opnsense_carp_maintenance_mode"),
        unit="short", w=6, h=4,
        mappings=YESNO,
        color_mode="background",
        desc="Whether CARP maintenance mode is active; in maintenance mode the node demotes itself.",
    )

    vips_total = b.stat(
        "CARP VIPs Total",
        sel("opnsense_carp_vips_total"),
        unit="short", w=6, h=4,
        desc="Total number of configured CARP Virtual IPs (instantaneous count).",
    )

    # ══════════════════════════════════════════════════════════════════════
    # ROW 2 — VIP status & advertisement parameters (gated on has_carp_vips)
    # ══════════════════════════════════════════════════════════════════════
    vip_status = b.statetimeline(
        "CARP VIP Status",
        [
            (sel("opnsense_carp_vip_status"), "{{interface}} vhid={{vhid}} {{vip}}"),
        ],
        mappings=_VIP_STATUS,
        w=24, h=8,
        desc="CARP VIP state over time: MASTER, BACKUP, INIT, or Unknown.",
    )

    vip_adv_table = b.table(
        "VIP Advertisement Parameters",
        [
            sel("opnsense_carp_vip_advbase_seconds"),
            sel("opnsense_carp_vip_advskew"),
        ],
        renames={
            "interface": "Interface",
            "vhid":      "VHID",
            "vip":       "VIP",
            "Value #A":  "Advbase (s)",
            "Value #B":  "Advskew",
        },
        excludes=["opnsense_instance", "Time", "__name__", "job", "instance"],
        sort_by="Interface", sort_desc=False,
        w=24, h=10,
        desc="CARP VIP advertisement base interval (advbase) and advertisement skew (advskew) "
             "for each virtual IP.",
    )

    # ══════════════════════════════════════════════════════════════════════
    # Assemble tab (gated on has_carp)
    # ══════════════════════════════════════════════════════════════════════
    b.tab("CARP / HA", [
        b.row("CARP Global State",
              [demotion, allow, maintenance, vips_total]),
        b.row("VIP Status & Advertisement",
              [vip_status, vip_adv_table],
              present="has_carp_vips"),
    ], present="has_carp")
