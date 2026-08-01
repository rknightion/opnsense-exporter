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

plus the syslog-derived transition counter:
 - opnsense_log_events_carp_total  (timeseries, #405)

The tab itself is gated on has_carp; the VIP detail row is additionally gated
on has_carp_vips, and the transition-event row on has_log_events_carp.
"""

from builder import Builder, RATE, sel, YESNO
from uids import to_tab


# Custom mappings for CARP allow and VIP status.
_CARP_ALLOW = {
    "0": ("No", "red"),
    "1": ("Yes", "green"),
}

_VIP_STATUS = {
    "0":  ("BACKUP",  "blue"),
    "1":  ("MASTER",  "green"),
    "2":  ("INIT",    "orange"),
    # #503 added 3 = DISABLED: emitted for any configured VIP the ifconfig pass did not
    # find (admin-disabled, or its interface is down). Routine, so it must not be green —
    # unmapped it fell through to the >=1 threshold and looked exactly like MASTER (#511).
    "3":  ("DISABLED", "text"),
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
    # #405. Plain existence, and NOT nonzero: unlike vips_total above, this counter is
    # absent entirely until syslog shipping sees a kernel CARP line, so the series IS
    # the presence signal. Deliberately its own sentinel rather than has_carp — a box
    # can have CARP configured and running while shipping no syslog to the exporter,
    # and gating on has_carp would render this row permanently empty there.
    b.sentinel("has_log_events_carp", metric="opnsense_log_events_carp_total")

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
            "Value #B":  "Advskew", "opnsense_instance": "Instance"},
        excludes=["Time", "__name__", "job", "instance"],
        sort_by="Interface", sort_desc=False,
        w=24, h=10,
        desc="CARP VIP advertisement base interval (advbase) and advertisement skew (advskew) "
             "for each virtual IP.",
    )

    # ══════════════════════════════════════════════════════════════════════
    # ROW 3 — kernel CARP transition events (#405, gated on has_log_events_carp)
    # ══════════════════════════════════════════════════════════════════════
    carp_events = b.ts(
        "CARP Transition Events",
        [(f'sum by (opnsense_instance, event, from, to, interface, vhid) '
          f'(rate({sel("opnsense_log_events_carp_total")}[{RATE}]))',
          "{{event}} {{from}}->{{to}} {{interface}} vhid={{vhid}}")],
        unit="ops", w=24, h=8,
        desc="Rate of FreeBSD kernel CARP transitions parsed from received syslog. event is "
             "state_changed (a MASTER/BACKUP/INIT move), demoted or promoted; demoted and "
             "promoted are the same kernel line distinguished by the SIGN of its demotion "
             "delta. from/to/interface/vhid are empty on a demotion, which is global to the "
             "node and names neither. Read it beside the CARP VIP Status timeline above: that "
             "shows the state now, this shows the transitions that produced it - a VIP sitting "
             "on MASTER while this stays busy is a flapping pair. The kernel's CAUSE is "
             "deliberately not a label (it is open-ended free text across FreeBSD versions); "
             "it ships on the log record as carp.reason, with carp.demotion.delta and "
             "carp.demotion.total. Absent until syslog shipping sees a kernel CARP line.",
    )

    # ══════════════════════════════════════════════════════════════════════
    # Assemble tab (gated on has_carp)
    # ══════════════════════════════════════════════════════════════════════
    # ---- drilldowns (#419) ------------------------------------------------
    # A failover is only half a story on this tab: the kernel's reason ships on the
    # syslog record (carp.reason), and whether the peer pair is actually in sync is
    # the HA Sync tab. Both links keep the window, which is what makes them useful
    # during an incident rather than after it.
    b.panel_links(vip_status, [
        to_tab("HA sync state for this window", "System", "HA Sync"),
        to_tab("Raw syslog for this window", "Services", "Syslog", loki=True),
    ])
    b.panel_links(carp_events, [
        to_tab("Raw syslog for this window", "Services", "Syslog", loki=True),
    ])

    b.tab("CARP / HA", [
        b.autogrid_row("CARP Global State",
              [demotion, allow, maintenance, vips_total]),
        b.row("VIP Status & Advertisement",
              [vip_status, vip_adv_table],
              present="has_carp_vips"),
        b.row("Transition Events (from syslog)",
              [carp_events],
              present="has_log_events_carp"),
    ], present="has_carp")
