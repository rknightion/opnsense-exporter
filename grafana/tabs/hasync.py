"""
HA Sync Status tab — covers all opnsense_hasync_* metrics.

This collector is opt-in (--exporter.enable-hasync) and performs a live
XML-RPC call to the HA peer on every scrape. The tab is gated on the
presence of opnsense_hasync_remote_reachable so it stays hidden when the
collector is disabled or the peer is unconfigured.

Rows:
  1. HA Sync Status    — remote_reachable, version_match stats; version_info table
  2. Remote Services   — services_total stat; per-service running statetimeline
"""

from builder import Builder, sel, RUNSTOP, UPDOWN


def build(b: Builder):
    # ---- Sentinels ---------------------------------------------------------
    b.sentinel("has_hasync", metric="opnsense_hasync_remote_reachable")

    # ================================================================
    # Row 1: HA Sync Status
    # ================================================================
    reachable = b.stat(
        "Remote Reachable",
        sel("opnsense_hasync_remote_reachable"),
        mappings=UPDOWN, color_mode="background",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        w=6, h=4,
        desc="1 = HA peer is reachable via XML-RPC, 0 = unreachable.",
    )
    version_match = b.stat(
        "Version Match",
        sel("opnsense_hasync_remote_version_match"),
        mappings={"0": ("Mismatch", "orange"), "1": ("Match", "green")},
        color_mode="background",
        thresholds=[{"color": "orange", "value": None}, {"color": "green", "value": 1}],
        w=6, h=4,
        desc=(
            "1 = remote firmware version matches local version. "
            "A mismatch indicates an in-progress upgrade."
        ),
    )
    version_info = b.table(
        "HA Sync Version Info",
        [sel("opnsense_hasync_remote_version_info")],
        w=12, h=4,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "remote_version": "Remote Version",
            "local_version": "Local Version",
        },
        sort_by="Remote Version",
        desc="Remote and local firmware version labels (value always 1).",
    )

    # ================================================================
    # Row 2: Remote Services
    # ================================================================
    services_total = b.stat(
        "Remote Services",
        sel("opnsense_hasync_remote_services"),
        unit="short", w=6, h=4,
        desc="Number of services reported by the HA peer.",
    )
    service_state = b.statetimeline(
        "Remote Service Status",
        [(sel("opnsense_hasync_remote_service_running"),
          "{{service}} ({{id}})")],
        RUNSTOP, w=24, h=8,
        desc="Running state of each service on the HA peer over time.",
    )

    # ================================================================
    # Tab assembly
    # ================================================================
    b.tab("HA Sync", [
        b.row("HA Sync Status",
              [reachable, version_match, version_info],
              present="has_hasync"),
        b.row("Remote Services",
              [services_total, service_state],
              present="has_hasync"),
    ])
