"""
ClamAV tab — covers all opnsense_clamav_* metrics.

The os-clamav plugin is default-on (--exporter.disable-clamav) but plugin-gated
(silent 404 when not installed), so the whole tab is gated on the presence of
opnsense_clamav_version_info. Running state is already covered by the Services
tab; this tab is purely about signature freshness — a stale/broken freshclam
mirror is otherwise a silent failure mode (#204).

Rows:
  1. Engine & Signatures — engine version info table; total signatures stat
  2. Signature Databases  — per-database (daily/main/bytecode) version bar
                             gauge and build-age table
"""

from builder import Builder, sel, epoch_ms


def build(b: Builder):
    # ---- Sentinels ---------------------------------------------------------
    b.sentinel("has_clamav", "label_values(opnsense_clamav_version_info, __name__)")

    # ================================================================
    # Row 1: Engine & Signatures
    # ================================================================
    engine_info = b.table(
        "ClamAV Engine Version",
        [sel("opnsense_clamav_version_info")],
        w=12, h=4,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "version": "Engine Version",
            "opnsense_instance": "Instance",
        },
        desc="ClamAV (clamd) engine version (info metric — value is always 1; use labels).",
    )
    signatures_total = b.stat(
        "Total Signatures Loaded",
        sel("opnsense_clamav_signatures"),
        unit="short", w=6, h=4,
        thresholds=[{"color": "blue", "value": None}, {"color": "red", "value": 0}],
        desc=(
            "Total number of virus signatures loaded across all databases. "
            "0 both when freshclam has never run and when the field is unavailable."
        ),
    )

    # ================================================================
    # Row 2: Signature Databases
    # ================================================================
    db_version = b.bargauge(
        "Signature Database Versions",
        [(sel("opnsense_clamav_signature_db_version"), "{{db}}")],
        unit="short", w=8, h=8,
        desc="Numeric version of each signature database (daily/main/bytecode); increments on every freshclam update.",
    )
    db_age = b.table(
        "Signature Database Freshness",
        [f"(time() - {sel('opnsense_clamav_signature_db_built_timestamp_seconds')}) / 3600"],
        w=16, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "db": "Database",
            "Value": "Age (hours)",
            "opnsense_instance": "Instance",
        },
        unit_overrides={"Age (hours)": "h"},
        sort_by="Age (hours)",
        sort_desc=True,
        desc=(
            "Hours since each signature database was last built by freshclam "
            "(sorted oldest first). A large or growing value indicates freshclam "
            "is failing or the mirror is unreachable — the whole point of this metric."
        ),
    )
    db_built = b.table(
        "Signature Database Built",
        [epoch_ms(sel("opnsense_clamav_signature_db_built_timestamp_seconds"))],
        w=8, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "db": "Database",
            "Value": "Built",
            "opnsense_instance": "Instance",
        },
        unit_overrides={"Built": "dateTimeAsIso"},
        sort_by="Database",
        desc="Timestamp each signature database was built, from the freshclam build metadata.",
    )

    # ================================================================
    # Tab assembly
    # ================================================================
    b.tab("ClamAV", [
        b.row("Engine & Signatures",
              [engine_info, signatures_total],
              present="has_clamav"),
        b.row("Signature Databases",
              [db_version, db_age, db_built],
              present="has_clamav"),
    ])
