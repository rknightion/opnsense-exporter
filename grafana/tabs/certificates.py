"""
Certificates tab for the OPNsense Exporter dashboard.

Covers all 10 opnsense_certificate_* and opnsense_acme_certificate* metrics:

  Row 1 — Certificates (always visible):
    • Expiry table (days left, sorted ascending)
    • valid_from table
    • certificate_info table
    • certificate_total stat

  Row 2 — ACME Client (gated has_acme):
    • acme_certificates_total stat
    • acme_certificate_last_update_timestamp_seconds table
    • acme_certificate_status_code table
    • acme_certificate_status_last_update_timestamp_seconds table
    • acme_certificate_enabled stat/table
    • acme_certificate_info table
"""

from builder import Builder, sel, ENABLED


def build(b: Builder):
    b.sentinel("has_acme", "label_values(opnsense_acme_certificates_total, __name__)")

    # =====================================================================
    # Row 1: Certificates
    # =====================================================================

    # Days-to-expiry table: (valid_to - now) / 86400, sorted ascending
    cert_expiry = b.table(
        "Certificate Expiry (days left)",
        [f"({sel('opnsense_certificate_valid_to_seconds')} - time()) / 86400"],
        w=24, h=10,
        excludes=["__name__", "job", "instance"],
        renames={
            "description": "Description",
            "commonname": "Common Name",
            "cert_type": "Type",
            "in_use": "In Use",
            "Value": "Days Left",
            "opnsense_instance": "Instance",
        },
        unit_overrides={"Days Left": "d"},
        sort_by="Days Left",
        sort_desc=False,
        desc=(
            "Days remaining until each certificate expires "
            "(sorted ascending — soonest expiry first). "
            "Negative = already expired."
        ),
    )

    # valid_from table (epoch timestamp)
    cert_valid_from = b.table(
        "Certificate Valid From",
        [sel("opnsense_certificate_valid_from_seconds")],
        w=16, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "description": "Description",
            "commonname": "Common Name",
            "cert_type": "Type",
            "in_use": "In Use",
            "Value": "Valid From",
            "opnsense_instance": "Instance",
        },
        unit_overrides={"Valid From": "dateTimeAsIso"},
        sort_by="Description",
        desc="Certificate issuance (not-before) date.",
    )

    # cert_info table (info metric, value always 1)
    cert_info = b.table(
        "Certificate Info",
        [sel("opnsense_certificate_info")],
        w=24, h=8,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "description": "Description",
            "commonname": "Common Name",
            "cert_type": "Type",
            "in_use": "In Use",
            "opnsense_instance": "Instance",
        },
        sort_by="Description",
        desc="Certificate metadata (info metric — value is always 1; use labels).",
    )

    # Total certificates stat (instantaneous gauge)
    cert_total = b.stat(
        "Certificates Total",
        sel("opnsense_certificate_total"),
        unit="short",
        w=4, h=4,
        thresholds=[{"color": "blue", "value": None}],
        desc="Total number of certificates managed by OPNsense.",
    )

    row_certs = b.row(
        "Certificates",
        [cert_expiry, cert_valid_from, cert_total, cert_info],
    )

    # =====================================================================
    # Row 2: ACME Client (gated)
    # =====================================================================

    # Total ACME certificates (instantaneous — RAW per AUTHORING.md)
    acme_total = b.stat(
        "ACME Certificates",
        sel("opnsense_acme_certificates_total"),
        unit="short",
        w=4, h=4,
        thresholds=[{"color": "blue", "value": None}],
        desc="Total number of ACME-managed certificates.",
    )

    # Last successful renewal timestamp
    acme_last_update = b.table(
        "ACME Last Renewal",
        [sel("opnsense_acme_certificate_last_update_timestamp_seconds")],
        w=12, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "name": "Name",
            "description": "Description",
            "Value": "Last Renewal",
            "opnsense_instance": "Instance",
        },
        unit_overrides={"Last Renewal": "dateTimeAsIso"},
        sort_by="Name",
        desc="Unix timestamp of the last successful ACME certificate issue or renewal (0 = never).",
    )

    # ACME operation status code
    acme_status_code = b.table(
        "ACME Status Code",
        [sel("opnsense_acme_certificate_status_code")],
        w=12, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "name": "Name",
            "description": "Description",
            "Value": "Status Code",
            "opnsense_instance": "Instance",
        },
        sort_by="Name",
        desc="Numeric ACME operation status code from the last run (100 = default/unknown).",
    )

    # Timestamp of last ACME client run
    acme_status_ts = b.table(
        "ACME Status Last Run",
        [sel("opnsense_acme_certificate_status_last_update_timestamp_seconds")],
        w=12, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "name": "Name",
            "description": "Description",
            "Value": "Last Run",
            "opnsense_instance": "Instance",
        },
        unit_overrides={"Last Run": "dateTimeAsIso"},
        sort_by="Name",
        desc="Unix timestamp of the last ACME client run for this certificate (0 = never run).",
    )

    # Enabled flag table (1 = enabled, 0 = disabled)
    acme_enabled = b.table(
        "ACME Certificate Enabled",
        [sel("opnsense_acme_certificate_enabled")],
        w=12, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "name": "Name",
            "description": "Description",
            "Value": "Enabled",
            "opnsense_instance": "Instance",
        },
        sort_by="Name",
        desc="Whether each ACME-managed certificate is enabled (1 = enabled, 0 = disabled).",
    )

    # ACME info table (info metric, value always 1)
    acme_info = b.table(
        "ACME Certificate Info",
        [sel("opnsense_acme_certificate_info")],
        w=24, h=8,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "name": "Name",
            "description": "Description",
            "alt_names": "Alt Names",
            "opnsense_instance": "Instance",
        },
        sort_by="Name",
        desc="ACME certificate details including subject alternative names (info metric).",
    )

    row_acme = b.row(
        "ACME Client",
        [acme_total, acme_last_update, acme_status_code, acme_status_ts,
         acme_enabled, acme_info],
        present="has_acme",
    )

    # =====================================================================
    # Assemble the tab
    # =====================================================================
    b.tab(
        "Certificates",
        [row_certs, row_acme],
    )
