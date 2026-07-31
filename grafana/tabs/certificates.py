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

  CA panels live in row 1 alongside the leaf certificates: ca_total stat, ca_expiry,
  ca_valid_from and ca_references (#583) tables.
"""

from builder import Builder, sel, epoch_ms


def build(b: Builder):
    b.sentinel("has_acme", metric="opnsense_acme_certificates_total")

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
        [epoch_ms(sel("opnsense_certificate_valid_from_seconds"))],
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

    # CA certificate panels
    ca_total = b.stat(
        "Certificate Authorities",
        sel("opnsense_certificate_ca_total"),
        unit="short", w=4, h=4,
        thresholds=[{"color": "blue", "value": None}],
        desc="Total number of CA certificates managed by OPNsense.",
    )
    ca_expiry = b.table(
        "CA Expiry",
        [f'({sel("opnsense_certificate_ca_valid_to_seconds")} - time()) / 86400'],
        w=10, h=8,
        excludes=["__name__", "job", "instance"],
        renames={"description": "Description", "commonname": "Common Name",
                 "Value": "Days Left"},
        unit_overrides={"Days Left": "d"},
        sort_by="Days Left", sort_desc=False,
        desc="Days remaining until each CA certificate expires (sorted ascending).",
    )
    # #583. Joined on the SAME (description, commonname) tuple as CA Expiry, on
    # purpose: refcount only means anything read against expiry. A CA 20 days
    # out with 50 references is a dated outage; one with 0 is dead config to
    # delete. Sorted ascending so the 0s — the ones safe to remove — surface.
    ca_references = b.table(
        "CA References",
        [sel("opnsense_certificate_ca_references")],
        w=4, h=8,
        excludes=["__name__", "job", "instance"],
        renames={"description": "Description", "commonname": "Common Name",
                 "Value": "References", "opnsense_instance": "Instance"},
        sort_by="References", sort_desc=False,
        desc=(
            "How many other configuration objects reference each CA (OPNsense's own "
            "refcount). Read it against CA Expiry: an expiring CA with a high count is "
            "a scheduled outage, one with 0 is dead config. A CA whose payload carries "
            "no refcount at all has no row here."
        ),
    )
    ca_valid_from = b.table(
        "CA Validity Start",
        [epoch_ms(sel("opnsense_certificate_ca_valid_from_seconds"))],
        w=10, h=8,
        excludes=["__name__", "job", "instance"],
        renames={"description": "Description", "commonname": "Common Name"},
        unit_overrides={"Value": "dateTimeAsIso"},
        desc="CA certificate issuance (not-before) date.",
    )

    row_certs = b.row(
        "Certificates",
        [cert_expiry, cert_valid_from, cert_total, cert_info,
         ca_total, ca_expiry, ca_valid_from, ca_references],
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
        [epoch_ms(sel("opnsense_acme_certificate_last_update_timestamp_seconds"))],
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
        [epoch_ms(sel("opnsense_acme_certificate_status_last_update_timestamp_seconds"))],
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
