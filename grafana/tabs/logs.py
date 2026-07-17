"""
Log Shipping tab — self-metrics for the opt-in internal/logship pipeline
(--logs.enabled, #228). These are EXPORTER self-metrics
(opnsense_exporter_logs_*), not OPNsense data: they describe the health of the
background poll -> queue -> sink loop that ships events to Loki.

All panels are gated on has_logs so the tab stays hidden unless the log-shipping
pipeline is enabled (it emits logs_queue_capacity unconditionally when running).
There are deliberately no per-source label panels beyond the low-cardinality
`source` dimension (one value per registered source, e.g. firewall/ids/audit) —
the high-cardinality event data itself never becomes a metric.
"""

from builder import Builder, sel, RATE


def build(b: Builder):
    b.sentinel("has_logs", "label_values(opnsense_exporter_logs_queue_capacity, __name__)")

    shipped = b.ts(
        "Records Shipped (rate)",
        [(f'sum by (source) (rate({sel("opnsense_exporter_logs_shipped_total")}[{RATE}]))', "{{source}}")],
        unit="short",
        desc="opnsense_exporter_logs_shipped_total: records successfully handed to the "
             "sink per second, by source. This is the primary throughput signal.",
    )
    dropped = b.ts(
        "Records Dropped (rate)",
        [(f'sum by (source, reason) (rate({sel("opnsense_exporter_logs_dropped_total")}[{RATE}]))',
          "{{source}} / {{reason}}")],
        unit="short",
        desc="opnsense_exporter_logs_dropped_total: records dropped before delivery, by "
             "source and reason (reason=overflow means the backpressure queue was full and "
             "the oldest record was evicted). Sustained drops mean the sink cannot keep up.",
    )

    queue_len = b.ts(
        "Queue Depth",
        [(f'{sel("opnsense_exporter_logs_queue_length")}', "depth"),
         (f'{sel("opnsense_exporter_logs_queue_capacity")}', "capacity")],
        unit="short",
        desc="opnsense_exporter_logs_queue_length vs opnsense_exporter_logs_queue_capacity: "
             "depth of the poller->emitter backpressure queue. Approaching capacity precedes "
             "overflow drops.",
    )

    ship_errors = b.ts(
        "Sink Errors (rate)",
        [(f'rate({sel("opnsense_exporter_logs_ship_errors_total")}[{RATE}])', "ship errors")],
        unit="short",
        desc="opnsense_exporter_logs_ship_errors_total: failed sink Emit calls per second "
             "(each failed batch is dropped). A dead OTLP endpoint shows up here.",
    )
    poll_errors = b.ts(
        "Source Poll Errors (rate)",
        [(f'sum by (source) (rate({sel("opnsense_exporter_logs_poll_errors_total")}[{RATE}]))', "{{source}}")],
        unit="short",
        desc="opnsense_exporter_logs_poll_errors_total: source Poll errors per second, by "
             "source (e.g. the OPNsense API being unreachable). The poller retries next tick.",
    )
    cursor_lag = b.ts(
        "Cursor Lag (time since last event)",
        [(f'time() - {sel("opnsense_exporter_logs_last_event_timestamp_seconds")}', "{{source}}")],
        unit="s",
        desc="Seconds since the most recent shipped event per source, derived from "
             "opnsense_exporter_logs_last_event_timestamp_seconds. Steady growth on an active "
             "box indicates the source stopped producing (or the poll is failing).",
    )
    possible_gaps = b.ts(
        "Possible Sampling Gaps (rate)",
        [(f'sum by (source) (rate({sel("opnsense_exporter_logs_possible_gap_total")}[{RATE}]))', "{{source}}")],
        unit="short",
        desc="opnsense_exporter_logs_possible_gap_total: possible sampling gaps detected by a "
             "source whose only view of its data is a bounded window (e.g. the unbound source's "
             "latest-1000-row DNS query log, #233) — incremented when a poll's page shows no "
             "continuity with the previous cursor, meaning an unknown amount of data was "
             "skipped between polls. Non-zero on a quiet box is expected occasionally; sustained "
             "non-zero means the source cannot keep up with event volume at its poll interval.",
    )

    # --- Syslog receiver (--logs.syslog.enabled, #248) -------------------------
    # The receiver is a PUSH source: OPNsense forwards its logs to us. These panels
    # cover the two things that can go wrong on that path but still look healthy
    # from the throughput panels above -- input refused before it is ever parsed,
    # and enrichment quietly going stale.

    parse_errors = b.ts(
        "Parse Errors (rate)",
        [(f'sum by (source, stage) (rate({sel("opnsense_exporter_logs_parse_errors_total")}[{RATE}]))',
          "{{source}} / {{stage}}")],
        unit="short",
        desc="opnsense_exporter_logs_parse_errors_total: received records that failed to parse, "
             "by source and stage (envelope = not valid RFC5424/RFC3164 syslog; filterlog = a "
             "malformed pf log row; document = a Zenarmor document that would not decode). These "
             "records are NOT dropped -- they ship with their raw body -- so this counts fidelity "
             "lost, not data lost.",
    )
    rejected = b.ts(
        "Input Rejected (rate)",
        [(f'sum by (source, reason) (rate({sel("opnsense_exporter_logs_rejected_total")}[{RATE}]))',
          "{{source}} / {{reason}}")],
        unit="short",
        desc="opnsense_exporter_logs_rejected_total: receiver input refused rather than shipped. "
             "reason=peer means a sender outside the allowlist (check this first when a receiver "
             "appears to receive nothing); oversized means a frame beyond the message cap; "
             "unhandled_endpoint means Zenarmor called an Elasticsearch route the receiver does "
             "not implement -- a sustained rate there means its client changed and the receiver "
             "needs teaching. self_traffic is Zenarmor reporting the connection that delivers its "
             "own records to us (#278): a steady rate is normal and healthy, roughly one per bulk "
             "request, and is the feature working.",
    )
    resource_capped = b.ts(
        "Resource Label Cap Hit (rate)",
        [(f'rate({sel("opnsense_exporter_logs_resource_capped_total")}[{RATE}])', "capped")],
        unit="short",
        desc="opnsense_exporter_logs_resource_capped_total: records shipped with their "
             "opnsense.* index labels DROPPED because the distinct (source, subsystem, action) "
             "count exceeded the sink's resource cap. The records still arrive, so throughput "
             "looks fine -- but every label-scoped query silently under-reports, and which "
             "records lose their labels depends on arrival order. Any non-zero value means the "
             "closed label sets grew beyond budget and needs investigating.",
    )
    enrich_misses = b.ts(
        "Enrichment Misses (rate)",
        [(f'sum by (table) (rate({sel("opnsense_exporter_logs_enrich_misses_total")}[{RATE}]))', "{{table}}")],
        unit="short",
        desc="opnsense_exporter_logs_enrich_misses_total: enrichment lookups that missed, by "
             "table. A sustained rate on table=rules means the rule snapshot is behind the box's "
             "ruleset, so log lines are shipping without a rule description. A miss triggers a "
             "rate-limited refresh, so a brief spike after a ruleset change is normal.",
    )
    enrich_errors = b.ts(
        "Enrichment Refresh Errors (rate)",
        [(f'sum by (table) (rate({sel("opnsense_exporter_logs_enrich_refresh_errors_total")}[{RATE}]))',
          "{{table}}")],
        unit="short",
        desc="opnsense_exporter_logs_enrich_refresh_errors_total: failed enrichment refreshes "
             "against the OPNsense API, by table. The previous snapshot keeps serving, so records "
             "still ship -- enriched with increasingly stale data. Pair with the staleness panel.",
    )
    enrich_stale = b.ts(
        "Enrichment Staleness",
        [(f'time() - {sel("opnsense_exporter_logs_enrich_last_refresh_timestamp_seconds")}', "{{table}}")],
        unit="s",
        desc="Seconds since each enrichment table last refreshed successfully, derived from "
             "opnsense_exporter_logs_enrich_last_refresh_timestamp_seconds. Rules refresh every "
             "60s, interfaces every 5m, leases every 60s -- a value climbing far past those means "
             "the API is failing and enrichment is silently going stale.",
    )

    # --- Zenarmor receiver (--logs.zenarmor.enabled, #276) --------------------
    # Zenarmor streams ~2.5-3.3M records/day, so the derived counters below are how
    # you ask rate questions without querying the raw stream -- and they outlive
    # Loki's retention, which the log lines do not.

    zen_events = b.ts(
        "Zenarmor Events (rate)",
        [(f'sum by (family, action) (rate({sel("opnsense_log_events_zenarmor_total")}[{RATE}]))',
          "{{family}} / {{action}}")],
        unit="short",
        desc="opnsense_log_events_zenarmor_total: Zenarmor records per second by family "
             "(flow/dns/tls/web/ids/voip) and disposition. action=block is what the firewall "
             "stopped. An action with no value is a record that stated no verdict -- it is not "
             "counted as a pass, deliberately.",
    )
    zen_blocked = b.ts(
        "Zenarmor Blocks by Category (rate)",
        [(f'sum by (category) (rate({sel("opnsense_log_events_zenarmor_total")}{{action="block"}}[{RATE}]))',
          "{{category}}")],
        unit="short",
        desc="Blocked Zenarmor records per second by category -- application category for "
             "flows, domain category for DNS/TLS, alert category for threats. Application "
             "names, IPs and hostnames are never labels; query the log stream for those.",
    )
    zen_bulk = b.ts(
        "Zenarmor Bulk Ingest (rate)",
        [(f'rate({sel("opnsense_exporter_logs_zenarmor_bulk_requests_total")}[{RATE}])', "requests/s"),
         (f'rate({sel("opnsense_exporter_logs_zenarmor_bulk_bytes_total")}[{RATE}])', "bytes/s")],
        unit="short",
        desc="Elasticsearch _bulk requests and bytes Zenarmor pushes per second. Bytes is the "
             "one to watch: a live box measured ~70 KB/s sustained, which is ~4-6 GB/day of raw "
             "JSON into Loki. Cut families at the Zenarmor end (its own indexes setting) rather "
             "than here -- data cut at source never crosses the wire.",
    )

    zen_excluded = b.ts(
        "Zenarmor Records Excluded (rate)",
        [(f'sum by (rule) (rate({sel("opnsense_exporter_logs_zenarmor_excluded_total")}[{RATE}]))',
          "{{rule}}")],
        unit="short",
        desc="opnsense_exporter_logs_zenarmor_excluded_total: records dropped per second by a "
             "--logs.zenarmor.exclude rule, by rule (#279). This panel IS the blind spot: every "
             "record counted here was real traffic that is now absent from the log stream, and "
             "unlike syslog sampling the derived counters cannot make up for it -- they carry no "
             "server_name, query or device_name. A rule climbing unexpectedly is eating more than "
             "it was written for. Flat zero is the default: exclusion is opt-in.",
    )

    b.tab("Log Shipping", [
        b.row("Throughput", [shipped, dropped], present="has_logs"),
        b.row("Queue & Errors", [queue_len, ship_errors, poll_errors], present="has_logs"),
        b.row("Cursor", [cursor_lag, possible_gaps], present="has_logs"),
        b.row("Receivers", [parse_errors, rejected, resource_capped], present="has_logs"),
        b.row("Zenarmor", [zen_events, zen_blocked, zen_bulk], present="has_logs"),
        b.row("Zenarmor Exclusion", [zen_excluded], present="has_logs"),
        b.row("Enrichment", [enrich_misses, enrich_errors, enrich_stale], present="has_logs"),
    ])
