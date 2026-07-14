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
        "Syslog Parse Errors (rate)",
        [(f'sum by (stage) (rate({sel("opnsense_exporter_logs_parse_errors_total")}[{RATE}]))', "{{stage}}")],
        unit="short",
        desc="opnsense_exporter_logs_parse_errors_total: received lines that failed to parse, "
             "by stage (envelope = not valid RFC5424/RFC3164 syslog; filterlog = a malformed pf "
             "log row). These records are NOT dropped -- they ship with their raw body -- so this "
             "counts fidelity lost, not data lost.",
    )
    rejected = b.ts(
        "Syslog Input Rejected (rate)",
        [(f'sum by (reason) (rate({sel("opnsense_exporter_logs_rejected_total")}[{RATE}]))', "{{reason}}")],
        unit="short",
        desc="opnsense_exporter_logs_rejected_total: syslog input refused before parsing. "
             "reason=peer means a sender outside --logs.syslog.allowed-peers (check this first "
             "when the receiver appears to receive nothing); reason=oversized means a frame "
             "beyond the 64KB message cap.",
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

    b.tab("Log Shipping", [
        b.row("Throughput", [shipped, dropped], present="has_logs"),
        b.row("Queue & Errors", [queue_len, ship_errors, poll_errors], present="has_logs"),
        b.row("Cursor", [cursor_lag, possible_gaps], present="has_logs"),
        b.row("Syslog Receiver", [parse_errors, rejected], present="has_logs"),
        b.row("Enrichment", [enrich_misses, enrich_errors, enrich_stale], present="has_logs"),
    ])
