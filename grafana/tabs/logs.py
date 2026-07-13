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

    b.tab("Log Shipping", [
        b.row("Throughput", [shipped, dropped], present="has_logs"),
        b.row("Queue & Errors", [queue_len, ship_errors, poll_errors], present="has_logs"),
        b.row("Cursor", [cursor_lag], present="has_logs"),
    ])
