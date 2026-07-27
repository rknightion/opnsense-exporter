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

Every opnsense_exporter_logs_* metric carries the stable opnsense_instance label,
so b.sel_pipeline keeps the dashboard's box picker in step with the pipeline
self-metrics.
"""

from builder import Builder, grp, RATE
from uids import HEALTH_UID, to_tab


def build(b: Builder):
    # scope="self_labeled": an exporter self-metric, but one that DOES carry
    # opnsense_instance because internal/logship wraps its registerer in
    # SelfMetricsRegisterer. Same matcher as a collector metric; the distinct mode
    # records WHY it is available, so a future self-metric family registered on the
    # raw registry cannot copy this line and read as scoped when it is not.
    b.sentinel("has_logs", metric="opnsense_exporter_logs_queue_capacity",
               scope="self_labeled")
    # Debug capture is opt-in twice over (--logs.debug-capture.dir plus a per-receiver
    # --logs.<recv>.debug-capture), so its own row gets its own sentinel rather than
    # riding has_logs: on the overwhelmingly common deployment these two series do not
    # exist at all, and an always-on row would be two permanently blank panels on the
    # tab an operator opens when shipping is already broken. Same registerer as the
    # rest of the family, so it carries opnsense_instance (#428).
    b.sentinel("has_debug_capture", metric="opnsense_exporter_logs_debug_captured_total",
               scope="self_labeled")

    shipped = b.ts(
        "Records Shipped (rate)",
        [(f'sum {grp("source")} (rate({b.sel_pipeline("opnsense_exporter_logs_shipped_total")}[{RATE}]))', "{{source}}")],
        unit="short",
        desc="opnsense_exporter_logs_shipped_total: records successfully handed to the "
             "sink per second, by source. This is the primary throughput signal.",
    )
    dropped = b.ts(
        "Records Dropped (rate)",
        [(f'sum {grp("source", "reason")} (rate({b.sel_pipeline("opnsense_exporter_logs_dropped_total")}[{RATE}]))',
          "{{source}} / {{reason}}")],
        unit="short",
        desc="opnsense_exporter_logs_dropped_total: records dropped before delivery, by "
             "source and reason (reason=overflow means the backpressure queue was full and "
             "the oldest record was evicted). Sustained drops mean the sink cannot keep up.",
    )

    queue_len = b.ts(
        "Queue Depth",
        [(f'{b.sel_pipeline("opnsense_exporter_logs_queue_length")}', "depth"),
         (f'{b.sel_pipeline("opnsense_exporter_logs_queue_capacity")}', "capacity")],
        unit="short",
        desc="opnsense_exporter_logs_queue_length vs opnsense_exporter_logs_queue_capacity: "
             "depth of the poller->emitter backpressure queue. Approaching capacity precedes "
             "overflow drops.",
    )
    queue_bytes = b.ts(
        "Queue Bytes",
        [(f'{b.sel_pipeline("opnsense_exporter_logs_queue_bytes")}', "queued bytes"),
         (f'{b.sel_pipeline("opnsense_exporter_logs_queue_max_bytes")}', "max bytes")],
        unit="bytes",
        desc="opnsense_exporter_logs_queue_bytes vs opnsense_exporter_logs_queue_max_bytes: "
             "estimated retained queue memory and its aggregate byte budget. A max of 0 disables "
             "the byte bound; otherwise this can reach its budget while record depth remains low.",
    )

    ship_errors = b.ts(
        "Sink Errors (rate)",
        [(f'rate({b.sel_pipeline("opnsense_exporter_logs_ship_errors_total")}[{RATE}])', "ship errors")],
        unit="short",
        desc="opnsense_exporter_logs_ship_errors_total: sink Emit attempts that did not fully "
             "deliver per second. The pipeline retries their unacknowledged remainder, so this is "
             "a retry/degradation signal, not a record-loss counter. A dead OTLP endpoint shows up here.",
    )
    poll_errors = b.ts(
        "Source Poll Errors (rate)",
        [(f'sum {grp("source")} (rate({b.sel_pipeline("opnsense_exporter_logs_poll_errors_total")}[{RATE}]))', "{{source}}")],
        unit="short",
        desc="opnsense_exporter_logs_poll_errors_total: source Poll errors per second, by "
             "source (e.g. the OPNsense API being unreachable). The poller retries next tick.",
    )
    received_lag = b.ts(
        "Source Input Lag",
        [(f'time() - {b.sel_pipeline("opnsense_exporter_logs_last_received_timestamp_seconds")}', "{{source}}")],
        unit="s",
        desc="Seconds since a source last admitted a record to the queue, derived from "
             "opnsense_exporter_logs_last_received_timestamp_seconds on the exporter clock. "
             "Steady growth on an active box indicates the source stopped producing or polling.",
    )
    exported_lag = b.ts(
        "Delivery Lag",
        [(f'time() - {b.sel_pipeline("opnsense_exporter_logs_last_exported_timestamp_seconds")}', "{{source}}")],
        unit="s",
        desc="Seconds since the sink last acknowledged a record from each source, derived from "
             "opnsense_exporter_logs_last_exported_timestamp_seconds on the exporter clock. A wide "
             "gap against Source Input Lag means records are arriving but delivery is retrying or blocked.",
    )
    possible_gaps = b.ts(
        "Possible Sampling Gaps (rate)",
        [(f'sum {grp("source")} (rate({b.sel_pipeline("opnsense_exporter_logs_possible_gap_total")}[{RATE}]))', "{{source}}")],
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
        [(f'sum {grp("source", "stage")} (rate({b.sel_pipeline("opnsense_exporter_logs_parse_errors_total")}[{RATE}]))',
          "{{source}} / {{stage}}")],
        unit="short",
        desc="opnsense_exporter_logs_parse_errors_total: received records that failed to parse, "
             "by source and stage (syslog envelope = not valid RFC5424/RFC3164; Zenarmor bulk = "
             "an invalid _bulk envelope; Zenarmor document = one document that would not decode). These "
             "records are NOT dropped -- they ship with their raw body -- so this counts fidelity "
             "lost, not data lost.",
    )
    rejected = b.ts(
        "Input Rejected (rate)",
        [(f'sum {grp("source", "reason")} (rate({b.sel_pipeline("opnsense_exporter_logs_rejected_total")}[{RATE}]))',
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
        [(f'rate({b.sel_pipeline("opnsense_exporter_logs_resource_capped_total")}[{RATE}])', "capped")],
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
        [(f'sum {grp("table")} (rate({b.sel_pipeline("opnsense_exporter_logs_enrich_misses_total")}[{RATE}]))', "{{table}}")],
        unit="short",
        desc="opnsense_exporter_logs_enrich_misses_total: enrichment lookups that missed, by "
             "table. A sustained rate on table=rules means the rule snapshot is behind the box's "
             "ruleset, so log lines are shipping without a rule description. A miss triggers a "
             "rate-limited refresh, so a brief spike after a ruleset change is normal.",
    )
    enrich_errors = b.ts(
        "Enrichment Refresh Errors (rate)",
        [(f'sum {grp("table")} (rate({b.sel_pipeline("opnsense_exporter_logs_enrich_refresh_errors_total")}[{RATE}]))',
          "{{table}}")],
        unit="short",
        desc="opnsense_exporter_logs_enrich_refresh_errors_total: failed enrichment refreshes "
             "against the OPNsense API, by table. The previous snapshot keeps serving, so records "
             "still ship -- enriched with increasingly stale data. Pair with the staleness panel.",
    )
    enrich_stale = b.ts(
        "Enrichment Staleness",
        [(f'time() - {b.sel_pipeline("opnsense_exporter_logs_enrich_last_refresh_timestamp_seconds")}', "{{table}}")],
        unit="s",
        desc="Seconds since each enrichment table last refreshed successfully, derived from "
             "opnsense_exporter_logs_enrich_last_refresh_timestamp_seconds. Rules refresh every "
             "60s, interfaces every 5m, leases every 60s -- a value climbing far past those means "
             "the API is failing and enrichment is silently going stale.",
    )

    # ---- debug capture (#428) ---------------------------------------------
    # These two series existed with no panel anywhere, and the coverage gate could not
    # notice because it only ever read the collector catalogue.
    debug_captured = b.ts(
        "Debug Captures Written (rate)",
        [(f'sum {grp("receiver", "kind")} (rate({b.sel_pipeline("opnsense_exporter_logs_debug_captured_total")}[{RATE}]))',
          "{{receiver}} {{kind}}")],
        unit="short",
        desc="opnsense_exporter_logs_debug_captured_total: signals written to the debug-capture "
             "dir per second, by receiver and kind. Only signals the exporter does NOT model are "
             "captured — unhandled endpoints, unknown families, parse errors, unparsed syslog "
             "lines — so a non-zero rate here is a shopping list of things worth teaching the "
             "parser, not an error rate. Silence means everything arriving is understood.",
    )
    debug_dropped = b.ts(
        "Debug Captures Dropped (rate)",
        [(f'sum {grp("receiver", "reason")} (rate({b.sel_pipeline("opnsense_exporter_logs_debug_capture_dropped_total")}[{RATE}]))',
          "{{receiver}} {{reason}}")],
        unit="short",
        desc="opnsense_exporter_logs_debug_capture_dropped_total: capture entries dropped rather "
             "than written, by receiver and reason. Read the reasons differently: duplicate_shape "
             "is the healthy steady state (one example of each shape is already on disk, and this "
             "rate — not the file size — tells you how busy the lane is), while cap_reached means "
             "--logs.debug-capture.max-bytes is full and buffer_full or write_error mean the disk "
             "is not keeping up. Capture never blocks ingest, so none of these cost log records.",
    )

    # ---- drilldowns (#419) ------------------------------------------------
    # This tab is the pipeline's own health; the two questions it raises point
    # elsewhere. "Is anything arriving?" is the Loki-backed syslog stream, and "is the
    # exporter itself healthy?" is Diagnostics. Shipping errors specifically implicate
    # the sink, which is the same OTLP/endpoint story Diagnostics carries.
    b.panel_links(shipped, [
        to_tab("Shipped lines in Loki for this window", "Services", "Syslog", loki=True),
        to_tab("Log-derived event metrics", "Observability", "Log-derived Events"),
    ])
    b.panel_links(ship_errors, [
        to_tab("Exporter delivery health for this window", "Diagnostics", "",
               uid=HEALTH_UID),
    ])
    b.panel_links(dropped, [
        to_tab("Exporter delivery health for this window", "Diagnostics", "",
               uid=HEALTH_UID),
    ])

    b.tab("Log Shipping", [
        b.row("Throughput", [shipped, dropped], present="has_logs"),
        b.row("Queue & Errors", [queue_len, queue_bytes, ship_errors, poll_errors], present="has_logs"),
        b.row("Cursor", [received_lag, exported_lag, possible_gaps], present="has_logs"),
        b.row("Receivers", [parse_errors, rejected, resource_capped], present="has_logs"),
        b.row("Enrichment", [enrich_misses, enrich_errors, enrich_stale], present="has_logs"),
        b.row("Debug Capture", [debug_captured, debug_dropped], present="has_debug_capture"),
    ])
