"""
Syslog tab — syslog-ng statistics (opnsense_syslog_*).

Counters (processed/dropped/written/truncated) are cumulative -> rate().
queued / memory_usage / eps / message_size are instantaneous -> RAW.
"""

from builder import Builder, sel, grp, loki_sel, loki_grp, RATE, RUNSTOP

SYSLOG_STREAM = loki_sel('opnsense_source="syslog"')


def build(b: Builder):
    b.sentinel("has_syslog", metric="opnsense_syslog_service_running")
    b.loki_sentinel("has_syslog_logs", matchers='opnsense_source="syslog"',
                    label="opnsense_source")

    svc = b.stat("Syslog Service", sel("opnsense_syslog_service_running"),
                 unit="short", w=4, h=4, mappings=RUNSTOP,
                 desc="syslog-ng service status.")
    eps = b.ts("Events/s (syslog-ng centre)",
               [(f'{sel("opnsense_syslog_events_per_second")}',
                 "{{source_id}}{{source_instance}} {{window}}")],
               unit="short", w=10, h=8,
               desc="syslog-ng events per second per reporting window.")
    queued = b.ts("Queued Messages",
                  [(f'{sel("opnsense_syslog_queued")}',
                    "{{source_name}}/{{source_id}}")],
                  unit="short", w=10, h=8,
                  desc=(
                       "Messages currently held in each syslog-ng object's queue. A queue that "
                       "climbs and does not drain means the destination is unreachable or too "
                       "slow; syslog-ng drops once the queue is full."
                  ))

    processed = b.ts("Processed Rate by Destination",
                     [(f'topk {grp()} (20, rate({sel("opnsense_syslog_processed_total")}[{RATE}]))',
                       "{{source_name}}/{{source_id}}")],
                     unit="ops", w=12, h=8,
                     desc=(
                          "Messages per second processed by each syslog-ng object (source, "
                          "destination or filter), from the box's own syslog-ng statistics — NOT "
                          "the exporter's syslog receiver. Counters reset when syslog-ng stats "
                          "are reset. Shows the top 20 per firewall, not the top 20 overall. A "
                          "series outside the top 20 is ABSENT rather than zero, and one that "
                          "leaves and re-enters reads as a counter reset on that one series."
                     ))
    # #416: dropped/truncated MESSAGE counts and truncated BYTE volume used to
    # share one "short" field unit on a single panel. The byte series' magnitude
    # flattened the message-rate series it was meant to sit next to, and the
    # axis mislabelled a byte rate as a unitless count. Split into a
    # message-rate panel and a dedicated byte-rate panel (unit="Bps") instead
    # of forcing two incompatible quantities onto one axis; the underlying
    # queries are unchanged.
    dropped = b.ts("Dropped / Truncated Message Rate (msgs/sec)",
                   [(f'rate({sel("opnsense_syslog_dropped_total")}[{RATE}])',
                     "dropped msgs/s {{source_name}}/{{source_id}}"),
                    (f'rate({sel("opnsense_syslog_truncated_messages_total")}[{RATE}])',
                     "truncated msgs/s {{source_name}}/{{source_id}}")],
                   unit="ops", w=6, h=8,
                   desc="syslog-ng dropped and truncated MESSAGE counts per second "
                        "(messages/sec), by destination -- not bytes. dropped = messages "
                        "discarded outright; truncated = messages shortened rather than "
                        "dropped. See 'Truncated Bytes Rate' for the separate BYTE-volume "
                        "view of the same truncation events: it used to share this axis, "
                        "where its magnitude flattened this message-rate series.")
    truncated_bytes = b.ts("Truncated Bytes Rate (bytes/sec)",
                   [(f'rate({sel("opnsense_syslog_truncated_bytes_total")}[{RATE}])',
                     "truncated bytes/s {{source_name}}/{{source_id}}")],
                   unit="Bps", w=6, h=8,
                   desc="Bytes of syslog-ng message content cut per second by truncation "
                        "(bytes/sec) -- not a message count. Pairs with 'Dropped / "
                        "Truncated Message Rate' for how many messages that byte volume "
                        "represents.")
    written = b.ts("Written Rate",
                   [(f'rate({sel("opnsense_syslog_written_total")}[{RATE}])',
                     "{{source_name}}/{{source_id}}")],
                   unit="ops", w=8, h=8,
                   desc=(
                        "Messages per second written by each syslog-ng object. Written well "
                        "below processed for a destination means syslog-ng is dropping or "
                        "queueing, so read it against Queued Messages."
                   ))
    memory = b.ts("Memory Usage",
                  [(f'{sel("opnsense_syslog_memory_usage_bytes")}',
                    "{{source_name}}/{{source_id}}")],
                  unit="bytes", w=8, h=8)
    msgsize = b.ts("Message Size",
                   [(f'{sel("opnsense_syslog_message_size_bytes")}',
                     "{{source_id}} {{stat}}")],
                   unit="bytes", w=8, h=8)

    raw_logs = b.logs("Raw syslog stream", SYSLOG_STREAM,
                   desc=(
                        "The live shipped log lines from Loki, scoped to the selected firewall "
                        "via service_instance_id (a shipped stream carries no opnsense_instance "
                        "label). Loki returns NO SERIES rather than zero when nothing matched, "
                        "so an empty panel means no lines in the window, not a broken receiver."
                   ))
    lines_by_subsystem = b.loki_ts(
        "Syslog lines/s by subsystem",
        [(f'sum {loki_grp("opnsense_subsystem")} (rate({SYSLOG_STREAM} [$__auto]))',
          "{{opnsense_subsystem}}")],
        unit="ops",
        desc=(
            "Shipped log lines per second by subsystem, counted in Loki rather than from a "
            "metric. Uses $__auto for the range so the step follows the picked window; "
            "absence of a subsystem means no lines, not zero."
        ))

    b.tab("Syslog", [
        b.row("Syslog-ng Overview", [svc, eps, queued], present="has_syslog"),
        b.row("Syslog-ng Throughput",
              [processed, dropped, truncated_bytes, written, memory, msgsize],
              present="has_syslog"),
        b.row("Shipped Syslog Logs", [raw_logs, lines_by_subsystem],
              present="has_syslog_logs"),
    ])
