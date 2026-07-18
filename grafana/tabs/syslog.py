"""
Syslog tab — syslog-ng statistics (opnsense_syslog_*).

Counters (processed/dropped/written/truncated) are cumulative -> rate().
queued / memory_usage / eps / message_size are instantaneous -> RAW.
"""

from builder import Builder, sel, RATE, RUNSTOP


def build(b: Builder):
    b.sentinel("has_syslog",
               "label_values(opnsense_syslog_service_running, __name__)")
    b.loki_sentinel("has_syslog_logs",
                     'label_values({opnsense_source="syslog"}, opnsense_source)')

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
                  unit="short", w=10, h=8)

    processed = b.ts("Processed Rate by Destination",
                     [(f'topk(20, rate({sel("opnsense_syslog_processed_total")}[{RATE}]))',
                       "{{source_name}}/{{source_id}}")],
                     unit="short", w=12, h=8)
    dropped = b.ts("Dropped / Truncated Rates",
                   [(f'rate({sel("opnsense_syslog_dropped_total")}[{RATE}])',
                     "dropped {{source_name}}/{{source_id}}"),
                    (f'rate({sel("opnsense_syslog_truncated_messages_total")}[{RATE}])',
                     "truncated msgs {{source_name}}/{{source_id}}"),
                    (f'rate({sel("opnsense_syslog_truncated_bytes_total")}[{RATE}])',
                     "truncated bytes {{source_name}}/{{source_id}}")],
                   unit="short", w=12, h=8)
    written = b.ts("Written Rate",
                   [(f'rate({sel("opnsense_syslog_written_total")}[{RATE}])',
                     "{{source_name}}/{{source_id}}")],
                   unit="short", w=8, h=8)
    memory = b.ts("Memory Usage",
                  [(f'{sel("opnsense_syslog_memory_usage_bytes")}',
                    "{{source_name}}/{{source_id}}")],
                  unit="bytes", w=8, h=8)
    msgsize = b.ts("Message Size",
                   [(f'{sel("opnsense_syslog_message_size_bytes")}',
                     "{{source_id}} {{stat}}")],
                   unit="bytes", w=8, h=8)

    raw_logs = b.logs("Raw syslog stream", '{opnsense_source="syslog"}')
    lines_by_subsystem = b.loki_ts(
        "Syslog lines/s by subsystem",
        [('sum by (opnsense_subsystem) (rate({opnsense_source="syslog"} [$__auto]))',
          "{{opnsense_subsystem}}")])

    b.tab("Syslog", [
        b.row("Syslog-ng Overview", [svc, eps, queued], present="has_syslog"),
        b.row("Syslog-ng Throughput", [processed, dropped, written, memory, msgsize],
              present="has_syslog"),
        b.row("Shipped Syslog Logs", [raw_logs, lines_by_subsystem],
              present="has_syslog_logs"),
    ])
