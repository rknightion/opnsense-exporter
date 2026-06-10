"""
Aliases tab — pf alias table sizes and counters (opnsense_alias_*).
Default row always present (core feature); pf-counter row gated on the
opt-in details flag.
"""

from builder import Builder, sel, RATE


def build(b: Builder):
    b.sentinel("has_alias",
               "label_values(opnsense_alias_tables_total, __name__)")
    b.sentinel("has_alias_details",
               "label_values(opnsense_alias_table_packets_total, __name__)")

    tables = b.stat("Alias Tables", sel("opnsense_alias_tables_total"),
                    unit="short", w=4, h=4)
    used = b.stat("Table Entries Used", sel("opnsense_alias_table_entries_used"),
                  unit="short", w=4, h=4)
    limit = b.stat("Table Entries Limit", sel("opnsense_alias_table_entries_limit"),
                   unit="short", w=4, h=4)
    util = b.gauge("Table Utilization",
                   f'100 * {sel("opnsense_alias_table_entries_used")} / {sel("opnsense_alias_table_entries_limit")}',
                   unit="percent", w=4, h=6,
                   thresholds=[{"color": "green", "value": None},
                               {"color": "orange", "value": 70},
                               {"color": "red", "value": 90}])
    top_tables = b.bargauge("Largest Tables",
                            [(f'topk(20, {sel("opnsense_alias_table_entries")})', "{{table}}")],
                            unit="short", w=8, h=8)
    entries_ts = b.ts("Table Entries Over Time",
                      [(f'topk(20, {sel("opnsense_alias_table_entries")})', "{{table}}")],
                      unit="short", w=24, h=8)

    eval_rate = b.ts("Evaluation Rate (match vs nomatch)",
                     [(f'topk(20, rate({sel("opnsense_alias_table_evaluations_total")}[{RATE}]))',
                       "{{table}} {{result}}")],
                     unit="short", w=12, h=8)
    pkt_rate = b.ts("Packet Rate by Table",
                    [(f'topk(20, rate({sel("opnsense_alias_table_packets_total")}[{RATE}]))',
                      "{{table}} {{direction}}/{{action}}")],
                    unit="pps", w=12, h=8)
    byte_rate = b.ts("Throughput by Table",
                     [(f'topk(20, rate({sel("opnsense_alias_table_bytes_total")}[{RATE}]))*8',
                       "{{table}} {{direction}}/{{action}}")],
                     unit="bps", w=24, h=8)

    b.tab("Aliases", [
        b.row("Alias Tables", [tables, used, limit, util, top_tables, entries_ts],
              present="has_alias"),
        b.row("Alias pf Counters (details flag)", [eval_rate, pkt_rate, byte_rate],
              present="has_alias_details"),
    ])
