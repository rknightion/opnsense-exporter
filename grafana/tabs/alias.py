"""
Aliases tab — pf alias table sizes and counters (opnsense_alias_*).
Default row always present (core feature); pf-counter row gated on the
opt-in details flag.
"""

from builder import Builder, sel, grp, RATE


def build(b: Builder):
    b.sentinel("has_alias", metric="opnsense_alias_tables_total")
    b.sentinel("has_alias_details", metric="opnsense_alias_table_packets_total")

    tables = b.stat("Alias Tables", sel("opnsense_alias_tables_total"),
                    unit="short", w=4, h=4)
    used = b.stat("Table Entries Used", sel("opnsense_alias_table_entries_used"),
                  unit="short", w=4, h=4,
                  desc=(
                       "pf table-entry slots in use across EVERY table on this firewall — the pf "
                       "limit is global, not per table, so one oversized alias can starve the "
                       "rest."
                  ))
    limit = b.stat("Table Entries Limit", sel("opnsense_alias_table_entries_limit"),
                   unit="short", w=4, h=4,
                   desc=(
                        "The firewall's global pf table-entries limit (net.pf.request_maxcount), "
                        "the denominator for Table Utilization. Not a per-table cap."
                   ))
    util = b.gauge("Table Utilization",
                   f'100 * {sel("opnsense_alias_table_entries_used")} / {sel("opnsense_alias_table_entries_limit")}',
                   unit="percent", w=4, h=6,
                   thresholds=[{"color": "green", "value": None},
                               {"color": "orange", "value": 70},
                               {"color": "red", "value": 90}],
                   desc=(
                        "Global pf table-entry slots in use as a percentage of the "
                        "global limit. Filling this stops new alias entries loading, "
                        "which fails silently at ruleset reload."
                   ))
    top_tables = b.bargauge("Largest Tables",
                            [(f'topk {grp()} (20, {sel("opnsense_alias_table_entries")})', "{{table}}")],
                            unit="short", w=8, h=8,
                            desc=(
                                 "Entry count per alias table. Shows the top 20 per firewall, "
                                 "not the top 20 overall. A series outside the top 20 is ABSENT "
                                 "rather than zero, and one that leaves and re-enters reads as a "
                                 "counter reset on that one series."
                            ))
    entries_ts = b.ts("Table Entries Over Time",
                      [(f'topk {grp()} (20, {sel("opnsense_alias_table_entries")})', "{{table}}")],
                      unit="short", w=24, h=8,
                      desc=(
                           "Entry count per alias table over time. Shows the top 20 per "
                           "firewall, not the top 20 overall. A series outside the top 20 is "
                           "ABSENT rather than zero, and one that leaves and re-enters reads as "
                           "a counter reset on that one series."
                      ))

    eval_rate = b.ts("Evaluation Rate (match vs nomatch)",
                     [(f'topk {grp()} (20, rate({sel("opnsense_alias_table_evaluations_total")}[{RATE}]))',
                       "{{table}} {{result}}")],
                     unit="ops", w=12, h=8,
                     desc=(
                          "Packet evaluations per second against each alias table, split by "
                          "whether the packet matched. A table with evaluations and no matches "
                          "is dead weight in the ruleset. Shows the top 20 per firewall, not the "
                          "top 20 overall. A series outside the top 20 is ABSENT rather than "
                          "zero, and one that leaves and re-enters reads as a counter reset on "
                          "that one series."
                     ))
    pkt_rate = b.ts("Packet Rate by Table",
                    [(f'topk {grp()} (20, rate({sel("opnsense_alias_table_packets_total")}[{RATE}]))',
                      "{{table}} {{direction}}/{{action}}")],
                    unit="pps", w=12, h=8,
                    desc=(
                         "Packets per second matched by each alias table. Shows the top 20 per "
                         "firewall, not the top 20 overall. A series outside the top 20 is "
                         "ABSENT rather than zero, and one that leaves and re-enters reads as a "
                         "counter reset on that one series."
                    ))
    byte_rate = b.ts("Throughput by Table",
                     [(f'topk {grp()} (20, rate({sel("opnsense_alias_table_bytes_total")}[{RATE}]))*8',
                       "{{table}} {{direction}}/{{action}}")],
                     unit="bps", w=24, h=8,
                     desc=(
                          "Bits per second matched by each alias table — the underlying counter "
                          "is BYTES, multiplied by 8 here, so this reads in the same units as an "
                          "interface graph. Shows the top 20 per firewall, not the top 20 "
                          "overall. A series outside the top 20 is ABSENT rather than zero, and "
                          "one that leaves and re-enters reads as a counter reset on that one "
                          "series."
                     ))

    b.tab("Aliases", [
        b.row("Alias Tables", [tables, used, limit, util, top_tables, entries_ts],
              present="has_alias"),
        b.row("Alias pf Counters (details flag)", [eval_rate, pkt_rate, byte_rate],
              present="has_alias_details"),
    ])
