"""
Aliases tab — pf alias table sizes and counters (opnsense_alias_*).
Default row always present (core feature); pf-counter row gated on the
opt-in details flag.
"""

from builder import Builder, sel, grp, RATE


def build(b: Builder):
    b.sentinel("has_alias", metric="opnsense_alias_tables_total")
    b.sentinel("has_alias_details", metric="opnsense_alias_table_packets_total")
    # #583: the freshness row is only meaningful on a box that actually has a
    # DNS- or URL-backed alias. Static-alias-only boxes emit no series at all,
    # so the row would render permanently empty without this gate.
    b.sentinel("has_alias_feeds", metric="opnsense_alias_table_updated_timestamp_seconds")

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

    # #583. Charted as an AGE, not a wall clock: the metric is derived from a
    # timezone-less file mtime read as UTC, so the absolute epoch can be off by
    # the firewall's UTC offset while the age is right. Ascending sort is wrong
    # here — the stalest feed is the finding, so descending.
    #
    # Only DNS- and URL-backed aliases have a series at all; a static
    # host/network alias has no refresh cycle and is deliberately absent rather
    # than shown as infinitely stale.
    feed_age = b.table(
        "Alias Table Refresh Age",
        [f'(time() - {sel("opnsense_alias_table_updated_timestamp_seconds")})'],
        w=12, h=8,
        excludes=["__name__", "job", "instance"],
        renames={"table": "Table", "Value": "Age",
                 "opnsense_instance": "Instance"},
        unit_overrides={"Age": "s"},
        sort_by="Age", sort_desc=True,
        desc=(
            "How long ago each alias table's persisted content was last written — i.e. "
            "how stale a DNS- or URL-backed alias (a threat feed) is. This is the only "
            "signal for a feed that has silently stopped refreshing: the table keeps its "
            "stale rows, so Table Entries stays perfectly healthy. Static host/network "
            "aliases have no refresh cycle and correctly have no row. Shown as an age "
            "rather than a date because the underlying timestamp carries no timezone."
        ),
    )
    feed_age_ts = b.ts(
        "Alias Table Refresh Age Over Time",
        [(f'topk {grp()} (20, time() - {sel("opnsense_alias_table_updated_timestamp_seconds")})',
          "{{table}}")],
        unit="s", w=12, h=8,
        desc=(
            "Refresh age per alias table over time. A healthy feed saw-tooths — climbing, "
            "then dropping to near zero on each refresh. A line that just keeps climbing "
            "is a feed that has stopped updating. Shows the top 20 per firewall, not the "
            "top 20 overall; a series outside the top 20 is ABSENT rather than zero."
        ),
    )

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
        b.row("Alias Feed Freshness", [feed_age, feed_age_ts],
              present="has_alias_feeds"),
        b.row("Alias pf Counters (details flag)", [eval_rate, pkt_rate, byte_rate],
              present="has_alias_details"),
    ])
