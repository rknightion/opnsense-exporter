"""
Q-Feeds tab — threat-intel feed statistics (opnsense_qfeeds_*). Plugin-gated.

Blocked packets/bytes counters -> rate(). Entry/address counts, timestamps,
license -> RAW/instant.
"""

from builder import Builder, sel, epoch_ms, RATE


def build(b: Builder):
    b.sentinel("has_qfeeds", metric="opnsense_qfeeds_feeds_total")

    feeds = b.stat("Configured Feeds", sel("opnsense_qfeeds_feeds_total"),
                   unit="short", w=4, h=4)
    entries = b.stat("Total Entries", sel("opnsense_qfeeds_entries"),
                     unit="short", w=4, h=4)
    addrs = b.stat("Addresses Blocked", sel("opnsense_qfeeds_addresses_blocked"),
                   unit="short", w=4, h=4)
    lic_days = b.stat("License Days Left",
                      f'({sel("opnsense_qfeeds_license_expiry_timestamp_seconds")} - time()) / 86400',
                      unit="d", w=4, h=4, decimals=0,
                      thresholds=[{"color": "red", "value": None},
                                  {"color": "orange", "value": 14},
                                  {"color": "green", "value": 45}])
    lic_info = b.table("License",
                       [sel("opnsense_qfeeds_license_info")],
                       w=8, h=4,
                       excludes=["Value", "__name__", "job", "instance"],
                       renames={"license": "License"})

    blocked_pps = b.ts("Blocked Packet Rate",
                       [(f'rate({sel("opnsense_qfeeds_packets_blocked_total")}[{RATE}])', "all feeds"),
                        (f'rate({sel("opnsense_qfeeds_feed_packets_blocked_total")}[{RATE}])', "{{feed}}")],
                       unit="pps", w=12, h=8)
    blocked_bps = b.ts("Blocked Byte Rate",
                       [(f'rate({sel("opnsense_qfeeds_bytes_blocked_total")}[{RATE}])*8', "all feeds"),
                        (f'rate({sel("opnsense_qfeeds_feed_bytes_blocked_total")}[{RATE}])*8', "{{feed}}")],
                       unit="bps", w=12, h=8)
    feed_entries = b.ts("Feed Entries / Addresses Blocked",
                        [(sel("opnsense_qfeeds_feed_entries"), "entries {{feed}}"),
                         (sel("opnsense_qfeeds_feed_addresses_blocked"), "addresses blocked {{feed}}")],
                        unit="short", w=12, h=8)
    feed_updates = b.table("Feed Update Schedule",
                           [epoch_ms(sel("opnsense_qfeeds_feed_last_update_timestamp_seconds")),
                            epoch_ms(sel("opnsense_qfeeds_feed_next_update_timestamp_seconds"))],
                           w=12, h=8,
                           excludes=["__name__", "job", "instance"],
                           renames={"feed": "Feed"},
                           unit_overrides={"Value #A": "dateTimeAsIso", "Value #B": "dateTimeAsIso"})

    b.tab("Q-Feeds", [
        b.row("Q-Feeds Overview", [feeds, entries, addrs, lic_days, lic_info],
              present="has_qfeeds"),
        b.row("Q-Feeds Activity", [blocked_pps, blocked_bps, feed_entries, feed_updates],
              present="has_qfeeds"),
    ])
