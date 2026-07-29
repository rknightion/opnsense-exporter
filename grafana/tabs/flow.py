"""
Flow Volume tab — byte and packet volume rolled up from flow records
(opnsense_flow_*, the flow collector, #346).

Phase 1's source is the Zenarmor receiver's conn documents; phase 2 adds a NetFlow
v5/v9 receiver producing the same normalized record. This answers volume questions
from metrics — bytes and packets by interface, direction, transport, application
category, verdict and scope — instead of scanning 4-6 GB/day of Loki.

Two things a reader of these panels has to know, both stated on the panels
themselves rather than only here:

  * __other__ is the folded remainder, not an interface/category/direction. Keys
    beyond --flow.top-n fold into one series per SOURCE, so the family still sums
    exactly at any limit. It keeps the source label precisely so the query below
    stays writable.
  * The family will carry TWO independent measurements of the same traffic once the
    NetFlow lane lands — Zenarmor measures what it inspects, NetFlow measures the
    packet path, and #346 decision 3 forbids summing them. Every volume query here
    therefore aggregates BY source rather than over it, so it is already correct
    when the second source appears.
"""

from builder import Builder, sel, grp, RATE
from uids import focus_interface, to_tab

# Aggregating by source rather than over it is the whole point — see the module
# docstring. Adding this to a `sum by (...)` costs one extra legend field and makes
# the panel correct for phase 2 by construction instead of by a later edit.
BY_SOURCE = "source"


def build(b: Builder):
    b.sentinel("has_flow_volume", metric="opnsense_flow_bytes_total")

    iface = b.ts(
        "Throughput by Interface (bits/sec)",
        [(f'sum {grp(BY_SOURCE, "interface")} (rate({sel("opnsense_flow_bytes_total")}[{RATE}])) * 8',
          "{{interface}} ({{source}})")],
        unit="bps",
        desc="opnsense_flow_bytes_total: flow bytes per second by interface, x8 for bits. "
             "interface is the DEVICE-derived name with VLAN children split out (ixl0_vlan50 -> "
             "IOT), so VLAN traffic is attributed to its own interface rather than to the parent "
             "LAN. An interface of __other__ is the folded remainder, not a real interface. "
             "Summed BY source: the two flow sources measure the same traffic at different points "
             "and must never be added together.",
    )

    direction = b.ts(
        "Throughput by Direction (bits/sec)",
        [(f'sum {grp(BY_SOURCE, "direction")} (rate({sel("opnsense_flow_bytes_total")}[{RATE}])) * 8',
          "{{direction}} ({{source}})")],
        unit="bps",
        desc="opnsense_flow_bytes_total by direction. internal is LAN-to-LAN traffic (including "
             "traffic to the firewall itself, and multicast, which never leaves the L2 domain); "
             "inbound and outbound involve a remote endpoint. unknown is emitted honestly when "
             "neither the firewall's topology nor the source's own direction field could classify "
             "the flow — it is never guessed away.",
    )

    category = b.ts(
        "Top Application Categories by Throughput",
        [(f'topk {grp()} (20, sum {grp(BY_SOURCE, "category")} (rate({sel("opnsense_flow_bytes_total")}[{RATE}])) * 8)',
          "{{category}} ({{source}})")],
        unit="bps",
        desc="opnsense_flow_bytes_total by Zenarmor application category — a bounded 24-value "
             "taxonomy. Application NAME is deliberately not a label (it is unbounded); it stays "
             "as structured metadata on the shipped log record, so drill down there.",
    )

    transport = b.piechart(
        "Bytes by Transport",
        [(f'sum {grp("transport")} (rate({sel("opnsense_flow_bytes_total")}[{RATE}]))', "{{transport}}")],
        unit="Bps",
        desc="opnsense_flow_bytes_total by transport protocol. A protocol the exporter does not "
             "name folds to 'other' rather than appearing as a raw number, so a misbehaving "
             "sender cannot mint label values.",
    )

    scope = b.piechart(
        "Bytes by Destination Scope",
        [(f'sum {grp("scope")} (rate({sel("opnsense_flow_bytes_total")}[{RATE}]))', "{{scope}}")],
        unit="Bps",
        desc="opnsense_flow_bytes_total by destination scope, resolved from the firewall's own "
             "configured subnets: self is the firewall, local is an attached subnet, remote is "
             "everything else. Empty means the enrichment snapshot could not classify it, which "
             "is reported rather than guessed.",
    )

    action = b.ts(
        "Flow Records by Verdict (rate)",
        [(f'sum {grp(BY_SOURCE, "action")} (rate({sel("opnsense_flow_records_total")}[{RATE}]))',
          "{{action}} ({{source}})")],
        unit="ops",
        desc="opnsense_flow_records_total by firewall verdict. An empty action means the source "
             "stated no disposition — NetFlow never does — and is NOT the same as 'pass'. Note "
             "this counts RECORDS, not connections: a Zenarmor conn document is one per "
             "connection, but one connection produces several NetFlow records.",
    )

    packets = b.ts(
        "Packet Rate by Interface & Direction",
        [(f'sum {grp(BY_SOURCE, "interface", "direction")} (rate({sel("opnsense_flow_packets_total")}[{RATE}]))',
          "{{interface}} / {{direction}} ({{source}})")],
        unit="pps",
        desc="opnsense_flow_packets_total: packets per second. Divided into the byte rate this "
             "gives mean packet size, which is a cheap way to spot a flood (small packets, high "
             "rate) against a bulk transfer.",
    )

    # ---- Domain enrichment, talkers & source disagreement (#353) ----------------
    dnscache = b.ts(
        "DNS Answer Cache",
        [(f'{sel("opnsense_flow_dns_cache_entries")}', "entries"),
         (f'rate({sel("opnsense_flow_dns_cache_hits_total")}[{RATE}])', "hits/sec"),
         (f'rate({sel("opnsense_flow_dns_cache_misses_total")}[{RATE}])', "misses/sec"),
         (f'rate({sel("opnsense_flow_dns_cache_rejected_total")}[{RATE}])', "rejected/sec")],
        unit="short",
        desc="The DNS answer cache maps a client's resolved answer IPs to the name it looked up, so a "
             "flow to a bare IP recovers dst.domain (structured metadata, never a label). Fed from the "
             "Zenarmor dns family. entries approaching --flow.dns-cache.size with a rising rejected/sec "
             "means the cap is binding and new answers stop being cached — raise the size. A high "
             "misses/sec against hits is normal for a mostly-IP workload; it is the denominator that "
             "distinguishes a cold cache from a thrashing one.",
    )

    uniquedest = b.ts(
        "Unique Destinations per Interface",
        [(f'{sel("opnsense_flow_unique_destinations")}', "{{interface}}")],
        unit="short",
        desc="opnsense_flow_unique_destinations: distinct destination addresses seen per interface — a "
             "bounded stand-in for per-destination series (one gauge per interface, never one per "
             "destination). A set, not a sum, so a destination reported by both lanes counts once. A "
             "value pinned at the internal per-interface cap means the true count is at least that "
             "high, which is itself a scanning/fan-out signal worth an alert.",
    )

    toptalkers = b.table(
        "Top Talkers by Bytes (host, direction)",
        [f'topk {grp()} (25, sum {grp("host", "direction")} (rate({sel("opnsense_flow_top_talker_bytes_total")}[{RATE}])))'],
        # The instance column is RENAMED rather than left as a raw label name, matching
        # the Build Info / NTP peer convention. #425 called this the worst panel in the
        # dashboard: `host` is a raw IP, so two firewalls both NATing 192.168.1.0/24 had
        # their top talkers fused under one address, and the table had no instance column
        # to give the merge away because the inner `sum` had already destroyed it (#468).
        renames={"opnsense_instance": "Instance", "host": "Host",
                 "direction": "Direction", "Value": "Bytes/s"},
        desc="opnsense_flow_top_talker_bytes_total: byte rate per internal host and direction. OPT-IN "
             "behind --flow.top-talkers because the host label is unbounded cardinality; empty unless "
             "enabled. Bounded by top-N with an __other__ remainder per direction, so a host that "
             "leaves and re-enters the top-N reads as a counter reset on that one series. Counts a "
             "single source, so a two-source box does not double a host's bytes.",
    )

    delta = b.ts(
        "Source Byte-Delta Ratio (NetFlow / Zenarmor)",
        [(f'histogram_quantile(0.5, sum {grp("le", "interface")} '
          f'(rate({sel("opnsense_flow_source_byte_delta_ratio_bucket")}[{RATE}])))', "p50 {{interface}}"),
         (f'histogram_quantile(0.9, sum {grp("le", "interface")} '
          f'(rate({sel("opnsense_flow_source_byte_delta_ratio_bucket")}[{RATE}])))', "p90 {{interface}}"),
         (f'histogram_quantile(0.99, sum {grp("le", "interface")} '
          f'(rate({sel("opnsense_flow_source_byte_delta_ratio_bucket")}[{RATE}])))', "p99 {{interface}}")],
        unit="ops",
        desc="Distribution of NetFlow-over-Zenarmor byte ratios on merged flow records, by interface — "
             "the payoff of correlating the two sources (#346 decision 3). 1.0 is agreement; a p90/p99 "
             "well above 1 means Zenarmor inspected far fewer bytes than crossed the wire on those "
             "flows, which is a security signal (traffic Zenarmor is not seeing), not an error. Present "
             "only where both lanes run and correlate (--flow.log-mode=per_flow); absent otherwise, "
             "since there is no disagreement to measure.",
    )

    # ---- drilldowns (#419) ------------------------------------------------
    # Flow's `interface` label is description space, not device space: live values on
    # 2026-07-27 were AAISP, CAM, IOT, LAN, MGMT, VIRGIN — the same set
    # opnsense_interfaces_link_state carries — plus unresolved device names and the
    # synthetic `locally-originated`/`__other__` keys, which simply select nothing.
    # So $interface is the right variable here and $device is not.
    for panel in (iface, packets):
        b.field_links(panel, [focus_interface()])
        b.panel_links(panel, [
            to_tab("Interface counters for this selection", "Network", "Interfaces"),
            to_tab("Firewall verdicts for this selection", "Security", "Firewall & PF"),
        ])

    b.tab("Flow Volume", [
        b.row("Volume", [iface, direction], present="has_flow_volume"),
        b.row("Breakdown", [category, transport, scope], present="has_flow_volume"),
        b.row("Records & Packets", [action, packets], present="has_flow_volume"),
        b.row("Domain, Talkers & Source Delta", [dnscache, uniquedest, toptalkers, delta]),
    ], present="has_flow_volume")
