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

from builder import Builder, sel, RATE

# Aggregating by source rather than over it is the whole point — see the module
# docstring. Adding this to a `sum by (...)` costs one extra legend field and makes
# the panel correct for phase 2 by construction instead of by a later edit.
BY_SOURCE = "source"


def build(b: Builder):
    b.sentinel("has_flow", 'label_values({__name__=~"opnsense_flow_.+"}, __name__)')
    b.sentinel("has_flow_volume", "label_values(opnsense_flow_bytes_total, __name__)")

    iface = b.ts(
        "Throughput by Interface (bits/sec)",
        [(f'sum by ({BY_SOURCE}, interface) (rate({sel("opnsense_flow_bytes_total")}[{RATE}])) * 8',
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
        [(f'sum by ({BY_SOURCE}, direction) (rate({sel("opnsense_flow_bytes_total")}[{RATE}])) * 8',
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
        [(f'topk(20, sum by ({BY_SOURCE}, category) (rate({sel("opnsense_flow_bytes_total")}[{RATE}])) * 8)',
          "{{category}} ({{source}})")],
        unit="bps",
        desc="opnsense_flow_bytes_total by Zenarmor application category — a bounded 24-value "
             "taxonomy. Application NAME is deliberately not a label (it is unbounded); it stays "
             "as structured metadata on the shipped log record, so drill down there.",
    )

    transport = b.piechart(
        "Bytes by Transport",
        [(f'sum by (transport) (rate({sel("opnsense_flow_bytes_total")}[{RATE}]))', "{{transport}}")],
        unit="Bps",
        desc="opnsense_flow_bytes_total by transport protocol. A protocol the exporter does not "
             "name folds to 'other' rather than appearing as a raw number, so a misbehaving "
             "sender cannot mint label values.",
    )

    scope = b.piechart(
        "Bytes by Destination Scope",
        [(f'sum by (scope) (rate({sel("opnsense_flow_bytes_total")}[{RATE}]))', "{{scope}}")],
        unit="Bps",
        desc="opnsense_flow_bytes_total by destination scope, resolved from the firewall's own "
             "configured subnets: self is the firewall, local is an attached subnet, remote is "
             "everything else. Empty means the enrichment snapshot could not classify it, which "
             "is reported rather than guessed.",
    )

    action = b.ts(
        "Flow Records by Verdict (rate)",
        [(f'sum by ({BY_SOURCE}, action) (rate({sel("opnsense_flow_records_total")}[{RATE}]))',
          "{{action}} ({{source}})")],
        unit="short",
        desc="opnsense_flow_records_total by firewall verdict. An empty action means the source "
             "stated no disposition — NetFlow never does — and is NOT the same as 'pass'. Note "
             "this counts RECORDS, not connections: a Zenarmor conn document is one per "
             "connection, but one connection produces several NetFlow records.",
    )

    packets = b.ts(
        "Packet Rate by Interface & Direction",
        [(f'sum by ({BY_SOURCE}, interface, direction) (rate({sel("opnsense_flow_packets_total")}[{RATE}]))',
          "{{interface}} / {{direction}} ({{source}})")],
        unit="pps",
        desc="opnsense_flow_packets_total: packets per second. Divided into the byte rate this "
             "gives mean packet size, which is a cheap way to spot a flood (small packets, high "
             "rate) against a bulk transfer.",
    )

    other_bytes = sel("opnsense_flow_bytes_total", 'interface="__other__"')
    all_bytes = sel("opnsense_flow_bytes_total")
    other_share = b.ts(
        "__other__ Share of Total Bytes",
        [(f'sum by ({BY_SOURCE}) (rate({other_bytes}[{RATE}])) '
          f'/ clamp_min(sum by ({BY_SOURCE}) (rate({all_bytes}[{RATE}])), 1)',
          "{{source}}")],
        unit="percentunit",
        desc="How much of the traffic is landing in the folded remainder rather than in a named "
             "series. Small is normal and healthy — it is the long tail of tiny categories. Large "
             "and rising means --flow.top-n is too small to describe this network, and the "
             "dimensions an operator actually wants are being folded away. The family total stays "
             "exact either way; only the breakdown is lost.",
    )

    keys = b.ts(
        "Rollup Key Usage",
        [(f'{sel("opnsense_flow_rollup_keys")}', "tracked"),
         (f'{sel("opnsense_flow_rollup_keys_folded")}', "folded out of top-N"),
         (f'{sel("opnsense_flow_rollup_keys_max")}', "max-keys ceiling"),
         (f'{sel("opnsense_flow_rollup_top_n")}', "top-n ceiling")],
        unit="short",
        desc="The accumulator's two INDEPENDENT bounds and how close it is to each. tracked "
             "approaching the max-keys ceiling is the one to watch: at the ceiling every NEW label "
             "combination folds into __other__ indefinitely, so an operator otherwise cannot tell "
             "'a few small categories folded' from 'the map saturated weeks ago and everything new "
             "since is invisible'. folded is the ordinary top-N overflow and is expected to be "
             "non-zero.",
    )

    capped = b.ts(
        "Rollup Saturation & Byte-field Repairs (rate)",
        [(f'sum by ({BY_SOURCE}) (rate({sel("opnsense_flow_rollup_capped_total")}[{RATE}]))',
          "records lost to the max-keys cap"),
         (f'rate({sel("opnsense_flow_payload_byte_fallback_total")}[{RATE}])',
          "records using the payload-byte fallback")],
        unit="short",
        desc="Two counters that must never be silent. capped_total rising means new label "
             "combinations are hitting the memory cap, not merely the top-N — raise --flow.max-keys "
             "or narrow what is being rolled up. payload_byte_fallback_total counts records whose "
             "byte figure came from Zenarmor's payload counter because its wire counter read zero, "
             "which it does on short UDP flows (DNS, STUN, SSDP); without the fallback those "
             "records would be counted with no bytes at all, so a steady rate here is normal and "
             "is the repair working.",
    )

    b.tab("Flow Volume", [
        b.row("Volume", [iface, direction], present="has_flow_volume"),
        b.row("Breakdown", [category, transport, scope], present="has_flow_volume"),
        b.row("Records & Packets", [action, packets], present="has_flow_volume"),
        b.row("Accumulator Health", [other_share, keys, capped]),
    ], present="has_flow")
