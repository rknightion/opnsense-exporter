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

The last row is the LOG drilldown (#592 item 1 / #591 item 5), and it is here rather
than on Flow Pipeline deliberately: Flow Pipeline is the exporter watching its own
ingest machinery, while the question this row answers — "WAN egress is at 400 Mbit,
which conversation is it?" — is asked by an operator standing in front of these
volume panels, usually because `instance:opnsense_flow_bytes:rate5m` just alerted.
Every panel above is an aggregate by construction (host and application NAME are
unbounded and can never be metric labels), so before this row the drilldown simply
ended there, even though the exporter already ships src.ip, dst.ip, app.name and
flow.community_id on one record per connection-window.
"""

from builder import Builder, sel, grp, loki_sel, loki_grp, RATE
from uids import focus_interface, to_tab

# Aggregating by source rather than over it is the whole point — see the module
# docstring. Adding this to a `sum by (...)` costs one extra legend field and makes
# the panel correct for phase 2 by construction instead of by a later edit.
BY_SOURCE = "source"

# The correlated flow-log stream (#346, --flow.log-mode=per_flow). Two lanes, one
# record schema (internal/flow Record.LogAttributes): `netflow` is a record the
# correlator emitted with no Zenarmor conn document matched, `merged` is one where a
# match folded L7 in. They are selected TOGETHER because an operator asking which
# conversation moved the bytes does not know in advance which lane produced it — and
# splitting them would hide exactly the un-correlated half.
#
# Unlike the unbound/ids/crowdsec lanes, this one DOES stamp a subsystem
# (logship.AttrSubsystem = "flow", set by internal/logship/flowlog). It is not used
# here: Zenarmor's own receiver also ships subsystem="flow" records, which are its
# conn documents rather than these correlated ones, so the source label is the only
# matcher that selects this schema and nothing else.
FLOW_LOG_STREAM = loki_sel('opnsense_source=~"netflow|merged"')

# Attribute names lose their dots in Loki (docs/syslog-receiver.md): the record emits
# `dst.ip` / `app.name` / `flow.nf.bytes`, and LogQL sees dst_ip / app_name /
# flow_nf_bytes. A query written with the dotted name matches nothing and reports no
# error, which is why these are named once here.
NF_BYTES = "flow_nf_bytes"

# Endpoint addresses are unbounded, so the table ranking them pins its own window
# (#479) — Loki's max_query_series is enforced on a query INTERMEDIATE, so `topk`
# does not bound it and only the range moves the cliff. Same measured 1h fit the
# Zenarmor tab uses against the same tenant.
UNBOUNDED_LABEL_WINDOW = "1h"


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
    # Three availability conditions, not one (#649). `DNS Answer Cache` and `Unique
    # Destinations` ship with the flow lane, so `has_flow_volume` covers them. The other
    # two do not: `--flow.top-talkers` is opt-in because the host label is unbounded
    # cardinality, and the delta-ratio histogram exists only where BOTH lanes correlate.
    # They shared an ungated row with the first pair, so a default flow box rendered two
    # permanently blank panels — the same defect `has_flow_country` and `has_flow_logs`
    # were added to avoid, and the reason this row is now split in two. The second row
    # gates on the OR of the two, which is the available primitive: enabling one of the
    # pair can still leave the other panel blank, but the row no longer appears at all on
    # a box that enabled neither, which is the common case this exists to fix.
    b.sentinel("has_flow_top_talkers", metric="opnsense_flow_top_talker_bytes_total")
    b.sentinel("has_flow_delta_ratio", metric="opnsense_flow_source_byte_delta_ratio_bucket")

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
        [(f'{sel("opnsense_flow_unique_destinations")}', "{{interface}}"),
         (f'sum {grp()} (rate({sel("opnsense_flow_unique_destinations_capped_total")}[{RATE}]))',
          "folded — interface budget reached")],
        unit="short",
        desc="opnsense_flow_unique_destinations: distinct destination addresses seen per interface — a "
             "bounded stand-in for per-destination series (one gauge per interface, never one per "
             "destination). A set, not a sum, so a destination reported by both lanes counts once. A "
             "value pinned at the internal per-interface cap means the true count is at least that "
             "high, which is itself a scanning/fan-out signal worth an alert. The second series is the "
             "OUTER bound: the interface and VLAN strings come from the Zenarmor sender, so past a "
             "fixed interface budget a previously unseen label folds into __other__ instead of minting "
             "another map and another series (#563). Non-zero means the per-interface counts above are "
             "no longer complete — either the box has more interfaces than the budget, or a sender is "
             "inventing them.",
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
          f'(rate({sel("opnsense_flow_source_byte_delta_ratio_bucket")}[{RATE}])))', "p99 {{interface}}"),
         (f'rate({sel("opnsense_flow_source_byte_delta_excluded_total")}[{RATE}])',
          "excluded (window partial)/sec")],
        unit="ops",
        desc="Distribution of NetFlow-over-Zenarmor byte ratios on merged flow records, by interface — "
             "the payoff of correlating the two sources (#346 decision 3). 1.0 is agreement; a p90/p99 "
             "well above 1 means Zenarmor inspected far fewer bytes than crossed the wire on those "
             "flows, which is a security signal (traffic Zenarmor is not seeing), not an error. Present "
             "only where both lanes run and correlate (--flow.log-mode=per_flow); absent otherwise, "
             "since there is no disagreement to measure. "
             "READ THE DEVIATION CAREFULLY — most of it is accounting basis, not blindness (#604). "
             "NetFlow counts WIRE bytes; Zenarmor falls back to PAYLOAD bytes on roughly HALF of all "
             "flow records, because it does not accumulate wire bytes until it has tracked a flow past "
             "its first packets — which is every short UDP flow. On that population this panel is "
             "showing per-packet header overhead: the gap clusters at 28 bytes (the IPv4 IP+UDP "
             "header) and p90 there alone reaches 1.96. Records carry flow.zen_bytes_are_payload so "
             "the two bases can be told apart in the logs. The excluded series is the other half of "
             "#604: a connection longer than --flow.correlate.window would compare one window of "
             "NetFlow bytes against a whole connection's Zenarmor bytes, reading as an impossible "
             "ratio near 0.01, so those records are kept out of the histogram entirely and counted "
             "here instead. They still ship with both sides' volume — only the comparison is dropped. "
             "If the question is really \"is traffic evading inspection\", use a BYTE-WEIGHTED "
             "comparison (summed NetFlow bytes over summed Zenarmor bytes on merged records) rather "
             "than a percentile of per-flow ratios; byte-weighted, the reference box reads 1.22-1.36.",
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

    # ---- geo (#520) -------------------------------------------------------
    # The `country` label exists on the volume family only behind
    # --flow.geoip.metric-dims, because it multiplies every existing flow series
    # roughly 250-fold. The sentinel therefore tests for a NON-EMPTY country rather
    # than for the metric: the family is always present, and on the default
    # deployment every series carries country="" — which Prometheus treats as absent,
    # so an ungated row would render one flat "unknown" line on every box that has
    # not opted in.
    b.sentinel("has_flow_country", metric="opnsense_flow_bytes_total", more='country!=""')

    country = b.ts(
        "Traffic by Country (bits/sec)",
        [(f'topk {grp()} (15, sum {grp(BY_SOURCE, "country")} '
          f'(rate({sel("opnsense_flow_bytes_total")}[{RATE}]))) * 8', "{{country}} ({{source}})")],
        unit="bps",
        desc="Bytes per second by the country of the flow's REMOTE end, from the exporter's own "
             "MaxMind database — so it is the same answer whether or not Zenarmor saw the connection, "
             "which is the asymmetry #520 exists to close. Present only with "
             "--flow.geoip.metric-dims, which is OFF by default: country is a ~250-value dimension "
             "multiplied against every other flow label, and --flow.top-n/--flow.max-keys will start "
             "folding real series into __other__ before the family grows without bound. ASN and city "
             "are never labels at any setting — they are on the flow LOG records, as "
             "<src|dst>.geo.asn and <src|dst>.geo.city. Pin `source` in any query of your own or the "
             "two lanes' measurements of the same traffic are summed.",
    )

    # ---- flow-log drilldown (#592 item 1 / #591 item 5) -------------------
    # The panels above are the only aggregate view; these are the individual
    # conversations behind them. Present only with --flow.log-mode=per_flow, which is
    # why the row has its own sentinel rather than riding has_flow_volume: the metric
    # rollup runs whether or not log records are emitted.
    b.loki_sentinel("has_flow_logs", matchers='opnsense_source=~"netflow|merged"',
                    label="opnsense_source")

    flow_raw_logs = b.logs(
        "Raw Flow Records",
        FLOW_LOG_STREAM,
        desc="One log record per connection-window, from the #346 correlator "
             "(--flow.log-mode=per_flow). The body is a one-line src -> dst summary; the "
             "structured metadata is ~24 keys — src_ip, dst_ip, ports, net_transport, "
             "flow_community_id, flow_direction, flow_interface, flow_action, app_name, "
             "dst_domain, dst_hostname, the geo fields, and BOTH sources' byte and packet "
             "counters as flow_nf_bytes and flow_zen_bytes. The two byte counters are never "
             "summed (#346 decision 3): they measure at different points and their disagreement "
             "is itself the signal, which the Source Byte-Delta Ratio panel above quantifies. "
             "flow_community_id is the cross-tool connection id — the same value Suricata and "
             "Zenarmor compute, so it joins this record to an IDS alert.",
        w=24,
    )
    flow_records_rate = b.loki_ts(
        "Flow Records/s by Lane",
        [(f'sum {loki_grp("opnsense_source")} (rate({FLOW_LOG_STREAM} [$__auto]))',
          "{{opnsense_source}}")],
        unit="ops",
        desc="Correlated flow-log records per second, split by lane. `merged` is a connection "
             "where a Zenarmor conn document matched the NetFlow record, so it carries L7 "
             "(app_name, dst_domain, encryption); `netflow` is one where none did, so those keys "
             "are absent rather than empty. The merged share is the join hit-rate seen from the "
             "log side — the Flow Correlator panel on the Flow Pipeline tab is the same ratio "
             "from the exporter's own counters, and is the cheaper one to alert on. Both lanes "
             "are subject to the --flow.max-logs-per-window budget, so a flood truncates this "
             "while the metric panels above stay complete.",
    )
    flow_top_dst = b.loki_table(
        "Top Flow Destinations by Bytes",
        [f'topk {loki_grp()} (200, sum {loki_grp("dst_ip")} (sum_over_time({FLOW_LOG_STREAM} '
         f'| dst_ip!="" | unwrap {NF_BYTES} [$__range])))'],
        field_title="Destination",
        value_unit="bytes",
        # NetFlow's counter, not Zenarmor's, and not a sum of the two. NF counts at the
        # packet path and is authoritative for volume (internal/flow/deltaratio.go);
        # both lanes selected here always carry it, while flow_zen_bytes exists only on
        # the merged half — ranking on that would silently rank a subset.
        desc="The destinations that actually moved the bytes, over this panel's own 1h window. "
             "THIS is the drilldown from Throughput by Interface: that panel says WAN egress is "
             "at 400 Mbit, this says which conversations it is. Value is NetFlow's byte counter "
             "(flow_nf_bytes) — the packet-path measurement, which is authoritative for volume "
             "and is present on both lanes; Zenarmor's counter is deliberately not summed with "
             "it and exists only on merged records. Pinned to 1h rather than following the time "
             "picker because addresses are unbounded and Loki's series ceiling is enforced on a "
             "query intermediate, so a wider range returns a query error rather than fewer rows.",
        time_from=UNBOUNDED_LABEL_WINDOW,
    )
    flow_top_apps = b.loki_table(
        "Top Flow Applications by Bytes",
        [f'topk {loki_grp()} (200, sum {loki_grp("app_name")} (sum_over_time({FLOW_LOG_STREAM} '
         f'| app_name!="" | unwrap {NF_BYTES} [$__range])))'],
        field_title="Application",
        value_unit="bytes",
        desc="Application NAMES behind the Top Application Categories panel above, which can "
             "only show the bounded 24-value category taxonomy because names are unbounded and "
             "must not be a metric label. Merged records only, by construction: app_name comes "
             "from the Zenarmor conn document, so an uncorrelated NetFlow record carries none "
             "and is absent here rather than counted as unknown — read the merged share on Flow "
             "Records/s by Lane before treating this as a complete picture of the traffic. "
             "Zenarmor's own Top Applications table counts RECORDS; this one weighs them by "
             "NetFlow's bytes, so a chatty app and a heavy one rank differently.",
    )

    b.tab("Flow Volume", [
        b.row("Volume", [iface, direction], present="has_flow_volume"),
        b.row("Breakdown", [category, transport, scope], present="has_flow_volume"),
        b.row("Records & Packets", [action, packets], present="has_flow_volume"),
        b.row("Domain & Destinations", [dnscache, uniquedest], present="has_flow_volume"),
        b.row("Talkers & Source Delta", [toptalkers, delta],
              present=["has_flow_top_talkers", "has_flow_delta_ratio"]),
        b.row("Geography", [country], present="has_flow_country"),
        # Collapsed (#422): four round-trips against a per-connection stream on every
        # cold load, and this row is by definition opened AFTER a volume panel above
        # has raised the question it answers.
        b.row("Flow Record Drilldown",
              [flow_raw_logs, flow_records_rate, flow_top_dst, flow_top_apps],
              present="has_flow_logs", collapse=True),
    ], present="has_flow_volume")
