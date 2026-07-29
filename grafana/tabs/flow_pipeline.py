"""
Flow Pipeline tab (exporter health) — the flow ingest path watching itself (#523).

Everything here is a counter about the exporter's own machinery: the rollup
accumulator's two bounds, the NetFlow receiver's refusals, the decoder's template
state, the de-duplication and egress repairs, the correlator, and the flow-log
emission budget. None of it says anything about the firewall's traffic — that is
the `Flow Volume` tab on the operational dashboard, which these panels shared a tab
with until the Observability domain was retired.

The split is by audience, not by metric prefix. An operator asking "how much is
crossing WAN2" and an operator asking "is the NetFlow receiver dropping datagrams"
are not the same person on the same day, and the second question belongs beside
scrape health and OTLP delivery.

Two things a reader has to know, both stated on the panels themselves:

  * __other__ is the folded remainder, not an interface/category/direction. Keys
    beyond --flow.top-n fold into one series per SOURCE, so the family still sums
    exactly at any limit.
  * The family carries TWO independent measurements of the same traffic — Zenarmor
    measures what it inspects, NetFlow measures the packet path, and #346 decision 3
    forbids summing them. Queries here aggregate BY source rather than over it.
"""

from builder import Builder, sel, grp, RATE

# Aggregating by source rather than over it is the whole point — see the module
# docstring and tabs/flow.py, which holds the same constant for the same reason.
BY_SOURCE = "source"


def build(b: Builder):
    b.sentinel("has_flow", name_regex="opnsense_flow_.+")
    # The NetFlow rows stay hidden entirely where the receiver was never enabled: its
    # metrics are absent rather than zero there, deliberately, so a row of flat zeros
    # would imply a receiver that does not exist.
    #
    # Named has_flow_NETFLOW, not has_netflow (#414) — and that rename FIXED A LATENT
    # MIS-GATING BUG, it is not cosmetic. It used to collide with the NetFlow tab's own
    # sentinel on opnsense_netflow_active, which asks a DIFFERENT question ("has
    # OPNsense's own netflow export been configured?") than this one ("is OUR receiver
    # actually taking datagrams?"). The two tabs now live on different dashboards, so
    # the names could no longer collide even if they were the same — the distinct name
    # is kept because the questions are still distinct and a reader of either module
    # should not have to know which dashboard resolved the ambiguity.
    b.sentinel("has_flow_netflow", metric="opnsense_flow_netflow_datagrams_total")

    other_bytes = sel("opnsense_flow_bytes_total", 'interface="__other__"')
    all_bytes = sel("opnsense_flow_bytes_total")
    other_share = b.ts(
        "__other__ Share of Total Bytes",
        [(f'sum {grp(BY_SOURCE)} (rate({other_bytes}[{RATE}])) '
          f'/ clamp_min(sum {grp(BY_SOURCE)} (rate({all_bytes}[{RATE}])), 1)',
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
        [(f'sum {grp(BY_SOURCE)} (rate({sel("opnsense_flow_rollup_capped_total")}[{RATE}]))',
          "records lost to the max-keys cap"),
         (f'rate({sel("opnsense_flow_payload_byte_fallback_total")}[{RATE}])',
          "records using the payload-byte fallback")],
        unit="ops",
        desc="Two counters that must never be silent. capped_total rising means new label "
             "combinations are hitting the memory cap, not merely the top-N — raise --flow.max-keys "
             "or narrow what is being rolled up. payload_byte_fallback_total counts records whose "
             "byte figure came from Zenarmor's payload counter because its wire counter read zero, "
             "which it does on short UDP flows (DNS, STUN, SSDP); without the fallback those "
             "records would be counted with no bytes at all, so a steady rate here is normal and "
             "is the repair working.",
    )

    # ---- NetFlow lane (phase 2) -------------------------------------------------
    # These are all "what did we refuse to trust" counters. On an unauthenticated UDP
    # ingress that distinction is the whole security story, so none of them is allowed
    # to be silent.
    # #416: datagram counts and the export's byte volume used to share one
    # "short" field unit on a single panel, so the byte series' magnitude
    # flattened the per-outcome datagram-rate series and the axis mislabelled
    # a byte rate as a unitless count. Split into a datagram-rate panel and a
    # dedicated byte-rate panel (unit="Bps"); both queries are unchanged.
    ingest = b.ts(
        "NetFlow Ingest (datagrams/sec)",
        [(f'sum {grp("result")} (rate({sel("opnsense_flow_netflow_datagrams_total")}[{RATE}]))', "{{result}}")],
        unit="pps",
        desc="Datagrams per second by outcome (datagrams/sec, not bytes). result=\"accepted\" "
             "passed the peer allowlist; \"peer_rejected\" came from outside "
             "--flow.netflow.allowed-peers and is the signal that something else on the network is "
             "pointed here; \"queue_dropped\" arrived faster than the decoders drained them, which is "
             "real data loss and means raising the worker count or the queue. The decode outcomes "
             "(malformed, unsupported_version, varlen_rejected) are a SUBSET of accepted, not "
             "additional to it. See 'NetFlow Ingest Bytes' for the wire byte volume of the export "
             "itself: it used to share this axis, where its magnitude flattened this datagram-rate "
             "series.",
    )
    ingest_bytes = b.ts(
        "NetFlow Ingest Bytes (bytes/sec)",
        [(f'rate({sel("opnsense_flow_netflow_bytes_received_total")}[{RATE}])', "bytes/sec received")],
        unit="Bps",
        desc="Wire byte volume of the NetFlow export itself, per second (bytes/sec) -- not a "
             "datagram count, and not the traffic the export describes. Pairs with 'NetFlow Ingest "
             "(datagrams/sec)' for the per-outcome breakdown of the same datagrams.",
    )

    funnel = b.ts(
        "NetFlow Record Funnel (records/sec)",
        [(f'rate({sel("opnsense_flow_netflow_records_decoded_total")}[{RATE}])', "decoded"),
         (f'rate({sel("opnsense_flow_netflow_records_emitted_total")}[{RATE}])', "emitted to rollup"),
         (f'sum {grp("reason")} (rate({sel("opnsense_flow_netflow_records_dropped_total")}[{RATE}]))',
          "dropped: {{reason}}")],
        unit="ops",
        desc="decoded = emitted + dropped. reason=\"vlan_duplicate\" is the parent-interface copy of a "
             "VLAN flow being suppressed — ng_netflow captures both the trunk and the child, so this "
             "SHOULD be non-zero on a VLAN'd box (~4% of bytes on the reference capture) and a flat "
             "zero there means the de-dup is not firing and volume is double-counted. "
             "reason=\"no_template\" is normal for ~2 minutes after either end restarts; sustained, it "
             "means template datagrams are being lost and records are being discarded wholesale.",
    )

    decoder = b.ts(
        "NetFlow Decoder Health",
        [(f'sum {grp("result")} (rate({sel("opnsense_flow_netflow_templates_total")}[{RATE}]))',
          "templates {{result}}"),
         (f'sum {grp("field")} (rate({sel("opnsense_flow_netflow_unexpected_field_total")}[{RATE}]))',
          "unexpected {{field}}"),
         (f'sum {grp("kind")} (rate({sel("opnsense_flow_netflow_unidentified_total")}[{RATE}]))',
          "unidentified {{kind}}")],
        unit="ops",
        desc="templates \"learned\" settles to ~0 after startup; a steady \"replaced\" rate means the "
             "exporter is re-sending a template id with a DIFFERENT field shape, which invalidates the "
             "decoder's understanding of every record behind it. unexpected_field counts records "
             "carrying a field asserted to be always-empty on this export (today OUT_BYTES, zero "
             "across all 84,513 records of the reference capture): non-zero does NOT mean volume is "
             "currently wrong, it means that assumption has expired and the decoder needs revisiting. "
             "unidentified counts what the decoder stepped over rather than interpreted — an "
             "unmodelled template element, an options template, an unknown control flowset. Stepping "
             "over is CORRECT (assuming a width would corrupt every field behind it); a non-zero "
             "unknown_field is expected, since the box's IPv4 template declares four elements we do "
             "not model, so it is a CHANGE here that means the export gained something. The element "
             "IDs are in the log line, not a label — this socket is unauthenticated. Set "
             "--flow.netflow.debug-capture=unidentified to keep the datagrams themselves.",
    )

    repairs = b.ts(
        "Flow Repairs & De-duplication",
        [(f'rate({sel("opnsense_flow_egress_corrected_total")}[{RATE}])', "egress corrections/sec"),
         (f'rate({sel("opnsense_flow_vlan_child_preferred_total")}[{RATE}])', "vlan child preferred/sec"),
         (f'rate({sel("opnsense_flow_vlan_subnet_attributed_total")}[{RATE}])', "vlan subnet attributed/sec"),
         (f'rate({sel("opnsense_flow_vlan_late_child_copies_total")}[{RATE}])', "late child copies/sec"),
         (f'{sel("opnsense_flow_dedupe_entries")}', "dedupe table entries"),
         (f'{sel("opnsense_flow_repair_held_records")}', "records held"),
         (f'sum {grp("reason")} (rate({sel("opnsense_flow_dedupe_entries_dropped_total")}[{RATE}]))',
          "dedupe dropped: {{reason}}")],
        unit="short",
        desc="egress_corrected counts flows whose egress was corrected from the WAN the FIB lookup "
             "named to the WAN the traffic actually left by — OPNsense policy routing happens in pf, "
             "which ng_netflow never sees, and on the reference capture this mislabelled 3.36 GB of "
             "WAN2 traffic as WAN1. On a policy-routed multi-WAN box a flat zero means the correction "
             "is NOT firing and per-WAN volume is wrong. vlan_child_preferred counts duplicates "
             "resolved in favour of the VLAN child rather than the trunk: ng_netflow flushes the trunk "
             "hook's copy FIRST, so on a box with VLAN interfaces a flat zero means every VLAN's "
             "traffic is being attributed to the trunk. records held is the short queue that makes "
             "that possible — it should hover near the per-window record rate and never grow without "
             "bound. dedupe dropped reason=\"ttl\" is the healthy path; \"capacity\" means the table "
             "filled and later duplicates are no longer suppressed; \"hold_overflow\" means the hold "
             "buffer filled and those records fell back to whichever copy arrived first. "
             "vlan_subnet_attributed is the mechanism that made the hold mostly unnecessary: a "
             "trunk-named record whose address falls inside exactly one VLAN child's configured "
             "subnet is moved onto that child on FIRST SIGHT, so arrival order stops mattering - the "
             "hold covers only 70.8% of real pairs (p95 gap 5.7 s, p99 31.2 s against a 2 s window), "
             "and it also reaches the records that have no second copy at all. On a box whose VLANs "
             "have configured subnets, expect this to carry most of the attribution and "
             "vlan_child_preferred to sit near zero. late_child_copies is the RESIDUAL: a better copy "
             "that arrived after the first was already emitted and counted, so it could not be "
             "corrected without double-counting. It was 29.2% of pairs before subnet attribution "
             "existed; a sustained non-zero rate now means a VLAN is missing a configured subnet, or "
             "two children's subnets overlap.",
    )

    ifindex = b.ts(
        "NetFlow ifIndex Map",
        [(f'{sel("opnsense_flow_ifindex_entries")}', "entries"),
         (f'{sel("opnsense_flow_ifindex_conflicts")}', "override conflict: {{reason}}"),
         (f'{sel("opnsense_flow_ifindex_map_age_seconds")}', "map age (s)"),
         (f'rate({sel("opnsense_flow_ifindex_unmapped_total")}[{RATE}])', "unmapped lookups/sec"),
         (f'rate({sel("opnsense_flow_netflow_records_unmapped_total")}[{RATE}])',
          "unmapped records/sec"),
         (f'{sel("opnsense_flow_ifindex_source_disagreements")}', "guard: {{reason}}")],
        unit="short",
        # map age is the one series here whose absolute magnitude is the alarm, and it was
        # the only one rendered unitless — a day-old map read "86.4 K" (#513).
        overrides=[{"matcher": {"id": "byRegexp", "options": "^map age \\(s\\)$"},
             "properties": [{"id": "unit", "value": "s"}]}],
        desc="Two unmapped series, and they are NOT the same number. \"unmapped lookups\" counts "
             "ifIndex lookups that missed against a map that EXISTS; \"unmapped records\" counts whole "
             "records that ended up with an empty interface label, and it is the only one of the two "
             "that fires while the map is still nil — the cold-start window between the receiver "
             "starting and the first interface fetch landing. A burst of unmapped records right after "
             "a restart with no matching lookups is that window; both rising together means the "
             "enumeration shifted. Those records still counted in the volume totals, with an empty "
             "label. "
             "ng_netflow numbers interfaces POSITIONALLY over ifinfo output, so adding or removing any "
             "interface renumbers everything and silently remaps historical series. conflicts > 0 "
             "means the operator's --flow.netflow.ifindex-map disagrees with the map derived from the "
             "API: the override wins so pinned indices are right, but every index NOT pinned is "
             "suspect. Rising unmapped lookups after a network change means the enumeration shifted — "
             "those records still count, with an empty interface label, because a wrong interface "
             "name is worse than a missing one. The guard series cross-check the enumeration against "
             "the index the API states per device and against the set of interfaces the box reports; "
             "either one non-zero means every NetFlow interface label is suspect. This map was "
             "measurably wrong for months and read entirely clean while it was (#361), so treat a "
             "flat zero here as 'checked', not as 'nothing to check'.",
    )

    correlator = b.ts(
        "Flow Correlator",
        [(f'{sel("opnsense_flow_correlator_entries")}', "live entries"),
         (f'rate({sel("opnsense_flow_correlator_emitted_total")}[{RATE}])', "emitted/sec"),
         (f'rate({sel("opnsense_flow_correlator_matched_total")}[{RATE}])', "merged/sec"),
         (f'rate({sel("opnsense_flow_correlator_evicted_total")}[{RATE}])', "force-evicted/sec"),
         (f'rate({sel("opnsense_flow_correlator_expired_total")}[{RATE}])', "expired/sec")],
        unit="short",
        desc="The correlator collapses NetFlow's 1:N fragmentation (mean 3.75 records per connection) "
             "into one record per connection-window and merges Zenarmor L7 where a conn document "
             "matched. merged/sec against emitted/sec is the join hit-rate, which #346 shows is "
             "materially lower for long flows whose NetFlow records arrive up to ~30m after the "
             "connection ended. A rising force-evicted rate means --flow.correlate.max-entries is "
             "binding under load and should be raised; expired is the healthy path.",
    )

    flowlogs = b.ts(
        "Flow Log Emission",
        [(f'rate({sel("opnsense_flow_logs_emitted_total")}[{RATE}])', "emitted/sec"),
         (f'rate({sel("opnsense_flow_logs_truncated_total")}[{RATE}])', "truncated/sec"),
         (f'rate({sel("opnsense_flow_logs_dropped_total")}[{RATE}])', "dropped/sec")],
        unit="ops",
        desc="Flow records shipped to the OTLP log pipeline in --flow.log-mode=per_flow. truncated is "
             "the --flow.max-logs-per-window budget dropping records under a flood on the "
             "unauthenticated NetFlow ingress — truncated, never sampled, and metrics are never "
             "affected. dropped means the log pipeline was not accepting records (before start / after "
             "shutdown began). Flat zero throughout when --flow.log-mode=off.",
    )

    b.tab("Flow Pipeline", [
        b.row("Accumulator Health", [other_share, keys, capped]),
        b.row("NetFlow Receiver", [ingest, ingest_bytes, funnel, decoder],
              present="has_flow_netflow"),
        b.row("NetFlow Repairs & Topology", [repairs, ifindex], present="has_flow_netflow"),
        b.row("Correlator & Log Emission", [correlator, flowlogs]),
    ], present="has_flow")
