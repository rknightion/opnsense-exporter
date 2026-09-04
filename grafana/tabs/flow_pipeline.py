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
          "records using the payload-byte fallback"),
         (f'rate({sel("opnsense_flow_interface_unresolved_total")}[{RATE}])',
          "records labelled interface=unresolved")],
        unit="ops",
        desc="Two counters that must never be silent. capped_total rising means new label "
             "combinations are hitting the memory cap, not merely the top-N — raise --flow.max-keys "
             "or narrow what is being rolled up. payload_byte_fallback_total counts records whose "
             "byte figure came from Zenarmor's payload counter because its wire counter read zero, "
             "which it does on short UDP flows (DNS, STUN, SSDP); without the fallback those "
             "records would be counted with no bytes at all, so a steady rate here is normal and "
             "is the repair working. "
             "interface_unresolved_total is the startup window (#606): the flow lanes are push-based "
             "and the interface DESCRIPTIONS arrive on the exporter's own schedule, so records "
             "ingested before the first snapshot name a kernel device we cannot yet translate. They "
             "are labelled interface=\"unresolved\" rather than with the raw device, which would "
             "invent a second series for an interface that already has one and leave every "
             "`sum by (interface)` short on both. Expect one burst per restart and nothing between: "
             "on the reference box every such record landed inside 300 seconds of process uptime, "
             "across 7 days and 51 restarts. A rate continuing past that means the interface fetch "
             "is failing, not that something restarted - correlate against "
             "changes(process_start_time_seconds).",
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
             "carrying a field asserted to be always-empty on this export: OUT_BYTES/OUT_PKTS (zero "
             "across all 84,513 records of the reference capture) and SRC_AS/DST_AS (#586, zero across "
             "all 131 records of the reference capture - ng_netflow hardcodes both under an explicit "
             "source comment, and a better ASN already ships via the GeoIP asn label). Non-zero does "
             "NOT mean volume is currently wrong, it means that assumption has expired and the decoder "
             "needs revisiting. "
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

    policy_route = b.ts(
        "Multi-WAN Policy-Route Attribution",
        [(f'rate({sel("opnsense_flow_policy_route_corrected_total")}[{RATE}])',
          "policy-route corrections/sec"),
         (f'sum {grp("reason")} (rate({sel("opnsense_flow_policy_route_refused_total")}[{RATE}]))',
          "refused: {{reason}}"),
         # Split by WHERE THE BYTES ARE CURRENTLY ATTRIBUTED, not where they went - a
         # refused record has no known real egress. Read it as a distribution: misses
         # piling up on the default-route WAN say policy-routed traffic is hiding
         # inside it and more is worth recovering; misses spread evenly across every
         # WAN say the remainder is structural and the mechanism is done.
         (f'sum {grp("interface")} (rate('
          f'{sel("opnsense_flow_policy_route_refused_total", 'reason="no_state"')}[{RATE}]))',
          "no_state by attributed iface: {{interface}}"),
         (f'sum {grp("kind")} ({sel("opnsense_flow_pf_state_entries")})', "pf states: {{kind}}"),
         # The four ways the repair correctly declines to act. Three of them moved no
         # counter at all until #624, so a box where the repair was never running looked
         # exactly like one where it had nothing to correct.
         (f'sum {grp("reason")} (rate({sel("opnsense_flow_policy_route_skipped_total")}[{RATE}]))',
          "skipped: {{reason}}"),
         (f'{sel("opnsense_flow_pf_state_age_seconds")}', "pf state age (s)")],
        unit="short",
        overrides=[{"matcher": {"id": "byRegexp", "options": "^pf state age \\(s\\)$"},
                    "properties": [{"id": "unit", "value": "s"}]}],
        desc="This is the PRE-NAT half of the multi-WAN problem, and it is a different repair from "
             "egress_corrected on the panel beside it. egress_corrected resolves the POST-NAT copy "
             "from its source address; the pre-NAT copy carries a private LAN address, so that repair "
             "cannot see it at all - yet the pre-NAT copy is the ONLY one that can ever correlate "
             "with a Zenarmor conn document. Left alone it inherits ng_netflow's OUTPUT_SNMP, which "
             "is a FIB lookup and therefore always names the default-route WAN. On the reference box "
             "that put every inspected byte that actually left by WAN2 onto WAN1, and WAN2's "
             "correlated series read empty against 11.1 GB of real traffic. The correction reads pf's "
             "own state table, whose route-to field IS the routing decision. "
             "refused reason=\"no_state\" is the genuine miss window - the flow ended and its pf "
             "state expired before the NetFlow record arrived, which is short flows, and NO poll "
             "interval closes it; those records are emitted exactly as reported rather than guessed. "
             "reason=\"unresolved_device\" means pf named an egress device the interface enumeration "
             "does not know, so the fix is the enumeration. pf states kind=\"policy_routed\" is the "
             "subset of states that can change anything: a flat zero there on a box with policy-route "
             "rules means the mechanism has nothing to work with. kind=\"conflict\" measured zero on "
             "the reference box, so any non-zero value means the pre-NAT 5-tuple stopped being unique "
             "upstream and every correction from this table wants re-checking. pf state age rising "
             "past a few multiples of the 5-minute poll means the fetch is failing and corrections "
             "are being made against a stale routing picture. The poll is ONE minute (it was five "
             "until #620 measured the policy-routed states as mostly sub-90-second), so judge the age "
             "against that. "
             "skipped=\"not_wan_egress\" is the biggest series here and that is normal - it is every "
             "record not leaving by a WAN, about half of them on the reference box. Watch it as a "
             "SHARE of decoded records rather than as a rate: if the interface map stops reporting a "
             "device as a WAN, every record on it moves into this bucket and the repair silently "
             "ceases to exist, with no other counter moving at all. skipped=\"fib_agreed\" is a state "
             "with no route-to (the FIB decided, so OUTPUT_SNMP was already right) and "
             "skipped=\"already_on_wan\" is a policy-routed state naming the device ng_netflow had "
             "also named; a high fib_agreed means the box barely policy-routes, a high "
             "already_on_wan means it does and we agree with it. skipped=\"post_nat\" belongs to "
             "repair 2.",
    )

    nat_pairs = b.ts(
        "NAT-Pair De-duplication",
        [(f'sum {grp("outcome")} (rate({sel("opnsense_flow_nat_pair_deduped_total")}[{RATE}]))',
          "{{outcome}}/sec"),
         (f'sum {grp("kind")} ({sel("opnsense_flow_nat_pair_entries")})', "{{kind}}")],
        unit="short",
        desc="A NAT'd conversation crossing a captured LAN interface AND a captured ETHERNET WAN is "
             "exported TWICE by ng_netflow - pre-NAT where it entered, post-NAT where it left - and "
             "nothing in either record says so, because the whole point of NAT is that the tuples "
             "differ. Both used to be counted: the reference box's policy-routed WAN read 62.40 GB "
             "against 45.05 GB on the kernel's own interface counter, +38.5%. pf's nat_addr/nat_port "
             "pairs them exactly. "
             "outcome=\"suppressed\" is the post-NAT copy discarded. ONLY the post-NAT copy is ever "
             "suppressed, because the pre-NAT copy carries the LAN host's own 5-tuple and is the only "
             "one that can correlate with Zenarmor - dropping it would trade a visible double count "
             "for an invisible hole in correlation coverage. outcome=\"late_pre_nat\" is the "
             "residual, where the pre-NAT copy arrived after its twin had already shipped and the "
             "double count could no longer be prevented; measured at ~8-11% of pairs, it should stay "
             "a small fraction of \"suppressed\" and the two move together. "
             "BOTH FLAT ZERO IS CORRECT on a box with no captured ethernet WAN - including one whose "
             "WAN is PPPoE, which exports nothing at all upstream however the GUI presents it. "
             "kind=\"translations\" counts BOTH directional forms of each translated state, so it "
             "is roughly twice the translated-state count; kind=\"conflict\" is small and normal "
             "(6-14 per build against ~7,000 entries measured) and fails safe toward emitting rather "
             "than suppressing.",
    )

    nat_unpaired = sel("opnsense_flow_nat_pair_deduped_total", 'outcome="unpaired"')
    nat_decided = sel("opnsense_flow_nat_pair_deduped_total",
                      'outcome=~"unpaired|suppressed|suppressed_by_conversation"')
    nat_unpaired_share = b.ts(
        "NAT-Pair Unpaired Share",
        [(f'sum {grp()} (rate({nat_unpaired}[{RATE}])) '
          f'/ clamp_min(sum {grp()} (rate({nat_decided}[{RATE}])), 0.0001)',
          "unpaired share")],
        unit="percentunit",
        desc="The share of post-NAT copies pf CALLS a translation that the stage emitted anyway "
             "because it could pair them with neither proof. This panel exists because #636 was a "
             "mechanism that fell silent while every other number stayed plausible - the translation "
             "index was populated, the identity table was populated, conflicts were in band, and the "
             "two de-dup counters simply read zero, which is exactly what a box with nothing to "
             "de-duplicate looks like. This one reads HIGH instead of reading nothing, so near 1 "
             "with the suppression counters flat is the #636 signature. "
             "IT IS A SHARE OF RECORDS, NOT OF BYTES, and the two come apart badly when a WAN's "
             "NAT'd traffic sits in a few large flows: measured 55% on the reference box while its "
             "byte ratio against the kernel counter was 0.94, because the unpaired remainder is the "
             "firewall's own small ICMP and DNS flows and the duplicated GIGABYTES are all paired. "
             "So read it WITH the interface-counter ratio, never instead of it - this panel says "
             "whether the mechanism is alive, that ratio says whether the bytes are right. A moderate "
             "value is also normal because a post-NAT copy that legitimately arrives first is "
             "unpaired at that instant and counted again as \"late_pre_nat\" when its twin lands. "
             "NO SERIES AT ALL is the healthy reading on a box with no captured ethernet WAN.",
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
         (f'rate({sel("opnsense_flow_correlator_evicted_total")}[{RATE}])', "evicted/sec"),
         (f'rate({sel("opnsense_flow_correlator_expired_total")}[{RATE}])', "expired/sec"),
         (f'rate({sel("opnsense_flow_correlator_enrichment_overwrites_total")}[{RATE}])',
          "enrichment overwrites/sec"),
         (f'rate({sel("opnsense_flow_correlator_fragment_disagreement_total")}[{RATE}])',
          "fragment disagreements/sec"),
         (f'rate({sel("opnsense_flow_correlator_fragment_mirrored_total")}[{RATE}])',
          "reverse-half fragments/sec")],
        unit="short",
        desc="The correlator collapses NetFlow's 1:N fragmentation (mean 3.75 records per connection) "
             "into one record per connection-window and merges Zenarmor L7 where a conn document "
             "matched. merged/sec against emitted/sec is the join hit-rate, which #346 shows is "
             "materially lower for long flows whose NetFlow records arrive up to ~30m after the "
             "connection ended. A rising evicted rate means --flow.correlate.max-entries is "
             "binding under load and should be raised; NetFlow-bearing entries are force-emitted, "
             "while a Zenarmor-only eviction loses a future join opportunity. expired is the "
             "healthy path. enrichment "
             "overwrites (#590) counts a second Zenarmor conn document for the same connection-window "
             "replacing the first wholesale rather than merging - a non-zero rate means Zenarmor "
             "re-reported a connection and only the latest report survived. fragment disagreements "
             "(#590) counts a later NetFlow fragment reporting a different interface, direction, VLAN "
             "or enrichment than the entry's first fragment OF THE SAME ORIENTATION, whose copy of "
             "those fields is what the merged record actually carries - a non-zero rate means that "
             "dimension silently disagreed and only one fragment's answer survived. reverse-half "
             "fragments (#605) counts the conversation's OTHER direction, which shares a correlator "
             "key by design because the community id is direction-independent: expect it to track "
             "roughly the merged rate on any bidirectional traffic, and read a collapse to zero as the "
             "two halves having stopped sharing a key, which would break correlation itself. It used "
             "to be counted as a disagreement and was 48.6% of every examinable fragment on a real "
             "box, which is why the two are now separate. Neither disagreement counter fires on the "
             "TCP-flags union across fragments (#585) or on the reverse half, both merges by design "
             "rather than losses.",
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

    # ---- GeoIP enrichment (#520) -----------------------------------------
    # Gated on the databases existing at all: geo is opt-in (--geoip.enabled) and
    # its metrics are ABSENT rather than zero where it was never turned on, so an
    # ungated row would show flat zeros on every deployment that does not use it.
    b.sentinel("has_flow_geoip", metric="opnsense_flow_geoip_lookups_total")

    geoip_lookups = b.ts(
        "GeoIP Lookups",
        [(f'sum {grp("database", "result")} '
          f'(rate({sel("opnsense_flow_geoip_lookups_total")}[{RATE}]))', "{{database}} {{result}}"),
         (f'rate({sel("opnsense_flow_geoip_enriched_records_total")}[{RATE}])', "records enriched/sec")],
        unit="ops",
        desc="Local MaxMind lookups per second, by database and result. Enrichment is FAIL-OPEN, which "
             "means a database that failed to load looks exactly like a quiet network — so read these "
             "together: country hits at zero while asn hits move is a country database that "
             "specifically did not load, and records-enriched at zero with lookups moving means every "
             "address missed. database=\"skipped\" is not a failure: it counts addresses that never "
             "reached a database because they are not globally routable (RFC 1918, link-local, and "
             "carrier-grade NAT, which MaxMind publishes no records for at all), and on a LAN-heavy "
             "box it is legitimately the largest series here.",
    )

    geoip_freshness = b.ts(
        "GeoIP Database Age & Updates",
        [(f'(time() - {sel("opnsense_flow_geoip_database_build_timestamp_seconds")})', "{{database}} age"),
         (f'sum {grp("result")} (rate({sel("opnsense_flow_geoip_downloads_total")}[{RATE}])) * 86400',
          "downloads/day {{result}}"),
         (f'sum {grp("database", "result")} '
          f'(rate({sel("opnsense_flow_geoip_reloads_total")}[{RATE}])) * 86400',
          "reloads/day {{database}} {{result}}")],
        unit="s",
        desc="Age of each loaded database against MaxMind's own BUILD date — not the download time, "
             "which is why it is the right staleness signal and what OPNsenseFlowGeoIPDatabaseStale "
             "alerts on. GeoLite2 rebuilds twice a week, so an age past ~14 days means the updater has "
             "silently stopped: with --geoip.download.enabled that is a failed fetch (expired license "
             "key, blocked egress), and without it a geoipupdate cron or sidecar that is no longer "
             "running. A steady stream of result=\"unmodified\" downloads is the HEALTHY state — a 304 "
             "costs no MaxMind quota. reloads move only when a file on disk actually changed; a "
             "result=\"failure\" reload means the previously loaded database is still serving.",
        overrides=[("downloads/day .*", "unit", "short"), ("reloads/day .*", "unit", "short")],
    )

    geoip_agreement = b.ts(
        "GeoIP Country: Ours vs Zenarmor",
        [(f'sum {grp("result")} '
          f'(rate({sel("opnsense_flow_geoip_country_comparisons_total")}[{RATE}]))', "{{result}}/sec")],
        unit="ops",
        desc="Flow endpoints where BOTH databases answered with a country, split by whether they "
             "agreed. This is what makes the cost of the ours-wins precedence rule measurable rather "
             "than assumed: Zenarmor backs its geo with a commercial GeoIP2-City build (verified on a "
             "live firewall — database_type \"GeoIP2-City\", 126 MB against a stock GeoLite2's 63 MB), "
             "so a free GeoLite2 answer overwriting it can genuinely be the worse attribution. Ours "
             "still wins the exported country either way — the point is that the disagreement is "
             "visible, and the disagreeing value is kept on the log record as <src|dst>.geo.zen_country "
             "so an investigation can see both. Absent entirely without Zenarmor, since there is "
             "nothing to compare against.",
    )

    geoip_merge_mismatch = b.ts(
        "GeoIP Merge: Unpairable Records",
        [(f'sum {grp()} (rate({sel("opnsense_flow_geoip_merge_address_mismatches_total")}[{RATE}]))',
          "unpairable/sec")],
        unit="ops",
        desc="Correlator merges where the Zenarmor record and the NetFlow record could not be lined "
             "up in EITHER orientation, so no geo was folded across. Expected FLAT AT ZERO: the "
             "correlator already paired the two records by connection key, so their naming the same "
             "two addresses is the premise of the merge rather than a hope. Anything above zero means "
             "that premise is false and merged records are silently missing Zenarmor's city and its "
             "zen_country audit value — worth investigating the correlator's keying rather than this "
             "panel. It exists because what it replaced was worse and invisible (#647): endpoints "
             "were paired by POSITION, so a Zenarmor conn document describing the connection from the "
             "initiator's side attached each end's geo to the OPPOSITE address. On a private "
             "destination that produced a fabricated country whose provenance claimed maxmind — for "
             "an address MaxMind categorically declines to look up. Absent entirely without Zenarmor, "
             "since nothing is being merged.",
    )

    b.tab("Flow Pipeline", [
        b.row("Accumulator Health", [other_share, keys, capped]),
        b.row("NetFlow Receiver", [ingest, ingest_bytes, funnel, decoder],
              present="has_flow_netflow"),
        b.row("NetFlow Repairs & Topology",
              [repairs, policy_route, nat_pairs, nat_unpaired_share, ifindex],
              present="has_flow_netflow"),
        b.row("Correlator & Log Emission", [correlator, flowlogs]),
        b.row("GeoIP Enrichment", [geoip_lookups, geoip_freshness, geoip_agreement,
                                   geoip_merge_mismatch],
              present="has_flow_geoip"),
    ], present="has_flow")
