"""
DNS - Unbound tab for the opnsense2otel dashboard.

Covers all opnsense_unbound_dns_* metrics across seven rows:
  1. Service         — uptime, service running, blocklist, queries qps, cache hit ratio
  2. Cache & Recursion — prefetch/expired/recursive/recursion times/request list
  3. DNSSEC & Anomalies — secure/bogus/rrset_bogus/unwanted/timed_out/ratelimited
  4. Query Breakdowns   — by type / protocol / rcode / flags / edns
  5. Cache & Memory     — cache_count, memory_bytes, tcp_usage_ratio
  6. Upstream Infra Cache (opt-in) — infra_rtt/rto
  7. DNSBL / Query Stats (opt-in)  — qstats totals, blocklist size, local zones/data/insecure domains
  8. Per-Query Log (opt-in, Loki)  — the `unbound` log lane's per-query records

Row 8 reads a LOG STREAM, not metrics (#591 item 5). The `unbound` source
(`--logs.unbound.enabled`, internal/logship/unbound.go) ships one record per DNS
query carrying client / domain / qtype / action / query_source / rcode / blocklist /
dnssec_status — and until #591 nothing on the dashboard read any of it, so "which
client is being blocked by which list" was unanswerable from the estate even though
the data was already in Loki.

**Select on `opnsense_source`, never on `opnsense_subsystem`.** The lane builds its
attributes without `logship.AttrSubsystem` (verified in internal/logship/unbound.go),
so its records carry no subsystem label at all: a selector naming it there matches
nothing and reports no error. `tests/test_loki_scoping.py` pins both ends of that.

The row 7 qstats leaderboards and row 8's tables look similar and answer different
questions. qstats is Unbound's OWN rolling ~7-day aggregate, cheap, truncated at 512
domains, and available with no log shipping. The Loki tables are per-query records
over the dashboard's window, complete, and carry the CLIENT — which is the field
qstats has no equivalent for and the reason this row exists.
"""

from builder import Builder, sel, grp, loki_sel, loki_grp, RATE, RUNSTOP, ENABLED

# One record per DNS query, so this is the highest-volume poll lane the exporter has.
# Hoisted to module constants so the row's panels cannot drift apart (AUTHORING.md).
UNBOUND_STREAM = loki_sel('opnsense_source="unbound"')
# `opnsense_action` is the normalised disposition (MapUnboundAction: Pass -> pass,
# Block/Drop -> block) and IS an indexed label, so filtering blocked queries belongs
# in the stream selector rather than after the `|`. The resolver's own capitalised
# verb survives as the structured-metadata `action` key, where Drop and Block stay
# distinguishable.
UNBOUND_BLOCKED = loki_sel('opnsense_source="unbound", opnsense_action="block"')

# Domain names are unbounded, so the table ranking them pins its own window rather
# than following the dashboard picker (#479): Loki's max_query_series is enforced on
# an intermediate of the query, so `topk` does not bound it and only the RANGE moves
# it. 1h is the same measured fit the Zenarmor tab uses on the same tenant; lower it
# if the panel starts returning "No data" with a query error.
UNBOUNDED_LABEL_WINDOW = "1h"


def build(b: Builder):
    b.sentinel("has_unbound", metric="opnsense_unbound_dns_uptime_seconds")
    b.sentinel("has_unbound_infra", metric="opnsense_unbound_dns_infra_rtt_seconds")
    b.sentinel("has_unbound_qstats", metric="opnsense_unbound_dns_qstats_enabled")

    # ---- convenience shorthands -----------------------------------------
    def u(metric, extra=""):
        return sel(f"opnsense_unbound_dns_{metric}", extra)

    def r(metric, extra=""):
        return f"rate({u(metric, extra)}[{RATE}])"

    # =====================================================================
    # Row 1: Service
    # =====================================================================
    uptime = b.stat(
        "Uptime", u("uptime_seconds"),
        unit="s", w=4, h=4,
        graph="none", color="thresholds",
        thresholds=[{"color": "blue", "value": None}],
        desc="Uptime of the Unbound DNS service.",
    )
    svc_running = b.stat(
        "Service Running", u("service_running"),
        mappings=RUNSTOP,
        color_mode="background",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        w=4, h=4,
    )
    blocklist = b.stat(
        "Blocklist Enabled", u("blocklist_enabled"),
        mappings=ENABLED,
        color_mode="background",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        w=4, h=4,
        desc="Whether the DNS blocklist (DNSBL) is active.",
    )
    queries_qps = b.ts(
        "Queries / s",
        [(r("queries_total"), "queries/s")],
        unit="reqps", w=12, h=8,
        desc="Total DNS queries received per second.",
    )
    # Cache hit ratio: 100 * hits / (hits + misses). The (Y > 0) boolean filter guards ÷0 without
    # distorting real values — clamp_min(Y, 1) pinned the denominator to 1 qps and collapsed the
    # ratio on quiet/low-traffic boxes below 1 qps (#96).
    cache_hit_ratio = b.gauge(
        "Cache Hit Ratio",
        (
            f"100 * {r('cache_hits_total')}"
            f" / ({r('cache_hits_total')} + {r('cache_miss_total')} > 0)"
        ),
        unit="percent", mn=0, mx=100, w=4, h=8,
        thresholds=[
            {"color": "red", "value": None},
            {"color": "yellow", "value": 50},
            {"color": "green", "value": 75},
        ],
        desc="Percentage of queries answered from cache.",
    )

    row_service = b.row("Service", [uptime, svc_running, blocklist, queries_qps, cache_hit_ratio])

    # =====================================================================
    # Row 2: Cache & Recursion
    # =====================================================================
    cache_activity = b.ts(
        "Cache Activity",
        [
            (r("cache_hits_total"), "hits"),
            (r("cache_miss_total"), "misses"),
            (r("prefetch_total"), "prefetches"),
            (r("expired_total"), "expired served"),
        ],
        unit="reqps", w=12, h=8,
        desc="Cache hits, misses, prefetches and expired-entry answers per second.",
    )
    recursion_ts = b.ts(
        "Recursive Replies / s",
        [(r("recursive_replies_total"), "recursive replies/s")],
        unit="reqps", w=6, h=8,
        desc="Replies that required a full recursive lookup.",
    )
    recursion_times = b.ts(
        "Recursion Time",
        [
            (u("recursion_time_avg_seconds"), "avg"),
            (u("recursion_time_median_seconds"), "median"),
        ],
        unit="s", w=6, h=8,
        desc="Average and median time for a recursive DNS resolution.",
    )
    req_list_ts = b.ts(
        "Request List",
        [
            (u("request_list_avg"), "avg depth"),
            (u("request_list_max"), "high-water"),
            (u('request_list_current', 'scope="all"'), "current (all)"),
            (u('request_list_current', 'scope="user"'), "current (user)"),
            (u('request_list_current', 'scope="replies"'), "current (replies)"),
            (r("request_list_overwritten_total"), "overwritten/s"),
            (r("request_list_exceeded_total"), "exceeded/s"),
        ],
        unit="short", w=12, h=8, stack=False,
        desc="Internal request list depth, overwritten entries, and capacity exceedances. "
             "The 'replies' scope (#237) is a base statistic present on all supported releases.",
    )

    # #581. Queried only through its _bucket series — the base name
    # opnsense_unbound_dns_recursion_time_seconds is in build_dashboard.py's
    # COVERAGE_EXEMPT for that reason, like every other histogram on this dashboard.
    recursion_quantiles = b.ts(
        "Recursion Time Distribution",
        [(f'histogram_quantile({q}, sum {grp("le")} '
          f'(rate({sel("opnsense_unbound_dns_recursion_time_seconds_bucket")}[{RATE}])))', label)
         for q, label in ((0.5, "p50"), (0.9, "p90"), (0.99, "p99"))],
        unit="s", w=12, h=8,
        desc="opnsense_unbound_dns_recursion_time_seconds: percentiles of how long recursive "
             "lookups took, from Unbound's own exponential histogram. This is the tail the "
             "Recursion Time panel's mean and median hide - a p99 climbing while the mean stays "
             "flat is a subset of upstreams going slow, which is what the Upstream Infra Cache "
             "row diagnoses. EMPTY UNLESS the resolver runs with extended-statistics: yes; that "
             "is OFF by default from OPNsense 26.7 and Unbound does not compute the data at all "
             "in that state, so no data here means not enabled, not zero latency.",
    )

    row_cache = b.row("Cache & Recursion",
                      [cache_activity, recursion_ts, recursion_times, req_list_ts, recursion_quantiles])

    # =====================================================================
    # Row 3: DNSSEC & Anomalies
    # =====================================================================
    dnssec_ts = b.ts(
        "DNSSEC Answers / s",
        [
            (r("answers_secure_total"), "secure"),
            (r("answers_bogus_total"), "bogus"),
            (r("rrset_bogus_total"), "rrset bogus"),
        ],
        unit="reqps", w=12, h=8,
        desc="DNSSEC-validated secure answers and bogus/failed validations per second.",
    )
    anomalies_ts = b.ts(
        "Anomalies / s",
        [
            (r("unwanted_total"), "unwanted"),
            (r("queries_timed_out_total"), "timed out"),
            (r("queries_ip_ratelimited_total"), "IP rate-limited"),
            (r("queries_discard_timeout_total"), "discarded (wait timeout)"),
            (r("queries_wait_limit_total"), "dropped (wait limit)"),
            (r("queries_replyaddr_limit_total"), "dropped (reply-addr limit)"),
            (r("dns_error_reports_total"), "RFC 9567 error reports"),
        ],
        unit="reqps", w=12, h=8,
        desc="Unwanted traffic, timed-out/discarded/rate-limited queries, and RFC 9567 DNS "
             "error reports per second (#237: the four drop/limit/report counters are base "
             "statistics, so they populate even with extended-statistics: no).",
    )

    validation_ops = b.ts(
        "DNSSEC Validation Work",
        [(r("validation_operations_total"), "RRSIG verifications/s"),
         (r("answers_secure_total"), "secure answers/s")],
        unit="ops", w=12, h=8,
        desc="opnsense_unbound_dns_validation_operations_total: RRSIG verifications the validator "
             "attempted, pass or fail. Plotted against secure answers because the ratio is the "
             "point: heavy verification work producing few secure answers means the validator is "
             "burning CPU on zones that will not validate, which the secure/bogus counters alone "
             "cannot distinguish from doing no work at all. Extended-statistics only.",
    )

    row_dnssec = b.row("DNSSEC & Anomalies", [dnssec_ts, anomalies_ts, validation_ops])

    # =====================================================================
    # Row 4: Query Breakdowns
    # =====================================================================
    # Piecharts use instant rate over the dashboard's selected range via irate/increase
    # — we use rate(...) to get an instantaneous per-second value for a distribution slice.
    # For piecharts the builder always sets instant=True on each query.
    by_type = b.piechart(
        "Queries by Type",
        [(
            f"topk {grp()} (15, sum {grp('type')} ({r('queries_by_type_total')}))",
            "{{type}}",
        )],
        unit="reqps", w=8, h=8,
        desc="Distribution of DNS query types (A, AAAA, MX, …).",
    )
    by_protocol = b.piechart(
        "Queries by Protocol",
        [(
            f"sum {grp('protocol')} ({r('queries_by_protocol_total')})",
            "{{protocol}}",
        )],
        unit="reqps", w=8, h=8,
        desc="DNS queries split by transport protocol (UDP/TCP).",
    )
    by_rcode = b.piechart(
        "Answers by RCode",
        [(
            f"sum {grp('rcode')} ({r('answers_by_rcode_total')})",
            "{{rcode}}",
        )],
        unit="reqps", w=8, h=8,
        desc="DNS answer distribution by response code (NOERROR, NXDOMAIN, SERVFAIL, …).",
    )
    query_flags = b.bargauge(
        "Query Flags",
        [(
            f"sum {grp('flag')} ({r('query_flags_total')})",
            "{{flag}}",
        )],
        unit="reqps", w=12, h=8,
        orient="horizontal",
        desc="DNS query flags breakdown (RD, CD, DO, …).",
    )
    edns = b.bargauge(
        "EDNS",
        [(
            f"sum {grp('type')} ({r('edns_total')})",
            "{{type}}",
        )],
        unit="reqps", w=12, h=8,
        orient="horizontal",
        desc="EDNS query types per second.",
    )

    row_breakdowns = b.row("Query Breakdowns", [by_type, by_protocol, by_rcode, query_flags, edns])

    # =====================================================================
    # Row 5: Cache & Memory
    # =====================================================================
    cache_count = b.bargauge(
        "Cache Entries",
        [(
            f"sum {grp('cache')} ({u('cache_count')})",
            "{{cache}}",
        )],
        unit="short", w=8, h=8,
        orient="horizontal",
        desc="Number of entries currently held in each Unbound cache (rrset, msg, infra, key).",
    )
    memory_bytes = b.bargauge(
        "Memory Usage",
        [(
            f"sum {grp('component')} ({u('memory_bytes')})",
            "{{component}}",
        )],
        unit="bytes", w=8, h=8,
        orient="horizontal",
        desc="Unbound memory consumption split by component.",
    )
    tcp_usage = b.gauge(
        "TCP Usage Ratio",
        u("tcp_usage_ratio"),
        unit="percentunit", mn=0, mx=1, w=4, h=8,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "yellow", "value": 0.7},
            {"color": "red", "value": 0.9},
        ],
        desc="Fraction of TCP connections in use (0.0–1.0). High values indicate TCP saturation.",
    )

    row_cache_mem = b.row("Cache & Memory", [cache_count, memory_bytes, tcp_usage])

    # =====================================================================
    # Row 6: Upstream Infra Cache (opt-in, gated on has_unbound_infra)
    # =====================================================================
    infra_rtt = b.ts(
        "Upstream RTT (infra cache, top 20)",
        [(f'topk {grp()} (20, {u("infra_rtt_seconds")})', "{{ip}} {{host}}")],
        unit="s", w=12, h=8,
        desc="opnsense_unbound_dns_infra_rtt_seconds: smoothed RTT per upstream "
             "server/zone from Unbound's infra cache (requires --exporter.enable-unbound-infra).",
    )
    infra_rto = b.ts(
        "Upstream RTO (infra cache, top 20)",
        [(f'topk {grp()} (20, {u("infra_rto_seconds")})', "{{ip}} {{host}}")],
        unit="s", w=12, h=8,
        desc="opnsense_unbound_dns_infra_rto_seconds: retransmission timeout per "
             "upstream server/zone.",
    )

    # #581. The whole point of these three is that RTT CANNOT show them: Unbound
    # stops querying an upstream it has marked lame, so that upstream's RTT stays
    # healthy exactly while resolution through it fails. Sum rather than topk - a
    # single lame upstream is the event, so the count must not be truncated away.
    infra_health = b.ts(
        "Unhealthy Upstreams",
        [(f'sum {grp("kind")} ({sel("opnsense_unbound_dns_infra_host_lame")})', "lame: {{kind}}"),
         (f'sum {grp()} ({sel("opnsense_unbound_dns_infra_host_dnssec_lame")})', "DNSSEC-lame"),
         (f'sum {grp()} ({sel("opnsense_unbound_dns_infra_host_edns_broken")})', "EDNS broken")],
        unit="short", w=12, h=8,
        desc="Upstream servers Unbound currently considers unhealthy, counted by problem. Any "
             "non-zero value on a configured forwarder is worth investigating: lame means the "
             "server is not authoritative for what it was asked, DNSSEC-lame means it answers but "
             "will not serve validation records, EDNS broken means EDNS traffic to it is being "
             "dropped in transit (usually a middlebox or MTU problem, not the server). These stay "
             "invisible in the RTT panels above because Unbound stops asking a server it has "
             "written off. Requires --exporter.enable-unbound-infra.",
    )
    infra_health_table = b.table(
        "Upstream Health Detail",
        [sel("opnsense_unbound_dns_infra_host_lame", 'kind="recursion"'),
         sel("opnsense_unbound_dns_infra_host_dnssec_lame"),
         sel("opnsense_unbound_dns_infra_host_edns_broken")],
        w=12, h=8,
        excludes=["__name__", "job", "instance", "kind"],
        renames={"ip": "Upstream IP", "host": "Zone"},
        sort_by="Upstream IP", sort_desc=False,
        desc="Which upstream server has which problem: one row per infra-cache entry, 1 = "
             "affected. The recursion-lameness column is shown; the type_a and other kinds are on "
             "opnsense_unbound_dns_infra_host_lame's kind label and are summarised in the panel "
             "beside this one.",
    )

    row_infra = b.row("Upstream Infra Cache",
                      [infra_rtt, infra_rto, infra_health, infra_health_table],
                      present="has_unbound_infra")

    # =====================================================================
    # Row 7: DNSBL / Query Stats (opt-in, gated on has_unbound_qstats)
    #
    # All qstats_* series are GAUGES, never counters: the underlying qstats
    # backend is a rolling ~7-day window that Unbound's logger.py truncates
    # hourly (and a `qstats reset` truncates entirely), so the totals can and
    # do decrease. No rate()/increase() on any of these.
    # =====================================================================
    qstats_enabled_stat = b.stat(
        "Query-Stats Logging", u("qstats_enabled"),
        mappings=ENABLED,
        color_mode="background",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        w=4, h=4,
        desc="opnsense_unbound_dns_qstats_enabled: whether Unbound query-stats "
             "logging (general.stats) is on. Requires --exporter.enable-unbound-qstats.",
    )
    blocklist_size = b.stat(
        "DNSBL Blocklist Size", u("dnsbl_blocklist_size"),
        unit="short", w=4, h=4,
        color_mode="value",
        thresholds=[{"color": "blue", "value": None}],
        desc="opnsense_unbound_dns_dnsbl_blocklist_size: number of entries in the "
             "currently loaded DNSBL blocklist.",
    )
    total_7d = b.stat(
        "Total Queries (7d window)", u("qstats_queries_total_7d"),
        unit="short", w=4, h=4,
        color_mode="value",
        thresholds=[{"color": "blue", "value": None}],
        desc="opnsense_unbound_dns_qstats_queries_total_7d: total queries over "
             "Unbound's rolling query-stats window (typically 7 days). Gauge, not a rate.",
    )
    window_age = b.stat(
        "Query-Stats Window Age",
        f"time() - {u('qstats_start_time_seconds')}",
        unit="s", w=6, h=4,
        color_mode="value",
        thresholds=[{"color": "blue", "value": None}],
        desc="Time since the current query-stats rolling window started "
             "(time() - opnsense_unbound_dns_qstats_start_time_seconds). A sudden drop "
             "close to zero signals the underlying qstats database was reset.",
    )
    queries_by_result = b.piechart(
        "Queries by Result (7d window)",
        [(
            f"sum {grp('result')} ({u('qstats_queries_7d')})",
            "{{result}}",
        )],
        unit="short", w=10, h=8,
        desc="opnsense_unbound_dns_qstats_queries_7d: DNSBL query outcome totals "
             "(passed/resolved/blocked/local) over the rolling query-stats window. Gauge, not a rate.",
    )
    local_zones = b.bargauge(
        "Local Zones by Type",
        [(
            f"sum {grp('type')} ({u('local_zones')})",
            "{{type}}",
        )],
        unit="short", w=8, h=8,
        orient="horizontal",
        desc="opnsense_unbound_dns_local_zones: configured Unbound local zones, "
             "aggregated by zone type.",
    )
    local_data_records = b.stat(
        "Local Data Records", u("local_data_records"),
        unit="short", w=4, h=4,
        color_mode="value",
        thresholds=[{"color": "blue", "value": None}],
        desc="opnsense_unbound_dns_local_data_records: total configured Unbound "
             "local-data resource records.",
    )
    insecure_domains = b.stat(
        "Insecure Domains", u("insecure_domains"),
        unit="short", w=4, h=4,
        color_mode="value",
        thresholds=[{"color": "blue", "value": None}],
        desc="opnsense_unbound_dns_insecure_domains: domains configured as "
             "DNSSEC-insecure.",
    )

    # #587: the pi-hole-style leaderboards, reversing #209's rejection now that the
    # bounded-inventory primitive exists. topk on top of an already-truncated,
    # already-capped series set - the metric is at most 512 domains per outcome, and
    # 15 rows is what fits a panel.
    BLOCKED, PASSED = 'result="blocked"', 'result="passed"'

    def top_domains(result_selector):
        return u("qstats_top_domain_queries_7d", result_selector)

    top_blocked_domains = b.bargauge(
        "Top Blocked Domains (7d window)",
        [(f'topk {grp()} (15, {top_domains(BLOCKED)})', "{{domain}}")],
        unit="short", w=12, h=10,
        orient="horizontal",
        desc="opnsense_unbound_dns_qstats_top_domain_queries_7d{result=\"blocked\"}: the domains a "
             "DNSBL policy blocked most over Unbound's rolling query-stats window. Gauge over the "
             "whole window, NOT a rate - the window is truncated hourly, so these counts fall as "
             "well as rise. Truncated by design at 512 domains; if Leaderboard Refusals below is "
             "rising, this is no longer the true top-N. Requires --exporter.enable-unbound-qstats.",
    )
    top_passed_domains = b.bargauge(
        "Top Resolved Domains (7d window)",
        [(f'topk {grp()} (15, {top_domains(PASSED)})', "{{domain}}")],
        unit="short", w=12, h=10,
        orient="horizontal",
        desc="opnsense_unbound_dns_qstats_top_domain_queries_7d{result=\"passed\"}: the domains "
             "Unbound answered most over the rolling query-stats window. Same gauge semantics and "
             "the same 512-domain truncation as the blocked leaderboard beside it. A domain can "
             "appear in both panels - some queries for it passed before a policy started blocking "
             "it.",
    )
    leaderboard_refusals = b.ts(
        "Leaderboard Refusals",
        [(f'sum {grp("family")} (rate({sel("opnsense_unbound_dns_cardinality_capped_total")}[{RATE}]))',
          "{{family}}")],
        unit="short", w=12, h=8,
        desc="opnsense_unbound_dns_cardinality_capped_total: domains refused their own series "
             "because the leaderboard was already holding its full 512-key budget. This panel is "
             "what stops a truncated top-N looking like a quiet network. Sustained non-zero means "
             "something is minting domains faster than the cap turns over - random-subdomain or "
             "DNS-tunnelling traffic does exactly that, so a rise here is worth investigating on "
             "its own account and not only as a metrics problem.",
    )

    row_qstats = b.row(
        "DNSBL / Query Stats",
        [
            qstats_enabled_stat, blocklist_size, total_7d, window_age,
            queries_by_result, local_zones, local_data_records, insecure_domains,
            top_blocked_domains, top_passed_domains, leaderboard_refusals,
        ],
        present="has_unbound_qstats",
    )

    # =====================================================================
    # Row 8: Per-Query Log (opt-in, Loki — #591 item 5)
    # =====================================================================
    b.loki_sentinel("has_unbound_logs", matchers='opnsense_source="unbound"',
                    label="opnsense_source")

    unbound_raw_logs = b.logs(
        "Raw Unbound Query Log",
        UNBOUND_STREAM,
        desc="The `unbound` log stream (--logs.unbound.enabled): one record per DNS query, body "
             "carrying the full row and structured metadata carrying client, domain, qtype, "
             "action, query_source (Recursion/Cache/Local — where the ANSWER came from, not the "
             "log source), rcode, blocklist and dnssec_status. Open the log details on any line "
             "to filter on those. Accepted-loss lane: OPNsense exposes only the newest 1000 rows "
             "resolver-wide, so a busy resolver can push rows out before a poll fetches them — "
             "Possible Sampling Gaps on the Log Shipping tab counts when that happened.",
        w=24,
    )
    unbound_disposition = b.loki_ts(
        "Query Dispositions/s (log stream)",
        [(f'sum {loki_grp("opnsense_action")} (rate({UNBOUND_STREAM} [$__auto]))',
          "{{opnsense_action}}")],
        unit="ops",
        desc="Per-query log records per second by normalised disposition, from the `unbound` "
             "stream. This is the log-side twin of the metrics Queries/s panel, and the two will "
             "NOT match: the metric is Unbound's own complete counter, while this counts the "
             "records the bounded 1000-row window actually yielded. Read it for the pass/block "
             "SPLIT, which the metric side cannot give at all; read Queries/s for the volume. An "
             "empty disposition means the resolver reported a verb outside Pass/Block/Drop.",
    )
    unbound_blocked_clients = b.loki_table(
        "Top Blocked Clients",
        [f'topk {loki_grp()} (200, sum {loki_grp("client")} (count_over_time({UNBOUND_BLOCKED} '
         '| client!="" [$__range])))'],
        field_title="Client",
        desc="Which LAN clients had the most DNS queries blocked by policy, over the selected "
             "range. `client` is structured metadata on the per-query record, so it exists "
             "nowhere in metrics at any setting — this table is the only place the estate can "
             "attribute a block to a device. A single client dominating is usually one app "
             "retrying a blocked endpoint rather than a policy problem; pair it with Top "
             "Blocklists beside it to see which list is doing the blocking.",
    )
    unbound_blocklists = b.loki_table(
        "Top Blocklists",
        [f'topk {loki_grp()} (200, sum {loki_grp("blocklist")} (count_over_time({UNBOUND_BLOCKED} '
         '| blocklist!="" [$__range])))'],
        field_title="Blocklist",
        desc="Which configured DNSBL list matched, counted over blocked query records. Together "
             "with Top Blocked Clients this answers 'which client is being blocked by which "
             "list', which #591 found the estate could not ask despite shipping both fields. A "
             "list with no rows is not matching anything — either it is redundant with a broader "
             "list ahead of it, or it failed to load.",
    )
    unbound_blocked_names = b.loki_table(
        "Top Blocked Query Names",
        [f'topk {loki_grp()} (200, sum {loki_grp("domain")} (count_over_time({UNBOUND_BLOCKED} '
         '| domain!="" [$__range])))'],
        field_title="Query Name",
        desc="The domains policy blocked most, over this panel's own 1h window rather than the "
             "dashboard picker — query names are unbounded and Loki's series ceiling is enforced "
             "on an intermediate of the query, so a wider range returns a query error rather "
             "than a partial result. The Top Blocked Domains leaderboard in the DNSBL row is the "
             "cheaper 7-day view of roughly the same question, truncated at 512 domains and with "
             "no client attribution; this one is complete for its window and joins to the client "
             "and blocklist tables beside it.",
        time_from=UNBOUNDED_LABEL_WINDOW,
    )

    row_query_log = b.row(
        "Per-Query Log",
        [unbound_raw_logs, unbound_disposition, unbound_blocked_clients,
         unbound_blocklists, unbound_blocked_names],
        present="has_unbound_logs",
        # Collapsed for the same reason the Zenarmor detail rows are (#422): cold-load
        # cost is round-trip COUNT, and this is one log record per DNS query on a
        # resolver answering continuously. A collapsed row issues nothing until opened.
        collapse=True,
    )

    # =====================================================================
    # Assemble the tab
    # =====================================================================
    # Two sibling leaves (#619): 41 panels in one tab, and the split falls on an
    # existing seam — the first four rows are the resolver's own behaviour, always
    # present; the last three are opt-in feature rows behind their own gates.
    b.tab(
        "DNS - Unbound",
        [row_service, row_cache, row_dnssec, row_breakdowns, row_cache_mem],
        present="has_unbound",
    )
    b.tab(
        "DNS - Unbound Lists",
        [row_infra, row_qstats, row_query_log],
        present="has_unbound",
    )
