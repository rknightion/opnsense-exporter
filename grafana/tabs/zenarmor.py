"""
Zenarmor tab — the receiver's derived Prometheus counters plus the raw Loki
log stream side by side (--logs.zenarmor.enabled, #276). Zenarmor streams
~2.5-3.3M records/day, so the derived counters are how you ask rate
questions cheaply, and the log stream (Row B/C) is for anything that needs
a field the counters don't carry (server, device, country, JA3 fingerprint).

These panels moved here from logs.py (#276 follow-up) so Zenarmor has one
home instead of being split across the generic Log Shipping tab and
nowhere for the raw stream at all.

Label rules (verified live against the real Zenarmor stream, 2026-07-18):
- opnsense_log_events_zenarmor_total carries opnsense_instance -> sel().
- opnsense_exporter_logs_zenarmor_* self-metrics ALSO carry opnsense_instance
  -> sel(). They are registered through logship's SelfMetricsRegisterer like the
  rest of the pipeline family. This note previously claimed they carried no
  instance label and used a `sel_pipeline()` alias to say so; the alias was a
  pure alias of `sel()` and the claim was wrong, both removed by #466.
- LogQL stream selectors {} may ONLY use the three indexed labels
  (opnsense_source, opnsense_subsystem, opnsense_action) plus the transport's
  own service_instance_id. Every other field seen on the wire (device_name,
  server_name, ja3, dst_nbytes, dst_geoip_country_name, app_name, ...) is
  structured metadata: usable only after a `|` filter/unwrap, never inside `{}`.
- Every stream selector is built by loki_sel() so it is scoped to
  $opnsense_instance via service_instance_id (#413). That matters most on the
  Row C tables: their topk ranks whatever the selector admitted, so an
  unscoped selector would rank another firewall's servers and devices.
"""

from builder import Builder, sel, grp, loki_sel, loki_grp, RATE
from uids import CONTROLS_MENU

ZEN_STREAM = loki_sel('opnsense_source="zenarmor"')
ZEN_BLOCKED = loki_sel('opnsense_source="zenarmor", opnsense_action="block"')
ZEN_FLOW = loki_sel('opnsense_source="zenarmor", opnsense_subsystem="flow"')
ZEN_TLS = loki_sel('opnsense_source="zenarmor", opnsense_subsystem="tls"')
ZEN_DNS = loki_sel('opnsense_source="zenarmor", opnsense_subsystem="dns"')
ZEN_WEB = loki_sel('opnsense_source="zenarmor", opnsense_subsystem="web"')

# Zenarmor attributes traffic to a CLIENT device (a laptop, a phone) in the
# structured-metadata field `device_name`. That is a completely different label space
# from the dashboard's `$device`, which enumerates kernel interface names (igb0,
# ixl0_vlan25) — the same disjointness that #98 is about, one level further out. So it
# gets its own variable rather than reusing either existing picker (#435).
#
# It is a QUERY VARIABLE now, not a textbox (#474), but the underlying finding from
# #435 still holds: `device_name` is Loki structured metadata, so it is NOT an indexed
# Loki label, and `label_values(..., device_name)` against Loki still returns null
# (verified live 2026-07-27 — the label does not appear in the datasource's 44 label
# names). The retired companion dashboard tried a query variable whose query was a
# bare Loki stream selector, which cannot have populated anything.
#
# What changed is where the picker is populated FROM. #474 adds a bounded Prometheus
# info metric, opnsense_log_events_zenarmor_device_info{device_name, device_category,
# interface}, alongside the log_events collector's existing Zenarmor counters — a
# separate, closed label space from Loki's. The picker now enumerates that metric's
# device_name label via label_values(), while the Loki filter below is UNCHANGED: it
# still matches structured metadata with a `|` filter, never a stream-selector label.
# So this is fixing enumeration, not promoting a Loki label — #473 assessed and
# rejected promoting device_name itself (not a closed set; live values include DNS
# names like Plex's).
CLIENT_VAR = "zenarmor_client"
CLIENT_FILTER = f'| device_name=~"${CLIENT_VAR}"'
CLIENT_VAR_QUERY = ('label_values(opnsense_log_events_zenarmor_device_info'
                    '{opnsense_instance=~"$opnsense_instance"}, device_name)')

# Zenarmor delivers its records to the exporter over HTTP, so its own bulk-ingest
# requests appear in the WEB family as requests to our own endpoint. Left in, they are
# the top host, the top URI and a large share of the status codes — the dashboard would
# mostly describe itself. The exporter already drops these from shipping where it can
# (Self-Traffic Drop Rate, #278); this filter covers what still lands.
NOT_SELF = '| uri!~"/zenarmor_.*/_bulk"'


def build(b: Builder):
    b.sentinel("has_zenarmor_metrics", metric="opnsense_log_events_zenarmor_total")
    b.loki_sentinel("has_zenarmor_logs", matchers='opnsense_source="zenarmor"',
                    label="opnsense_source")
    # Query variable, not b.textbox() (#474): populated from the bounded Prometheus
    # info metric opnsense_log_events_zenarmor_device_info, instance-scoped the same
    # way $interface is in build_dashboard.py::add_core_variables. allValue=".+" keeps
    # an untouched dashboard filtering nothing, matching the old textbox default.
    b.variables.append({"kind": "QueryVariable", "spec": {
        "name": CLIENT_VAR, "label": "Zenarmor client device",
        "current": {"text": "All", "value": "$__all"}, "options": [],
        "query": {"kind": "DataQuery", "version": "v0", "group": "prometheus",
                  "datasource": {"name": "${datasource}"},
                  "spec": {"query": CLIENT_VAR_QUERY, "refId": CLIENT_VAR}},
        "refresh": "onDashboardLoad", "regex": "", "sort": "alphabeticalAsc",
        "hide": "dontHide", "includeAll": True, "multi": True, "allValue": ".+",
        "allowCustomValue": True, "skipUrlSync": False,
        "description": (
            "Filter the Zenarmor log panels to the client device Zenarmor "
            "attributed the traffic to (its own identification, not the "
            "exporter's). This is Zenarmor's device_name, NOT the kernel interface "
            "names in the Device picker. Multi-select or 'All'; the Loki panels "
            "below still filter on device_name as structured metadata."),
        # In the controls menu (#470): it applies to one tab of 41, so it does not
        # earn a permanent toolbar slot on every other tab.
        "placement": CONTROLS_MENU}})

    # --- Row A: Overview (Prometheus-derived counters) --------------------

    zen_events = b.ts(
        "Zenarmor Events (rate)",
        [(f'sum {grp("family", "action")} (rate({sel("opnsense_log_events_zenarmor_total")}[{RATE}]))',
          "{{family}} / {{action}}")],
        unit="short",
        desc="opnsense_log_events_zenarmor_total: Zenarmor records per second by family "
             "(flow/dns/tls/web/ids/voip) and disposition. action=block is what the firewall "
             "stopped. An action with no value is a record that stated no verdict -- it is not "
             "counted as a pass, deliberately.",
    )
    zen_blocked = b.ts(
        "Zenarmor Blocks by Category (rate)",
        [(f'sum {grp("category")} (rate({sel("opnsense_log_events_zenarmor_total", "action=\"block\"")}[{RATE}]))',
          "{{category}}")],
        unit="short",
        desc="Blocked Zenarmor records per second by category -- application category for "
             "flows, domain category for DNS/TLS, alert category for threats. Application "
             "names, IPs and hostnames are never labels; query the log stream for those.",
    )
    # #416: the _bulk request rate and the _bulk byte rate used to share one
    # "short" field unit on a single panel, so the byte series' magnitude
    # flattened the request-rate series and the axis mislabelled a byte rate
    # as a unitless count. Split into a request-rate panel (unit="reqps",
    # matching the reqps convention already used for request rates elsewhere,
    # e.g. grafana/tabs/dns_unbound.py) and a dedicated byte-rate panel
    # (unit="Bps"); both queries are unchanged.
    zen_bulk_requests = b.ts(
        "Zenarmor Bulk Ingest Requests (requests/sec)",
        [(f'rate({sel("opnsense_exporter_logs_zenarmor_bulk_requests_total")}[{RATE}])', "requests/s")],
        unit="reqps",
        desc="Elasticsearch _bulk requests Zenarmor pushes per second (requests/sec, not "
             "bytes). See 'Zenarmor Bulk Ingest Bytes' for the payload volume of those same "
             "requests: it used to share this axis, where its magnitude flattened this "
             "request-rate series. Self-metric: aggregates across exporter instances on a "
             "multi-box setup (no opnsense_instance label).",
    )
    zen_bulk_bytes = b.ts(
        "Zenarmor Bulk Ingest Bytes (bytes/sec)",
        [(f'rate({sel("opnsense_exporter_logs_zenarmor_bulk_bytes_total")}[{RATE}])', "bytes/s")],
        unit="Bps",
        desc="Elasticsearch _bulk payload bytes Zenarmor pushes per second (bytes/sec, not a "
             "request count). A live box measured ~70 KB/s sustained, which is ~4-6 GB/day of "
             "raw JSON into Loki. Cut families at the Zenarmor end (its own indexes setting) "
             "rather than here -- data cut at source never crosses the wire. Self-metric: "
             "aggregates across exporter instances on a multi-box setup (no opnsense_instance "
             "label).",
    )
    zen_excluded = b.ts(
        "Zenarmor Records Excluded (rate)",
        [(f'sum {grp("rule")} (rate({sel("opnsense_exporter_logs_zenarmor_excluded_total")}[{RATE}]))',
          "{{rule}}")],
        unit="short",
        desc="opnsense_exporter_logs_zenarmor_excluded_total: records dropped per second by a "
             "--logs.zenarmor.exclude rule, by rule (#279). This panel IS the blind spot: every "
             "record counted here was real traffic that is now absent from the log stream, and "
             "unlike syslog sampling the derived counters cannot make up for it -- they carry no "
             "server_name, query or device_name. A rule climbing unexpectedly is eating more than "
             "it was written for. Flat zero is the default: exclusion is opt-in. Self-metric: "
             "aggregates across exporter instances on a multi-box setup.",
    )
    zen_block_ratio = b.ts(
        "Block Ratio",
        [(f'sum by (opnsense_instance)(rate({sel("opnsense_log_events_zenarmor_total", "action=\"block\"")}[{RATE}])) / '
          f'sum by (opnsense_instance)(rate({sel("opnsense_log_events_zenarmor_total")}[{RATE}]))',
          "{{opnsense_instance}}")],
        unit="percentunit",
        desc="Fraction of Zenarmor records that were blocked, derived from "
             "opnsense_log_events_zenarmor_total. A sudden jump usually tracks a policy or "
             "signature update rather than an attack -- pair with Blocks by Category.",
    )
    zen_family_pie = b.piechart(
        "Events by Family",
        [(f'sum {grp("family")} ({sel("opnsense_log_events_zenarmor_total")})', "{{family}}")],
        unit="short",
        desc="Current distribution of Zenarmor records across family (flow/dns/tls/web/ids/voip).",
    )
    # Info metric (#474): value always 1, table viz with the Value/__name__/job/instance
    # columns excluded per AUTHORING.md rule 7. This is also what makes $zenarmor_client
    # enumerable (see CLIENT_VAR above) -- the table doubles as a device inventory.
    zen_device_info = b.table(
        "Zenarmor Devices",
        [sel("opnsense_log_events_zenarmor_device_info")],
        w=24, h=8,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "device_name": "Device",
            "device_category": "Category",
            "interface": "Interface",
            "opnsense_instance": "Instance",
        },
        sort_by="Device",
        desc="Device inventory backing the $zenarmor_client picker: every device "
             "Zenarmor has attributed traffic to, its category and the interface it "
             "was seen on (info metric -- value is always 1; use labels). Bounded at "
             "512 devices, and a device drops off 24h after it was last seen, so this "
             "is recent activity rather than an all-time list. Refusals past the cap "
             "show up as cardinality_capped_total{family=\"zenarmor_device\"}.",
    )
    zen_self_traffic = b.ts(
        "Self-Traffic Drop Rate",
        [(f'rate({sel("opnsense_exporter_logs_rejected_total", "reason=\"self_traffic\",source=\"zenarmor\"")}[{RATE}])',
          "self-traffic drops")],
        unit="short",
        desc="opnsense_exporter_logs_rejected_total{reason=\"self_traffic\",source=\"zenarmor\"}: "
             "Zenarmor's own connection delivering its bulk requests to us, correctly identified "
             "and dropped rather than shipped (#278). A steady rate is normal and healthy, "
             "roughly one per bulk request -- it's the feature working. Self-metric: aggregates "
             "across exporter instances on a multi-box setup.",
    )

    # --- Row B: Live records & rates (Loki) --------------------------------

    zen_raw_logs = b.logs(
        "Raw Zenarmor Records",
        ZEN_STREAM,
        desc="Unfiltered Zenarmor log stream. Use the log details panel to inspect structured "
             "metadata fields (device_name, server_name, ja3, dst_nbytes, ...) on any line.",
        w=24,
    )
    zen_records_rate = b.loki_ts(
        "Records/s by Family",
        [(f'sum {loki_grp("opnsense_subsystem")} (rate({ZEN_STREAM} [$__auto]))', "{{opnsense_subsystem}}")],
        desc="Raw Zenarmor log line rate by family, computed directly over the Loki stream "
             "(opnsense_subsystem is the indexed family label: flow/dns/tls/web/ids/voip).",
    )
    zen_blocked_rate = b.loki_ts(
        "Blocked/s by Family",
        [(f'sum {loki_grp("opnsense_subsystem")} (rate({ZEN_BLOCKED} [$__auto]))',
          "{{opnsense_subsystem}}")],
        desc="Blocked Zenarmor log line rate by family, computed directly over the Loki stream.",
    )

    # --- Row C: Security detail (Loki tables, cardinality-safe) ------------

    zen_top_blocked_servers = b.loki_table(
        "Top Blocked Servers",
        [f'topk {loki_grp()} (20, sum {loki_grp("server_name")} (count_over_time({ZEN_BLOCKED} '
         '| server_name!="" [$__auto])))'],
        field_title="Server Name",
        desc="Top 20 server names (TLS SNI / DNS query name) appearing in blocked Zenarmor "
             "records, over the selected range. server_name is structured metadata, so this "
             "MUST go through a range-query table rather than an instant/timeseries query.",
    )
    zen_top_talkers = b.loki_table(
        "Top Talkers by Bytes",
        [f'topk {loki_grp()} (20, sum {loki_grp("device_name")} (sum_over_time({ZEN_FLOW} '
         '| device_name!="" | unwrap dst_nbytes [$__auto])))'],
        field_title="Device",
        desc="Top 20 devices by inbound flow bytes (dst_nbytes), flow family only. Value column "
             "is raw bytes. device_name and dst_nbytes are structured metadata on the flow record.",
    )
    zen_blocked_by_country = b.loki_table(
        "Blocked by Country",
        [f'topk {loki_grp()} (20, sum {loki_grp("dst_geoip_country_name")} (count_over_time({ZEN_BLOCKED} '
         '| dst_geoip_country_name!="" [$__auto])))'],
        field_title="Country",
        desc="Top 20 destination countries (GeoIP) for blocked Zenarmor records.",
    )
    zen_top_ja3 = b.loki_table(
        "Top JA3 Fingerprints",
        [f'topk {loki_grp()} (20, sum {loki_grp("ja3")} (count_over_time({ZEN_TLS} '
         '| ja3!="" [$__auto])))'],
        field_title="JA3 Fingerprint",
        desc="Top 20 TLS client fingerprints (JA3) seen, tls family only. JA3 identifies the "
             "TLS client implementation, not the endpoint -- many distinct devices sharing a "
             "library/browser will share a fingerprint, so this is a coarse grouping, not a "
             "precise device count.",
    )

    # --- Row D: DNS (Loki, dns family) -------------------------------------
    # Merged from the retired `opnsense-zenarmor` companion (#435). Everything here
    # needs a field the derived counters do not carry: a query name, an rcode, a
    # domain category. The counters answer "how much"; these answer "what".
    #
    # Rewritten rather than copied: every selector goes through loki_sel() so it is
    # instance-scoped, and every topk carries loki_grp() so ranking cannot silently
    # drop a second firewall's rows (#413/#468). The companion had neither.
    zen_dns_queries = b.loki_table(
        "Top DNS Queries",
        [f'topk {loki_grp()} (25, sum {loki_grp("query")} (count_over_time({ZEN_DNS} '
         f'{CLIENT_FILTER} | query!="" [$__auto])))'],
        field_title="Query",
        desc="Top 25 DNS query names Zenarmor saw, over the selected range. `query` is "
             "structured metadata, so this is a range-query table rather than an instant "
             "query. High cardinality by nature — this is why it is not a metric.",
    )
    zen_dns_rcodes = b.loki_ts(
        "DNS Response Codes",
        [(f'sum {loki_grp("rcode")} (rate({ZEN_DNS} {CLIENT_FILTER} [$__auto]))',
          "{{rcode}}")],
        desc="DNS responses per second by response code. A climbing NXDOMAIN or SERVFAIL "
             "share is usually a resolver or upstream problem rather than a client one; "
             "read it beside the Unbound tab, which measures the same failures from the "
             "resolver's side.",
    )
    zen_dns_categories = b.loki_table(
        "Top DNS Domain Categories",
        [f'topk {loki_grp()} (15, sum {loki_grp("domain_category")} (count_over_time({ZEN_DNS} '
         f'{CLIENT_FILTER} | domain_category!="" [$__auto])))'],
        field_title="Category",
        desc="Top 15 domain categories for DNS records, Zenarmor's own classification. "
             "Unlike Blocks by Category above this counts ALL records, not just blocked "
             "ones, so it describes what the network asks for rather than what policy "
             "stopped.",
    )

    # --- Row E: Web / HTTP (Loki, web family) ------------------------------
    zen_web_hosts = b.loki_table(
        "Top HTTP Hosts",
        [f'topk {loki_grp()} (25, sum {loki_grp("host")} (count_over_time({ZEN_WEB} '
         f'{CLIENT_FILTER} {NOT_SELF} | host!="" [$__auto])))'],
        field_title="Host",
        desc="Top 25 plaintext-HTTP hosts. Zenarmor's own bulk-ingest requests to the "
             "exporter are excluded, or they would be the top host and the panel would "
             "mostly describe this exporter. HTTPS hosts are not here — they appear as TLS "
             "SNI in Top TLS Server Names.",
    )
    zen_web_uris = b.loki_table(
        "Top URIs",
        [f'topk {loki_grp()} (25, sum {loki_grp("uri")} (count_over_time({ZEN_WEB} '
         f'{CLIENT_FILTER} {NOT_SELF} | uri!="" [$__auto])))'],
        field_title="URI",
        desc="Top 25 request URIs on plaintext HTTP, excluding the exporter's own ingest "
             "endpoint. Only unencrypted traffic can be seen at this level.",
    )
    zen_web_agents = b.loki_table(
        "Top User Agents",
        [f'topk {loki_grp()} (15, sum {loki_grp("user_agent")} (count_over_time({ZEN_WEB} '
         f'{CLIENT_FILTER} {NOT_SELF} | user_agent!="" [$__auto])))'],
        field_title="User Agent",
        desc="Top 15 user agents on plaintext HTTP. Useful for spotting an unexpected "
             "device class or an automated client; it is self-reported, so treat it as a "
             "hint rather than identification.",
    )
    zen_web_status = b.loki_ts(
        "HTTP Status Codes",
        [(f'sum {loki_grp("http_status_code")} (rate({ZEN_WEB} {CLIENT_FILTER} '
          f'{NOT_SELF} [$__auto]))', "{{http_status_code}}")],
        desc="Plaintext-HTTP responses per second by status code, excluding the exporter's "
             "own ingest endpoint. This is traffic Zenarmor OBSERVED passing through the "
             "firewall, not requests served by it — the exporter's own HTTP health is on "
             "the Diagnostics tab.",
    )

    # --- Row F: Applications & destinations (Loki, all verdicts) -----------
    # The companion's all-verdict counterparts to the blocked-only tables in Row C.
    # Kept as separate panels rather than widening those: "what got blocked" and "what
    # the network does" are different questions, and merging them would answer neither.
    zen_apps = b.loki_table(
        "Top Applications",
        [f'topk {loki_grp()} (25, sum {loki_grp("app_name")} (count_over_time({ZEN_FLOW} '
         f'{CLIENT_FILTER} | app_name!="" [$__auto])))'],
        field_title="Application",
        desc="Top 25 applications Zenarmor identified on flow records, all verdicts. "
             "Application NAMES are deliberately not a metric label (cardinality), so this "
             "is the only place they appear; the Flow Volume tab has the same shape by "
             "application CATEGORY, from metrics, and is far cheaper to read.",
    )
    zen_server_names = b.loki_table(
        "Top TLS Server Names (SNI)",
        [f'topk {loki_grp()} (25, sum {loki_grp("server_name")} (count_over_time({ZEN_TLS} '
         f'{CLIENT_FILTER} | server_name!="" [$__auto])))'],
        field_title="Server Name",
        desc="Top 25 TLS server names (SNI) across ALL verdicts — where the network goes, "
             "not what policy stopped. Top Blocked Servers above is the blocked-only "
             "counterpart; a name high here and absent there is simply allowed traffic.",
    )
    zen_dst_countries = b.loki_table(
        "Destination Countries",
        [f'topk {loki_grp()} (15, sum {loki_grp("dst_geoip_country_name")} '
         f'(count_over_time({ZEN_TLS} {CLIENT_FILTER} | dst_geoip_country_name!="" '
         '[$__auto])))'],
        field_title="Country",
        desc="Top 15 destination countries (GeoIP) for TLS records, all verdicts. Blocked "
             "by Country above is the blocked-only counterpart.",
    )

    b.tab("Zenarmor", [
        b.row("Overview", [zen_events, zen_blocked, zen_block_ratio, zen_family_pie,
                           zen_bulk_requests, zen_bulk_bytes, zen_excluded, zen_self_traffic,
                           zen_device_info],
              present="has_zenarmor_metrics"),
        b.row("Live Records & Rates", [zen_raw_logs, zen_records_rate, zen_blocked_rate],
              present="has_zenarmor_logs"),
        b.row("Security Detail", [zen_top_blocked_servers, zen_top_talkers,
                                  zen_blocked_by_country, zen_top_ja3],
              present="has_zenarmor_logs"),
        # Rows D-F carry the retired companion's unique content (#435). Collapsed by
        # default: they are the expensive half of this tab — nine range queries over a
        # 2.5-3.3M records/day stream — and #422's finding was that cold-load cost is
        # round-trip COUNT. A collapsed row issues nothing until it is opened.
        b.row("DNS Detail", [zen_dns_queries, zen_dns_rcodes, zen_dns_categories],
              present="has_zenarmor_logs", collapse=True),
        b.row("Web / HTTP Detail", [zen_web_hosts, zen_web_uris, zen_web_agents,
                                    zen_web_status],
              present="has_zenarmor_logs", collapse=True),
        b.row("Applications & Destinations", [zen_apps, zen_server_names,
                                              zen_dst_countries],
              present="has_zenarmor_logs", collapse=True),
    ])
