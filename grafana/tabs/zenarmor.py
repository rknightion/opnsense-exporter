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
- opnsense_exporter_logs_zenarmor_* self-metrics carry NO opnsense_instance
  -> sel_pipeline(); these aggregate across exporter instances on a
  multi-box setup, since there's no instance label to split by.
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

ZEN_STREAM = loki_sel('opnsense_source="zenarmor"')
ZEN_BLOCKED = loki_sel('opnsense_source="zenarmor", opnsense_action="block"')
ZEN_FLOW = loki_sel('opnsense_source="zenarmor", opnsense_subsystem="flow"')
ZEN_TLS = loki_sel('opnsense_source="zenarmor", opnsense_subsystem="tls"')


def build(b: Builder):
    b.sentinel("has_zenarmor_metrics", metric="opnsense_log_events_zenarmor_total")
    b.loki_sentinel("has_zenarmor_logs", matchers='opnsense_source="zenarmor"',
                    label="opnsense_source")

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
        [(f'rate({b.sel_pipeline("opnsense_exporter_logs_zenarmor_bulk_requests_total")}[{RATE}])', "requests/s")],
        unit="reqps",
        desc="Elasticsearch _bulk requests Zenarmor pushes per second (requests/sec, not "
             "bytes). See 'Zenarmor Bulk Ingest Bytes' for the payload volume of those same "
             "requests: it used to share this axis, where its magnitude flattened this "
             "request-rate series. Self-metric: aggregates across exporter instances on a "
             "multi-box setup (no opnsense_instance label).",
    )
    zen_bulk_bytes = b.ts(
        "Zenarmor Bulk Ingest Bytes (bytes/sec)",
        [(f'rate({b.sel_pipeline("opnsense_exporter_logs_zenarmor_bulk_bytes_total")}[{RATE}])', "bytes/s")],
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
        [(f'sum {grp("rule")} (rate({b.sel_pipeline("opnsense_exporter_logs_zenarmor_excluded_total")}[{RATE}]))',
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
    zen_self_traffic = b.ts(
        "Self-Traffic Drop Rate",
        [(f'rate({b.sel_pipeline("opnsense_exporter_logs_rejected_total", "reason=\"self_traffic\",source=\"zenarmor\"")}[{RATE}])',
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
        desc="Top 20 server names (TLS SNI / DNS query name) appearing in blocked Zenarmor "
             "records, over the selected range. server_name is structured metadata, so this "
             "MUST go through a range+reduce table rather than an instant/timeseries query.",
    )
    zen_top_talkers = b.loki_table(
        "Top Talkers by Bytes",
        [f'topk {loki_grp()} (20, sum {loki_grp("device_name")} (sum_over_time({ZEN_FLOW} '
         '| device_name!="" | unwrap dst_nbytes [$__auto])))'],
        desc="Top 20 devices by inbound flow bytes (dst_nbytes), flow family only. Value column "
             "is raw bytes. device_name and dst_nbytes are structured metadata on the flow record.",
    )
    zen_blocked_by_country = b.loki_table(
        "Blocked by Country",
        [f'topk {loki_grp()} (20, sum {loki_grp("dst_geoip_country_name")} (count_over_time({ZEN_BLOCKED} '
         '| dst_geoip_country_name!="" [$__auto])))'],
        desc="Top 20 destination countries (GeoIP) for blocked Zenarmor records.",
    )
    zen_top_ja3 = b.loki_table(
        "Top JA3 Fingerprints",
        [f'topk {loki_grp()} (20, sum {loki_grp("ja3")} (count_over_time({ZEN_TLS} '
         '| ja3!="" [$__auto])))'],
        desc="Top 20 TLS client fingerprints (JA3) seen, tls family only. JA3 identifies the "
             "TLS client implementation, not the endpoint -- many distinct devices sharing a "
             "library/browser will share a fingerprint, so this is a coarse grouping, not a "
             "precise device count.",
    )

    b.tab("Zenarmor", [
        b.row("Overview", [zen_events, zen_blocked, zen_block_ratio, zen_family_pie,
                           zen_bulk_requests, zen_bulk_bytes, zen_excluded, zen_self_traffic],
              present="has_zenarmor_metrics"),
        b.row("Live Records & Rates", [zen_raw_logs, zen_records_rate, zen_blocked_rate],
              present="has_zenarmor_logs"),
        b.row("Security Detail", [zen_top_blocked_servers, zen_top_talkers,
                                  zen_blocked_by_country, zen_top_ja3],
              present="has_zenarmor_logs"),
    ])
