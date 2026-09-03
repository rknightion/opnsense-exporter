# Log shipping

The exporter can ship structured OPNsense **events** (firewall log lines, IDS
alerts, audit entries, and similar) to Loki, separately from the metrics it
exposes at `/metrics`. This is opt-in and off by default: it runs only when
`--logs.enabled` is set.

Log shipping is a long-lived background pipeline, not a scrape-time collector.
Registered sources poll OPNsense event APIs on their own cadence, records pass
through a bounded in-memory queue, and an emitter ships batches to the configured
sink. It is independent of OTLP metrics export (`--otlp.enabled`): metrics
and logs are gated by separate flags and neither turns the other on.

High-cardinality event data (IP addresses, ports, Suricata SIDs, domains) is
shipped as log **body** and Loki **structured metadata** - never as a metric and
never as a Loki label. The only labels are the resource identity, plus `opnsense.source`
and `opnsense.subsystem` if you promote them (see [Loki label model](#loki-label-model)).

The pipeline is implemented in
[`internal/logship/` on GitHub](https://github.com/rknightion/opnsense2otel/tree/main/internal/logship);
parsers live one file per program, so
[adding a parser](https://github.com/rknightion/opnsense2otel/tree/main/internal/logship) is a
self-contained contribution.

!!! note "Sources are added incrementally"
    Enabling `--logs.enabled` starts the pipeline, but nothing is shipped until at
    least one **source** is also enabled (each source has its own
    `--logs.<source>.enabled` flag), unless `--logs.self.enabled` admits the
    exporter's own process logs. With neither an event source nor self-logs enabled,
    the exporter logs a warning and ships nothing.

## Sinks

Select the sink with `--logs.sink`:

- **`otlp`** (default) - ships over OTLP logs. One sink covers both the Grafana
  Cloud OTLP gateway (which routes `/v1/logs` to Loki) and a self-hosted Loki 3.x
  native OTLP endpoint. It reuses the exporter's existing `--otlp.*` transport
  family (endpoint, protocol, headers, TLS/mTLS, and the Grafana Cloud shortcut),
  so no separate endpoint configuration is needed. Because the transport is shared
  but the gates are separate, the `--otlp.*` flags configure the logs endpoint
  even when `--otlp.enabled` (metrics export) is off.
- **`stdout`** - writes one compact JSON line per event to standard output. This is
  the zero-dependency path for container/Kubernetes setups where a node log
  collector already ships stdout.

When `--logs.sink=otlp` and no OTLP endpoint is resolvable (no `--otlp.endpoint`,
no Grafana Cloud endpoint, and no `OTEL_EXPORTER_OTLP_ENDPOINT` /
`OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` environment variable), startup fails with an
error naming the missing flag rather than silently shipping nothing.

## Sources

### Exporter self-logs (`--logs.self.enabled`)

`--logs.self.enabled` copies the exporter's own structured logs into the shared
log pipeline while preserving the normal stderr output. It is off by default and
requires both `--logs.enabled` and `--logs.sink=otlp`; stdout is refused because it
cannot carry the OTLP resource identity this stream relies on. Records enter the
same bounded queue and use the same retry, overflow, and delivery accounting as
the event sources. Sink and pipeline diagnostics bypass this adapter so an OTLP
outage cannot feed its own failure logs back into the failing sink.

The fixed resource dimensions are `opnsense.source=exporter` and
`opnsense.subsystem=self`. Logger attributes remain structured metadata, subject
to the pipeline's normal sanitisation; they are not promoted to Loki labels.

### Syslog receiver (`--logs.syslog.enabled`)

The receiver is a **push** source: OPNsense forwards its logs to the exporter and
the exporter enriches them from the API. It supersedes the old `firewall` and
`diaglog` poll lanes, which spawned configd on the box and re-read log files the
firewall will happily push. See **[Syslog receiver](syslog-receiver.md)** for the
full setup, including the target you must configure on the firewall.

In short: it listens for RFC5424 or RFC3164 syslog over UDP, TCP and/or TLS (port
5514 by default), parses `filterlog` records into structured fields, ships every
other program as a generic record, and enriches everything it can from the OPNsense
API. It also **derives low-cardinality Prometheus counters** (`opnsense_log_events_*`)
from what it parses, and can optionally **sample** high-volume raw lines away once
their metric is counted - see [Derived metrics and sampling](syslog-receiver.md#derived-metrics-and-sampling)
and [TLS transport](syslog-receiver.md#tls-transport-optional).

**Enrichment** is the reason this lives in the exporter rather than a generic
syslog collector. The exporter already holds an authenticated API client, so it
can resolve what Alloy, Vector or rsyslog structurally cannot:

| Attribute | Resolved from |
| --- | --- |
| `rule.description` | `diagnostics/firewall/list_rule_ids` |
| `interface.name` | the interface overview (`vtnet0` → `LAN`) |
| `src.hostname` / `dst.hostname` | DHCPv4/DHCPv6/Kea/dnsmasq leases |
| `src.mac` / `dst.mac` | the ARP and NDP tables |
| `src.scope` / `dst.scope` | `self`, `local` or `remote`, from the firewall's own subnets |
| `src.service` / `dst.service` | a compiled-in well-known-port table |

The rule description matters more than it looks. A filterlog rule id is *either* a
rule UUID (for rules you wrote) *or* a content hash (for the auto-generated ones -
anti-lockout, default-deny, bogon blocks, DHCP-allow). The config-level rule
inventory only contains the former, so it cannot label the majority of the lines a
real box emits. `list_rule_ids` resolves both.

Lookups read a lock-free snapshot refreshed on its own goroutine; the receive path
never makes an API call. **Enrichment failure never drops a record** - a cold or
stale snapshot ships the line unenriched.

**Fidelity:** the parser uses filterlog's true nine-field TCP tail (`srcport`,
`dstport`, `datalen`, `tcpflags`, `seq`, `ack`, `window`, `urg`, `options`).
OPNsense's own log reader declares eight, which mislabels the TCP window as the
urgent pointer and drops the options entirely - so the receiver recovers data the
API path silently loses.

**Caveat:** the filter log records the **first packet of a flow only** - it is an
event stream, not flow accounting. Do not read event counts as byte/connection
totals.

### Zenarmor (`--logs.zenarmor.enabled`)

The exporter can also pose as an Elasticsearch node and receive Zenarmor's reporting
data directly - a second **push** source, and the first high-volume one. See
**[Zenarmor receiver](zenarmor-receiver.md)** for the full setup, including the GUI
fields on the Zenarmor side and a warning about a similarly-named but destructive
install-time Elasticsearch option you must not confuse this with.

In short: it accepts Elasticsearch `_bulk` writes on port 9200 by default, ships all six
of Zenarmor's reporting families (`conn`, `dns`, `tls`, `http`, `alert`, `sip` - mapped
to `opnsense.subsystem` values `flow`, `dns`, `tls`, `web`, `ids`, `voip`) as enriched
OTLP logs, and derives a Prometheus counter (`opnsense_log_events_zenarmor_total`) from
every document. Volume is substantial - measured at ~39 docs/sec on a live box, ~4–6
GB/day of raw JSON - so prefer cutting families in Zenarmor's own `indexes` setting over
`--logs.zenarmor.families`: data cut at the source never crosses the wire.

### IDS (Suricata EVE alerts)

`--logs.ids.enabled` (off by default; requires `--logs.enabled`) ships full
Suricata EVE **alert** records - not just the aggregate counts the IDS metrics
collector exposes (`opnsense_ids_recent_alerts`, gated separately by
`--exporter.enable-ids-alerts`). It polls `POST api/ids/service/query_alerts`,
the same endpoint the metrics collector's opt-in alert-activity series already
uses, reading up to the newest 500 eve rows per poll (the same cap the metrics
collector's alert count is a floor against).

- **Body** is the compact JSON of the complete raw eve alert record exactly as
  Suricata wrote it - every field it emits, not a reconstructed subset. This
  includes fields the exporter never parses into typed metadata (the nested
  `flow` object, `app_proto`, `event_type`, `filepos`/`fileid`, …).
- **Structured metadata** (never a label): `alert_sid`, `alert_action`,
  `src_ip`, `dest_ip`, `in_iface`, `proto`, `signature`.
- **Severity** is `warn` for a `blocked` alert, `info` otherwise.
- **Cursor**: the record's own `timestamp` is the true cursor, with a
  `flow_id`+`alert_sid` dedupe ring scoped to records sharing the cursor's
  exact timestamp. `filepos`/`fileid` are never used to cursor - log rotation
  shifts `fileid`s, so they are fragile across restarts.
- **Gap accounting**: `query_alerts` is a windowed, saturating read. If a poll
  returns a full 500-row window whose oldest row is still newer than the prior
  cursor, the read could not reach back far enough to cover everything since
  the last poll - some alerts in that range were never observed. This is
  accepted, bounded loss: the source ships one synthetic gap record
  (`event=gap_detected` structured metadata, `warn` severity, a JSON body
  naming the gap bounds) instead of silently dropping it, so the loss is
  visible and queryable in Loki (e.g.
  `{service_name="opnsense2otel"} | opnsense_source="ids" | json | event="gap_detected"`).
- **First poll**: with no prior cursor (fresh start, or `--logs.state-file` not
  set/empty/corrupt), the whole initial window ships as a startup catch-up
  rather than being silently skipped or treated as a gap.

!!! note "Prefer native `syslog_eve` where it fits"
    OPNsense's IDS settings also offer `syslog_eve` (ships the identical EVE
    JSON via syslog - alerts only, with metadata and a community id) and
    `syslog` (fastlog lines). If the box already forwards EVE JSON via
    `syslog_eve` to your log pipeline, enable that instead of this source -
    running both double-ships the same alerts. `syslog_eve` shares the
    `suricata`/`local5` facility with engine logs, so a demux step is needed on
    that path (not a concern for the API-polling source documented here).

### CrowdSec (`--logs.crowdsec.enabled`)

Ships CrowdSec **alert** and **decision** records. There is no native syslog
path for these - the plugin registers no syslog scope, so alerts and
decisions live only in the local API (LAPI). Off by default; enable with
`--logs.crowdsec.enabled` (requires `--logs.enabled`). Silent when the
os-crowdsec plugin is absent. Polls at a 60s floor regardless of
`--logs.poll-interval` - each poll is a full `cscli` alerts/decisions dump
(one configd exec each), so polling faster buys nothing at homelab/SMB event
volumes.

- **Cursor:** alert ids and decision ids are each a separate, server-side
  monotonic counter. The source tracks the highest id shipped per record kind
  and ships only rows whose id is greater on the next poll - a plain id-diff,
  no timestamp windowing. On a cold start every currently-active alert/decision
  is shipped once, so enabling the source surfaces current state instead of
  silently starting from a blank slate.
- **Body:** compact JSON of the alert or decision (`kind`, `id`, `scope_value`,
  `scenario`, plus alert-only `decisions`/`created` or decision-only
  `alert_id`/`action`/`expiration`/`events_count`).
- **Attributes** (structured metadata, never labels): `scenario`, `value`
  (the scope:ip the alert/decision concerns - high cardinality, so metadata
  only, never a label), `country`, `as` (both often empty without a GeoIP
  database configured), plus `decisions` (alerts: a `type:count` summary, e.g.
  `ban:1`) or `decision_type` and `duration` (decisions: the CrowdSec action
  and the remaining-duration string, e.g. `693h46m29s`).
- **Timestamps:** alerts carry an RFC3339 `created` field, used as the
  record's timestamp. Decisions carry no absolute timestamp (only a
  remaining-duration string), so the record is stamped at emit time.

### Unbound (per-query DNS log)

`--logs.unbound.enabled` (default `false`) ships a pi-hole-style per-query DNS
log: domain, client, action (`Pass`/`Block`/`Drop`), resolution source
(`Recursion`/`Local`/`Local-data`/`Cache`), blocklist/policy enrichment and
DNSSEC status per query - data unavailable anywhere else in OPNsense's API
(syslog only carries raw unbound daemon lines). It requires Unbound
reporting/statistics to be enabled on the firewall, and raises the poll floor
to 15s (`IntervalSource`) because each poll spawns python+pandas+DuckDB on the
box (~1s CPU).

**Accepted sampling loss - read this before enabling on a busy resolver.**
Unbound's query-log backend (`api/unbound/overview/search_queries`) has no true
cursor: without a per-client filter it only ever returns the newest **1000
rows across the whole resolver**, newest first. This source reconstructs a
best-effort cursor from each row's `time` (unix seconds) plus a dedup
fingerprint for rows sharing the same second - the `uuid` field is part of the
documented schema but has been observed to always be `null` in practice, so it
is used only when present. On a resolver sustaining more than roughly 1000
queries between two polls, the oldest rows in the next page will all be newer
than the previous cursor - a full discontinuity - meaning some number of
queries fell out of the window before this exporter ever fetched them. That
loss is never silent: it is counted via
`opnsense_exporter_logs_possible_gap_total{source="unbound"}` (see
[Self-metrics](#self-metrics)) every time it is detected. Homelab/SMB query
volumes (a handful to ~100 qps) are fine; a busy enterprise resolver should not
enable this source.

Loki structured metadata for this source: `dns.client_label`, `domain`, `qtype`,
`action`, `query_source`, `rcode`, `blocklist` when its legacy short code is
recoverable, `dnssec_status`, plus `src.ip` and its enrichment (`src.hostname`,
`src.mac`, `src.scope`) on the minority of records where the client value is an
address - see below. (Unbound's own `source` field - where the answer came from -
is deliberately mapped to the `query_source` attribute rather than a bare `source`,
to keep it clear of this pipeline's own `opnsense.source` stamp; see [Loki label
model](#loki-label-model).) The log body is compact JSON encoding of the row's
stable fields, including fields not promoted to structured metadata (`family`,
`resolve_time_ms`, `ttl`, `policy`).

**Blocklist compatibility limitation.** Legacy `search_queries` responses carry
the backend blocklist short code, so the exporter keeps that value as `blocklist`
in both the JSON body and structured metadata. OPNsense 26.7 adds `category` and
replaces the short code with the configured display value; the original code is
not present in that response and cannot be recovered. The exporter therefore
omits `blocklist` from both places for that shape rather than presenting the
display value as a stable identity. Consumers must treat a missing `blocklist` as
expected on 26.7; there is no display-valued replacement attribute.

**This lane cannot be joined to flow records by IP.** OPNsense collapses the client
address and its resolved hostname into one column before serialising the query log -
`stats.py handle_details()` picks the hostname when its client table has one, then
drops the address entirely, on every code path - so the raw client IP is not present
anywhere in the API response. What arrives is therefore sometimes a hostname
(`camden.rob-knight.net`), sometimes a bare IPv4 or IPv6 literal, sometimes a
non-FQDN name (`poly-office`) or `localhost`, and sometimes empty.

The exporter does not guess. That value ships as `dns.client_label` - always set when
non-empty, and the field to group a per-client panel on. `src.ip` is set **only** when
the value already parses as an address (roughly 3% of rows on a box with reverse
lookups working), and only then is it enriched to `src.hostname` / `src.mac` /
`src.scope` from the exporter's own ARP/DHCP-lease tables. So `src.ip` on this source
is either a real address or absent, never a hostname - but on most rows it is absent,
and a query joining DNS to NetFlow, Zenarmor or firewall records by `src.ip` will
match only that minority.

Reverse-mapping the hostname back to an address was measured against a live 1000-row
page and rejected: it covered 35% of queries, missed the busiest client entirely (a
static-IP host with no lease and no ARP hostname), and was four-way ambiguous on the
second busiest. If you need IP-keyed DNS correlation, use the syslog per-query route
below - Unbound's own daemon log carries the raw client address and never substitutes
it.

Separately, the syslog receiver's `unbound` parser structures a plainer slice of
this same data - query name/type/class and the matched local-zone - straight off
Unbound's daemon log, with no blocklist, policy or DNSSEC detail. See
[Structured parsers](syslog-receiver.md#what-you-get) for what it captures.

### Unbound per-query DNS via syslog (`--logs.syslog.unbound-per-query.enabled`)

The **second** per-query DNS route. Unbound can log every query and every reply to
its own daemon log; this parses that output instead of polling OPNsense's reporting
database. The two routes are complementary and **mutually exclusive** - the exporter
refuses to start with both enabled, because both log the same queries and running
both ships two Loki records per query, silently doubling every per-query panel.

Which one to pick:

| | poll (`--logs.unbound.enabled`) | syslog (`--logs.syslog.unbound-per-query.enabled`) |
|---|---|---|
| completeness | newest 1000 rows resolver-wide per poll; loss counted via `logs_possible_gap_total{source="unbound"}` | complete, every query |
| client identity | hostname substituted when a PTR exists (see above) | **raw client IP**, never substituted |
| resolve time / cache-hit flag | no | **yes**, from `log-replies` |
| action / blocklist / policy | **yes** - the DNSBL disposition | no |
| `dnssec_status`, `ttl` | yes | no |
| rcode | yes | yes (`log-replies` only) |
| cost model | firewall API + DuckDB lock contention | ~2 extra syslog lines per query, forever |
| transport | poll | push |

**Firewall prerequisites.** In Unbound's advanced settings, enable `log-replies`
(and optionally `log-queries`) **and `log-tag-queryreply`**. The last one is not
optional: without it Unbound tags these lines `info:` rather than `query:`/`reply:`,
and the parser will not match them. Upstream defaults it **off**.

**Prefer `log-replies` alone.** A reply line carries every field a query line does
plus four more (rcode, resolve time, from-cache flag, response size), so enabling
only `log-replies` halves the ingest for strictly more data. `log-queries` is worth
adding only if you specifically need evidence that a query arrived and was never
answered.

**Performance.** Upstream's `man unbound.conf` warns that `log-queries` "Prints one
line per query to the log ... Note that it takes time to print these lines which
makes the server (significantly) slower", and says the same of `log-replies`. This is
a synchronous write in the resolution hot path, per query, per worker thread. Measured
on a homelab resolver at up to roughly 60x its ~6 qps baseline, enabling both settings
had **no detectable effect** on loss, latency or throughput, and every saturation
counter stayed at zero. That test cannot clear a genuinely busy resolver - the cost is
per query, so it is invisible at these rates and would be orders of magnitude larger
where it matters. Do not cite it to justify enabling this on a high-volume resolver.

The measurable cost is log volume: about **2.05 lines per DNS query**, which on the
test box was 1.14M lines/day and took DNS from 5.6% to 41% of all syslog.

Loki structured metadata: `dns.query_name`, `dns.query_type`, `dns.query_class`,
`src.ip` (plus enrichment), `unbound.thread` and `dns.event` (`query` or `reply`) on
every record; `dns.rcode`, `dns.resolve_time_seconds`, `dns.cached` and
`dns.response_size_bytes` on reply records; `dst.ip`, `dst.port` and `net.transport`
when `log-destaddr` is also on. Records land under `opnsense_source="syslog"` and
`opnsense_subsystem="dns"`, alongside the other syslog parsers - select them with
`{opnsense_source="syslog", opnsense_subsystem="dns"} | program="unbound"`.

Read the flag, not the timing, to identify a cache hit: a hit is always `0.000000`
seconds, but a fast uncached reply is not.

When this route is **off**, these lines are not dropped - they ship as generic
records exactly as they did before the parser existed. The firewall sends them either
way; the flag decides whether the exporter structures them.

### Configuration revision diffs (`configchange`)

`--logs.configchange.enabled` polls the retained OPNsense configuration history and
ships one `configchange` record for each revision observed after the persisted
cursor. The record body is OPNsense's unified diff, HTML-unescaped and capped at
192 KiB with an explicit truncation marker; `revision`, `user`, and `uri` remain
structured metadata rather than stream labels. A fresh source, or a cursor whose
revision has fallen out of the retained history, re-baselines at the newest revision
without replaying older configuration. Configure `--logs.state-file` to preserve
that cursor across restarts. This source is independent of the syslog receiver.

### Configuration snapshots (`configstate`)

Configuration snapshots are default-off and enabled per family. The firewall family,
`--logs.config-snapshot.firewall.enabled`, emits compact `configstate` JSON records
for firewall and NAT entities. `--logs.config-snapshot.devices.enabled` adds a fused
device inventory from ARP, NDP, DHCP, hostdiscovery and LLDP. The independent
`--logs.config-snapshot.security-posture.enabled` family carries OPNsense's firmware
update verdict, pending package versions, certificate-expiry roll-up and API-key owners;
it deliberately excludes listening-socket detail because the current API proves active
socket counts, not listener state. A content hash suppresses unchanged batches; the
firewall and device families repeat after a six-hour heartbeat, while security posture
repeats weekly. Records share an opaque `snapshot.id` and
carry ordered `snapshot.seq`, `snapshot.total`, `snapshot.family`, `snapshot.reason`,
and `snapshot.entity_id` metadata. Bodies remain valid JSON under the 192 KiB bound:
an oversized entity becomes a bounded envelope with `truncated=true`, its original
size, and a content digest rather than a byte-sliced document. These records contain
firewall policy and topology detail, so enabling the general logs pipeline does not
enable them.

`--logs.config-snapshot.routing-changes.enabled` is a separate `routingchange` source.
Its first poll establishes a baseline; later effective default-route changes emit one
before/after record, with changes inside a one-minute cooldown folded into a bounded
flap-detail record. dpinger-only status changes do not count as a route move.

### Flow log records (`netflow`, `merged`)

A **push** source layered on the separate NetFlow/Zenarmor flow pipeline
(`--flow.enabled`, `--flow.netflow.enabled`, `--flow.zenarmor` - see
[NetFlow & flow metrics](flow.md)): the same correlator that builds the `netflow_*`
metrics also ships one OTLP log record per correlated flow, stamped
`opnsense.source` = `netflow` (NetFlow only) or `merged` (a NetFlow fragment joined
with a matching Zenarmor `conn` document). Gated on three settings rather than its
own `--logs.<source>.enabled` flag: `--logs.enabled`, `--flow.enabled`, and
`--flow.log-mode` (`per_flow`, the default, ships the logs; `off` keeps deriving the
metrics without them). See **[Flow log records](flow.md#flow-log-records)** for the
full attribute set, timestamp semantics and the `--flow.max-logs-per-window` flood
guard.

## Loki label model

Loki promotes **only OTLP resource attributes** to index labels. Scope and log
attributes can never become labels - `otlp_config` has no `index_label` action for
them, whatever the tenant config says. Cardinality discipline therefore falls out of
*where an attribute is put*, not out of policy:

**On the resource** (promotable - a closed, code-defined set):

| attribute | value | indexed by default? |
| --- | --- | --- |
| `service.name` | `--otlp.service-name` | **yes** |
| `service.instance.id` | the resolved instance label | **yes** |
| `service.version` | the exporter version | no |
| `opnsense.source` | `syslog`, `unbound`, `ids`, `crowdsec`, `zenarmor`, `configchange`, `configstate`, `routingchange`, `exporter`, `netflow`, `merged` | no - opt in below |
| `opnsense.subsystem` | `firewall`, `dns`, `auth`, `dhcp`, `vpn`, … (26) | no - opt in below |
| `opnsense.action` | `pass`, `block` | no - opt in below |
| `opnsense.device_category` | `laptop`, `camera`, `iot`, `server`, … (9) | no - opt in below |
| `opnsense.interface` | the interface *descriptions* - `LAN`, `IOT`, `MGMT` | no - opt in below |

The 26 `opnsense.subsystem` values are the syslog receiver's 22-entry
program→subsystem map (`internal/logship/syslog/registry.go`) plus the four
Zenarmor-only families that don't overlap it: `flow`, `tls`, `web`, `voip` (its other
two, `dns` and `ids`, already exist in the syslog map).

The last two are Zenarmor-only: they are absent on every other source's records, and
absent rather than empty, so they never pool unrelated records into one empty-valued
stream. `opnsense.device_category` is clamped to a code-defined vocabulary before it
reaches the resource - the receiver is a push endpoint, so an unrecognised value is a
sender minting streams rather than data, and it folds into Zenarmor's own `other`
bucket. `opnsense.interface` needs no clamp because it is resolved from the exporter's
own view of the firewall's interface config: an interface the box does not have simply
does not resolve. Note it is the interface **description** space, not the kernel device
space (`igb0`, `ixl0`) - the two are disjoint.

Each lane's own verbatim keys (`device.category`, `interface.name`) stay on the record
untouched, so queries already written against them keep working either way.

`service.name` and `service.instance.id` are indexed because they are on Loki's
[default promotion list][otlp-defaults]. No host or SDK resource detectors are
attached, so nothing else can leak into that set. The two custom keys are namespaced
(`opnsense.source`, `opnsense.subsystem`) so they can never collide with a
semconv/Loki-reserved key; Loki mangles the dot, so in LogQL they read
`opnsense_source` and `opnsense_subsystem`.

**On the record** (structured metadata - never promotable): everything else.
`program`, `action`, `rule_id`, `rule_description`, IPs, ports, MACs, hostnames,
SIDs, `tcp_*`, `dhcp_*`, `auth_*`. Note `program` in particular: it comes off the
syslog wire and *any* process on the firewall can pick its own tag with `logger(1)`,
so it is deliberately kept where it cannot become a label.

### Promoting the `opnsense.*` attributes (optional)

Out of the box they all land in structured metadata, so you filter with `|`:

```logql
{service_name="opnsense2otel"} | opnsense_subsystem="firewall" | action="block"
```

That scans every chunk for the instance. To turn it into a stream selection instead,
promote them on the Loki side. Promotion is a **tenant-side opt-in and costs the
exporter nothing**: it changes nothing about what is shipped, only how Loki indexes
what arrives. Promote none, some or all of them, in any combination.

Self-hosted, put this in the Loki config:

```yaml
limits_config:
  otlp_config:
    resource_attributes:
      # leave ignore_defaults false, or service.name stops being a label too
      attributes_config:
        - action: index_label
          attributes:
            - opnsense.source
            - opnsense.subsystem
            - opnsense.action
            - opnsense.device_category
            - opnsense.interface
```

On **Grafana Cloud** there is no config file, but the same `otlp_config` is settable
per-tenant through the [OTLP config self-serve API][gc-selfserve] - `PUT` the
`resource_attributes` block above to
`/loki/api/v1/config/limits/otlp_config` with your Loki write token. No support ticket.
The change is queued and can take a couple of business days to apply.

Then the same query becomes:

```logql
{service_name="opnsense2otel", opnsense_subsystem="firewall"} | action="block"
```

Cost: bounded, because every one of these is a closed set. The combinations are a
product, but most never occur - a printer does not appear on the WAN, a syslog record
has no device at all - so the real figure is far below the theoretical one: **79
distinct streams** per instance measured over an hour on a live box with all five
promoted. Promoting fewer costs proportionally less: 16 with the original three.

Promotion does **not** reduce ingest cost. Loki bills on volume, and labels only change
what a query has to scan.

A promoted attribute moves out of structured metadata and into the label, so
`| opnsense_subsystem=…` stops matching once `{opnsense_subsystem=…}` starts - switch
your queries when you switch the config. This applies per attribute, so a partial
promotion leaves the rest filterable with `|` exactly as before.

Two different limits get conflated here, and conflating them invents a scarcity that is not
there. `max_label_names_per_series` (default **15**) bounds the label names on a **single
stream** - it is per stream, so another exporter writing to the same tenant does not consume
any of it, because its streams never carry an `opnsense_*` label. The exporter's widest stream
carries seven. Separately, the tenant's promoted-attribute **list** is one shared list, so
adding entries to it is a coordinated change - but adding another exporter's attributes cannot
affect an `opnsense_*` stream. See [OTLP attribute contract](otlp-attribute-contract.md).

Do **not** promote anything else. `src_ip` as a label is one stream per address: the
classic Loki cardinality footgun, and the reason the exporter keeps it out of reach.

[otlp-defaults]: https://grafana.com/docs/loki/latest/send-data/otel/
[gc-selfserve]: https://grafana.com/docs/grafana-cloud/send-data/logs/config-self-serve-api/#otlp-label-mappings

## Delivery semantics

Stated honestly, because this pipeline is pull-based over a lossy source:

- **Within a run: at-least-once.** Each source tracks its own cursor and a dedup
  ring, so rotation overlap does not duplicate and normal operation does not lose.
  The sink exports each batch **synchronously** and reports the real outcome: a record
  is counted `opnsense_exporter_logs_shipped_total` only once the OTLP endpoint has
  acknowledged it, never merely on enqueue. When one resource partition succeeds and a
  sibling fails, the acknowledged partition is removed and only the retryable remainder
  is sent again. Permanent HTTP/gRPC failures and OTLP partial-success rejections are
  terminal: they are counted once under `reason="rejected"` and are not retried.
  Transient failures are **retried in memory** (the records stay queued, never
  re-fetched) until the endpoint recovers or `--logs.ship-max-attempts` is reached, so a
  transient outage is ridden out for as long as the bounded queue behind it holds.
  Every loss path is counted: queue overflow, an oversized input record, a terminal
  destination rejection, exhausted retries, or a batch abandoned during shutdown. Each
  attempt that does not fully deliver is visible as
  `opnsense_exporter_logs_ship_errors_total` - degraded but never silent.
- **Across restarts: at-most-once by default.** Cursors are in memory, so a restart
  resumes from now. The in-memory retry does **not** survive a process restart: records
  polled but not yet delivered when the process exits mid-outage are lost (counted
  `ship_failed` if a graceful shutdown abandons them, unrecoverable on a hard kill).
  Set `--logs.state-file` to persist cursors (atomic JSON, rewritten only when a cursor
  changes) for best-effort resume across restarts.
- **Never exactly-once.**
- **One path per log type:** do not both ship a log type through this pipeline and
  forward the same type via native syslog - that double-ships. Pick one path per
  log type.
- **One logs-enabled instance per firewall:** running multiple logs-enabled
  replicas against the same firewall double-ships.

## Debug capture

When a receiver reports a signal the exporter does not model - a Zenarmor
Elasticsearch endpoint it does not implement, a document whose family or shape it
does not recognise, a syslog line from a program with no parser - that signal is
counted but its payload is not kept. Debug capture is an opt-in escape hatch that
dumps those unmodelled payloads to disk as NDJSON, so you can see the real data and
decide to model it or drop it without a packet capture on a multi-GB/day stream.

It captures **only** signals the exporter does not already handle - never the
parsed, shipped stream:

| Receiver | Captured `kind` | What it is |
| --- | --- | --- |
| `zenarmor` | `unhandled_endpoint` | an ES route the receiver does not implement (method, path, headers, bounded body) |
| `zenarmor` | `unknown_family` | a bulk document addressed to an index whose family is not recognised |
| `zenarmor` | `parse_error` | a document that would not parse (still shipped with its raw body) |
| `syslog` | `unparsed` | a line whose program has no parser, whose parser did not match, or whose envelope would not parse (still shipped as a generic record) |

Enable it with a shared directory plus a per-receiver toggle:

| Flag | Env | Default |
| --- | --- | --- |
| `--logs.debug-capture.dir` | `OPN2OTEL_LOGS_DEBUG_CAPTURE_DIR` | *(empty - off)* |
| `--logs.debug-capture.max-bytes` | `OPN2OTEL_LOGS_DEBUG_CAPTURE_MAX_BYTES` | `256MiB` |
| `--logs.zenarmor.debug-capture` | `OPN2OTEL_LOGS_ZENARMOR_DEBUG_CAPTURE` | `false` |
| `--logs.syslog.debug-capture` | `OPN2OTEL_LOGS_SYSLOG_DEBUG_CAPTURE` | `false` |

A per-receiver toggle with no `--logs.debug-capture.dir` set is a startup error - it
would read as "on" but write nowhere. When Zenarmor capture is on, the receiver's
"unhandled endpoint" warning is suppressed (the capture file carries the same
signal); the `logs_rejected_total{reason="unhandled_endpoint"}` counter still fires,
so the rate is never lost.

Files land as `<dir>/<receiver>/capture-NNN.ndjson`, rotating at 32 MiB. The
`--logs.debug-capture.max-bytes` cap governs the **whole** directory, counting bytes
left by previous runs: when it is reached capture **stops and keeps the oldest
samples** (the first time an unknown appears is the sample worth having) - it never
deletes to make room, so a debug capture can never fill the disk. Capture writes are
best-effort and never block ingest: if the disk cannot keep up, entries are dropped
and counted rather than stalling a receiver.

**The capture files carry real network data** - client addresses, DNS queries, TLS
SNI, HTTP hosts - so they are written `0600` and should be treated as sensitive. They
do **not** carry reusable authentication credentials: `Authorization`,
`Proxy-Authorization`, `Cookie`, `Set-Cookie`, `X-Api-Key` and `X-Auth-Token` header
values are redacted to a fixed placeholder before a captured request ever reaches
disk, whatever receiver or auth scheme captured it. Point the directory at a writable
bind mount and remove the captures once you are done with them. For the containerised
exporter (runs as UID/GID `65532` nonroot):

```yaml
# docker-compose.yml
services:
  opnsense2otel:
    volumes:
      - ./capture:/capture
    environment:
      OPN2OTEL_LOGS_DEBUG_CAPTURE_DIR: /capture
      OPN2OTEL_LOGS_ZENARMOR_DEBUG_CAPTURE: "true"
```

```bash
mkdir -p ./capture && sudo chown 65532:65532 ./capture   # match the nonroot container user
```

Watch capture activity with `logs_debug_captured_total{receiver,kind}` and
`logs_debug_capture_dropped_total{receiver,reason}` (see [Self-metrics](#self-metrics)).

## Configuration

The pipeline flags are listed in the [Configuration reference](configuration.md).
The complete top-level pipeline set is `--logs.enabled`, `--logs.sink`,
`--logs.poll-interval` (floor 5s), `--logs.buffer-size`,
`--logs.buffer-max-bytes`, `--logs.batch-max`, `--logs.max-record-bytes`,
`--logs.max-export-bytes`, `--logs.ship-max-attempts`, `--logs.ship-concurrency`,
`--logs.max-metric-keys`, and `--logs.state-file`.
Per-source `--logs.<source>.enabled` flags are documented alongside each source
above as they land.

### Sink throughput

The OTLP sink ships one **resource partition** per wire request — a partition being
one distinct `(source, subsystem, action, device_category, interface)` tuple in the
batch. That is what makes a partial-success rejection attributable to a single
source, and it is not negotiable. It does mean a batch costs one round-trip per
distinct partition, so throughput is governed by round-trips rather than by record
count:

    records/sec  =  ship-concurrency x (batch-max / partitions per batch) / latency

Two levers follow from that shape, and they multiply:

- `--logs.ship-concurrency` (default 8) exports that many partitions at once instead
  of strictly one after another.
- `--logs.batch-max` (default 5000) amortises the fixed per-partition round-trip.
  Distinct partitions **plateau** with batch duration while records keep growing
  linearly, so a larger batch costs barely more round-trips and carries far more
  records per round-trip.

Raise `--logs.buffer-size` if bursts still outrun the sink; it absorbs a burst but
does nothing for sustained rate. If the queue is *chronically* deep rather than
spiky, the sink rate is the problem, not the buffer.

A batch is bounded by bytes as well as by `--logs.batch-max`, by **two** bounds that
answer different questions. Neither is about memory — the queue's own
`--logs.buffer-max-bytes` covers memory.

The **transport** bound is half the OTLP exporter's serialized-request ceiling. It is
not configurable. It exists because an oversized request is refused by the exporter
*before* it reaches the wire, which yields no delivery outcome to classify, so the
batch would be retried to exhaustion against bytes that can never be accepted. Note
that gzip does not raise that ceiling: it is checked against the uncompressed
protobuf.

The **ingest-rate** bound is `--logs.max-export-bytes` (default 1MiB), and it is the
one that normally binds. A Loki tenant's ingestion limit is a bytes-per-*second*
budget, which the transport ceiling knows nothing about: a 7.5MB push is worth many
seconds of that budget and is rejected atomically however long the exporter waits,
while being comfortably under the 32MiB transport bound. Set it to roughly one second
of the destination's per-tenant bytes/sec budget. `0` falls back to the transport
bound alone.

A single record larger than either bound is still shipped on its own rather than
stalling the queue behind it; `--logs.max-record-bytes` is the bound that rejects
those, at ingest.

### Rate limits, splitting and pacing

An `HTTP 429` or a gRPC `RESOURCE_EXHAUSTED` is classified separately from an ordinary
transient failure, because the correct response is different. A generic 503 means the
endpoint could not take the request *right now*, so resending the same bytes is right.
A rate limit means the request was too much *at once* for a bytes/sec budget, so a
byte-identical resend is guaranteed to fail again.

On a rate limit the emitter therefore **halves** the number of records it puts into
one delivery attempt (floored at 32) and **paces** subsequent attempts by the
advertised `Retry-After` — both the delay-seconds and the HTTP-date form are parsed,
clamped to 30s so a misconfigured header cannot park the emitter — or by a 2s floor
when nothing is advertised. The reduced size is carried forward across batches and
walks back up geometrically once deliveries are clean again, so a sustained burst
above the tenant's limit degrades into steady paced delivery rather than into whole
batches dropped plus collateral queue overflow.

The gRPC path detects the rate limit but does not read an advertised delay
(`google.rpc.RetryInfo` would need a new direct module dependency); the 2s pacing
floor applies there instead.

Worst-case time spent on one undeliverable batch is bounded and accounts for **both**
retry layers — the pipeline's `--logs.ship-max-attempts` and the OTLP exporter's own
in-request retry, which is pinned to a 5s max-elapsed rather than the SDK's default of
one minute so the two compose instead of multiplying:

    t_worst  =  attempts x (sdk_max_elapsed + export_timeout)  +  (attempts - 1) x max_wait
             =  10 x (5s + 10s) + 9 x 30s  =  420s

420s is the pathological case where the destination advertises the maximum
`Retry-After` on every attempt; with none advertised it is 195s. Attempts are counted
across the whole batch rather than per chunk, so splitting never multiplies the bound.

Over HTTP the client's idle-connection pool is sized to the concurrency
automatically. Note that an endpoint which does not negotiate HTTP/2 needs one TCP
connection per concurrent flush — the Grafana Cloud OTLP gateway is HTTP/1.1-only,
so this matters there. The gRPC transport multiplexes every flush over one
connection and is unaffected.

## Self-metrics

The pipeline exposes its own health metrics (visible at `/metrics` and on the
**Log Shipping** dashboard tab). Every series carries the stable
`opnsense_instance` identity label, matching the collector metrics. The remaining
labels are listed exactly below; `source`, `reason`, `stage`, `table`, `receiver`,
`kind`, and `rule` are not substitutes for that box identity.

- `opnsense_exporter_logs_shipped_total{source}` - records the sink confirmed exported
  (an acknowledged OTLP delivery, not merely enqueued).
- `opnsense_exporter_logs_dropped_total{source,reason}` - records dropped before
  delivery. Its closed `reason` values are `overflow` (the count or byte queue bound
  evicted the oldest record), `record_too_large` (rejected at ingest), `rejected`
  (terminal destination refusal), `ship_failed_permanent` (the configured retry bound
  was exhausted), and `ship_failed` (shutdown abandoned the retryable remainder).
- `opnsense_exporter_logs_ship_errors_total` - attempts that did not fully deliver.
  Acknowledged partitions are removed before retry, so this is an attempt counter rather
  than a record-loss counter.
- `opnsense_exporter_logs_poll_errors_total{source}` - source poll failures.
- `opnsense_exporter_logs_last_received_timestamp_seconds{source}` - exporter-clock
  time when this source most recently **admitted** a record to the queue: source-input
  liveness, not an origin event timestamp.
- `opnsense_exporter_logs_last_exported_timestamp_seconds{source}` - exporter-clock
  time when the sink most recently **acknowledged** a record from this source: delivery
  liveness, not queue admission or an origin event timestamp.
- `opnsense_exporter_logs_queue_length` / `opnsense_exporter_logs_queue_capacity` -
  record depth and configured record-count capacity; `opnsense_exporter_logs_queue_bytes`
  / `opnsense_exporter_logs_queue_max_bytes` are retained bytes and the aggregate byte
  budget (a max of 0 disables the byte bound).
- `opnsense_exporter_logs_parse_errors_total{source,stage}` - lines that failed to
  parse. Its closed stages are syslog `envelope` and Zenarmor `bulk` / `document`.
  These are **not** dropped: they ship with their raw body, so this counts fidelity
  lost, not data lost.
- `opnsense_exporter_logs_rejected_total{source,reason}` - receiver input refused
  before shipping. Closed syslog reasons are `peer`, `oversized`, `filtered`,
  `sampled`, `conn_limit`, `tls_timeout`, `tls_auth_failed`, `tls_deadline_error`,
  and `queue_full`;
  closed Zenarmor reasons are `peer`, `auth`, `unhandled_endpoint`, `body`,
  `overloaded`, `index_limit`, `unknown_family`, `filtered`, `self_traffic`, and
  `excluded`.
- `opnsense_exporter_logs_enrich_misses_total{table}` - enrichment lookups that
  missed. A steady rate on `table=rules` means the snapshot is behind the box's
  ruleset.
- `opnsense_exporter_logs_enrich_refresh_errors_total{table}` - failed enrichment
  refreshes. The previous snapshot keeps serving, so records still ship - enriched
  with increasingly stale data.
- `opnsense_exporter_logs_enrich_last_refresh_timestamp_seconds{table}` - when each
  lookup table last refreshed successfully. Alert on
  `time() - ...` to catch a silently-stale cache.
- `opnsense_exporter_logs_enrich_seam_reads_total{endpoint,outcome}` - attempts to
  source an enrichment input from the shared-result seam rather than the OPNsense
  API. A `hit` is a request the firewall never received, because a metrics collector
  had already decoded that endpoint on its own poll; a `miss` means the refresher
  fetched it itself. Expect a hit ratio at or near 1 for every endpoint listed. An
  endpoint sliding toward all-misses means its owning collector is disabled, its poll
  is failing, or its plugin was removed - enrichment is unaffected (it falls back to
  fetching, exactly as it did before the seam existed), but the duplicate requests
  are back.
- `opnsense_exporter_logs_possible_gap_total{source}` - a bounded-window source found
  no continuity with its previous cursor, so an unknown amount may have been skipped.
- `opnsense_exporter_logs_resource_capped_total` - records shipped without their
  `opnsense.*` index labels because the resource-label budget was exceeded; the record
  still arrives, but label-scoped queries under-report.
- `opnsense_exporter_logs_debug_captured_total{receiver,kind}` - unmodelled signals
  written to the debug-capture dir (see [Debug capture](#debug-capture)). Zero unless
  capture is enabled.
- `opnsense_exporter_logs_debug_capture_dropped_total{receiver,reason}` - capture
  entries dropped rather than written: `reason=buffer_full` (disk could not keep up),
  `reason=cap_reached` (`--logs.debug-capture.max-bytes` hit; capture paused),
  `reason=write_error`, `reason=duplicate_shape` (a repeat of a message shape already
  captured this window - see below).
- `opnsense_exporter_logs_zenarmor_excluded_total{rule}` - Zenarmor records dropped
  by each configured exclusion rule; this is docs-only because it is a deliberate
  operator-configured blind spot, not a general pipeline-health panel.
- `opnsense_exporter_logs_zenarmor_bulk_requests_total` /
  `opnsense_exporter_logs_zenarmor_bulk_bytes_total` - accepted Zenarmor `_bulk`
  request count and decompressed request bytes; these are docs-only receiver-volume
  diagnostics.

`opnsense_log_events_observation_dropped_total{reason}` is **not a Log Shipping
pipeline self-metric**. It belongs to the separate Log-derived Events collector's
bounded receiver-to-collector handoff. It is documented in the generated metric reference and
charted in the **Derived Metric Budget** row of the health dashboard's Log Shipping
tab, with the closed reason `handoff_full`. The rest of that collector's counters are
firewall data, so they sit on the operational dashboard beside the subsystem each one
describes (filterlog events on Firewall & PF, tunnel lifecycle on VPN, and so on).

### Why the syslog capture keeps one example per shape

The syslog lane captures any line whose program has no parser, and on a real firewall
that is most lines: one reference box produced 60,073 entries and 31 MB in a day, 70%
of it three repeated shapes (`arpresolve` failures, a chatty cron job, `unbound`
blocklist updates). The byte cap governs the whole directory and **stops** when
reached, so that one lane would fill it and permanently starve the NetFlow and
Zenarmor captures sharing it - and a starved capture looks exactly like a quiet one.

So the syslog lane keeps the **first example of each message shape per 15-minute
window** and counts the rest as `reason=duplicate_shape`. A shape is the message with
its varying parts collapsed, so `arpresolve: ... for 198.51.100.106` and the same line
for another address are one shape. A shape never seen before is always captured
immediately, and the suppressed count is what tells you the difference between a quiet
lane and a busy one - a small capture file no longer means silence.

The NetFlow and Zenarmor lanes are **not** deduplicated. Both are bounded by design -
a couple of datagrams at startup and nothing after - so a window would throw away
samples they need to be complete.

## See also

- [Native Log Export](log-export-native.md) - the syslog-ng/Alloy/NetFlow
  alternative to this pipeline, and the decision matrix for choosing between
  the two paths per log type.
- `opnsense_exporter_logs_possible_gap_total{source}` - possible sampling gaps
  detected by a source whose only view of its data is a bounded window (e.g. the
  unbound source's latest-1000-row DNS query log, see [Sources](#sources) above):
  incremented when a poll's page shows no continuity with the previous cursor,
  meaning an unknown amount of data was skipped between polls.
