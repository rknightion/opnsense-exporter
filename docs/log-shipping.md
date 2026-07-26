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
[`internal/logship/` on GitHub](https://github.com/rknightion/opnsense-exporter/tree/main/internal/logship);
parsers live one file per program, so
[adding a parser](https://github.com/rknightion/opnsense-exporter/tree/main/internal/logship) is a
self-contained contribution.

!!! note "Sources are added incrementally"
    Enabling `--logs.enabled` starts the pipeline, but nothing is shipped until at
    least one **source** is also enabled (each source has its own
    `--logs.<source>.enabled` flag). With the pipeline enabled and no source
    enabled, the exporter logs a warning and ships nothing.

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
  `{service_name="opnsense-exporter"} | opnsense_source="ids" | json | event="gap_detected"`).
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

Loki structured metadata for this source: `client`, `domain`, `qtype`,
`action`, `query_source`, `rcode`, `blocklist`, `dnssec_status`. (Unbound's own
`source` field - where the answer came from - is deliberately mapped to the
`query_source` attribute rather than a bare `source`, to keep it clear of this
pipeline's own `opnsense.source` stamp; see [Loki label model](#loki-label-model).) The
log body is a compact JSON encoding of the full row, including fields not
promoted to structured metadata (`family`, `resolve_time_ms`, `ttl`, `policy`).

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
| `opnsense.source` | `syslog`, `unbound`, `ids`, `crowdsec`, `zenarmor` | no - opt in below |
| `opnsense.subsystem` | `firewall`, `dns`, `auth`, `dhcp`, `vpn`, … (~22) | no - opt in below |
| `opnsense.action` | `pass`, `block` | no - opt in below |

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

### Promoting `opnsense.source` and `opnsense.subsystem` (optional)

Out of the box both land in structured metadata, so you filter with `|`:

```logql
{service_name="opnsense-exporter"} | opnsense_subsystem="firewall" | action="block"
```

That scans every chunk for the instance. To turn it into a stream selection instead,
promote the two on the Loki side. Self-hosted, put this in the Loki config:

```yaml
limits_config:
  otlp_config:
    resource_attributes:
      # leave ignore_defaults false, or service.name stops being a label too
      attributes_config:
        - action: index_label
          attributes: [opnsense.subsystem, opnsense.source]
```

On **Grafana Cloud** there is no config file, but the same `otlp_config` is settable
per-tenant through the [OTLP config self-serve API][gc-selfserve] - `PUT` the
`resource_attributes` block above to
`/loki/api/v1/config/limits/otlp_config` with your Loki write token. No support ticket.
The change is queued and can take a couple of business days to apply.

Then the same query becomes:

```logql
{service_name="opnsense-exporter", opnsense_subsystem="firewall"} | action="block"
```

Cost: at most `sources × subsystems` ≈ **26 streams** per instance, because both are
closed sets defined in the exporter's own code. A promoted attribute moves out of
structured metadata and into the label, so `| opnsense_subsystem=…` stops matching once
`{opnsense_subsystem=…}` starts - switch your queries when you switch the config.

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
| `--logs.debug-capture.dir` | `OPNSENSE_EXPORTER_LOGS_DEBUG_CAPTURE_DIR` | *(empty - off)* |
| `--logs.debug-capture.max-bytes` | `OPNSENSE_EXPORTER_LOGS_DEBUG_CAPTURE_MAX_BYTES` | `256MiB` |
| `--logs.zenarmor.debug-capture` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_DEBUG_CAPTURE` | `false` |
| `--logs.syslog.debug-capture` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_DEBUG_CAPTURE` | `false` |

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
SNI, HTTP hosts - so they are written `0600` and should be treated as sensitive.
Point the directory at a writable bind mount and remove the captures once you are
done with them. For the containerised exporter (runs as UID/GID `65532` nonroot):

```yaml
# docker-compose.yml
services:
  opnsense-exporter:
    volumes:
      - ./capture:/capture
    environment:
      OPNSENSE_EXPORTER_LOGS_DEBUG_CAPTURE_DIR: /capture
      OPNSENSE_EXPORTER_LOGS_ZENARMOR_DEBUG_CAPTURE: "true"
```

```bash
mkdir -p ./capture && sudo chown 65532:65532 ./capture   # match the nonroot container user
```

Watch capture activity with `logs_debug_captured_total{receiver,kind}` and
`logs_debug_capture_dropped_total{receiver,reason}` (see [Self-metrics](#self-metrics)).

## Configuration

The pipeline flags are listed in the [Configuration reference](configuration.md);
the pipeline-level flags are `--logs.enabled`, `--logs.sink`,
`--logs.poll-interval` (floor 5s), `--logs.buffer-size`, `--logs.batch-max`, and
`--logs.state-file`. Per-source `--logs.<source>.enabled` flags are documented
alongside each source above as it lands.

## Self-metrics

The pipeline exposes its own health metrics (visible at `/metrics` and on the
**Log Shipping** dashboard tab). Every series also carries
`opnsense_instance`, matching the collector metrics:

- `opnsense_exporter_logs_shipped_total{source}` - records the sink confirmed exported
  (an acknowledged OTLP delivery, not merely enqueued).
- `opnsense_exporter_logs_dropped_total{source,reason}` - records dropped before
  delivery (`reason=overflow` = queue full; `reason=record_too_large` = rejected at
  ingest; `reason=rejected` = terminal destination refusal;
  `reason=ship_failed_permanent` = bounded retries exhausted; `reason=ship_failed` =
  shutdown abandoned the retryable remainder).
- `opnsense_exporter_logs_ship_errors_total` - attempts that did not fully deliver.
  Acknowledged partitions are removed before retry, so this is an attempt counter rather
  than a record-loss counter.
- `opnsense_exporter_logs_poll_errors_total{source}` - source poll failures.
- `opnsense_exporter_logs_last_received_timestamp_seconds{source}` - exporter-clock
  time when this source most recently admitted a record to the queue.
- `opnsense_exporter_logs_last_exported_timestamp_seconds{source}` - exporter-clock
  time when the sink most recently acknowledged a record from this source.
- `opnsense_exporter_logs_queue_length` / `opnsense_exporter_logs_queue_capacity` -
  backpressure queue depth and capacity.
- `opnsense_exporter_logs_parse_errors_total{stage}` - lines that failed to parse
  (`stage=envelope` or `stage=filterlog`). These are **not** dropped: they ship with
  their raw body, so this counts fidelity lost, not data lost.
- `opnsense_exporter_logs_rejected_total{reason}` - syslog input refused before
  parsing (`reason=peer` for a sender outside `--logs.syslog.allowed-peers`,
  `reason=oversized` for a frame beyond the 64KB cap).
- `opnsense_exporter_logs_enrich_misses_total{table}` - enrichment lookups that
  missed. A steady rate on `table=rules` means the snapshot is behind the box's
  ruleset.
- `opnsense_exporter_logs_enrich_refresh_errors_total{table}` - failed enrichment
  refreshes. The previous snapshot keeps serving, so records still ship - enriched
  with increasingly stale data.
- `opnsense_exporter_logs_enrich_last_refresh_timestamp_seconds{table}` - when each
  lookup table last refreshed successfully. Alert on
  `time() - ...` to catch a silently-stale cache.
- `opnsense_exporter_logs_debug_captured_total{receiver,kind}` - unmodelled signals
  written to the debug-capture dir (see [Debug capture](#debug-capture)). Zero unless
  capture is enabled.
- `opnsense_exporter_logs_debug_capture_dropped_total{receiver,reason}` - capture
  entries dropped rather than written: `reason=buffer_full` (disk could not keep up),
  `reason=cap_reached` (`--logs.debug-capture.max-bytes` hit; capture paused),
  `reason=write_error`, `reason=duplicate_shape` (a repeat of a message shape already
  captured this window - see below).

### Why the syslog capture keeps one example per shape

The syslog lane captures any line whose program has no parser, and on a real firewall
that is most lines: one reference box produced 60,073 entries and 31 MB in a day, 70%
of it three repeated shapes (`arpresolve` failures, a chatty cron job, `unbound`
blocklist updates). The byte cap governs the whole directory and **stops** when
reached, so that one lane would fill it and permanently starve the NetFlow and
Zenarmor captures sharing it - and a starved capture looks exactly like a quiet one.

So the syslog lane keeps the **first example of each message shape per 15-minute
window** and counts the rest as `reason=duplicate_shape`. A shape is the message with
its varying parts collapsed, so `arpresolve: ... for 86.31.203.106` and the same line
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
