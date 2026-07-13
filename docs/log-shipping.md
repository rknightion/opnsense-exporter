# Log shipping

The exporter can ship structured OPNsense **events** (firewall log lines, IDS
alerts, audit entries, and similar) to Loki, separately from the metrics it
exposes at `/metrics`. This is opt-in and off by default: it runs only when
`--logs.enabled` is set.

Log shipping is a long-lived background pipeline, not a scrape-time collector.
Registered sources poll OPNsense event APIs on their own cadence, records pass
through a bounded in-memory queue, and an emitter ships batches to the configured
sink. It is fully independent of OTLP metrics export (`--otlp.enabled`): metrics
and logs are gated by separate flags and neither turns the other on.

High-cardinality event data (IP addresses, ports, Suricata SIDs, domains) is
shipped as log **body** and Loki **structured metadata** — never as a metric and
never as a Loki label. The only labels are the resource identity plus a promotable
`source` attribute (see [Loki label model](#loki-label-model)).

!!! note "Sources are added incrementally"
    Enabling `--logs.enabled` starts the pipeline, but nothing is shipped until at
    least one **source** is also enabled (each source has its own
    `--logs.<source>.enabled` flag). With the pipeline enabled and no source
    enabled, the exporter logs a warning and ships nothing.

## Sinks

Select the sink with `--logs.sink`:

- **`otlp`** (default) — ships over OTLP logs. One sink covers both the Grafana
  Cloud OTLP gateway (which routes `/v1/logs` to Loki) and a self-hosted Loki 3.x
  native OTLP endpoint. It reuses the exporter's existing `--otlp.*` transport
  family (endpoint, protocol, headers, TLS/mTLS, and the Grafana Cloud shortcut),
  so no separate endpoint configuration is needed. Because the transport is shared
  but the gates are separate, the `--otlp.*` flags configure the logs endpoint
  even when `--otlp.enabled` (metrics export) is off.
- **`stdout`** — writes one compact JSON line per event to standard output. This is
  the zero-dependency path for container/Kubernetes setups where a node log
  collector already ships stdout.

When `--logs.sink=otlp` and no OTLP endpoint is resolvable (no `--otlp.endpoint`,
no Grafana Cloud endpoint, and no `OTEL_EXPORTER_OTLP_ENDPOINT` /
`OTEL_EXPORTER_OTLP_LOGS_ENDPOINT` environment variable), startup fails with an
error naming the missing flag rather than silently shipping nothing.

## Sources

### Firewall (`--logs.firewall.enabled`)

Ships parsed firewall filter-log events. Off by default; requires `--logs.enabled`.

It polls `api/diagnostics/firewall/log`, the paged endpoint that returns each
filterlog record already parsed into fields (`action`, `interface`, `dir`,
`proto`, `src`/`dst`, ports, `rulenr`, `rid`) plus an **`__digest__`** (an md5 of
the raw line) and a **`label`** — the human rule description the box resolves from
the rule id against `/tmp/rules.debug`. That label is the reason to poll this API
rather than tail native filterlog syslog: syslog ships a headerless CSV carrying
only the rule md5, so the description is unavailable there.

**Cursor.** Each poll passes the last-seen `__digest__` back as `?digest=`; the
backend reverse-reads the rotation-aware logs and returns every newer row plus
the cursor row itself, which the exporter drops. Tailing is lossless unless more
than the row cap (1000) of events arrive between polls. On a fresh start with no
`--logs.state-file`, the source primes its cursor at the newest row and ships
nothing (resume-from-now — it does not dump the box's backlog); set
`--logs.state-file` to persist the digest and resume across restarts. If the
cursor has rotated out of the window, the source resumes from the newest row and
logs a warning — bounded, visible loss, never silent. The source polls no faster
than every 10s regardless of `--logs.poll-interval`, since each poll spawns
configd and re-parses the rules on the box.

**Loki mapping.** Body is a compact JSON encoding of the parsed event (the API
does not return the original raw line). IPs, ports, rule ids and the rule label
travel as structured metadata, never as labels.

**Volume guidance.** This path targets **homelab/SMB** event rates. A box logging
pass rules at hundreds to thousands of events per second (common on enterprise
edges) will overwhelm API polling — use native filterlog syslog into an Alloy
pipeline for that class instead. Do not run both paths for the firewall log at
once: that double-ships (see [Delivery semantics](#delivery-semantics)).

**Caveats.**

- The filter log records the **first packet of a flow only** — it is an event
  stream, not flow accounting. Do not read event counts as byte/connection totals.
- qfeeds' `search_events` is a filtered, ~300s-stale subset of this same feed;
  qfeeds blocks already appear here natively with their rule label.

### IDS (Suricata EVE alerts)

`--logs.ids.enabled` (off by default; requires `--logs.enabled`) ships full
Suricata EVE **alert** records — not just the aggregate counts the IDS metrics
collector exposes (`opnsense_ids_recent_alerts`, gated separately by
`--exporter.enable-ids-alerts`). It polls `POST api/ids/service/query_alerts`,
the same endpoint the metrics collector's opt-in alert-activity series already
uses, reading up to the newest 500 eve rows per poll (the same cap the metrics
collector's alert count is a floor against).

- **Body** is the compact JSON of the complete raw eve alert record exactly as
  Suricata wrote it — every field it emits, not a reconstructed subset. This
  includes fields the exporter never parses into typed metadata (the nested
  `flow` object, `app_proto`, `event_type`, `filepos`/`fileid`, …).
- **Structured metadata** (never a label): `alert_sid`, `alert_action`,
  `src_ip`, `dest_ip`, `in_iface`, `proto`, `signature`.
- **Severity** is `warn` for a `blocked` alert, `info` otherwise.
- **Cursor**: the record's own `timestamp` is the true cursor, with a
  `flow_id`+`alert_sid` dedupe ring scoped to records sharing the cursor's
  exact timestamp. `filepos`/`fileid` are never used to cursor — log rotation
  shifts `fileid`s, so they are fragile across restarts.
- **Gap accounting**: `query_alerts` is a windowed, saturating read. If a poll
  returns a full 500-row window whose oldest row is still newer than the prior
  cursor, the read could not reach back far enough to cover everything since
  the last poll — some alerts in that range were never observed. This is
  accepted, bounded loss: the source ships one synthetic gap record
  (`event=gap_detected` structured metadata, `warn` severity, a JSON body
  naming the gap bounds) instead of silently dropping it, so the loss is
  visible and queryable in Loki (e.g. `{source="ids"} | json | event="gap_detected"`).
- **First poll**: with no prior cursor (fresh start, or `--logs.state-file` not
  set/empty/corrupt), the whole initial window ships as a startup catch-up
  rather than being silently skipped or treated as a gap.

!!! note "Prefer native `syslog_eve` where it fits"
    OPNsense's IDS settings also offer `syslog_eve` (ships the identical EVE
    JSON via syslog — alerts only, with metadata and a community id) and
    `syslog` (fastlog lines). If the box already forwards EVE JSON via
    `syslog_eve` to your log pipeline, enable that instead of this source —
    running both double-ships the same alerts. `syslog_eve` shares the
    `suricata`/`local5` facility with engine logs, so a demux step is needed on
    that path (not a concern for the API-polling source documented here).

### CrowdSec (`--logs.crowdsec.enabled`)

Ships CrowdSec **alert** and **decision** records. There is no native syslog
path for these — the plugin registers no syslog scope, so alerts and
decisions live only in the local API (LAPI). Off by default; enable with
`--logs.crowdsec.enabled` (requires `--logs.enabled`). Silent when the
os-crowdsec plugin is absent. Polls at a 60s floor regardless of
`--logs.poll-interval` — each poll is a full `cscli` alerts/decisions dump
(one configd exec each), so polling faster buys nothing at homelab/SMB event
volumes.

- **Cursor.** Alert ids and decision ids are each a separate, server-side
  monotonic counter. The source tracks the highest id shipped per record kind
  and ships only rows whose id is greater on the next poll — a plain id-diff,
  no timestamp windowing. On a cold start every currently-active alert/decision
  is shipped once, so enabling the source surfaces current state instead of
  silently starting from a blank slate.
- **Body.** Compact JSON of the alert or decision (`kind`, `id`, `scope_value`,
  `scenario`, plus alert-only `decisions`/`created` or decision-only
  `alert_id`/`action`/`expiration`/`events_count`).
- **Attributes** (structured metadata, never labels): `scenario`, `value`
  (the scope:ip the alert/decision concerns — high cardinality, so metadata
  only, never a label), `country`, `as` (both often empty without a GeoIP
  database configured), plus `decisions` (alerts: a `type:count` summary, e.g.
  `ban:1`) or `decision_type` and `duration` (decisions: the CrowdSec action
  and the remaining-duration string, e.g. `693h46m29s`).
- **Timestamps.** Alerts carry an RFC3339 `created` field, used as the
  record's timestamp. Decisions carry no absolute timestamp (only a
  remaining-duration string), so the record is stamped at emit time.

### Unbound (per-query DNS log)

`--logs.unbound.enabled` (default `false`) ships a pi-hole-style per-query DNS
log: domain, client, action (`Pass`/`Block`/`Drop`), resolution source
(`Recursion`/`Local`/`Local-data`/`Cache`), blocklist/policy enrichment and
DNSSEC status per query — data unavailable anywhere else in OPNsense's API
(syslog only carries raw unbound daemon lines). It requires Unbound
reporting/statistics to be enabled on the firewall, and raises the poll floor
to 15s (`IntervalSource`) because each poll spawns python+pandas+DuckDB on the
box (~1s CPU).

**Accepted sampling loss — read this before enabling on a busy resolver.**
Unbound's query-log backend (`api/unbound/overview/search_queries`) has no true
cursor: without a per-client filter it only ever returns the newest **1000
rows across the whole resolver**, newest first. This source reconstructs a
best-effort cursor from each row's `time` (unix seconds) plus a dedup
fingerprint for rows sharing the same second — the `uuid` field is part of the
documented schema but has been observed to always be `null` in practice, so it
is used only when present. On a resolver sustaining more than roughly 1000
queries between two polls, the oldest rows in the next page will all be newer
than the previous cursor — a full discontinuity — meaning some number of
queries fell out of the window before this exporter ever fetched them. That
loss is never silent: it is counted via
`opnsense_exporter_logs_possible_gap_total{source="unbound"}` (see
[Self-metrics](#self-metrics)) every time it is detected. Homelab/SMB query
volumes (a handful to ~100 qps) are fine; a busy enterprise resolver should not
enable this source.

Loki structured metadata for this source: `client`, `domain`, `qtype`,
`action`, `query_source`, `rcode`, `blocklist`, `dnssec_status`. (Unbound's own
`source` field — where the answer came from — is deliberately mapped to the
`query_source` attribute rather than `source`, which is reserved for this
pipeline's own `source` stamp; see [Loki label model](#loki-label-model).) The
log body is a compact JSON encoding of the full row, including fields not
promoted to structured metadata (`family`, `resolve_time_ms`, `ttl`, `policy`).

## Loki label model

Cardinality discipline is enforced by construction:

- **Labels** (resource identity): `service.name` (from `--otlp.service-name`) and
  `service.instance.id` (the resolved instance label). No host or SDK detectors are
  attached to the resource, so nothing else can leak into the label set.
- **`source`** (`firewall`, `ids`, `audit`, …): shipped as an OTLP attribute, so it
  lands as Loki structured metadata by default. It can be promoted to a label
  through Grafana Cloud / Loki OTLP config if you want to filter on it.
- **Everything else** — IPs, ports, SIDs, domains, rule ids — is structured
  metadata or body. It is never a label.

## Delivery semantics

Stated honestly, because this pipeline is pull-based over a lossy source:

- **Within a run: at-least-once.** Each source tracks its own cursor and a dedup
  ring, so rotation overlap does not duplicate and normal operation does not lose.
  Under sustained backpressure the bounded queue drops the **oldest** record and
  counts it (`opnsense_exporter_logs_dropped_total{reason="overflow"}`) — degraded
  but visible, never silent.
- **Across restarts: at-most-once by default.** Cursors are in memory, so a restart
  resumes from now. Set `--logs.state-file` to persist cursors (atomic JSON,
  rewritten only when a cursor changes) for best-effort resume across restarts.
- **Never exactly-once.**
- **One path per log type.** Do not both ship a log type through this pipeline and
  forward the same type via native syslog — that double-ships. Pick one path per
  log type.
- **One logs-enabled instance per firewall.** Running multiple logs-enabled
  replicas against the same firewall double-ships.

## Sources

### diaglog — the generic diagnostics-log reader

`diaglog` is one Source that polls `api/diagnostics/log/<module>/<scope>` for
every module/scope pair listed in `--logs.scopes`, and multiplexes them all
through a single poller — there is one `source="diaglog"` label/state-file
entry covering every configured scope, not one per scope. This is OPNsense's
generic event backbone: config-change audit entries, dpinger gateway/latency
alarms, CARP and other kernel events, captive-portal connect/disconnect, and
DHCP lease events (`DHCPACK`/`DHCPREQUEST`/…) are all served through this one
reader by selecting the right scope, rather than needing a dedicated API per
event type (mostly there isn't one — see the caveat below).

Enable/disable independently of the scope list with `--logs.diaglog.enabled`
(default `true`). The default `--logs.scopes` covers five high-signal core
scopes:

| module/scope | what it carries |
|---|---|
| `core/audit` | Config-change trail (`Config::auditLogChange()`), API/GUI action log, login success/failure, sudo/sshd |
| `core/gateways` | dpinger latency alarms and gateway up/down state transitions (no dedicated event API exists for these) |
| `core/portalauth` | Captive-portal connect/disconnect |
| `core/system` | Kernel messages, including CARP MASTER/BACKUP transitions |
| `core/configd` | configd service-lifecycle events |

Other scopes exist (`core/system` also covers general kernel noise; DHCP scopes
are `core/dhcpd` for the legacy ISC server, `core/kea` and `core/dnsmasq` for
those backends; plugin-provided scopes like `haproxy`/`suricata`/`ipsec` follow
the same `api/diagnostics/log/<module>/<scope>` shape) — add any of them to
`--logs.scopes` as `module/scope` pairs, comma-separated
(`core/audit,core/gateways,core/portalauth,core/system,core/configd,core/kea`).
Only `core/audit`, `core/gateways`, `core/portalauth`, `core/system`, and
`core/configd` are exercised by the daily live-canary; a scope you add yourself
is not schema-validated against a live box.

**Cursor mechanics.** OPNsense's search endpoint pages backwards from newest to
oldest and accepts a `validFrom` epoch-seconds bound: the server stops scanning
the instant it passes a record older than `validFrom`, so the bound is
**inclusive** — the record exactly at `validFrom` is returned again on the next
poll. `diaglog` tracks one cursor per scope, dedupes that repeated boundary
record client-side, and persists cursors (with `--logs.state-file` set) as
`module/scope -> last-seen epoch`. A scope with no prior cursor (first run, or
a scope newly added to `--logs.scopes`) bootstraps to "now" rather than
replaying the box's full retained log for that scope — consistent with the
pipeline's own "restart resumes from now" default — so nothing is shipped for
that scope until the following poll.

**Known limitation — timestamp timezone.** The rows this endpoint returns
carry a naive wall-clock timestamp with no UTC offset
(`"2026-07-13T20:22:11"`), and OPNsense's own backend interprets `validFrom`
the same naive way, in the box's **local system timezone**. `diaglog` reads
this timestamp as UTC, matching how this exporter already treats every other
naive OPNsense timestamp. If the box's system clock is not UTC, the computed
cursor is off by the box's UTC offset — harmless (just a wider rescan) when the
box is behind UTC, but capable of skipping up to that many seconds of events
immediately after a cursor advance when the box is ahead of UTC. Run the box on
UTC to avoid this entirely; see
[issue #230](https://github.com/rknightion/opnsense-exporter/issues/230) for
the tracking discussion if you need proper timezone-aware correction.

**Never the `/live` variant.** OPNsense also exposes
`api/diagnostics/log/<module>/<scope>/live`, an SSE stream. It tails the
scope's active log file with `tail -f` (not `-F`), so it silently stops
receiving new lines the moment that file rotates — keepalive frames keep
flowing, but no more events do. `diaglog` only ever uses the paged `validFrom`
search action, never `/live`.

**Attributes.** Every record carries `module`, `scope`, `process_name`, `pid`,
and `facility`. `core/audit` config-change lines are additionally parsed into
`config_user`, `config_revision`, and `config_uri`.

## Configuration

The pipeline flags are listed in the [Configuration reference](configuration.md);
the pipeline-level flags are `--logs.enabled`, `--logs.sink`,
`--logs.poll-interval` (floor 5s), `--logs.buffer-size`, `--logs.batch-max`, and
`--logs.state-file`. Per-source `--logs.<source>.enabled` flags are documented
alongside each source above as it lands.

## Self-metrics

The pipeline exposes its own health metrics (visible at `/metrics` and on the
**Log Shipping** dashboard tab):

- `opnsense_exporter_logs_shipped_total{source}` — records handed to the sink.
- `opnsense_exporter_logs_dropped_total{source,reason}` — records dropped before
  delivery (`reason=overflow` = queue full).
- `opnsense_exporter_logs_ship_errors_total` — failed sink emits (batch dropped).
- `opnsense_exporter_logs_poll_errors_total{source}` — source poll failures.
- `opnsense_exporter_logs_last_event_timestamp_seconds{source}` — timestamp of the
  most recent shipped event (cursor lag).
- `opnsense_exporter_logs_queue_length` / `opnsense_exporter_logs_queue_capacity` —
  backpressure queue depth and capacity.

## See also

- [Native Log Export](log-export-native.md) — the syslog-ng/Alloy/NetFlow
  alternative to this pipeline, and the decision matrix for choosing between
  the two paths per log type.
- `opnsense_exporter_logs_possible_gap_total{source}` — possible sampling gaps
  detected by a source whose only view of its data is a bounded window (e.g. the
  unbound source's latest-1000-row DNS query log, see [Sources](#sources) above):
  incremented when a poll's page shows no continuity with the previous cursor,
  meaning an unknown amount of data was skipped between polls.
