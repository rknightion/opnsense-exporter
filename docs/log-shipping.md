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

## Configuration

The pipeline flags are listed in the [Configuration reference](configuration.md);
the pipeline-level flags are `--logs.enabled`, `--logs.sink`,
`--logs.poll-interval` (floor 5s), `--logs.buffer-size`, `--logs.batch-max`, and
`--logs.state-file`. Per-source `--logs.<source>.enabled` flags are documented
alongside each source as it lands.

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
