---
title: Configuration
description: Complete reference for all OPNsense Exporter CLI flags, environment variables, and collector switches
tags:
  - Configuration
---

# Configuration

The OPNsense Exporter follows standard Prometheus ecosystem conventions. It can be configured using command-line flags, environment variables, or a combination of both. Environment variables take the prefix `OPNSENSE_EXPORTER_` unless noted otherwise.

The flag tables on this page are generated from the exporter's own flag definitions by `make docs`, so they always match the binary.

## OPNsense connection

These settings control how the exporter connects to the OPNsense API.

<!-- docgen:begin:flags-connection -->
| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--opnsense.address` | `OPNSENSE_EXPORTER_OPS_API` | -- | **Required.** Hostname or IP address of OPNsense API |
| `--opnsense.api-key` | `OPNSENSE_EXPORTER_OPS_API_KEY` | -- | API key to use to connect to OPNsense API. This flag/ENV or the OPS_API_KEY_FILE may be set. |
| `--opnsense.api-secret` | `OPNSENSE_EXPORTER_OPS_API_SECRET` | -- | API secret to use to connect to OPNsense API. This flag/ENV or the OPS_API_SECRET_FILE may be set. |
| `--opnsense.insecure` | `OPNSENSE_EXPORTER_OPS_INSECURE` | `false` | Disable TLS certificate verification |
| `--opnsense.max-retries` | `OPNSENSE_EXPORTER_OPS_MAX_RETRIES` | `3` | Number of attempts for a failed OPNsense API request (transport errors / retryable 5xx). Worst-case block time is --opnsense.timeout x this value. |
| `--opnsense.protocol` | `OPNSENSE_EXPORTER_OPS_PROTOCOL` | -- | **Required.** Protocol to use to connect to OPNsense API. One of: [http, https] |
| `--opnsense.timeout` | `OPNSENSE_EXPORTER_OPS_TIMEOUT` | `15s` | Per-request HTTP timeout for calls to the OPNsense API. Combined with --opnsense.max-retries this bounds the worst-case time a collector blocks on a slow endpoint (timeout x retries). Keep the product comfortably under Prometheus' scrape_timeout. |
<!-- docgen:end:flags-connection -->

!!! note
    `--opnsense.api-key` / `--opnsense.api-secret` are not marked required because the
    file-based secrets below are an alternative source — but one of the two must be set
    for each credential. See [Security: File-based secrets](security.md#file-based-secrets).

### File-based secrets

For secure credential management in containers and orchestrated environments, credentials can be read from files:

| Env Var | Description |
|---------|-------------|
| `OPS_API_KEY_FILE` | Path to a file containing the API key (first line is read) |
| `OPS_API_SECRET_FILE` | Path to a file containing the API secret (first line is read) |

!!! note
    These environment variables do **not** use the `OPNSENSE_EXPORTER_` prefix. They are checked first -- if a file-based secret is set and non-empty, it takes precedence over the flag/env var value.

## Exporter settings

<!-- docgen:begin:flags-exporter -->
| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--exporter.cache-ttl` | `OPNSENSE_EXPORTER_CACHE_TTL` | `1h` | How long to cache responses from slow-moving API endpoints (system/CPU identity, certificate inventory, Unbound DNS blocklist policy config) and to remember that a plugin-gated endpoint is absent (its 404). This data changes only on an admin action — a config edit, a certificate renewal, a plugin install — so re-fetching it every scrape only costs firewall CPU. The cost is staleness: a newly installed plugin, or a cert change, can take up to this long to show up. Set to 0 to fetch everything on every scrape. Live data (counters, rates, service run-state) is never cached regardless of this setting. |
| `--exporter.firmware-cache-ttl` | `OPNSENSE_EXPORTER_FIRMWARE_CACHE_TTL` | `12h` | How long to cache firmware API responses (status and, when enabled, package details). The firmware data OPNsense serves is the stored result of the box's own update check, which it refreshes roughly daily, so re-fetching it every scrape only costs firewall CPU. Set to 0 to fetch on every scrape. |
| `--exporter.ids-alert-lookback` | `OPNSENSE_EXPORTER_IDS_ALERT_LOOKBACK` | `15m` | Lookback window over which opnsense_ids_recent_alerts counts Suricata eve alerts (a gauge). Only used when --exporter.enable-ids-alerts is set. Counts are a floor when more than 500 alerts fall inside the window. |
| `--exporter.instance-label` | `OPNSENSE_EXPORTER_INSTANCE_LABEL` | -- | Label to use to identify the instance in every metric. If you have multiple instances of the exporter, you can differentiate them by using different value in this flag, that represents the instance of the target OPNsense. If left empty, it defaults to the configured OPNsense address (deterministic). Set --exporter.instance-use-hostname to derive it from the OPNsense hostname instead. |
| `--exporter.instance-use-hostname` | `OPNSENSE_EXPORTER_INSTANCE_USE_HOSTNAME` | `false` | When --exporter.instance-label is empty, derive the instance label from the OPNsense hostname reported by the API instead of the configured address. This lookup is deterministic: it blocks at startup and, if the hostname cannot be obtained, the exporter refuses to start (rather than silently falling back to the address, which would make the label depend on startup timing and flip between restarts). |
| `--exporter.max-scrape-duration` | `OPNSENSE_EXPORTER_MAX_SCRAPE_DURATION` | `50s` | Upper bound on a single collection when the caller supplies no deadline of its own (a header-less /metrics scrape or the OTLP-bridge periodic gather). Prevents a stalled/blackholed firewall from holding the shared collector lock unbounded and blacking out every concurrent deadline-bound scrape. |
| `--exporter.scrape-timeout-offset` | `OPNSENSE_EXPORTER_SCRAPE_TIMEOUT_OFFSET` | `500ms` | Duration subtracted from Prometheus' X-Prometheus-Scrape-Timeout-Seconds header when deriving the scrape deadline, so the exporter finishes and responds before Prometheus gives up. If the offset would consume the whole budget, the raw header timeout is used. |
| `--log.format` | -- | `logfmt` | Output format of log messages. One of: [logfmt, json] |
| `--log.level` | -- | `info` | Only log messages with the given severity or above. One of: [debug, info, warn, error] |
| `--logs.batch-max` | `OPNSENSE_EXPORTER_LOGS_BATCH_MAX` | `1000` | Maximum number of records the emitter hands to the sink per batch. |
| `--logs.buffer-size` | `OPNSENSE_EXPORTER_LOGS_BUFFER_SIZE` | `4096` | Capacity of the in-memory backpressure queue between pollers and the sink. On overflow the oldest record is dropped and counted (logs_dropped_total). |
| `--logs.crowdsec.enabled` | `OPNSENSE_EXPORTER_LOGS_CROWDSEC_ENABLED` | `false` | Enable the crowdsec log source: ships CrowdSec alert and decision records to Loki (there is no native syslog path for these — the plugin registers no syslog scope; alerts live only in the LAPI). Requires --logs.enabled. Polls at a 60s floor regardless of --logs.poll-interval. Silent when the os-crowdsec plugin is absent. Off by default. |
| `--logs.enabled` | `OPNSENSE_EXPORTER_LOGS_ENABLED` | `false` | Enable the opt-in log/event shipping pipeline (polls OPNsense event APIs and ships to Loki via OTLP). Off by default. Independent of --otlp.enabled (which gates metrics). |
| `--logs.ids.enabled` | `OPNSENSE_EXPORTER_LOGS_IDS_ENABLED` | `false` | Enable the IDS (Suricata EVE alert) log source: ships full Suricata alert records polled via ids/service/query_alerts. Off by default. Requires --logs.enabled. If the box already forwards EVE JSON via syslog (ids.general.syslog_eve), prefer that native path instead of also enabling this source — do not ship the same alerts twice. |
| `--logs.poll-interval` | `OPNSENSE_EXPORTER_LOGS_POLL_INTERVAL` | `10s` | Base interval between event polls per source (floor 5s). Sources may raise their own floor. |
| `--logs.sink` | `OPNSENSE_EXPORTER_LOGS_SINK` | `otlp` | Log shipping sink: otlp (OTLP logs, reuses the --otlp.* transport) or stdout (one JSON line per event). |
| `--logs.state-file` | `OPNSENSE_EXPORTER_LOGS_STATE_FILE` | -- | Optional path to persist per-source cursors across restarts (atomic JSON). Empty = in-memory only (resume from now on restart). |
| `--logs.syslog.allowed-peers` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_ALLOWED_PEERS` | -- | Comma-separated CIDR allowlist of hosts permitted to send syslog (e.g. 10.0.0.254/32). Empty accepts any sender. Syslog is unauthenticated, so set this on a shared network. |
| `--logs.syslog.enabled` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_ENABLED` | `false` | Enable the syslog receiver: listens for logs pushed by OPNsense (RFC5424 or RFC3164, UDP and/or TCP) and ships them enriched with rule descriptions, interface names and hostnames. Off by default. Requires --logs.enabled. Configure a matching target on the firewall under System > Settings > Logging > Targets. |
| `--logs.syslog.enrich` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_ENRICH` | `true` | Enrich received syslog records from the OPNsense API: firewall rule descriptions (including auto-generated system rules), friendly interface names, DHCP hostnames, MAC addresses, local/remote scope and well-known service names. |
| `--logs.syslog.listen-tcp` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_LISTEN_TCP` | `:5514` | TCP listen address for the syslog receiver. Empty disables the TCP listener. Prefer TCP for firewall logs: UDP datagram loss is silent and unrecoverable. |
| `--logs.syslog.listen-udp` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_LISTEN_UDP` | `:5514` | UDP listen address for the syslog receiver. Empty disables the UDP listener. Port 5514 (not 514) because 514 is privileged and the container runs non-root. |
| `--logs.syslog.max-conns` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_MAX_CONNS` | `64` | Maximum concurrent TCP connections to the syslog receiver. Bounds goroutine growth on an unauthenticated ingress. |
| `--logs.unbound.enabled` | `OPNSENSE_EXPORTER_LOGS_UNBOUND_ENABLED` | `false` | Enable the opt-in Unbound per-query DNS log source (pi-hole-style query log to Loki: domain, client, action, resolution source, blocklist and dnssec_status per query). Off by default; requires --logs.enabled. CAVEAT: without a per-client filter, Unbound's query-log backend (DuckDB) only ever exposes the newest 1000 rows across the WHOLE resolver — on a firewall sustaining more than roughly 1000 queries between polls, older rows silently fall out of that window before this exporter ever sees them. This is accepted, honestly-counted sampling loss, not a bug: it is tracked via opnsense_exporter_logs_possible_gap_total{source="unbound"}, never silently dropped. Homelab/SMB query volumes are fine; a busy enterprise resolver should not enable this. Also requires Unbound reporting/statistics enabled on the firewall. Poll floor 15s regardless of --logs.poll-interval. |
| `--web.config.file` | -- | -- | Path to configuration file that can enable TLS or authentication. See: https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md |
| `--web.disable-exporter-metrics` | `OPNSENSE_EXPORTER_DISABLE_EXPORTER_METRICS` | -- | Exclude metrics about the exporter itself (process_*, go_*). |
| `--web.listen-address` | -- | `:8080` | Addresses on which to expose metrics and web interface. Repeatable for multiple addresses. Examples: `:9100` or `[::1]:9100` for http, `vsock://:9100` for vsock |
| `--web.systemd-socket` | -- | -- | Use systemd socket activation listeners instead of port listeners (Linux only). |
| `--web.telemetry-path` | `OPNSENSE_EXPORTER_WEB_TELEMETRY_PATH` | `/metrics` | Path under which to expose metrics. |
<!-- docgen:end:flags-exporter -->

## Health endpoints & scrape filtering

The exporter serves two probe endpoints alongside `/metrics`:

| Path | Behavior |
|------|----------|
| `/-/healthy` | Liveness: always `200 OK` while the process is serving. No upstream dependency. |
| `/-/ready` | Readiness: `200 OK` when the OPNsense API health check succeeds, `503` otherwise. Results (including failures) are cached for 10 seconds so Kubernetes probes cannot hammer the firewall API; each upstream probe is bounded to 5 seconds and detached from the prober's own request timeout. |

!!! warning "Kubernetes: do not gate readiness on the firewall"
    `/-/ready` depends on the OPNsense API. If Prometheus discovers the exporter via Kubernetes Service endpoints, a not-ready pod drops out of the endpoints list — so an unreachable firewall would stop the exporter being scraped and you would lose the `opnsense_up=0` signal exactly when the firewall is down. **Do not use `/-/ready` as a `readinessProbe` in that setup — use `/-/healthy` for both probes** (as the bundled `deploy/k8s/deployment.yaml` does). `/-/ready` is intended for ordered startup and manual/external checks.

Note: if you configure `basic_auth_users` in the exporter-toolkit web config file (`--web.config.file`), authentication applies to **all** endpoints including `/-/healthy` and `/-/ready` — Kubernetes probes cannot easily send basic-auth credentials, so prefer network-level protection over basic auth when probes are in use.

`/metrics` supports node_exporter-style per-scrape collector filtering:

```
curl 'http://localhost:8080/metrics?collect[]=gateways&collect[]=interfaces'
curl 'http://localhost:8080/metrics?exclude[]=firewall_rule'
```

`collect[]` and `exclude[]` are mutually exclusive (`400` if both are given); unknown collector names return `400` listing the valid names (the subsystem names of the collectors enabled in this instance). The always-on metrics (`opnsense_up`, health/status, `opnsense_exporter_*`) are emitted regardless of filtering.

The exporter also honors the `X-Prometheus-Scrape-Timeout-Seconds` header sent by Prometheus: the collector fan-out runs under a deadline of the header value minus `--exporter.scrape-timeout-offset`, so a slow firewall endpoint produces a partial-but-successful scrape (with the affected collector's `opnsense_exporter_scrape_collector_success` = 0) instead of a wholesale scrape failure.

## Continuous profiling (Pyroscope)

The exporter can push continuous profiles to Grafana Cloud Pyroscope using the
`pyroscope-go` SDK. Profiling is **disabled by default** and activates only when
`--pyroscope.server-address` (env `OPNSENSE_EXPORTER_PYROSCOPE_SERVER_ADDRESS`)
is set. There are no unauthenticated `/debug/pprof/*` endpoints.

<!-- docgen:begin:flags-pyroscope -->
| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--pyroscope.application-name` | `OPNSENSE_EXPORTER_PYROSCOPE_APPLICATION_NAME` | `opnsense-exporter` | Pyroscope application name profiles are reported under. |
| `--pyroscope.auth-password` | `OPNSENSE_EXPORTER_PYROSCOPE_AUTH_PASSWORD` | -- | HTTP basic auth password for Pyroscope (Grafana Cloud Access Policy token). This flag/ENV or PYROSCOPE_AUTH_PASSWORD_FILE may be set. |
| `--pyroscope.auth-user` | `OPNSENSE_EXPORTER_PYROSCOPE_AUTH_USER` | -- | HTTP basic auth user for Pyroscope (Grafana Cloud stack/instance ID). This flag/ENV or PYROSCOPE_AUTH_USER_FILE may be set. |
| `--pyroscope.enable-mutex-block` | `OPNSENSE_EXPORTER_PYROSCOPE_ENABLE_MUTEX_BLOCK` | `false` | Enable goroutine/mutex/block profiling (adds minor runtime overhead). |
| `--pyroscope.server-address` | `OPNSENSE_EXPORTER_PYROSCOPE_SERVER_ADDRESS` | -- | Grafana Cloud Pyroscope endpoint URL. When empty, continuous profiling is disabled. |
| `--pyroscope.tenant-id` | `OPNSENSE_EXPORTER_PYROSCOPE_TENANT_ID` | -- | Pyroscope tenant ID (only needed for multi-tenancy; unused for Grafana Cloud). |
<!-- docgen:end:flags-pyroscope -->

### File-based secrets

Like the OPNsense API credentials, the auth user and password can be read from
files instead of flags/env vars: set `PYROSCOPE_AUTH_USER_FILE` and/or
`PYROSCOPE_AUTH_PASSWORD_FILE` to a path whose first line holds the value. The
file value takes precedence over the corresponding flag/env var when present
and non-empty.

Profiles are tagged with `instance` (the resolved instance label) and `version`.

## OTLP metrics export

In addition to the `/metrics` pull endpoint, the exporter can **push** the exact
same metrics to an OpenTelemetry (OTLP) endpoint. A Prometheus-bridge producer reads
the existing registry on each export tick, so OTLP metric names, labels and values
are identical to what `/metrics` exposes (no native renaming) — existing dashboards
keep working against either backend. Export is **disabled by default** and activates
only when `--otlp.enabled` (env `OPNSENSE_EXPORTER_OTLP_ENABLED`) is set. The pull
endpoint is unaffected whether or not OTLP is enabled.

Any field left empty falls through to the corresponding **standard OpenTelemetry
environment variable** (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`,
`OTEL_EXPORTER_OTLP_PROTOCOL`, `OTEL_METRIC_EXPORT_INTERVAL`, `OTEL_SERVICE_NAME`,
`OTEL_RESOURCE_ATTRIBUTES`, …) read natively by the OTEL SDK. Explicit `--otlp.*`
flags take precedence over those env vars.

<!-- docgen:begin:flags-otlp -->
| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--otlp.enabled` | `OPNSENSE_EXPORTER_OTLP_ENABLED` | `false` | Enable pushing metrics to an OTLP endpoint (in addition to the /metrics pull endpoint). Off by default. |
| `--otlp.endpoint` | `OPNSENSE_EXPORTER_OTLP_ENDPOINT` | -- | OTLP endpoint URL. When empty, the standard OTEL_EXPORTER_OTLP_ENDPOINT env var is used. |
| `--otlp.export-interval` | `OPNSENSE_EXPORTER_OTLP_EXPORT_INTERVAL` | `60s` | Interval between OTLP metric exports (independent of Prometheus scrapes). |
| `--otlp.grafana-cloud-endpoint` | `OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_ENDPOINT` | -- | Grafana Cloud OTLP gateway base URL (required when using the Grafana Cloud shortcut). |
| `--otlp.grafana-cloud-instance-id` | `OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_INSTANCE_ID` | -- | Grafana Cloud OTLP instance ID. With --otlp.grafana-cloud-token, synthesizes basic-auth. This flag/ENV or OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_INSTANCE_ID_FILE may be set. |
| `--otlp.grafana-cloud-token` | `OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_TOKEN` | -- | Grafana Cloud Access Policy token. This flag/ENV or OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_TOKEN_FILE may be set. |
| `--otlp.headers` | `OPNSENSE_EXPORTER_OTLP_HEADERS` | -- | OTLP headers as comma-separated key=value pairs (e.g. X-Scope-OrgID=1,Authorization=Bearer x). When set, replaces OTEL_EXPORTER_OTLP_HEADERS entirely; when empty, that env var is used. |
| `--otlp.insecure` | `OPNSENSE_EXPORTER_OTLP_INSECURE` | `false` | Disable TLS for the OTLP connection (plaintext). |
| `--otlp.protocol` | `OPNSENSE_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` | OTLP transport protocol: grpc or http/protobuf. Defaults to http/protobuf; an empty value is rejected. |
| `--otlp.service-name` | `OPNSENSE_EXPORTER_OTLP_SERVICE_NAME` | `opnsense-exporter` | service.name resource attribute for exported metrics. |
| `--otlp.tls-ca-file` | `OPNSENSE_EXPORTER_OTLP_TLS_CA_FILE` | -- | Path to a CA certificate file used to verify the OTLP server. |
| `--otlp.tls-cert-file` | `OPNSENSE_EXPORTER_OTLP_TLS_CERT_FILE` | -- | Path to a client certificate file for OTLP mutual TLS (requires --otlp.tls-key-file). |
| `--otlp.tls-key-file` | `OPNSENSE_EXPORTER_OTLP_TLS_KEY_FILE` | -- | Path to a client key file for OTLP mutual TLS (requires --otlp.tls-cert-file). |
<!-- docgen:end:flags-otlp -->

The metric set exported over OTLP is the same as the Prometheus
catalogue (see the [metrics reference](metrics/metrics.md)), with one addition
described below: a synthetic `up` series.

### Liveness (`up`) in push mode

When Prometheus **scrapes** `/metrics` it synthesizes an `up` series per target for
free — `1` when the scrape succeeded, `0`/absent when the exporter was unreachable —
and liveness alerts (`up == 0`, `absent(up)`) key off it. In **OTLP push mode there
is no scraper**, so nothing generates that series and those alerts silently stop
working.

To keep them working, the exporter emits its own `up` series, but **only over
OTLP**: a gauge fixed at `1` while the exporter is running and exporting, labelled
with `opnsense_instance`. When the exporter stops, it stops pushing and the series
goes stale/absent — exactly the signal an `absent(up)` (or staleness) alert needs.
This mirrors Prometheus target-up semantics: `up` reports whether the **exporter**
is alive, not whether the firewall behind it is healthy (that is
[`opnsense_up`](metrics/metrics.md), which reflects OPNsense API reachability).

The synthetic `up` is deliberately **not** exposed at `/metrics`: a literal `up`
there would collide with the `up` a Prometheus server generates for the scrape
target. It therefore exists in the pushed OTLP stream alone, and does not appear in
the [metrics reference](metrics/metrics.md) (which catalogues the pull endpoint).

### Grafana Cloud shortcut

Setting `--otlp.grafana-cloud-instance-id`, `--otlp.grafana-cloud-token` and
`--otlp.grafana-cloud-endpoint` together synthesizes the
`Authorization: Basic base64(instanceID:token)` header and uses the gateway URL as
the endpoint, so you do not have to assemble the basic-auth header yourself. An
explicit `--otlp.endpoint` or `Authorization` header always wins over the shortcut.
The instance ID and token also support `*_FILE` secret variants
(`OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_INSTANCE_ID_FILE`,
`OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_TOKEN_FILE`), whose file contents take
precedence over the flag/env value, mirroring the OPNsense API credentials.

### Temporality

Exported metrics are always **cumulative**, and this is not configurable. They are
sourced from the Prometheus registry via a bridge producer, so they arrive already
aggregated as cumulative (Prometheus' model) and are exported as-is — exactly the
temporality Grafana Cloud's metrics backend (Mimir) and Prometheus' OTLP ingest
require. An exporter-side temporality selector cannot re-aggregate
producer-supplied metrics, so no delta option is offered.

## Collector switches

All collectors are **enabled by default** unless noted otherwise. Each can be individually disabled or enabled using CLI flags or environment variables.

### Enabled by default (disable with flag)

<!-- docgen:begin:flags-collectors-default-on -->
| Flag | Env Var | Collector | Description |
|------|---------|-----------|-------------|
| `--exporter.disable-acme` | `OPNSENSE_EXPORTER_DISABLE_ACME` | ACME Client | Disable the scraping of ACME client certificate renewal status and expiry metrics (silent when the os-acme-client plugin is absent) |
| `--exporter.disable-apcupsd` | `OPNSENSE_EXPORTER_DISABLE_APCUPSD` | APC UPS (apcupsd) | Disable the scraping of APC UPS (apcupsd) metrics (silent when the os-apcupsd plugin is absent) |
| `--exporter.disable-arp-table` | `OPNSENSE_EXPORTER_DISABLE_ARP_TABLE` | ARP Table | Disable the scraping of the ARP table |
| `--exporter.disable-activity` | `OPNSENSE_EXPORTER_DISABLE_ACTIVITY` | Activity | Disable the scraping of system activity metrics (CPU percentages, thread counts) |
| `--exporter.disable-bpf` | `OPNSENSE_EXPORTER_DISABLE_BPF` | BPF Statistics | Disable the scraping of BPF listener statistics |
| `--exporter.disable-carp` | `OPNSENSE_EXPORTER_DISABLE_CARP` | CARP | Disable the scraping of CARP/VIP status metrics |
| `--exporter.disable-captiveportal` | `OPNSENSE_EXPORTER_DISABLE_CAPTIVEPORTAL` | Captive Portal | Disable the scraping of captive portal zone/session metrics (silent when no zones are configured) |
| `--exporter.disable-certificates` | `OPNSENSE_EXPORTER_DISABLE_CERTIFICATES` | Certificates | Disable the scraping of certificate expiry metrics |
| `--exporter.disable-chrony` | `OPNSENSE_EXPORTER_DISABLE_CHRONY` | Chrony | Disable the scraping of chrony NTP tracking/source metrics (silent when the os-chrony plugin is absent) |
| `--exporter.disable-clamav` | `OPNSENSE_EXPORTER_DISABLE_CLAMAV` | ClamAV | Disable the scraping of ClamAV engine version and signature database freshness metrics (silent when the os-clamav plugin is absent) |
| `--exporter.disable-backup` | `OPNSENSE_EXPORTER_DISABLE_BACKUP` | Config Backup | Disable the scraping of config backup freshness metrics (last backup timestamp/count/size) |
| `--exporter.disable-cron-table` | `OPNSENSE_EXPORTER_DISABLE_CRON_TABLE` | Cron | Disable the scraping of the cron table |
| `--exporter.disable-crowdsec` | `OPNSENSE_EXPORTER_DISABLE_CROWDSEC` | CrowdSec | Disable the scraping of CrowdSec alert/decision/bouncer/machine counts (silent when the os-crowdsec plugin is absent) |
| `--exporter.disable-dnsmasq` | `OPNSENSE_EXPORTER_DISABLE_DNSMASQ` | Dnsmasq DHCP | Disable the scraping of Dnsmasq DHCP leases |
| `--exporter.disable-dyndns` | `OPNSENSE_EXPORTER_DISABLE_DYNDNS` | DynDNS | Disable the scraping of DynDNS (ddclient) account update status metrics (silent when the os-ddclient plugin is absent) |
| `--exporter.disable-frr` | `OPNSENSE_EXPORTER_DISABLE_FRR` | FRR Routing (BGP/OSPF/BFD) | Disable the scraping of FRR routing metrics (BGP/OSPF/BFD; silent when the os-frr plugin is absent) |
| `--exporter.disable-firewall` | `OPNSENSE_EXPORTER_DISABLE_FIREWALL` | Firewall | Disable the scraping of the firewall (pf) metrics |
| `--exporter.disable-alias` | `OPNSENSE_EXPORTER_DISABLE_ALIAS` | Firewall Aliases | Disable the scraping of firewall alias table sizes |
| `--exporter.disable-firewall-rules` | `OPNSENSE_EXPORTER_DISABLE_FIREWALL_RULES` | Firewall Rules | Disable the scraping of firewall rule statistics |
| `--exporter.disable-firmware` | `OPNSENSE_EXPORTER_DISABLE_FIRMWARE` | Firmware | Disable the scraping of the firmware metrics |
| `--exporter.disable-gateways` | `OPNSENSE_EXPORTER_DISABLE_GATEWAYS` | Gateways | Disable the scraping of gateway status metrics (RTT, packet loss, gateway state) |
| `--exporter.disable-haproxy` | `OPNSENSE_EXPORTER_DISABLE_HAPROXY` | HAProxy | Disable the scraping of HAProxy statistics (silent when the os-haproxy plugin is absent) |
| `--exporter.disable-hardware` | `OPNSENSE_EXPORTER_DISABLE_HARDWARE` | Hardware | Disable the scraping of hardware identity/PSU metrics (DMI system info via os-dmidecode; Deciso DEC-series PSU status via os-dec-hw). Silent when neither plugin is installed. |
| `--exporter.disable-hostdiscovery` | `OPNSENSE_EXPORTER_DISABLE_HOSTDISCOVERY` | Host Discovery | Disable the scraping of the discovered-host inventory (Interfaces > Host discovery / hostwatch): interface+source host counts, low-cardinality. A core OPNsense feature (not a plugin); reads absent/silent on releases predating it. |
| `--exporter.disable-ids` | `OPNSENSE_EXPORTER_DISABLE_IDS` | IDS/IPS (Suricata) | Disable the scraping of Suricata IDS/IPS metrics (service status, IPS mode, eve log and ruleset inventory, installed-rule count; silent structures when IDS is unconfigured) |
| `--exporter.disable-ipsec` | `OPNSENSE_EXPORTER_DISABLE_IPSEC` | IPsec | Disable the scraping of IPSec service |
| `--exporter.disable-dhcpv4` | `OPNSENSE_EXPORTER_DISABLE_DHCPV4` | ISC DHCPv4 | Disable the scraping of ISC DHCPv4 leases (silent when the legacy ISC DHCP backend is absent) |
| `--exporter.disable-dhcpv6` | `OPNSENSE_EXPORTER_DISABLE_DHCPV6` | ISC DHCPv6 | Disable the scraping of ISC DHCPv6 leases and delegated prefixes (silent when the legacy ISC DHCP backend is absent) |
| `--exporter.disable-interfaces` | `OPNSENSE_EXPORTER_DISABLE_INTERFACES` | Interfaces | Disable the interfaces collector (per-interface traffic/link metrics) |
| `--exporter.disable-kea` | `OPNSENSE_EXPORTER_DISABLE_KEA` | Kea DHCP | Disable the scraping of Kea DHCP lease metrics |
| `--exporter.disable-lldpd` | `OPNSENSE_EXPORTER_DISABLE_LLDPD` | LLDP Neighbors | Disable the scraping of LLDP neighbor table metrics (silent when the os-lldpd plugin is absent) |
| `--exporter.disable-auth` | `OPNSENSE_EXPORTER_DISABLE_AUTH` | Local Auth | Disable the scraping of local-auth security-posture metrics (user/group/API-key counts, aggregates only — no per-user data) |
| `--exporter.disable-mbuf` | `OPNSENSE_EXPORTER_DISABLE_MBUF` | Mbuf | Disable the scraping of mbuf statistics |
| `--exporter.disable-monit` | `OPNSENSE_EXPORTER_DISABLE_MONIT` | Monit | Disable the scraping of Monit service check status (silent when Monit is not running) |
| `--exporter.disable-ndp` | `OPNSENSE_EXPORTER_DISABLE_NDP` | NDP | Disable the scraping of the NDP (IPv6 neighbor discovery) table |
| `--exporter.disable-ntp` | `OPNSENSE_EXPORTER_DISABLE_NTP` | NTP | Disable the scraping of NTP peer metrics |
| `--exporter.disable-nut` | `OPNSENSE_EXPORTER_DISABLE_NUT` | NUT UPS | Disable the scraping of NUT UPS metrics (silent when the os-nut plugin is absent) |
| `--exporter.disable-netbird` | `OPNSENSE_EXPORTER_DISABLE_NETBIRD` | NetBird | Disable the scraping of NetBird management/signal connectivity, relay and peer metrics (silent when the os-netbird plugin is absent) |
| `--exporter.disable-nginx` | `OPNSENSE_EXPORTER_DISABLE_NGINX` | Nginx | Disable the scraping of nginx VTS statistics (silent when the os-nginx plugin is absent) |
| `--exporter.disable-openvpn` | `OPNSENSE_EXPORTER_DISABLE_OPENVPN` | OpenVPN | Disable the scraping of OpenVPN service |
| `--exporter.disable-pf-stats` | `OPNSENSE_EXPORTER_DISABLE_PF_STATS` | PF Statistics | Disable the scraping of PF statistics (state table, counters, memory limits, timeouts) |
| `--exporter.disable-protocol` | `OPNSENSE_EXPORTER_DISABLE_PROTOCOL` | Protocol Statistics | Disable the protocol-statistics collector (TCP/UDP/IP/ICMP/ARP/CARP/pfsync counters) |
| `--exporter.disable-qfeeds` | `OPNSENSE_EXPORTER_DISABLE_QFEEDS` | Q-Feeds | Disable the scraping of Q-Feeds threat intelligence statistics (silent when the os-q-feeds-connector plugin is absent) |
| `--exporter.disable-relayd` | `OPNSENSE_EXPORTER_DISABLE_RELAYD` | Relayd Load Balancer | Disable the scraping of relayd virtual server/table/host health (silent when the os-relayd plugin is absent) |
| `--exporter.disable-services` | `OPNSENSE_EXPORTER_DISABLE_SERVICES` | Services | Disable the services collector (per-service running state) |
| `--exporter.disable-siproxd` | `OPNSENSE_EXPORTER_DISABLE_SIPROXD` | Siproxd | Disable the scraping of the siproxd active SIP registration count (silent when the os-siproxd plugin is absent) |
| `--exporter.disable-syslog` | `OPNSENSE_EXPORTER_DISABLE_SYSLOG` | Syslog | Disable the scraping of syslog-ng statistics |
| `--exporter.disable-system` | `OPNSENSE_EXPORTER_DISABLE_SYSTEM` | System | Disable the scraping of system resource metrics (memory, uptime, disk, swap) |
| `--exporter.disable-tailscale` | `OPNSENSE_EXPORTER_DISABLE_TAILSCALE` | Tailscale | Disable the scraping of Tailscale node-local metrics (silent when the os-tailscale plugin is absent; complementary to tailscale2otel) |
| `--exporter.disable-temperature` | `OPNSENSE_EXPORTER_DISABLE_TEMPERATURE` | Temperature | Disable the scraping of temperature metrics |
| `--exporter.disable-trafficshaper` | `OPNSENSE_EXPORTER_DISABLE_TRAFFICSHAPER` | Traffic Shaper | Disable the scraping of traffic shaper pipe/queue/rule statistics (silent when the shaper is unconfigured) |
| `--exporter.disable-unbound` | `OPNSENSE_EXPORTER_DISABLE_UNBOUND` | Unbound DNS | Disable the scraping of Unbound service |
| `--exporter.disable-wireguard` | `OPNSENSE_EXPORTER_DISABLE_WIREGUARD` | Wireguard | Disable the scraping of Wireguard service |
| `--exporter.disable-snapshots` | `OPNSENSE_EXPORTER_DISABLE_SNAPSHOTS` | ZFS Boot Environments | Disable the scraping of ZFS boot-environment inventory metrics (silent/zero on non-ZFS filesystems such as UFS) |
<!-- docgen:end:flags-collectors-default-on -->

!!! info "Always-on collectors"
    The **Interfaces**, **Protocol Statistics**, **Services**, and built-in health-check
    collectors are always enabled and have no disable flag.

### Disabled by default (opt-in with flag)

These collectors are disabled by default because they make additional API calls per scrape. Enable them only if you need the data.

<!-- docgen:begin:flags-collectors-opt-in -->
| Flag | Env Var | Collector | Description |
|------|---------|-----------|-------------|
| `--exporter.enable-hasync` | `OPNSENSE_EXPORTER_ENABLE_HASYNC` | HA Sync Status | Enable the HA sync status collector (performs a live XML-RPC call to the CARP peer on every scrape). Disabled by default. |
| `--exporter.enable-netflow` | `OPNSENSE_EXPORTER_ENABLE_NETFLOW` | NetFlow | Enable the netflow collector (enabled status, service status, cache stats). Disabled by default. |
| `--exporter.enable-network-diagnostics` | `OPNSENSE_EXPORTER_ENABLE_NETWORK_DIAGNOSTICS` | Network Diagnostics | Enable the network diagnostics collector (netisr, sockets, routes). Disabled by default. |
| `--exporter.enable-smart` | `OPNSENSE_EXPORTER_ENABLE_SMART` | SMART Disk Health | Enable the SMART disk health collector. Off by default: each scrape does a per-disk POST fanout that runs `smartctl -a` on the firewall (extra API/latency cost, and wakes spun-down disks). Silent when the os-smart plugin is absent. |
| `--exporter.enable-tor` | `OPNSENSE_EXPORTER_ENABLE_TOR` | Tor | Enable the Tor circuit/stream telemetry collector (control-port GETINFO via the os-tor plugin). Off by default: each scrape does two extra configd execs to query the control port, and requires the plugin's control port + password to be configured. Silent when the os-tor plugin is absent. |
| `--exporter.enable-vnstat` | `OPNSENSE_EXPORTER_ENABLE_VNSTAT` | Vnstat Traffic Accounting | Enable the vnstat persistent traffic accounting collector (day/month/total bytes per interface, survives reboots). Off by default: each scrape does one interface_list call plus one get_json_data call per interface vnstat tracks. Silent when the os-vnstat plugin is absent. |
<!-- docgen:end:flags-collectors-opt-in -->

### High-cardinality detail options

These flags enable per-item detail metrics that can produce a large number of time series. Each unique label combination creates a separate time series in Prometheus.

!!! warning "Evaluate before enabling"
    On a firewall with hundreds of DHCP leases or firewall rules, enabling detail metrics can produce thousands of time series. Monitor your Prometheus storage and ingestion rate after enabling.

<!-- docgen:begin:flags-collectors-details -->
| Flag | Env Var | Collector | Description |
|------|---------|-----------|-------------|
| `--exporter.enable-arp-details` | `OPNSENSE_EXPORTER_ENABLE_ARP_DETAILS` | ARP Table | Enable per-entry ARP metrics (ip/mac/hostname labels — high, churning cardinality). Off by default; the low-cardinality entries_total aggregate is always emitted. |
| `--exporter.enable-dnsmasq-details` | `OPNSENSE_EXPORTER_ENABLE_DNSMASQ_DETAILS` | Dnsmasq DHCP | Enable per-lease detail metrics for Dnsmasq DHCP (high cardinality on large networks) |
| `--exporter.enable-frr-routes` | `OPNSENSE_EXPORTER_ENABLE_FRR_ROUTES` | FRR Routing (BGP/OSPF/BFD) | Enable FRR routing-state volume gauges (zebra RIB / OSPF route table / LSDB counts by protocol, route type, area and LSA type — never per-prefix or per-LSA series). Off by default: the underlying bootgrid endpoints have no success-body caching and their payload size scales with route-table size (up to 6 extra vtysh execs per scrape). |
| `--exporter.enable-firewall-nat-counts` | `OPNSENSE_EXPORTER_ENABLE_FIREWALL_NAT_COUNTS` | Firewall | Enable the NAT rule inventory count metric (opnsense_firewall_nat_rules), broken down by type (source_nat, d_nat, one_to_one, npt) and enabled state. Off by default: each scrape does four extra GETs, one per NAT rule type. Rules created before an admin migrated to the MVC-managed NAT backend are not counted; NAT rule pf hit/byte statistics do not exist upstream. |
| `--exporter.enable-alias-details` | `OPNSENSE_EXPORTER_ENABLE_ALIAS_DETAILS` | Firewall Aliases | Enable per-table pf evaluation/packet/byte counters for firewall aliases (~10 series per alias table) |
| `--exporter.enable-firewall-rules-details` | `OPNSENSE_EXPORTER_ENABLE_FIREWALL_RULES_DETAILS` | Firewall Rules | Enable per-rule detail metrics for firewall rules (high cardinality on large rulesets) |
| `--exporter.enable-firmware-package-details` | `OPNSENSE_EXPORTER_ENABLE_FIRMWARE_PACKAGE_DETAILS` | Firmware | Enable per-package firmware detail metrics (pending package updates and installed plugin inventory; adds one extra API call per scrape) |
| `--exporter.enable-ids-alerts` | `OPNSENSE_EXPORTER_ENABLE_IDS_ALERTS` | IDS/IPS (Suricata) | Enable the Suricata recent-alerts gauge (opnsense_ids_recent_alerts by action). Off by default: each scrape triggers a reverse read of eve.json on the box. Window set by --exporter.ids-alert-lookback. |
| `--exporter.enable-ipsec-lease-details` | `OPNSENSE_EXPORTER_ENABLE_IPSEC_LEASE_DETAILS` | IPsec | Enable per-lease IPsec mode-cfg detail metrics (opnsense_ipsec_lease_online with an unbounded road-warrior user label). Off by default; the per-pool lease aggregates stay always-on. |
| `--exporter.enable-dhcpv4-details` | `OPNSENSE_EXPORTER_ENABLE_DHCPV4_DETAILS` | ISC DHCPv4 | Enable per-lease detail metrics for ISC DHCPv4 (high cardinality on large networks) |
| `--exporter.enable-dhcpv6-details` | `OPNSENSE_EXPORTER_ENABLE_DHCPV6_DETAILS` | ISC DHCPv6 | Enable per-lease detail metrics for ISC DHCPv6 (high cardinality on large networks) |
| `--exporter.enable-kea-details` | `OPNSENSE_EXPORTER_ENABLE_KEA_DETAILS` | Kea DHCP | Enable per-lease detail metrics for Kea DHCP (high cardinality on large networks) |
| `--exporter.enable-ndp-details` | `OPNSENSE_EXPORTER_ENABLE_NDP_DETAILS` | NDP | Enable per-entry NDP metrics (ip/mac labels — high, churning cardinality from IPv6 privacy-address rotation). Off by default; the low-cardinality entries_total aggregate is always emitted. |
| `--exporter.enable-netbird-details` | `OPNSENSE_EXPORTER_ENABLE_NETBIRD_DETAILS` | NetBird | Enable per-peer detail metrics for NetBird (per-peer cardinality; peer FQDN labels) |
| `--exporter.enable-openvpn-details` | `OPNSENSE_EXPORTER_ENABLE_OPENVPN_DETAILS` | OpenVPN | Enable per-session detail metrics for OpenVPN (exposes usernames and per-client tunnel addresses) |
| `--exporter.enable-tailscale-peer-details` | `OPNSENSE_EXPORTER_ENABLE_TAILSCALE_PEER_DETAILS` | Tailscale | Enable per-peer detail metrics for Tailscale (per-peer cardinality; peer hostname labels) |
| `--exporter.enable-unbound-qstats` | `OPNSENSE_EXPORTER_ENABLE_UNBOUND_QSTATS` | Unbound DNS | Enable Unbound DNSBL query-stats totals and blocklist size metrics, plus local-zone/data/insecure-domain counts. Off by default: the query-stats totals call is backed by an expensive configd+python+pandas+DuckDB query (~1s per scrape) — skipped entirely while query-stats logging (general.stats) is off on the box, but still paid for on every scrape once it is on. |
| `--exporter.enable-unbound-infra` | `OPNSENSE_EXPORTER_ENABLE_UNBOUND_INFRA` | Unbound DNS | Enable per-upstream infra cache RTT metrics from Unbound (cardinality scales with the resolver's infra cache; one series pair per upstream ip/host) |
<!-- docgen:end:flags-collectors-details -->

## Full flag reference

Every flag the exporter accepts, generated from the binary's own flag definitions
(`--help` shows the same set):

<!-- docgen:begin:flags-full-reference -->
| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--exporter.cache-ttl` | `OPNSENSE_EXPORTER_CACHE_TTL` | `1h` | How long to cache responses from slow-moving API endpoints (system/CPU identity, certificate inventory, Unbound DNS blocklist policy config) and to remember that a plugin-gated endpoint is absent (its 404). This data changes only on an admin action — a config edit, a certificate renewal, a plugin install — so re-fetching it every scrape only costs firewall CPU. The cost is staleness: a newly installed plugin, or a cert change, can take up to this long to show up. Set to 0 to fetch everything on every scrape. Live data (counters, rates, service run-state) is never cached regardless of this setting. |
| `--exporter.disable-acme` | `OPNSENSE_EXPORTER_DISABLE_ACME` | `false` | Disable the scraping of ACME client certificate renewal status and expiry metrics (silent when the os-acme-client plugin is absent) |
| `--exporter.disable-activity` | `OPNSENSE_EXPORTER_DISABLE_ACTIVITY` | `false` | Disable the scraping of system activity metrics (CPU percentages, thread counts) |
| `--exporter.disable-alias` | `OPNSENSE_EXPORTER_DISABLE_ALIAS` | `false` | Disable the scraping of firewall alias table sizes |
| `--exporter.disable-apcupsd` | `OPNSENSE_EXPORTER_DISABLE_APCUPSD` | `false` | Disable the scraping of APC UPS (apcupsd) metrics (silent when the os-apcupsd plugin is absent) |
| `--exporter.disable-arp-table` | `OPNSENSE_EXPORTER_DISABLE_ARP_TABLE` | `false` | Disable the scraping of the ARP table |
| `--exporter.disable-auth` | `OPNSENSE_EXPORTER_DISABLE_AUTH` | `false` | Disable the scraping of local-auth security-posture metrics (user/group/API-key counts, aggregates only — no per-user data) |
| `--exporter.disable-backup` | `OPNSENSE_EXPORTER_DISABLE_BACKUP` | `false` | Disable the scraping of config backup freshness metrics (last backup timestamp/count/size) |
| `--exporter.disable-bpf` | `OPNSENSE_EXPORTER_DISABLE_BPF` | `false` | Disable the scraping of BPF listener statistics |
| `--exporter.disable-captiveportal` | `OPNSENSE_EXPORTER_DISABLE_CAPTIVEPORTAL` | `false` | Disable the scraping of captive portal zone/session metrics (silent when no zones are configured) |
| `--exporter.disable-carp` | `OPNSENSE_EXPORTER_DISABLE_CARP` | `false` | Disable the scraping of CARP/VIP status metrics |
| `--exporter.disable-certificates` | `OPNSENSE_EXPORTER_DISABLE_CERTIFICATES` | `false` | Disable the scraping of certificate expiry metrics |
| `--exporter.disable-chrony` | `OPNSENSE_EXPORTER_DISABLE_CHRONY` | `false` | Disable the scraping of chrony NTP tracking/source metrics (silent when the os-chrony plugin is absent) |
| `--exporter.disable-clamav` | `OPNSENSE_EXPORTER_DISABLE_CLAMAV` | `false` | Disable the scraping of ClamAV engine version and signature database freshness metrics (silent when the os-clamav plugin is absent) |
| `--exporter.disable-cron-table` | `OPNSENSE_EXPORTER_DISABLE_CRON_TABLE` | `false` | Disable the scraping of the cron table |
| `--exporter.disable-crowdsec` | `OPNSENSE_EXPORTER_DISABLE_CROWDSEC` | `false` | Disable the scraping of CrowdSec alert/decision/bouncer/machine counts (silent when the os-crowdsec plugin is absent) |
| `--exporter.disable-dhcpv4` | `OPNSENSE_EXPORTER_DISABLE_DHCPV4` | `false` | Disable the scraping of ISC DHCPv4 leases (silent when the legacy ISC DHCP backend is absent) |
| `--exporter.disable-dhcpv6` | `OPNSENSE_EXPORTER_DISABLE_DHCPV6` | `false` | Disable the scraping of ISC DHCPv6 leases and delegated prefixes (silent when the legacy ISC DHCP backend is absent) |
| `--exporter.disable-dnsmasq` | `OPNSENSE_EXPORTER_DISABLE_DNSMASQ` | `false` | Disable the scraping of Dnsmasq DHCP leases |
| `--exporter.disable-dyndns` | `OPNSENSE_EXPORTER_DISABLE_DYNDNS` | `false` | Disable the scraping of DynDNS (ddclient) account update status metrics (silent when the os-ddclient plugin is absent) |
| `--exporter.disable-firewall` | `OPNSENSE_EXPORTER_DISABLE_FIREWALL` | `false` | Disable the scraping of the firewall (pf) metrics |
| `--exporter.disable-firewall-rules` | `OPNSENSE_EXPORTER_DISABLE_FIREWALL_RULES` | `false` | Disable the scraping of firewall rule statistics |
| `--exporter.disable-firmware` | `OPNSENSE_EXPORTER_DISABLE_FIRMWARE` | `false` | Disable the scraping of the firmware metrics |
| `--exporter.disable-frr` | `OPNSENSE_EXPORTER_DISABLE_FRR` | `false` | Disable the scraping of FRR routing metrics (BGP/OSPF/BFD; silent when the os-frr plugin is absent) |
| `--exporter.disable-gateways` | `OPNSENSE_EXPORTER_DISABLE_GATEWAYS` | `false` | Disable the scraping of gateway status metrics (RTT, packet loss, gateway state) |
| `--exporter.disable-haproxy` | `OPNSENSE_EXPORTER_DISABLE_HAPROXY` | `false` | Disable the scraping of HAProxy statistics (silent when the os-haproxy plugin is absent) |
| `--exporter.disable-hardware` | `OPNSENSE_EXPORTER_DISABLE_HARDWARE` | `false` | Disable the scraping of hardware identity/PSU metrics (DMI system info via os-dmidecode; Deciso DEC-series PSU status via os-dec-hw). Silent when neither plugin is installed. |
| `--exporter.disable-hostdiscovery` | `OPNSENSE_EXPORTER_DISABLE_HOSTDISCOVERY` | `false` | Disable the scraping of the discovered-host inventory (Interfaces > Host discovery / hostwatch): interface+source host counts, low-cardinality. A core OPNsense feature (not a plugin); reads absent/silent on releases predating it. |
| `--exporter.disable-ids` | `OPNSENSE_EXPORTER_DISABLE_IDS` | `false` | Disable the scraping of Suricata IDS/IPS metrics (service status, IPS mode, eve log and ruleset inventory, installed-rule count; silent structures when IDS is unconfigured) |
| `--exporter.disable-interfaces` | `OPNSENSE_EXPORTER_DISABLE_INTERFACES` | `false` | Disable the interfaces collector (per-interface traffic/link metrics) |
| `--exporter.disable-ipsec` | `OPNSENSE_EXPORTER_DISABLE_IPSEC` | `false` | Disable the scraping of IPSec service |
| `--exporter.disable-kea` | `OPNSENSE_EXPORTER_DISABLE_KEA` | `false` | Disable the scraping of Kea DHCP lease metrics |
| `--exporter.disable-lldpd` | `OPNSENSE_EXPORTER_DISABLE_LLDPD` | `false` | Disable the scraping of LLDP neighbor table metrics (silent when the os-lldpd plugin is absent) |
| `--exporter.disable-mbuf` | `OPNSENSE_EXPORTER_DISABLE_MBUF` | `false` | Disable the scraping of mbuf statistics |
| `--exporter.disable-monit` | `OPNSENSE_EXPORTER_DISABLE_MONIT` | `false` | Disable the scraping of Monit service check status (silent when Monit is not running) |
| `--exporter.disable-ndp` | `OPNSENSE_EXPORTER_DISABLE_NDP` | `false` | Disable the scraping of the NDP (IPv6 neighbor discovery) table |
| `--exporter.disable-netbird` | `OPNSENSE_EXPORTER_DISABLE_NETBIRD` | `false` | Disable the scraping of NetBird management/signal connectivity, relay and peer metrics (silent when the os-netbird plugin is absent) |
| `--exporter.disable-nginx` | `OPNSENSE_EXPORTER_DISABLE_NGINX` | `false` | Disable the scraping of nginx VTS statistics (silent when the os-nginx plugin is absent) |
| `--exporter.disable-ntp` | `OPNSENSE_EXPORTER_DISABLE_NTP` | `false` | Disable the scraping of NTP peer metrics |
| `--exporter.disable-nut` | `OPNSENSE_EXPORTER_DISABLE_NUT` | `false` | Disable the scraping of NUT UPS metrics (silent when the os-nut plugin is absent) |
| `--exporter.disable-openvpn` | `OPNSENSE_EXPORTER_DISABLE_OPENVPN` | `false` | Disable the scraping of OpenVPN service |
| `--exporter.disable-pf-stats` | `OPNSENSE_EXPORTER_DISABLE_PF_STATS` | `false` | Disable the scraping of PF statistics (state table, counters, memory limits, timeouts) |
| `--exporter.disable-protocol` | `OPNSENSE_EXPORTER_DISABLE_PROTOCOL` | `false` | Disable the protocol-statistics collector (TCP/UDP/IP/ICMP/ARP/CARP/pfsync counters) |
| `--exporter.disable-qfeeds` | `OPNSENSE_EXPORTER_DISABLE_QFEEDS` | `false` | Disable the scraping of Q-Feeds threat intelligence statistics (silent when the os-q-feeds-connector plugin is absent) |
| `--exporter.disable-relayd` | `OPNSENSE_EXPORTER_DISABLE_RELAYD` | `false` | Disable the scraping of relayd virtual server/table/host health (silent when the os-relayd plugin is absent) |
| `--exporter.disable-services` | `OPNSENSE_EXPORTER_DISABLE_SERVICES` | `false` | Disable the services collector (per-service running state) |
| `--exporter.disable-siproxd` | `OPNSENSE_EXPORTER_DISABLE_SIPROXD` | `false` | Disable the scraping of the siproxd active SIP registration count (silent when the os-siproxd plugin is absent) |
| `--exporter.disable-snapshots` | `OPNSENSE_EXPORTER_DISABLE_SNAPSHOTS` | `false` | Disable the scraping of ZFS boot-environment inventory metrics (silent/zero on non-ZFS filesystems such as UFS) |
| `--exporter.disable-syslog` | `OPNSENSE_EXPORTER_DISABLE_SYSLOG` | `false` | Disable the scraping of syslog-ng statistics |
| `--exporter.disable-system` | `OPNSENSE_EXPORTER_DISABLE_SYSTEM` | `false` | Disable the scraping of system resource metrics (memory, uptime, disk, swap) |
| `--exporter.disable-tailscale` | `OPNSENSE_EXPORTER_DISABLE_TAILSCALE` | `false` | Disable the scraping of Tailscale node-local metrics (silent when the os-tailscale plugin is absent; complementary to tailscale2otel) |
| `--exporter.disable-temperature` | `OPNSENSE_EXPORTER_DISABLE_TEMPERATURE` | `false` | Disable the scraping of temperature metrics |
| `--exporter.disable-trafficshaper` | `OPNSENSE_EXPORTER_DISABLE_TRAFFICSHAPER` | `false` | Disable the scraping of traffic shaper pipe/queue/rule statistics (silent when the shaper is unconfigured) |
| `--exporter.disable-unbound` | `OPNSENSE_EXPORTER_DISABLE_UNBOUND` | `false` | Disable the scraping of Unbound service |
| `--exporter.disable-wireguard` | `OPNSENSE_EXPORTER_DISABLE_WIREGUARD` | `false` | Disable the scraping of Wireguard service |
| `--exporter.enable-alias-details` | `OPNSENSE_EXPORTER_ENABLE_ALIAS_DETAILS` | `false` | Enable per-table pf evaluation/packet/byte counters for firewall aliases (~10 series per alias table) |
| `--exporter.enable-arp-details` | `OPNSENSE_EXPORTER_ENABLE_ARP_DETAILS` | `false` | Enable per-entry ARP metrics (ip/mac/hostname labels — high, churning cardinality). Off by default; the low-cardinality entries_total aggregate is always emitted. |
| `--exporter.enable-dhcpv4-details` | `OPNSENSE_EXPORTER_ENABLE_DHCPV4_DETAILS` | `false` | Enable per-lease detail metrics for ISC DHCPv4 (high cardinality on large networks) |
| `--exporter.enable-dhcpv6-details` | `OPNSENSE_EXPORTER_ENABLE_DHCPV6_DETAILS` | `false` | Enable per-lease detail metrics for ISC DHCPv6 (high cardinality on large networks) |
| `--exporter.enable-dnsmasq-details` | `OPNSENSE_EXPORTER_ENABLE_DNSMASQ_DETAILS` | `false` | Enable per-lease detail metrics for Dnsmasq DHCP (high cardinality on large networks) |
| `--exporter.enable-firewall-nat-counts` | `OPNSENSE_EXPORTER_ENABLE_FIREWALL_NAT_COUNTS` | `false` | Enable the NAT rule inventory count metric (opnsense_firewall_nat_rules), broken down by type (source_nat, d_nat, one_to_one, npt) and enabled state. Off by default: each scrape does four extra GETs, one per NAT rule type. Rules created before an admin migrated to the MVC-managed NAT backend are not counted; NAT rule pf hit/byte statistics do not exist upstream. |
| `--exporter.enable-firewall-rules-details` | `OPNSENSE_EXPORTER_ENABLE_FIREWALL_RULES_DETAILS` | `false` | Enable per-rule detail metrics for firewall rules (high cardinality on large rulesets) |
| `--exporter.enable-firmware-package-details` | `OPNSENSE_EXPORTER_ENABLE_FIRMWARE_PACKAGE_DETAILS` | `false` | Enable per-package firmware detail metrics (pending package updates and installed plugin inventory; adds one extra API call per scrape) |
| `--exporter.enable-frr-routes` | `OPNSENSE_EXPORTER_ENABLE_FRR_ROUTES` | `false` | Enable FRR routing-state volume gauges (zebra RIB / OSPF route table / LSDB counts by protocol, route type, area and LSA type — never per-prefix or per-LSA series). Off by default: the underlying bootgrid endpoints have no success-body caching and their payload size scales with route-table size (up to 6 extra vtysh execs per scrape). |
| `--exporter.enable-hasync` | `OPNSENSE_EXPORTER_ENABLE_HASYNC` | `false` | Enable the HA sync status collector (performs a live XML-RPC call to the CARP peer on every scrape). Disabled by default. |
| `--exporter.enable-ids-alerts` | `OPNSENSE_EXPORTER_ENABLE_IDS_ALERTS` | `false` | Enable the Suricata recent-alerts gauge (opnsense_ids_recent_alerts by action). Off by default: each scrape triggers a reverse read of eve.json on the box. Window set by --exporter.ids-alert-lookback. |
| `--exporter.enable-ipsec-lease-details` | `OPNSENSE_EXPORTER_ENABLE_IPSEC_LEASE_DETAILS` | `false` | Enable per-lease IPsec mode-cfg detail metrics (opnsense_ipsec_lease_online with an unbounded road-warrior user label). Off by default; the per-pool lease aggregates stay always-on. |
| `--exporter.enable-kea-details` | `OPNSENSE_EXPORTER_ENABLE_KEA_DETAILS` | `false` | Enable per-lease detail metrics for Kea DHCP (high cardinality on large networks) |
| `--exporter.enable-ndp-details` | `OPNSENSE_EXPORTER_ENABLE_NDP_DETAILS` | `false` | Enable per-entry NDP metrics (ip/mac labels — high, churning cardinality from IPv6 privacy-address rotation). Off by default; the low-cardinality entries_total aggregate is always emitted. |
| `--exporter.enable-netbird-details` | `OPNSENSE_EXPORTER_ENABLE_NETBIRD_DETAILS` | `false` | Enable per-peer detail metrics for NetBird (per-peer cardinality; peer FQDN labels) |
| `--exporter.enable-netflow` | `OPNSENSE_EXPORTER_ENABLE_NETFLOW` | `false` | Enable the netflow collector (enabled status, service status, cache stats). Disabled by default. |
| `--exporter.enable-network-diagnostics` | `OPNSENSE_EXPORTER_ENABLE_NETWORK_DIAGNOSTICS` | `false` | Enable the network diagnostics collector (netisr, sockets, routes). Disabled by default. |
| `--exporter.enable-openvpn-details` | `OPNSENSE_EXPORTER_ENABLE_OPENVPN_DETAILS` | `false` | Enable per-session detail metrics for OpenVPN (exposes usernames and per-client tunnel addresses) |
| `--exporter.enable-smart` | `OPNSENSE_EXPORTER_ENABLE_SMART` | `false` | Enable the SMART disk health collector. Off by default: each scrape does a per-disk POST fanout that runs `smartctl -a` on the firewall (extra API/latency cost, and wakes spun-down disks). Silent when the os-smart plugin is absent. |
| `--exporter.enable-tailscale-peer-details` | `OPNSENSE_EXPORTER_ENABLE_TAILSCALE_PEER_DETAILS` | `false` | Enable per-peer detail metrics for Tailscale (per-peer cardinality; peer hostname labels) |
| `--exporter.enable-tor` | `OPNSENSE_EXPORTER_ENABLE_TOR` | `false` | Enable the Tor circuit/stream telemetry collector (control-port GETINFO via the os-tor plugin). Off by default: each scrape does two extra configd execs to query the control port, and requires the plugin's control port + password to be configured. Silent when the os-tor plugin is absent. |
| `--exporter.enable-unbound-infra` | `OPNSENSE_EXPORTER_ENABLE_UNBOUND_INFRA` | `false` | Enable per-upstream infra cache RTT metrics from Unbound (cardinality scales with the resolver's infra cache; one series pair per upstream ip/host) |
| `--exporter.enable-unbound-qstats` | `OPNSENSE_EXPORTER_ENABLE_UNBOUND_QSTATS` | `false` | Enable Unbound DNSBL query-stats totals and blocklist size metrics, plus local-zone/data/insecure-domain counts. Off by default: the query-stats totals call is backed by an expensive configd+python+pandas+DuckDB query (~1s per scrape) — skipped entirely while query-stats logging (general.stats) is off on the box, but still paid for on every scrape once it is on. |
| `--exporter.enable-vnstat` | `OPNSENSE_EXPORTER_ENABLE_VNSTAT` | `false` | Enable the vnstat persistent traffic accounting collector (day/month/total bytes per interface, survives reboots). Off by default: each scrape does one interface_list call plus one get_json_data call per interface vnstat tracks. Silent when the os-vnstat plugin is absent. |
| `--exporter.firmware-cache-ttl` | `OPNSENSE_EXPORTER_FIRMWARE_CACHE_TTL` | `12h` | How long to cache firmware API responses (status and, when enabled, package details). The firmware data OPNsense serves is the stored result of the box's own update check, which it refreshes roughly daily, so re-fetching it every scrape only costs firewall CPU. Set to 0 to fetch on every scrape. |
| `--exporter.ids-alert-lookback` | `OPNSENSE_EXPORTER_IDS_ALERT_LOOKBACK` | `15m` | Lookback window over which opnsense_ids_recent_alerts counts Suricata eve alerts (a gauge). Only used when --exporter.enable-ids-alerts is set. Counts are a floor when more than 500 alerts fall inside the window. |
| `--exporter.instance-label` | `OPNSENSE_EXPORTER_INSTANCE_LABEL` | -- | Label to use to identify the instance in every metric. If you have multiple instances of the exporter, you can differentiate them by using different value in this flag, that represents the instance of the target OPNsense. If left empty, it defaults to the configured OPNsense address (deterministic). Set --exporter.instance-use-hostname to derive it from the OPNsense hostname instead. |
| `--exporter.instance-use-hostname` | `OPNSENSE_EXPORTER_INSTANCE_USE_HOSTNAME` | `false` | When --exporter.instance-label is empty, derive the instance label from the OPNsense hostname reported by the API instead of the configured address. This lookup is deterministic: it blocks at startup and, if the hostname cannot be obtained, the exporter refuses to start (rather than silently falling back to the address, which would make the label depend on startup timing and flip between restarts). |
| `--exporter.max-scrape-duration` | `OPNSENSE_EXPORTER_MAX_SCRAPE_DURATION` | `50s` | Upper bound on a single collection when the caller supplies no deadline of its own (a header-less /metrics scrape or the OTLP-bridge periodic gather). Prevents a stalled/blackholed firewall from holding the shared collector lock unbounded and blacking out every concurrent deadline-bound scrape. |
| `--exporter.scrape-timeout-offset` | `OPNSENSE_EXPORTER_SCRAPE_TIMEOUT_OFFSET` | `500ms` | Duration subtracted from Prometheus' X-Prometheus-Scrape-Timeout-Seconds header when deriving the scrape deadline, so the exporter finishes and responds before Prometheus gives up. If the offset would consume the whole budget, the raw header timeout is used. |
| `--log.format` | -- | `logfmt` | Output format of log messages. One of: [logfmt, json] |
| `--log.level` | -- | `info` | Only log messages with the given severity or above. One of: [debug, info, warn, error] |
| `--logs.batch-max` | `OPNSENSE_EXPORTER_LOGS_BATCH_MAX` | `1000` | Maximum number of records the emitter hands to the sink per batch. |
| `--logs.buffer-size` | `OPNSENSE_EXPORTER_LOGS_BUFFER_SIZE` | `4096` | Capacity of the in-memory backpressure queue between pollers and the sink. On overflow the oldest record is dropped and counted (logs_dropped_total). |
| `--logs.crowdsec.enabled` | `OPNSENSE_EXPORTER_LOGS_CROWDSEC_ENABLED` | `false` | Enable the crowdsec log source: ships CrowdSec alert and decision records to Loki (there is no native syslog path for these — the plugin registers no syslog scope; alerts live only in the LAPI). Requires --logs.enabled. Polls at a 60s floor regardless of --logs.poll-interval. Silent when the os-crowdsec plugin is absent. Off by default. |
| `--logs.enabled` | `OPNSENSE_EXPORTER_LOGS_ENABLED` | `false` | Enable the opt-in log/event shipping pipeline (polls OPNsense event APIs and ships to Loki via OTLP). Off by default. Independent of --otlp.enabled (which gates metrics). |
| `--logs.ids.enabled` | `OPNSENSE_EXPORTER_LOGS_IDS_ENABLED` | `false` | Enable the IDS (Suricata EVE alert) log source: ships full Suricata alert records polled via ids/service/query_alerts. Off by default. Requires --logs.enabled. If the box already forwards EVE JSON via syslog (ids.general.syslog_eve), prefer that native path instead of also enabling this source — do not ship the same alerts twice. |
| `--logs.poll-interval` | `OPNSENSE_EXPORTER_LOGS_POLL_INTERVAL` | `10s` | Base interval between event polls per source (floor 5s). Sources may raise their own floor. |
| `--logs.sink` | `OPNSENSE_EXPORTER_LOGS_SINK` | `otlp` | Log shipping sink: otlp (OTLP logs, reuses the --otlp.* transport) or stdout (one JSON line per event). |
| `--logs.state-file` | `OPNSENSE_EXPORTER_LOGS_STATE_FILE` | -- | Optional path to persist per-source cursors across restarts (atomic JSON). Empty = in-memory only (resume from now on restart). |
| `--logs.syslog.allowed-peers` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_ALLOWED_PEERS` | -- | Comma-separated CIDR allowlist of hosts permitted to send syslog (e.g. 10.0.0.254/32). Empty accepts any sender. Syslog is unauthenticated, so set this on a shared network. |
| `--logs.syslog.enabled` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_ENABLED` | `false` | Enable the syslog receiver: listens for logs pushed by OPNsense (RFC5424 or RFC3164, UDP and/or TCP) and ships them enriched with rule descriptions, interface names and hostnames. Off by default. Requires --logs.enabled. Configure a matching target on the firewall under System > Settings > Logging > Targets. |
| `--logs.syslog.enrich` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_ENRICH` | `true` | Enrich received syslog records from the OPNsense API: firewall rule descriptions (including auto-generated system rules), friendly interface names, DHCP hostnames, MAC addresses, local/remote scope and well-known service names. |
| `--logs.syslog.listen-tcp` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_LISTEN_TCP` | `:5514` | TCP listen address for the syslog receiver. Empty disables the TCP listener. Prefer TCP for firewall logs: UDP datagram loss is silent and unrecoverable. |
| `--logs.syslog.listen-udp` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_LISTEN_UDP` | `:5514` | UDP listen address for the syslog receiver. Empty disables the UDP listener. Port 5514 (not 514) because 514 is privileged and the container runs non-root. |
| `--logs.syslog.max-conns` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_MAX_CONNS` | `64` | Maximum concurrent TCP connections to the syslog receiver. Bounds goroutine growth on an unauthenticated ingress. |
| `--logs.unbound.enabled` | `OPNSENSE_EXPORTER_LOGS_UNBOUND_ENABLED` | `false` | Enable the opt-in Unbound per-query DNS log source (pi-hole-style query log to Loki: domain, client, action, resolution source, blocklist and dnssec_status per query). Off by default; requires --logs.enabled. CAVEAT: without a per-client filter, Unbound's query-log backend (DuckDB) only ever exposes the newest 1000 rows across the WHOLE resolver — on a firewall sustaining more than roughly 1000 queries between polls, older rows silently fall out of that window before this exporter ever sees them. This is accepted, honestly-counted sampling loss, not a bug: it is tracked via opnsense_exporter_logs_possible_gap_total{source="unbound"}, never silently dropped. Homelab/SMB query volumes are fine; a busy enterprise resolver should not enable this. Also requires Unbound reporting/statistics enabled on the firewall. Poll floor 15s regardless of --logs.poll-interval. |
| `--opnsense.address` | `OPNSENSE_EXPORTER_OPS_API` | -- | **Required.** Hostname or IP address of OPNsense API |
| `--opnsense.api-key` | `OPNSENSE_EXPORTER_OPS_API_KEY` | -- | API key to use to connect to OPNsense API. This flag/ENV or the OPS_API_KEY_FILE may be set. |
| `--opnsense.api-secret` | `OPNSENSE_EXPORTER_OPS_API_SECRET` | -- | API secret to use to connect to OPNsense API. This flag/ENV or the OPS_API_SECRET_FILE may be set. |
| `--opnsense.insecure` | `OPNSENSE_EXPORTER_OPS_INSECURE` | `false` | Disable TLS certificate verification |
| `--opnsense.max-retries` | `OPNSENSE_EXPORTER_OPS_MAX_RETRIES` | `3` | Number of attempts for a failed OPNsense API request (transport errors / retryable 5xx). Worst-case block time is --opnsense.timeout x this value. |
| `--opnsense.protocol` | `OPNSENSE_EXPORTER_OPS_PROTOCOL` | -- | **Required.** Protocol to use to connect to OPNsense API. One of: [http, https] |
| `--opnsense.timeout` | `OPNSENSE_EXPORTER_OPS_TIMEOUT` | `15s` | Per-request HTTP timeout for calls to the OPNsense API. Combined with --opnsense.max-retries this bounds the worst-case time a collector blocks on a slow endpoint (timeout x retries). Keep the product comfortably under Prometheus' scrape_timeout. |
| `--otlp.enabled` | `OPNSENSE_EXPORTER_OTLP_ENABLED` | `false` | Enable pushing metrics to an OTLP endpoint (in addition to the /metrics pull endpoint). Off by default. |
| `--otlp.endpoint` | `OPNSENSE_EXPORTER_OTLP_ENDPOINT` | -- | OTLP endpoint URL. When empty, the standard OTEL_EXPORTER_OTLP_ENDPOINT env var is used. |
| `--otlp.export-interval` | `OPNSENSE_EXPORTER_OTLP_EXPORT_INTERVAL` | `60s` | Interval between OTLP metric exports (independent of Prometheus scrapes). |
| `--otlp.grafana-cloud-endpoint` | `OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_ENDPOINT` | -- | Grafana Cloud OTLP gateway base URL (required when using the Grafana Cloud shortcut). |
| `--otlp.grafana-cloud-instance-id` | `OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_INSTANCE_ID` | -- | Grafana Cloud OTLP instance ID. With --otlp.grafana-cloud-token, synthesizes basic-auth. This flag/ENV or OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_INSTANCE_ID_FILE may be set. |
| `--otlp.grafana-cloud-token` | `OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_TOKEN` | -- | Grafana Cloud Access Policy token. This flag/ENV or OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_TOKEN_FILE may be set. |
| `--otlp.headers` | `OPNSENSE_EXPORTER_OTLP_HEADERS` | -- | OTLP headers as comma-separated key=value pairs (e.g. X-Scope-OrgID=1,Authorization=Bearer x). When set, replaces OTEL_EXPORTER_OTLP_HEADERS entirely; when empty, that env var is used. |
| `--otlp.insecure` | `OPNSENSE_EXPORTER_OTLP_INSECURE` | `false` | Disable TLS for the OTLP connection (plaintext). |
| `--otlp.protocol` | `OPNSENSE_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` | OTLP transport protocol: grpc or http/protobuf. Defaults to http/protobuf; an empty value is rejected. |
| `--otlp.service-name` | `OPNSENSE_EXPORTER_OTLP_SERVICE_NAME` | `opnsense-exporter` | service.name resource attribute for exported metrics. |
| `--otlp.tls-ca-file` | `OPNSENSE_EXPORTER_OTLP_TLS_CA_FILE` | -- | Path to a CA certificate file used to verify the OTLP server. |
| `--otlp.tls-cert-file` | `OPNSENSE_EXPORTER_OTLP_TLS_CERT_FILE` | -- | Path to a client certificate file for OTLP mutual TLS (requires --otlp.tls-key-file). |
| `--otlp.tls-key-file` | `OPNSENSE_EXPORTER_OTLP_TLS_KEY_FILE` | -- | Path to a client key file for OTLP mutual TLS (requires --otlp.tls-cert-file). |
| `--pyroscope.application-name` | `OPNSENSE_EXPORTER_PYROSCOPE_APPLICATION_NAME` | `opnsense-exporter` | Pyroscope application name profiles are reported under. |
| `--pyroscope.auth-password` | `OPNSENSE_EXPORTER_PYROSCOPE_AUTH_PASSWORD` | -- | HTTP basic auth password for Pyroscope (Grafana Cloud Access Policy token). This flag/ENV or PYROSCOPE_AUTH_PASSWORD_FILE may be set. |
| `--pyroscope.auth-user` | `OPNSENSE_EXPORTER_PYROSCOPE_AUTH_USER` | -- | HTTP basic auth user for Pyroscope (Grafana Cloud stack/instance ID). This flag/ENV or PYROSCOPE_AUTH_USER_FILE may be set. |
| `--pyroscope.enable-mutex-block` | `OPNSENSE_EXPORTER_PYROSCOPE_ENABLE_MUTEX_BLOCK` | `false` | Enable goroutine/mutex/block profiling (adds minor runtime overhead). |
| `--pyroscope.server-address` | `OPNSENSE_EXPORTER_PYROSCOPE_SERVER_ADDRESS` | -- | Grafana Cloud Pyroscope endpoint URL. When empty, continuous profiling is disabled. |
| `--pyroscope.tenant-id` | `OPNSENSE_EXPORTER_PYROSCOPE_TENANT_ID` | -- | Pyroscope tenant ID (only needed for multi-tenancy; unused for Grafana Cloud). |
| `--web.config.file` | -- | -- | Path to configuration file that can enable TLS or authentication. See: https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md |
| `--web.disable-exporter-metrics` | `OPNSENSE_EXPORTER_DISABLE_EXPORTER_METRICS` | -- | Exclude metrics about the exporter itself (process_*, go_*). |
| `--web.listen-address` | -- | `:8080` | Addresses on which to expose metrics and web interface. Repeatable for multiple addresses. Examples: `:9100` or `[::1]:9100` for http, `vsock://:9100` for vsock |
| `--web.systemd-socket` | -- | -- | Use systemd socket activation listeners instead of port listeners (Linux only). |
| `--web.telemetry-path` | `OPNSENSE_EXPORTER_WEB_TELEMETRY_PATH` | `/metrics` | Path under which to expose metrics. |
<!-- docgen:end:flags-full-reference -->
