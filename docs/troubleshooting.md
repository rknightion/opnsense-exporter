---
title: Troubleshooting
description: Diagnosing common opnsense2otel problems - opnsense_up=0, missing metrics, permission errors, slow scrapes, and TLS failures
tags:
  - troubleshooting
---

# Troubleshooting

If nothing here matches what you are seeing, search the
[existing GitHub issues](https://github.com/rknightion/opnsense2otel/issues), ask in
[GitHub Discussions](https://github.com/rknightion/opnsense2otel/discussions), or
[file a bug report](https://github.com/rknightion/opnsense2otel/issues/new) with the exporter
version, your OPNsense release, and the relevant log lines.

## `opnsense_up` is 0

`opnsense_up 0` means the exporter could not complete the OPNsense health check. Work through:

1. **Connectivity** - can the exporter host reach the firewall?
   `curl -k https://<opnsense-address>/api/core/system/status -u "<key>:<secret>"`
2. **Credentials** - a `401` from the curl above means the API key/secret is wrong or
   the user is disabled. Regenerate the key pair under
   *System > Access > Users > [user] > API keys*.
3. **Permissions** - a `403` means the API user lacks privileges. Grant the
   permissions listed in [Security](security.md).
4. **TLS** - a certificate error means the firewall uses a self-signed or private-CA
   certificate. Either add the CA to the exporter's trust store (see
   [Docker deployment](deployment/docker.md#custom-ca-certificates)) or, for testing
   only, set `--opnsense.insecure`.

Run with `--log.level=debug` to see each API call and its failure reason.

## A collector's metrics are missing

- **Disabled?** Check `opnsense_exporter_collector_enabled{collector="<name>"}` - `0`
  means a `--exporter.disable-*` flag (or missing `--exporter.enable-*` flag for
  opt-in collectors) removed it. See [Configuration](configuration.md#collector-switches).
- **Plugin absent?** Plugin-backed collectors (ACME, SMART, DynDNS, ISC DHCPv4) stay
  silent when the OPNsense plugin is not installed - the API returns 404 and the
  exporter treats it as "feature absent" by design. Ask the exporter rather than
  guessing: `opnsense_feature_available{feature="<name>"}` is `1` when the plugin
  answered and `0` when it returned 404, and the `enabled` label says whether that
  collector is switched on. **No series at all** means availability has never been
  determined - not that the plugin is missing.
- **Installed but not being scraped?** `opnsense_feature_available{enabled="false"} == 1`
  lists every plugin the box has that nothing is reading, which covers both an opt-in
  collector nobody turned on and a default-on one somebody disabled. The exporter also
  names each one, with the flag that would enable it, in a `feature available but its
  collector is not enabled` log line - and a `plugin inventory` line summarising the
  counts. `--exporter.enable-all-available` turns on every collector whose plugin the
  startup probe found present.
- **Endpoint errors?** Check `opnsense_exporter_endpoint_errors_total` and the
  exporter logs for the failing endpoint.
- **Unbound statistics empty?** Enable *Unbound DNS > Advanced > Extended Statistics*
  on the firewall.

## Push receivers: nothing arrives

Syslog, Zenarmor, and NetFlow are push lanes, so a quiet dashboard can mean that
the sender never reached the exporter, the receiver rejected the input, or the
OTLP sink has not acknowledged it. Start with the receiver self-metrics on
`/metrics`:

- `opnsense_exporter_logs_shipped_total{source="syslog"}` and
  `opnsense_exporter_logs_shipped_total{source="zenarmor"}` count records the
  sink confirmed as delivered. Flow-log records use `source="netflow"` or
  `source="merged"`.
- `opnsense_exporter_logs_rejected_total{source="<receiver>",reason="<reason>"}`
  counts input refused before parsing. The `source` is `syslog` or `zenarmor`;
  `reason` identifies the allowlist, authentication, body, filter, capacity, or
  endpoint path that refused it.
- `opnsense_exporter_logs_parse_errors_total{source="<receiver>",stage="<stage>"}`
  means the record arrived but lost structure while parsing; the raw record still
  ships. Syslog reports `stage="envelope"`; Zenarmor reports `stage="bulk"` or
  `stage="document"`.
- If input is arriving but acknowledgement is not, check
  `opnsense_exporter_logs_dropped_total{source="<source>",reason="<reason>"}`
  and `opnsense_exporter_logs_ship_errors_total` for queue or destination
  failures.

Then follow the receiver-specific checklist:

- [Syslog receiver](syslog-receiver.md#troubleshooting) - verify both UDP and TCP
  publication, the enabled OPNsense target, and the peer allowlist.
- [Zenarmor receiver](zenarmor-receiver.md#troubleshooting) - verify the selected
  transport, its destination URI/port, and the matching receiver switch.
- [NetFlow and flow volume](flow.md#troubleshooting) - verify the OPNsense
  **Reporting → NetFlow** export target, UDP reachability, and template/decoder
  counters.

## Data is stale or collector polls are slow

Prometheus scrapes replay an in-memory snapshot; they do not fan out to OPNsense.
With ~81 collectors polling on independent schedules, use the per-collector clocks
to isolate stale data or a background collector missing its schedule:

- Check `opnsense_exporter_collector_snapshot_timestamp_seconds` and
  `opnsense_exporter_collector_last_success_timestamp_seconds` for retained-data
  age, then `opnsense_exporter_scrape_collector_duration_seconds` for the latest
  scheduled poll duration. The `scrape_` prefix is retained for compatibility.
- Check `opnsense_exporter_endpoint_errors_total` and per-endpoint request latency
  to identify the slow or failing OPNsense call.
- `--exporter.max-scrape-duration` is now the outer deadline for one background
  collector poll. `--opnsense.timeout` × `--opnsense.max-retries` bounds an endpoint
  attempt sequence inside it; keep that product below the poll deadline.
- Lower `--opnsense.max-concurrent-requests` to protect a low-power appliance, or
  raise it when independent polls are queuing behind the concurrency cap.
- The `activity` collector runs a `top(1)`-equivalent snapshot and is commonly the
  slowest default-on poll. SMART performs one `smartctl -a` POST per disk on each
  scheduled poll and can wake spun-down disks; it remains opt-in.

Prometheus `scrape_timeout` still bounds the `/metrics` HTTP request, but changing
it cannot change OPNsense API polling.

## Too many time series

The detail flags (`--exporter.enable-*-details`) emit one series per DHCP lease,
firewall rule, or VPN session and can produce thousands of series on busy networks.
Leave them off unless you need per-item data, and review
[high-cardinality options](configuration.md#high-cardinality-detail-options).

## What configuration is actually in force?

The exporter logs its **entire resolved configuration at startup**, at `Info`, one entry
per section (`effective config: Connection`, `effective config: Collectors`, and so on).
That is the resolved view - after file-based secrets are read and after
`--exporter.enable-all-available` and its availability probe have been applied - so it is
what the process is running, not what was typed. Credentials appear only as `set` or
`unset`, never as values.

A `plugin inventory` line follows once the first availability probe completes. It is
separate on purpose: availability needs the firewall to answer, and printing a
confidently empty list while the box is unreachable would be worse than printing it a
few seconds late.

The same content is available two other ways, rendered from the same source: the
`/config` page of the operator console, and `--config.check`, which prints it and exits
without contacting the firewall.

## Where are the exporter's own logs?

The exporter logs to stdout (`--log.format=logfmt|json`, `--log.level=debug|info|warn|error`).
In Docker/Kubernetes use `docker logs` / `kubectl logs` on the container.
