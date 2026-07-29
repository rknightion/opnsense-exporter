---
title: Troubleshooting
description: Diagnosing common OPNsense Exporter problems - opnsense_up=0, missing metrics, permission errors, slow scrapes, and TLS failures
tags:
  - troubleshooting
---

# Troubleshooting

If nothing here matches what you are seeing, search the
[existing GitHub issues](https://github.com/rknightion/opnsense-exporter/issues), ask in
[GitHub Discussions](https://github.com/rknightion/opnsense-exporter/discussions), or
[file a bug report](https://github.com/rknightion/opnsense-exporter/issues/new) with the exporter
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
  exporter treats it as "feature absent" by design.
- **Endpoint errors?** Check `opnsense_exporter_endpoint_errors_total` and the
  exporter logs for the failing endpoint.
- **Unbound statistics empty?** Enable *Unbound DNS > Advanced > Extended Statistics*
  on the firewall.

## Data is stale or collector polls are slow

Prometheus scrapes replay an in-memory snapshot; they do not fan out to OPNsense.
With ~63 collectors polling on independent schedules, use the per-collector clocks
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

## Where are the exporter's own logs?

The exporter logs to stdout (`--log.format=logfmt|json`, `--log.level=debug|info|warn|error`).
In Docker/Kubernetes use `docker logs` / `kubectl logs` on the container.
