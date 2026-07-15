---
title: Troubleshooting
description: Diagnosing common OPNsense Exporter problems — opnsense_up=0, missing metrics, permission errors, slow scrapes, and TLS failures
tags:
  - troubleshooting
---

# Troubleshooting

## `opnsense_up` is 0

`opnsense_up 0` means the exporter could not complete the OPNsense health check. Work through:

1. **Connectivity** — can the exporter host reach the firewall?
   `curl -k https://<opnsense-address>/api/core/system/status -u "<key>:<secret>"`
2. **Credentials** — a `401` from the curl above means the API key/secret is wrong or
   the user is disabled. Regenerate the key pair under
   *System > Access > Users > [user] > API keys*.
3. **Permissions** — a `403` means the API user lacks privileges. Grant the
   permissions listed in [Security](security.md).
4. **TLS** — a certificate error means the firewall uses a self-signed or private-CA
   certificate. Either add the CA to the exporter's trust store (see
   [Docker deployment](deployment/docker.md#custom-ca-certificates)) or, for testing
   only, set `--opnsense.insecure`.

Run with `--log.level=debug` to see each API call and its failure reason.

## A collector's metrics are missing

- **Disabled?** Check `opnsense_exporter_collector_enabled{collector="<name>"}` — `0`
  means a `--exporter.disable-*` flag (or missing `--exporter.enable-*` flag for
  opt-in collectors) removed it. See [Configuration](configuration.md#collector-switches).
- **Plugin absent?** Plugin-backed collectors (ACME, SMART, DynDNS, ISC DHCPv4) stay
  silent when the OPNsense plugin is not installed — the API returns 404 and the
  exporter treats it as "feature absent" by design.
- **Endpoint errors?** Check `opnsense_exporter_endpoint_errors_total` and the
  exporter logs for the failing endpoint.
- **Unbound statistics empty?** Enable *Unbound DNS > Advanced > Extended Statistics*
  on the firewall.

## Scrapes are slow or time out

Each scrape fans out to ~61 collectors in parallel; total scrape time is bounded by
the slowest OPNsense API endpoint. If scrapes approach your Prometheus
`scrape_timeout`:

- Check `opnsense_exporter_scrape_collector_duration_seconds` (per-collector,
  labelled by `collector`) to see which collector is actually slow before
  disabling anything.
- The `activity` collector is usually the single slowest default-on collector: it
  runs a `top(1)`-equivalent snapshot (load averages + a per-process array) on the
  firewall every scrape — commonly ~2-2.5s on a modest box, vs tens of ms for most
  other endpoints. Disable it with `--exporter.disable-activity` if you don't need
  per-process/load metrics.
- Disable other collectors you don't need (`--exporter.disable-*`).
- The SMART collector performs one POST per disk per scrape (running `smartctl`
  on the firewall); it is opt-in (`--exporter.enable-smart`) — leave it off if
  your hardware is slow to answer or you use spun-down disks.
- Raise `scrape_timeout`/`scrape_interval` in your Prometheus job (30s+ intervals are
  fine for firewall metrics).

## Too many time series

The detail flags (`--exporter.enable-*-details`) emit one series per DHCP lease,
firewall rule, or VPN session and can produce thousands of series on busy networks.
Leave them off unless you need per-item data, and review
[high-cardinality options](configuration.md#high-cardinality-detail-options).

## Where are the exporter's own logs?

The exporter logs to stdout (`--log.format=logfmt|json`, `--log.level=debug|info|warn|error`).
In Docker/Kubernetes use `docker logs` / `kubectl logs` on the container.
