---
title: Upgrading
description: Breaking changes and migration notes for OPNsense Exporter releases, including v2.0, v1.0 and migration from the upstream AthennaMind exporter
tags:
  - upgrading
  - migration
---

# Upgrading

This page lists breaking changes by release, most recent first, plus notes for users
migrating from the upstream AthennaMind exporter. Full details for every release:
[Changelog](changelog.md).

## Upgrading to v4.0 from v3.x

- **Scrape deadline compatibility surfaces removed** -
  the `exporter.scrape-timeout-offset` option (formerly passed with two leading
  hyphens),
  `opnsense_exporter_scrape_skips_total`, and the exporter's handling of
  `X-Prometheus-Scrape-Timeout-Seconds` have been removed. They became inert when
  collection moved to the background poll scheduler: `/metrics` now replays an
  in-memory snapshot and does not make OPNsense API calls. Remove the flag from
  deployment arguments and replace skip-counter alerts with scheduler freshness,
  duration, and failure signals. Prometheus's own `scrape_timeout` still bounds the
  HTTP request.

- **Log freshness gauges have stage-specific names** -
  `opnsense_exporter_logs_last_event_timestamp_seconds` has been removed. Use
  `opnsense_exporter_logs_last_received_timestamp_seconds{source}` to measure when
  the exporter last admitted input and
  `opnsense_exporter_logs_last_exported_timestamp_seconds{source}` to measure when
  the sink last acknowledged delivery. Both use the exporter clock; neither uses a
  sender-controlled event timestamp.

- **Container health uses the native `health` subcommand** - the distroless image
  now runs `opnsense-exporter health`, which probes `/-/healthy` without requiring a
  shell, `curl`, or `wget`. Custom images and Compose overrides that copied the old
  `wget` healthcheck should switch to this command. Docker health status alone does
  not trigger `restart:`; process exit or an external unhealthy-container
  remediation mechanism is still required for automatic replacement.

- **VLAN traffic on a trunk is now attributed by subnet, so interface labels move** -
  a NetFlow record captured on a trunk whose address falls inside exactly one VLAN
  child's configured subnet is now attributed to that child immediately, instead of
  waiting up to two seconds for the child's own copy to arrive and win. Nothing is
  dropped and no metric is renamed, but **per-interface flow volume shifts off the
  trunk and onto the VLAN children**, which is the correction: a production
  measurement found 29.2% of trunk/child pairs had a gap wider than the two-second
  window, and every one of those flows was being counted against the trunk. A further
  247,105 trunk-captured records over 18h35m had no child copy at all and could never
  have been attributed by timing. If you have dashboards or alerts with a hard-coded
  trunk interface name, or thresholds calibrated on trunk volume, expect both to
  change on upgrade. Two new counters make it observable:
  `opnsense_flow_vlan_subnet_attributed_total` counts the attributions and
  `opnsense_flow_vlan_late_child_copies_total` counts the residual that arrived too
  late to correct. The two-second hold remains for addresses that match no child
  subnet or several of them, so a VLAN with no configured subnet behaves exactly as
  before.

- **PF packet counters renamed with a `_total` suffix** - the eight
  `opnsense_firewall_{in,out}_{ipv4,ipv6}_{pass,block}_packets` series are now
  `..._packets_total`. They were always emitted as Prometheus counters, but the
  unsuffixed names only ever appeared on a direct `/metrics` scrape: OTLP-to-Prometheus
  canonicalization appends `_total` to every monotonic sum, so a stack fed through the
  OTLP bridge exposed only the `_total` names and every panel, recording rule, and alert
  written against the unsuffixed name silently returned no data. The descriptors now
  match what both paths expose. The sibling byte counters already carried `_total` and
  are unchanged. Update any custom dashboard, recording rule, or alert that referenced
  the unsuffixed names; the bundled Grafana dashboard and rules are already updated. The
  generated metric catalogue also now types all sixteen pf pass/block series as Counter
  - the eight packet series were previously mis-documented as Gauge.

- **IPsec and vnStat counters renamed with a `_total` suffix** - the eight
  `opnsense_ipsec_phase{1,2}_{bytes,packets}_{in,out}` series are now
  `..._{in,out}_total` (for example `opnsense_ipsec_phase1_bytes_in` is now
  `opnsense_ipsec_phase1_bytes_in_total`), and `opnsense_vnstat_total_bytes` is
  now `opnsense_vnstat_bytes_total`. All nine were always emitted as Prometheus
  counters, and OTLP-to-Prometheus canonicalization appends `_total` to every
  monotonic sum regardless of the Go-declared name, so the unsuffixed names
  would disagree with what the supported OTLP-fed live backend exports as soon
  as the series is populated (an IPsec tunnel exists, or vnStat is enabled) -
  the same convention violation #418 fixed for the firewall pf pass/block
  descriptors, closed here before it could bite in production. Update any
  custom dashboard, recording rule, or alert that referenced the unsuffixed
  names; the bundled Grafana dashboard is already updated. `vnstat_total_bytes`
  becomes `vnstat_bytes_total` rather than a mechanical `..._total_bytes_total`:
  "total" here has always meant "cumulative since vnstat's database was
  created," never "rx+tx combined," and the `direction` label carrying rx/tx is
  untouched by this rename.

- **Dashboard feature detection and log panels are now scoped to the selected
  instance** - the hidden feature sentinels that drive conditional rendering, and every
  Loki panel, previously searched the whole datasource. In a multi-firewall stack that
  made navigation lie: selecting appliance A could expose a tab because appliance B had
  the feature, and raw-log and top-talker panels could show another firewall's records.
  Prometheus sentinels now filter `opnsense_instance`, Loki queries filter
  `service_instance_id`, and runtime metrics with no appliance label join to
  `opnsense_up`. Three visible consequences after regenerating the dashboard: tabs for
  features the selected appliance lacks now correctly disappear; the Traffic Shaper and
  Captive Portal tabs now appear when the feature is deployed but idle, where a
  zero-count test previously hid them; and the NetFlow receiver rows are now gated on
  the exporter's own receiver metric rather than OPNsense's netflow-export setting, so
  they hide on a box that exports netflow without this exporter receiving it.

## Upgrading to v2.0 from v1.x

- **SMART collector is now opt-in** - the `opnsense_smart_*` metrics are no longer
  emitted by default. Set `--exporter.enable-smart` (env
  `OPNSENSE_EXPORTER_ENABLE_SMART=true`) to restore them. Querying SMART data is one
  of the more expensive per-scrape calls, so it now has to be requested explicitly.
- **ARP/NDP per-entry series are opt-in** - the per-entry `opnsense_arp_table_entries`
  and `opnsense_ndp_entries` series (one series per host, high cardinality) are no
  longer emitted by default. Set `--exporter.enable-arp-details` /
  `--exporter.enable-ndp-details` to restore them. Otherwise switch dashboards and
  alerts to the new `opnsense_arp_table_entries_total` /
  `opnsense_ndp_entries_total` aggregate gauges, which are always emitted.
- **`opnsense_firewall_interface_hits_total` renamed and re-typed** - it is now
  `opnsense_firewall_interface_log_entries_recent` and is a **gauge**, not a counter.
  It reflects the current count of recent log entries, so it no longer makes sense to
  wrap in `rate()`/`increase()` - plot the gauge directly. The bundled Grafana
  dashboard has already been updated.
- **Default instance label changed** - when `--exporter.instance-label` is unset, the
  `instance` label now defaults to the **configured OPNsense address** (deterministic
  across restarts) rather than the hostname reported by the API. To keep the old
  hostname-derived behaviour, set `--exporter.instance-use-hostname`; to pin an
  explicit value, set `--exporter.instance-label`. If you relied on the old default,
  existing series will change their `instance` label after the upgrade.
- **Portable Prometheus alert rules removed** - `grafana/alerts/opnsense.rules.yaml`
  no longer ships. If you were loading that file into Prometheus, Mimir, or the
  Grafana Cloud ruler, migrate to the Grafana-managed alert manifests under
  `grafana/alerts/grafana-managed/` (pushed as Grafana resources). See
  [Integration & Dashboards](integration-dashboards.md).
- **Unknown link state no longer reported as down** - interfaces whose link state the
  API reports as unknown (e.g. some PPPoE WANs) are now distinguished from interfaces
  that are actually down instead of being flattened to down. Alerts that treated "not up" as
  "down" may fire differently; check any rules built on interface link-state metrics.

## Upgrading to v1.0 from v0.x

- **IPsec SPI labels removed** - phase-2 metrics no longer carry `spi_in`/`spi_out`
  labels (remaining: `description`, `name`, `phase1_name`). SPIs rotate on every
  rekey, so the labels caused unbounded series churn. Update any PromQL that
  referenced them.
- **OpenVPN per-session metrics are opt-in** - the per-session
  `opnsense_openvpn_sessions` series (username and tunnel-address labels) is only
  emitted with `--exporter.enable-openvpn-details`. The aggregate
  `opnsense_openvpn_sessions_total` and `opnsense_openvpn_sessions_by_instance`
  series are always emitted. Set the flag to restore the old behaviour.
- **WireGuard handshake metric type** - `opnsense_wireguard_peer_last_handshake_seconds`
  changed from counter to gauge (it is a Unix timestamp). Replace
  `rate(opnsense_wireguard_peer_last_handshake_seconds[...])` with the purpose-built
  `opnsense_wireguard_peer_handshake_age_seconds` gauge.
- **`opnsense_up` semantics** - `opnsense_up` no longer flips to 0 for a box that is
  reachable but self-reports as degraded (e.g. a leftover crash report). Such a box
  now trips the warning-level `OPNsenseCrashReports` / `OPNsenseFirewallUnhealthy`
  alerts instead of the critical `OPNsenseExporterDown`. If you alerted on
  `opnsense_up == 0` for these cases, switch to those signals.

## Migrating from upstream (AthennaMind/opnsense-exporter)

In addition to the items above:

- **Image and module path** - pull `ghcr.io/rknightion/opnsense-exporter`; the Go
  module is `github.com/rknightion/opnsense-exporter`.
- **`--runtime.gomaxprocs` removed** - Go now auto-detects CPUs; delete the flag from
  any unit files or manifests.
- **`/debug/pprof/*` endpoints removed** - replaced by optional authenticated push
  profiling via `--pyroscope.*` flags. See
  [Configuration](configuration.md#continuous-profiling-pyroscope).
- **Firmware metrics reworked** - version strings consolidated into
  `opnsense_firmware_info` (labels) plus numeric gauges (`needs_reboot`,
  `upgrade_needs_reboot`, `last_check_timestamp_seconds`, `new_packages_count`,
  `upgrade_packages_count`).
- **`--exporter.instance-label` now optional** - when left empty it defaults to the
  configured OPNsense address (see the v2.0 note above for the change from the old
  hostname default; set `--exporter.instance-use-hostname` for hostname-derived
  labels).
- **Many new collectors are enabled by default** - review the
  [collector switches](configuration.md#collector-switches) and disable what you
  don't need.
