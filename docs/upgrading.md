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

- **CPU metrics are now cumulative counters fed by a stream, not percentage gauges** -
  `opnsense_activity_cpu_user_percent` and its `nice`/`system`/`interrupt`/`idle`
  siblings are **removed**. CPU utilisation now comes from
  `opnsense_cpu_seconds_total{mode="user|nice|system|interrupt|idle"}`, so a panel or
  alert reading the old gauges must become
  `100 * rate(opnsense_cpu_seconds_total[$__rate_interval])`. The bundled dashboard
  and rules are already migrated.

  This is a better number, not merely a renamed one. The old gauges came from
  `diagnostics/activity/get_activity`, which is a **2.15-second** call on the firewall
  because OPNsense runs `top -aHSTn -d2` and waits out top's inter-display delay - a
  permanent 14% firewall duty cycle at a 15s poll, 1.9 GB/day of payload, and it
  sampled two seconds in every fifteen, so **87% of the timeline was never observed**.
  The exporter now holds one Server-Sent Events connection to
  `api/diagnostics/cpu_usage/stream` (`iostat -w 1`), sees **every** second, and costs
  the firewall about 70 bytes/sec and no process-table walk. The `activity` collector
  survives for thread-state counts only and has moved to the 60s tier.

  Two operational consequences worth knowing before you upgrade:

    - **A new outbound long-lived connection ships on by default.** It holds one
      php-cgi worker on the firewall (~2.5% of the measured 40-worker capacity) plus a
      persistent `iostat`, permanently. Disable it with `--exporter.disable-cpu`,
      which leaves the box with no CPU utilisation series at all.
    - **`cpu_seconds_total` goes ABSENT, not flat, when the stream dies.** The
      exporter re-dials on a stall, but recovery bounds an outage rather than removing
      it - during a firewall reboot there is nothing to reconnect to. After one export
      interval of silence the counters are withdrawn, because a frozen counter reads
      as an idle CPU under `rate()` and is silently wrong. `opnsense_cpu_stream_up`,
      `opnsense_cpu_stream_last_frame_age_seconds` and
      `opnsense_cpu_stream_counters_published` are exported throughout so the cause is
      visible; `OPNsenseCPUStreamStalled` alerts on frame age, not on connectedness,
      because this endpoint's documented failure mode is keepalives continuing after
      the data stops.

- **GeoIP enrichment is now ON by default, and the image bundles a database** -
  `--geoip.enabled` defaults to `true`, and the container image ships the DB-IP Lite
  Country and ASN databases at `/usr/share/opnsense-exporter/geoip/`, which are the
  new default values of `--geoip.country-database` / `--geoip.asn-database`. A
  container deployment that had never configured GeoIP now emits
  `<src|dst>.geo.*` attributes on flow records **and on filterlog, sshd/auth and
  Suricata log lines** - filterlog is the highest-volume log stream on the box, so
  this is a real per-line ingest cost (~116 B on a line that resolves, measured) with
  no config change. Set `--geoip.enabled=false` to opt out entirely, or
  `--logs.syslog.geoip=false` to keep geo on flow records only. MaxMind still wins
  outright wherever it is configured, and an explicit database path is never
  overridden. Two things to know: **DB-IP Lite is a reduced-accuracy subset** (country
  is >95% accurate, city is not - see [GeoIP](geoip.md#accuracy-read-this-before-trusting-a-city)),
  and **non-container builds carry no database at all** and simply enrich nothing.
  `OPNsenseFlowGeoIPDatabaseStale` alerts at 14 days, while DB-IP republishes
  monthly, so expect that alert to fire on the bundled databases unless you retune
  it. Attribution: IP geolocation data by [DB-IP](https://db-ip.com), CC BY 4.0.

- **Six redundant Zenarmor structured-metadata keys are no longer shipped** -
  `organization`, `policyid`, `src_geoip.latitude`, `src_geoip.longitude`,
  `dst_geoip.latitude` and `dst_geoip.longitude` are no longer attributed onto each
  record, and the OTLP instrumentation scope name is now empty so Loki stops adding
  `scope_name`. Structured metadata is billed as ingested volume, and these measured
  ~231 bytes per line of pure repetition on the largest log source. **Every one of
  them is still in the log body**, which is unchanged, so a line-level lookup still
  has them; only the re-extracted copy is gone. A LogQL filter using
  `| organization=`, `| policyid=`, `| scope_name=` or either coordinate pair will
  stop matching - drop the filter, or read the value out of the body with `| json`.
  Nothing in the bundled dashboard, alert rules or exported metrics consumed any of
  them. **`--logs.zenarmor.exclude` rules naming `organization` or `policyid` now
  fail at startup** as unknown fields; such a rule was always either a no-op or a
  total drop, because both keys carry exactly one value per deployment.

- **`opnsense_exporter_otlp_*` now carries the `opnsense_instance` label** -
  the four OTLP delivery-health series (`otlp_enabled`,
  `otlp_exports_total{result}`, `otlp_consecutive_failures`,
  `otlp_last_success_timestamp_seconds`) were registered without appliance
  identity, so on a multi-firewall stack there was no way to tell whose push
  pipeline had stalled. They now carry `opnsense_instance` like every other
  `opnsense_exporter_*` family. **A recording rule, alert or dashboard query that
  aggregates these series without `by (opnsense_instance)` will now return one
  series per exporter instead of one overall** - add the grouping, or use
  `sum without (opnsense_instance) (...)` to keep the old shape. Single-instance
  deployments see no change beyond the extra label. The bundled dashboard and
  rules are already updated.

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
