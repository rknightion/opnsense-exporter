# OPNsense Prometheus Exporter

> **Fork notice:** This is a fork of [AthennaMind/opnsense-exporter](https://github.com/AthennaMind/opnsense-exporter), the original OPNsense Prometheus exporter. This fork includes significant additions and changes beyond the scope of the upstream project. Full credit to the original AthennaMind authors for building the foundation this work is based on.

![GitHub License](https://img.shields.io/github/license/rknightion/opnsense-exporter)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/rknightion/opnsense-exporter/ci.yml)
![GitHub go.mod Go version (branch)](https://img.shields.io/github/go-mod/go-version/rknightion/opnsense-exporter/main)

## Table of Contents

- **[Changes from Upstream](#changes-from-upstream)**
- **[About](#about)**
- **[Grafana Dashboard](#grafana-dashboard)**
- **[Full Documentation](https://m7kni.io/opnsense-exporter/)**
- **[Metrics List](https://m7kni.io/opnsense-exporter/metrics/metrics/)**
- **[Contributing](./CONTRIBUTING.md)**
- **[OPNsense User Permissions](#opnsense-user-permissions)**
- **[Usage](#usage)**
  - **[Docker](#docker)**
  - **[Docker Compose](#docker-compose)**
  - **[Systemd](#systemd)**
  - **[K8s](./deploy/k8s/readme.md)**
- **[Configuration](#configuration)**
  - **[OPNsense API](#opnsense-api)**
  - **[SSL/TLS](#ssltls)**
  - **[Collector Options](#collector-options)**
  - **[All Options](#all-options)**

## Changes from Upstream

This fork diverges from [AthennaMind/opnsense-exporter](https://github.com/AthennaMind/opnsense-exporter) with the following additions and changes:

### New Collectors

- **System resources collector** — New collector exposing memory (total, used, ZFS ARC), system uptime, load averages (1/5/15 min), configuration last change timestamp, per-device disk usage (total, used, ratio), and per-device swap usage. Polls 4 API endpoints. Includes new `--exporter.disable-system` / `OPNSENSE_EXPORTER_DISABLE_SYSTEM` flag.
- **Dnsmasq DHCP lease collector** — New collector exposing dnsmasq lease metrics: total leases, leases by interface, reserved vs dynamic counts, and optional per-lease detail metrics (enabled via `--exporter.enable-dnsmasq-details`). Includes new `--exporter.disable-dnsmasq` flag.
- **Temperature collector** — New collector exposing hardware temperature readings (`opnsense_temperature_celsius`) with per-device labels (device, type, device_seq). Polls `api/diagnostics/system/systemTemperature`. Includes new `--exporter.disable-temperature` / `OPNSENSE_EXPORTER_DISABLE_TEMPERATURE` flag.
- **Firewall rule statistics collector** — New collector exposing a summary metric (total rules count) by default, with opt-in high-cardinality per-rule detail metrics (evaluations, packets, bytes, active states, PF rule count) with rule metadata labels (UUID, description, action, interface, direction). Detail metrics are enabled via `--exporter.enable-firewall-rules-details` / `OPNSENSE_EXPORTER_ENABLE_FIREWALL_RULES_DETAILS` and fetch 2 API endpoints, joining rule stats with metadata. Includes new `--exporter.disable-firewall-rules` / `OPNSENSE_EXPORTER_DISABLE_FIREWALL_RULES` flag.
- **Mbuf statistics collector** — New collector exposing FreeBSD network buffer (mbuf) statistics: current/cache/total mbuf counts, cluster counts and max, allocation failures and sleeps by type (mbuf, cluster, packet, jumbop), and memory bytes in use/total. Polls `api/diagnostics/system/systemMbuf`. Includes new `--exporter.disable-mbuf` / `OPNSENSE_EXPORTER_DISABLE_MBUF` flag.
- **NTP collector** — New collector exposing NTP peer metrics: peer info, stratum, seconds since last response, poll interval, reachability register (octal decoded), round-trip delay, clock offset, and jitter (all in milliseconds), plus total peer count. Polls `api/ntpd/service/status`. Includes new `--exporter.disable-ntp` / `OPNSENSE_EXPORTER_DISABLE_NTP` flag.
- **Certificate expiry collector** — New collector exposing certificate validity timestamps (valid_from, valid_to as Unix epoch seconds), certificate info, and total certificate count with description, common name, cert type, and in-use labels. Enables alerting on approaching expiry. Polls `api/trust/cert/search`. Includes new `--exporter.disable-certificates` / `OPNSENSE_EXPORTER_DISABLE_CERTIFICATES` flag.
- **CARP/VIP status collector** — New collector exposing CARP high-availability metrics: demotion counter, allow status, maintenance mode, total VIP count, and per-VIP status (MASTER/BACKUP/INIT), advertisement base interval, and advertisement skew. Polls `api/diagnostics/interface/get_vip_status`. Includes new `--exporter.disable-carp` / `OPNSENSE_EXPORTER_DISABLE_CARP` flag.
- **System activity collector** — New collector exposing CPU usage percentages (user, nice, system, interrupt, idle) and thread counts (total, running, sleeping, waiting) parsed from the activity API headers. Polls `api/diagnostics/activity/get_activity`. Includes new `--exporter.disable-activity` / `OPNSENSE_EXPORTER_DISABLE_ACTIVITY` flag.
- **Kea DHCP lease collector** — New collector exposing Kea DHCPv4 and DHCPv6 lease metrics: total leases, leases by interface, reserved vs dynamic counts, and optional per-lease detail metrics (enabled via `--exporter.enable-kea-details`). Polls both `api/kea/leases4/search` and `api/kea/leases6/search`. Includes new `--exporter.disable-kea` / `OPNSENSE_EXPORTER_DISABLE_KEA` flag.
- **Network diagnostics collector** — New opt-in collector exposing kernel network ISR statistics (dispatched, hybrid dispatched, queued, handled, queue drops, queue length/watermark/limit per protocol), active socket counts by type, UNIX domain socket count, and routing table counts by protocol. Polls 3 API endpoints. Disabled by default; enable with `--exporter.enable-network-diagnostics` / `OPNSENSE_EXPORTER_ENABLE_NETWORK_DIAGNOSTICS=true`.
- **NetFlow collector** — New opt-in collector exposing netflow service status (enabled, local collection, active state, collector count) and per-interface cache statistics (packets total, unique source/destination IP addresses). Polls 3 API endpoints (`isEnabled`, `status`, `cacheStats`). Disabled by default; enable with `--exporter.enable-netflow` / `OPNSENSE_EXPORTER_ENABLE_NETFLOW=true`.
- **PF statistics deep dive collector** — New collector exposing detailed PF (packet filter) internals: state table entries/searches/inserts/removals, 16 PF counters (match, bad-offset, fragment, state-mismatch, map-failed, etc.), 10 limit counters (max-states-per-rule, synfloods-detected, syncookies, etc.), memory pool limits (states, src-nodes, frags, table-entries), and protocol timeout configurations. Polls 3 `pf_statistics` sub-endpoints. Includes new `--exporter.disable-pf-stats` / `OPNSENSE_EXPORTER_DISABLE_PF_STATS` flag.
- **NDP (IPv6 neighbor discovery) table collector** — New collector exposing IPv6 neighbor entries with IP, MAC, interface, and type labels (mirrors the ARP table collector for IPv6). Includes new `--exporter.disable-ndp` / `OPNSENSE_EXPORTER_DISABLE_NDP` flag.
- **ISC DHCPv4 lease collector** — New collector exposing ISC DHCPv4 lease metrics from the legacy `isc-dhcp` plugin: total leases, leases by interface, static (reserved) vs dynamic counts, and optional per-lease detail metrics (enabled via `--exporter.enable-dhcpv4-details` / `OPNSENSE_EXPORTER_ENABLE_DHCPV4_DETAILS`). Detail metrics include address, hostname, MAC, interface, type, state, and online status labels. Polls `api/dhcpv4/leases/searchLease`. The legacy ISC DHCP backend is deprecated/absent on modern OPNsense (the endpoint then returns 404, verified on 26.1); this is handled gracefully as "feature absent" (empty data, no error logging) so the collector stays quiet on boxes without it. Includes new `--exporter.disable-dhcpv4` / `OPNSENSE_EXPORTER_DISABLE_DHCPV4` flag.
- **ACME client certificate collector** — New collector exposing renewal status and expiry information for certificates managed by the `os-acme-client` plugin: total certificate count, per-certificate enabled state, numeric ACME status code (last operation result), last renewal timestamp, last ACME run timestamp, and an info metric with name/description/SAN labels. If the `os-acme-client` plugin is not installed the endpoint returns 404 (verified on OPNsense 26.1); this is handled gracefully as "feature absent" (empty data, no error logging). Polls `api/acmeclient/certificates/search`. Includes new `--exporter.disable-acme` / `OPNSENSE_EXPORTER_DISABLE_ACME` flag.
- **SMART disk health collector** — New opt-in collector exposing disk SMART data from the `os-smart` plugin via per-disk form-encoded POST fanout: total device count (`opnsense_smart_devices_total`), overall SMART health pass/fail per device with model and serial labels (`opnsense_smart_device_health`), current drive temperature in Celsius (`opnsense_smart_device_temperature_celsius`), and total power-on hours (`opnsense_smart_device_power_on_hours`). All per-disk metrics are only emitted when the corresponding field is present in the smartctl JSON output, making the collector tolerant of mixed SATA/NVMe/USB drive fleets. If the `os-smart` plugin is absent the list endpoint returns 404 and the collector stays silent (empty data, no error logging; verified on OPNsense 26.1). Enabled by default; disable with `--exporter.disable-smart` / `OPNSENSE_EXPORTER_DISABLE_SMART=true`. Note it makes one `list` plus one `info` POST per disk on every scrape.
- **DynDNS (ddclient) account collector** — New collector exposing per-account Dynamic DNS update status from the `os-ddclient` plugin (`api/dyndns` namespace): total configured account count (`opnsense_dyndns_accounts_total`), per-account enabled state (`opnsense_dyndns_account_enabled`, labels: description, service, hostnames, interface), last successful update timestamp in Unix seconds (`opnsense_dyndns_account_last_update_timestamp_seconds`, labels: description, service, hostnames — only emitted when `current_mtime` is non-empty; use `time() - this` to alert on stale updates), an info metric carrying the currently registered IP address (`opnsense_dyndns_account_info`, labels: description, service, hostnames, zone, interface, current_ip), and ddclient service running state (`opnsense_dyndns_service_running`). Passwords are intentionally never captured. If the `os-ddclient` plugin is absent the endpoint returns 404; this is handled gracefully as "feature absent" (empty data, no error logging). Enabled by default; disable with `--exporter.disable-dyndns` / `OPNSENSE_EXPORTER_DISABLE_DYNDNS=true`.

### Enhanced Collectors

- **Gateways** — Added 4 new per-gateway metrics emitted unconditionally (regardless of enabled/monitor state): `opnsense_gateways_force_down` (1 if administratively forced down, 0 otherwise), `opnsense_gateways_virtual` (1 if virtual, 0 otherwise), `opnsense_gateways_dynamic` (1 if dynamically configured, 0 otherwise), and `opnsense_gateways_priority` (numeric priority value; skipped entirely when the API returns an empty priority string to avoid misleading zeros). All four use `name` and `address` labels, where `address` is the gateway IP (`gateway` field) so they are emitted for every gateway including unmonitored ones (the RTT/loss metrics key `address` on the monitor target instead, and only exist when monitoring is enabled). Field presence verified against a live OPNsense 26.1 box.
- **Interfaces** — Added 8 new metrics: received/transmitted packet totals, send queue length/max/drops, input queue drops, link state, and line rate.
- **Protocol statistics** — Added 28 new metrics covering CARP (received/sent/dropped), pfsync (received/sent/dropped/errors), IP (received/forwarded/sent/dropped/fragments/reassembled), TCP (connections requested/accepted/established/closed/dropped, retransmit/keepalive timeouts, listen queue overflows, syncache entries), and ARP (sent failures/replies, received replies/packets, dropped no entry, entry timeouts). Additionally added 11 expanded metrics: TCP sent data bytes, retransmitted packets/bytes, received in-sequence/duplicate bytes, segments updated RTT, bad connection attempts, keepalive probes, syncache dropped; IP sent fragments; ARP dropped duplicate address.
- **Unbound DNS** — Comprehensive overhaul adding 26 new metrics: query totals, cache hits/misses, prefetch/expired counts, recursive replies, timed-out/rate-limited queries, DNSSEC secure/bogus answers, queries by type and protocol, answers by rcode, unwanted queries, query flags, EDNS counts, request list stats (avg/max/current/overwritten/exceeded), recursion time (avg/median), cache counts by type, and memory usage by component. Also added TCP usage ratio metric and DNS blocklist enabled status.
- **Firewall PF statistics** — Added 8 byte counter metrics (IPv4/IPv6 pass/block bytes by interface) complementing the existing packet counters. Added PF state table metrics (current states, state limit) for capacity monitoring.
- **Health check** — Added `opnsense_system_status_code` gauge exposing the numeric system status code from the health check API (2 = OK for OPNsense >= 25.1).
- **Health check** — Added `opnsense_crash_reporter_status` gauge (1 = ok/no crash reports, 0 = crash reports present) from the same `api/core/system/status` response, which was previously parsed but never exported. Left absent (not emitted as a misleading `0`) when OPNsense is unreachable.
- **Unbound DNS / Dnsmasq / IPsec / Wireguard** — Added `service_running` gauge to each collector (1 = running, 0 = stopped/disabled) via per-subsystem service status API endpoints.
- **WireGuard** — Added `opnsense_wireguard_peer_handshake_age_seconds` gauge: seconds elapsed since a peer's last successful handshake. Only emitted for peers that have completed at least one handshake (`latest-handshake > 0`); peers that have never handshaked are omitted to avoid misleading multi-decade values. Uses an injectable clock for deterministic testing.
- **Firmware** — Reworked metrics to follow Prometheus best practices: consolidated version strings into a single `opnsense_firmware_info` metric with labels, replaced value-in-label anti-patterns with proper numeric gauges (`needs_reboot`, `upgrade_needs_reboot`, `last_check_timestamp_seconds`, `new_packages_count`, `upgrade_packages_count`).
- **System resources** — Added `opnsense_system_info` gauge (always 1) with labels for hostname, OPNsense version, FreeBSD version, OpenSSL version, CPU model, cores, and threads. Polls 2 additional endpoints (`system_information`, `getCPUType`). Partial failure tolerant — existing system metrics still work if these new endpoints fail.
- **Mbuf statistics** — Added jumbo9 and jumbo16 buffer types to failure and sleep counters, plus 3 new sendfile metrics (`sendfile_syscalls_total`, `sendfile_io_total`, `sendfile_pages_sent_total`). Polls an additional `get_memory_statistics` endpoint with partial failure tolerance.
- **Firewall PF statistics** — Added `opnsense_firewall_interface_hits_total` counter showing per-interface rule match counts from the aggregate stats endpoint. Partial failure tolerant.
- **Network diagnostics** — Added pfsync HA cluster metrics: `pfsync_nodes_total` gauge and per-node `pfsync_node_info` with creatorid and is_local labels. Partial failure tolerant.
- **Exporter self-observability** — Added two always-on exporter-level metrics: `opnsense_exporter_build_info` (value 1, with `version` and `goversion` labels) for pinning the running build, and `opnsense_exporter_collector_enabled{collector="<subsystem>"}` (1 = enabled, 0 = disabled) emitted for every registered collector so dashboards/alerts can distinguish "collector disabled" from "feature absent / no data". Both carry the `opnsense_instance` label and are surfaced on the dashboard's Diagnostics tab.

### Bug Fixes

- **False `opnsense_firewall_status=0` on OPNsense 25.1+** — The firewall health was derived assuming a per-`Firewall` entry always exists in the health-check response. On OPNsense 25.1+/26.1 a healthy box reports an OK overall system status (`metadata.system.status = 2`) and **omits** the `Firewall` subsystem entirely (empty `subsystems`), so the exporter could not find a firewall status and defaulted the metric to `0` — making `opnsense_firewall_status` (and any alert on it) report a perfectly healthy firewall as unhealthy. Firewall health is now derived like the crash-reporter status: healthy by default, flagged `0` only on an explicit not-OK signal (legacy string status, or a 25.1+ metadata status that is present and not the OK code), tolerating numeric/string/absent metadata values.
- **OPNsense 26.1 API-compatibility sweep** — A systematic audit of every collector's structs/parsing against the live OPNsense 26.1 API surfaced a batch of expectation-vs-reality mismatches (the same bug class as the firewall-health issue above), now fixed:
  - **Interface link state always 0** — `opnsense_interfaces_link_state` reported every interface down. Modern OPNsense returns `link state` as a numeric string (`"2"` = up, `"0"`/`"1"` = down/unknown), but the code matched the old human string (`"link state is up"`). Now handles both shapes.
  - **DHCP reserved leases miscounted as dynamic** — `opnsense_dnsmasq_leases_reserved_total` and the Kea equivalents read `0` on boxes with reservations. The live API encodes `is_reserved` as a JSON array (`["hwaddr"]` = reserved, `[]` = dynamic), but the tolerant `flexString` collapsed any array to `""`, so the `== "1"` check never matched. Added a `flexBool` type (non-empty array → true) used by dnsmasq and Kea.
  - **Socket statistics discarded entirely** — `opnsense_network_diag_sockets_active` emitted a single bogus `{type="statistics"}=1` series and `sockets_unix_total` was always 0. The API nests sockets under a top-level `statistics` object (`Active Internet connections` / `Active UNIX domain sockets`); the parser iterated the wrong level. Now walks both sections, counting Internet sockets by protocol and Unix sockets by section.
  - **mbuf byte metrics 1024× too small** — `opnsense_mbuf_bytes_in_use`/`_bytes_total` are declared in bytes but the API sources them from `netstat -m` in kilobytes. Now converted to bytes.
  - **OpenVPN client/p2p sessions shown down** — `opnsense_openvpn_sessions` reported active client and point-to-point instances as down because only the server-mode status `"ok"` mapped to up; client/p2p instances report the OpenVPN state-machine value `"connected"`, now also mapped to up.
  - **WireGuard `stale` peer status** — peers idle for >300s (a normal WireGuard state) fell through to `unknown` (2) and logged a warning every scrape. Added a dedicated `stale` value (3) to `opnsense_wireguard_peer_status`.
  - **Gateway loss regex** — the packet-loss parser (`\d\.\d %`) only matched a single decimal digit, so a loss value ≥10 % (e.g. `"12.3 %"`) parsed the wrong substring. Widened to `\d+\.\d+ %`, matching the RTT regex.
- **System uptime / config-change timestamp skew in non-UTC timezones** — OPNsense reports `boottime`/`datetime`/`config` with only a timezone *abbreviation* (e.g. `BST`), which Go's `time.Parse` cannot map to a UTC offset — it falls back to a zero-offset zone, skewing the parsed instant by the box's real offset. `opnsense_system_uptime_seconds` was understated and `opnsense_system_config_last_change` shifted into the future by that offset (e.g. 1 h on a `BST` box) whenever the exporter's own timezone differed from the firewall's. Both values are now derived from *differences* against the box's own `datetime` (same zone, so the unknown offset cancels): uptime = `datetime − boottime`, and the config timestamp is anchored to the exporter clock via the offset-independent `datetime − config` age.
- **WireGuard peer_last_handshake_seconds metric type** — Fixed `opnsense_wireguard_peer_last_handshake_seconds` which was incorrectly emitted as `CounterValue`. A Unix epoch timestamp is not a monotonic counter: `rate()` on it is meaningless and Prometheus counter-reset detection misfires on reboots. Changed to `GaugeValue`. **Dashboard note:** this is a metric type change — any recording rules or dashboards that use `rate(opnsense_wireguard_peer_last_handshake_seconds[...])` should be updated to use the new `opnsense_wireguard_peer_handshake_age_seconds` gauge instead.
- **Gateway probe_period** — Fixed `probe_period_seconds` metric that was defined but never emitted. Fixed fallback logic that used a `switch` statement (only first match runs) instead of independent `if` blocks, causing empty gateway configuration fields to not be backfilled.
- **Interface line rate** — Fixed parsing of line rate values containing unit suffix (e.g. "64000 bit/s") which caused `strconv.Atoi` to fail and silently return 0.
- **Kea DHCP** — Fixed JSON unmarshal failure when Kea DHCP is not enabled on OPNsense. The API returns `"interfaces": []` (array) instead of `{}` (object) when Kea is disabled, which caused every scrape to log errors.
- **OPNsense 25.7 API model drift** — Fixed a class of JSON unmarshal failures on newer OPNsense releases where the PHP API serializes empty values as `[]`/scientific-notation numbers. Added tolerant JSON types (`flexString`, `flexStringMap`) and fixed four collectors that failed every scrape: **dnsmasq** and **kea** (`is_reserved` returned as `[]` instead of `"0"`/`"1"`, and dnsmasq `interfaces` as `[]`), **protocol** (counters returned at max-uint64 in scientific notation, e.g. `1.84e19`, which no longer fit Go `int`), and **unbound** (empty `up` uptime string that previously hard-failed the whole collector). Addresses [#40](https://github.com/rknightion/opnsense-exporter/issues/40).
- **Goroutine panic recovery** — A panic in any sub-collector goroutine (e.g. from `prometheus.MustNewConstMetric` on label/value mismatch) previously crashed the entire exporter process. Added `recover()` inside each goroutine so panics are caught, logged, counted in `endpoint_errors`, and the scrape continues for all other collectors. Also moved `wg.Done()` to a `defer` so it is guaranteed to run even on panic.
- **Response body leak on gzip responses** — The HTTP client never closed `resp.Body` on gzip responses, leaking one connection per scrape. Added `defer resp.Body.Close()` immediately after a successful `Do()` call to ensure the underlying TCP connection is always returned to the pool.

### Build & Infrastructure

- **Optional instance label** — `--exporter.instance-label` / `OPNSENSE_EXPORTER_INSTANCE_LABEL` is no longer required. When unset it now defaults to the hostname the OPNsense API reports for itself (via `api/diagnostics/system/system_information`), falling back to the configured OPNsense address if that lookup fails or does not return within a short timeout (so an unreachable box never delays startup). Single-instance deployments work with no label configuration; set it explicitly only to override or to disambiguate multiple exporters.
- **Go 1.26** — Upgraded from Go 1.25, gaining Green Tea GC (10-40% less GC overhead), ~2x faster `io.ReadAll` for API responses, and post-quantum TLS by default.
- **Go modernization** — Applied `go fix` modernizers: `interface{}` replaced with `any`, unused loop variables removed with `for range` syntax.
- **Standalone fork** — Module path changed to `github.com/rknightion/opnsense-exporter`. All container images, CI/CD, and deployment manifests updated accordingly.
- **Continuous profiling** — optional push-based profiling to Grafana Cloud Pyroscope via the `pyroscope-go` SDK (enable by setting `--pyroscope.server-address`). The previously always-on, unauthenticated `/debug/pprof/*` HTTP endpoints have been removed in favour of authenticated push.
- **Dead code removal** — Removed unreachable `opnsense/system.go` (dead `FetchSystemInfo()` with unregistered endpoint), replaced by the new temperature collector using the verified diagnostics API.
- **Release automation** — Migrated from manual tag-triggered releases to [release-please](https://github.com/googleapis/release-please) for automated conventional commit-driven versioning and changelogs. Docker builds use native multi-arch runners (amd64/arm64). All GitHub Actions pinned to commit hashes for supply-chain security.
- **Dockerfile modernization** — Alpine-based builder (smaller pulls), BuildKit cache mounts for faster rebuilds, `-trimpath` and `-mod=vendor` flags for reproducibility, distroless debian13 nonroot runtime image pinned by digest.
- **Fully off Docker Hub** — The Go toolchain build stage now pulls from Google's `mirror.gcr.io/library/golang` mirror instead of `docker.io`, eliminating the last Docker Hub dependency (and the anonymous-pull rate-limit/gateway-timeout failures it caused in CI). Both build and runtime base images are now served from Google infrastructure.
- **Removed GOMAXPROCS flag** — Removed the `--runtime.gomaxprocs` flag (previously defaulting to 2). Go's runtime now auto-detects available CPUs, which is the correct default for this I/O-bound exporter.

### Documentation

- **Zensical documentation site** — Added comprehensive documentation site at [m7kni.io/opnsense-exporter](https://m7kni.io/opnsense-exporter/) with auto-generated metrics reference, deployment guides, architecture overview, and integration with the m7kni.io docs hub.
- **Auto-generated metrics docs** — Added `scripts/docgen/main.go` that uses Go AST parsing to extract all 275 metrics from source code and generate the complete metrics reference page. Run `make docgen` to regenerate.

### Dashboard & Alerting

- **Single dynamic Grafana dashboard** — Replaced the previous dashboard with one comprehensive **Grafana v2 dynamic dashboard** (`dashboard.grafana.app/v2`, requires **Grafana 13+**) at [`grafana/dashboard.json`](grafana/dashboard.json). It uses `TabsLayout` across 16 tabs (Overview, System & Resources, Interfaces, Firewall & PF, Gateways & WAN, DNS — Unbound, DHCP, VPN, Routing & Neighbors, Protocol Stats, NTP, Certificates, Services/Cron/DynDNS, NetFlow, CARP/HA, Diagnostics) covering **all 303 metrics across 239 panels** with a wide variety of visualisations (timeseries, stat, gauge, bar-gauge, table, state-timeline, status-history, pie-chart). Tabs and rows **auto show/hide** via `conditionalRendering` + hidden sentinel variables, so unused collectors / absent OPNsense plugins disappear automatically (DHCP backends gate on actual lease data). A build-time coverage gate fails the build if any metric is left unreferenced.
- **Self-observability** — A Diagnostics tab covers scrape health, per-endpoint errors, the new `opnsense_exporter_build_info` / `opnsense_exporter_collector_enabled` metrics, and the exporter's own Go-runtime metrics.
- **Dashboard generator** — [`grafana/build_dashboard.py`](grafana/build_dashboard.py) (+ `builder.py` and per-tab modules under `grafana/tabs/`) programmatically generate the v2 manifest. Run `make dashboard`.
- **Alert & recording rules** — Added [`grafana/alerts/`](grafana/alerts/): 18 alert rules and 8 recording rules, shipped both as a portable Prometheus rule-group YAML and as Grafana-managed `rules.alerting.grafana.app/v0alpha1` manifests (`make rules`). See [`grafana/README.md`](grafana/README.md).

### Utilities

- **Safe string parsing** — Added utility functions for safe string-to-number conversion used across the enhanced collectors.

## About

Focusing specifically on OPNsense, this exporter provides metrics about OPNsense, the plugin ecosystem and the services running on the firewall. However, it's recommended to use it with `node_exporter`. You can combine the metrics from both exporters in Grafana and in your Alert System to create a dashboard that displays the full picture of your system.

While the `node_exporter` must be installed on the firewall itself, this exporter can be installed on any machine that has network access to the OPNsense API.

## Grafana Dashboard

> **Minimum Grafana version: 13+** — the dashboard uses the v2 dynamic schema (`dashboard.grafana.app/v2`) with `TabsLayout` and `conditionalRendering`.

A single comprehensive dashboard covers **all 303 metrics across 16 tabs**, auto-hiding tabs/rows for collectors and plugins you don't run. Import [`grafana/dashboard.json`](grafana/dashboard.json) via the Grafana UI, `gcx`, or GitOps. Alert and recording rules live alongside it in [`grafana/alerts/`](grafana/alerts/). Full deployment and customisation instructions: [`grafana/README.md`](grafana/README.md).

## OPNsense user permissions

| Type     |      Name                    |
|----------|:-------------:               |
| GUI |  Diagnostics: ARP Table           |
| GUI |  Diagnostics: Firewall statistics |
| GUI |  Diagnostics: Netstat             |
| GUI |  Reporting: Traffic               |
| GUI |  Services: Unbound (MVC)          |
| GUI |  Status: DHCP leases              |
| GUI |  Status: DNS Overview             |
| GUI |  Status: IPsec                    |
| GUI |  Status: OpenVPN                  |
| GUI |  Status: Services                 |
| GUI |  System: Firmware                 |
| GUI |  System: Gateways                 |
| GUI |  System: Settings: Cron           |
| GUI |  System: Status                   |
| GUI |  VPN: OpenVPN: Instances          |
| GUI |  VPN: WireGuard                   |

## OPNsense settings

The exporter requires that the following OPNsense settings be enabled:
* Unbound collector:
  * Unbound DNS > Advanced > Extended Statistics

## Usage

### Docker

The following command will start the exporter and expose the metrics on port 8080. Replace `ops.example.com`, `your-api-key`, `your-api-secret` and `instance1` with your own values.

```bash
docker run -p 8080:8080 ghcr.io/rknightion/opnsense-exporter:latest \
      /opnsense-exporter \
      --log.level=debug \
      --log.format=json \
      --opnsense.protocol=https \
      --opnsense.address=ops.example.com \
      --opnsense.api-key=your-api-key \
      --opnsense.api-secret=your-api-secret \
      --exporter.instance-label=instance1 \
      --web.listen-address=:8080
```

TODO: Add example how to add custom CA certificates to the container.

### Docker Compose

- With environment variables

```yaml
version: '3'
services:
  opnsense-exporter:
    image: ghcr.io/rknightion/opnsense-exporter:latest
    container_name: opensense-exporter
    restart: always
    command:
      - --opnsense.protocol=https
      - --opnsense.address=ops.example.com
      - --exporter.instance-label=instance1
      - --web.listen-address=:8080
      #- --exporter.disable-arp-table
      #- --exporter.disable-cron-table
      #- ....
    environment:
      OPNSENSE_EXPORTER_OPS_API_KEY: "<your-key>"
      OPNSENSE_EXPORTER_OPS_API_SECRET: "<your-secret>"
    ports:
      - "8080:8080"
```

- With docker secrets

Create the secrets

```bash
echo "<your-key>" | docker secret create opnsense-api-key -
echo "<your-secret>" | docker secret create opnsense-api-secret -
```

Run the compose

```yaml
version: '3'
services:
  opnsense-exporter:
    image: ghcr.io/rknightion/opnsense-exporter:latest
    container_name: opensense-exporter
    restart: always
    command:
      - --opnsense.protocol=https
      - --opnsense.address=ops.example.com
      - --exporter.instance-label=instance1
      - --web.listen-address=:8080
      #- --exporter.disable-arp-table
      #- --exporter.disable-cron-table
      #- ....
    environment:
      OPS_API_KEY_FILE: /run/secrets/opnsense-api-key
      OPS_API_SECRET_FILE: /run/secrets/opnsense-api-secret
    secrets:
      - opnsense-api-key
      - opnsense-api-secret
    ports:
      - "8080:8080"
```

### Systemd

**TODO**

## Configuration

The configuration of this tool is following the standard alongside the Prometheus ecosystem. This exporter can be configured using command-line flags or environment variables.

### OPNsense API

To configure where the connection to OPNsense is, use the following flags:

- `--opnsense.protocol` - The protocol to use to connect to the OPNsense API. Can be either `http` or `https`.
- `--opnsense.address` - The hostname or IP address of the OPNsense API.
- `--opnsense.api-key` - The API key to use to connect to the OPNsense API.
- `--opnsense.api-secret` - The API secret to use to connect to the OPNsense API
- `--exporter.instance-label` - Label to use to identify the instance in every metric. **Optional** — if left unset it defaults to the hostname the OPNsense API reports for itself (falling back to the configured OPNsense address if that lookup fails), so single-instance deployments need not set it. If you run multiple exporters, set a unique value per instance; you must not start more than one instance with the same value.

### SSL/TLS

For self-signed certificates, the CA certificate must be added to the system trust store.

If you want to disable TLS certificate verification, you can use the following flag:

- `--opnsense.insecure` - Disable TLS certificate verification. Defaults to `false`.

### Collector Options

All collectors are **enabled by default** unless noted otherwise. Each can be individually disabled (or enabled for opt-in collectors) using CLI flags or environment variables.

#### Enabled by default (disable with flag)

| Flag | Env Var | Description |
|------|---------|-------------|
| `--exporter.disable-arp-table` | `OPNSENSE_EXPORTER_DISABLE_ARP_TABLE` | ARP table |
| `--exporter.disable-cron-table` | `OPNSENSE_EXPORTER_DISABLE_CRON_TABLE` | Cron jobs |
| `--exporter.disable-wireguard` | `OPNSENSE_EXPORTER_DISABLE_WIREGUARD` | WireGuard tunnels and peers |
| `--exporter.disable-ipsec` | `OPNSENSE_EXPORTER_DISABLE_IPSEC` | IPsec tunnels and SAs |
| `--exporter.disable-unbound` | `OPNSENSE_EXPORTER_DISABLE_UNBOUND` | Unbound DNS resolver statistics |
| `--exporter.disable-openvpn` | `OPNSENSE_EXPORTER_DISABLE_OPENVPN` | OpenVPN instances and sessions |
| `--exporter.disable-firewall` | `OPNSENSE_EXPORTER_DISABLE_FIREWALL` | Firewall PF interface statistics (packet/byte counters, state table) |
| `--exporter.disable-firewall-rules` | `OPNSENSE_EXPORTER_DISABLE_FIREWALL_RULES` | Firewall rule statistics (total rule count; per-rule details opt-in) |
| `--exporter.disable-firmware` | `OPNSENSE_EXPORTER_DISABLE_FIRMWARE` | Firmware version info, update status, and reboot flags |
| `--exporter.disable-system` | `OPNSENSE_EXPORTER_DISABLE_SYSTEM` | System resources (memory, uptime, load, disk, swap) |
| `--exporter.disable-temperature` | `OPNSENSE_EXPORTER_DISABLE_TEMPERATURE` | Hardware temperature sensors |
| `--exporter.disable-dnsmasq` | `OPNSENSE_EXPORTER_DISABLE_DNSMASQ` | Dnsmasq DHCP leases |
| `--exporter.disable-mbuf` | `OPNSENSE_EXPORTER_DISABLE_MBUF` | FreeBSD mbuf (network buffer) statistics |
| `--exporter.disable-ntp` | `OPNSENSE_EXPORTER_DISABLE_NTP` | NTP peer metrics |
| `--exporter.disable-certificates` | `OPNSENSE_EXPORTER_DISABLE_CERTIFICATES` | Certificate validity and expiry timestamps |
| `--exporter.disable-carp` | `OPNSENSE_EXPORTER_DISABLE_CARP` | CARP/VIP high-availability status |
| `--exporter.disable-activity` | `OPNSENSE_EXPORTER_DISABLE_ACTIVITY` | System activity (CPU percentages, thread counts) |
| `--exporter.disable-kea` | `OPNSENSE_EXPORTER_DISABLE_KEA` | Kea DHCP lease metrics |
| `--exporter.disable-pf-stats` | `OPNSENSE_EXPORTER_DISABLE_PF_STATS` | PF statistics (state table, counters, memory limits, timeouts) |
| `--exporter.disable-ndp` | `OPNSENSE_EXPORTER_DISABLE_NDP` | NDP (IPv6 neighbor discovery) table |
| `--exporter.disable-dhcpv4` | `OPNSENSE_EXPORTER_DISABLE_DHCPV4` | ISC DHCPv4 lease metrics (silent when the legacy ISC DHCP backend is absent) |
| `--exporter.disable-acme` | `OPNSENSE_EXPORTER_DISABLE_ACME` | ACME client certificate renewal status and expiry (silent when `os-acme-client` is absent) |
| `--exporter.disable-smart` | `OPNSENSE_EXPORTER_DISABLE_SMART` | SMART disk health (per-disk POST fanout; silent when `os-smart` is absent) |
| `--exporter.disable-dyndns` | `OPNSENSE_EXPORTER_DISABLE_DYNDNS` | DynDNS (ddclient) account update status (silent when `os-ddclient` is absent) |

#### Disabled by default (opt-in with flag)

| Flag | Env Var | Description |
|------|---------|-------------|
| `--exporter.enable-network-diagnostics` | `OPNSENSE_EXPORTER_ENABLE_NETWORK_DIAGNOSTICS` | Network diagnostics: kernel netisr stats, socket counts, route counts. Makes 3 API calls per scrape. |
| `--exporter.enable-netflow` | `OPNSENSE_EXPORTER_ENABLE_NETFLOW` | NetFlow: service status, enabled state, per-interface cache statistics. Makes 3 API calls per scrape. |

#### High-cardinality detail options

These flags enable per-item detail metrics that can produce a large number of time series on busy networks or complex rulesets. **Evaluate your environment before enabling** — each unique label combination creates a separate time series in Prometheus.

| Flag | Env Var | Description |
|------|---------|-------------|
| `--exporter.enable-dnsmasq-details` | `OPNSENSE_EXPORTER_ENABLE_DNSMASQ_DETAILS` | Emit per-lease detail metrics for Dnsmasq DHCP. One time series per active DHCP lease (address, hostname, MAC, interface). |
| `--exporter.enable-firewall-rules-details` | `OPNSENSE_EXPORTER_ENABLE_FIREWALL_RULES_DETAILS` | Emit per-rule detail metrics for firewall rules. One time series per firewall rule per metric (UUID, description, action, interface, direction). |
| `--exporter.enable-kea-details` | `OPNSENSE_EXPORTER_ENABLE_KEA_DETAILS` | Emit per-lease detail metrics for Kea DHCP. One time series per active DHCP lease (address, hostname, MAC, interface). |
| `--exporter.enable-dhcpv4-details` | `OPNSENSE_EXPORTER_ENABLE_DHCPV4_DETAILS` | Emit per-lease detail metrics for ISC DHCPv4. One time series per active DHCP lease (address, hostname, MAC, interface). |

#### Exporter meta-metrics

| Flag | Env Var | Description |
|------|---------|-------------|
| `--web.disable-exporter-metrics` | `OPNSENSE_EXPORTER_DISABLE_EXPORTER_METRICS` | Exclude metrics about the exporter itself (`promhttp_*`, `process_*`, `go_*`). Defaults to `false`. |

### All Options

```
usage: opnsense-exporter --opnsense.protocol=OPNSENSE.PROTOCOL --opnsense.address=OPNSENSE.ADDRESS [<flags>]


Flags:
  -h, --[no-]help               Show context-sensitive help (also try
                                --help-long and --help-man).
      --[no-]exporter.disable-arp-table  
                                Disable the scraping of the ARP table
                                ($OPNSENSE_EXPORTER_DISABLE_ARP_TABLE)
      --[no-]exporter.disable-cron-table  
                                Disable the scraping of the cron table
                                ($OPNSENSE_EXPORTER_DISABLE_CRON_TABLE)
      --[no-]exporter.disable-wireguard  
                                Disable the scraping of Wireguard service
                                ($OPNSENSE_EXPORTER_DISABLE_WIREGUARD)
      --[no-]exporter.disable-ipsec  
                                Disable the scraping of IPSec service
                                ($OPNSENSE_EXPORTER_DISABLE_IPSEC)
      --[no-]exporter.disable-unbound  
                                Disable the scraping of Unbound service
                                ($OPNSENSE_EXPORTER_DISABLE_UNBOUND)
      --[no-]exporter.disable-openvpn  
                                Disable the scraping of OpenVPN service
                                ($OPNSENSE_EXPORTER_DISABLE_OPENVPN)
      --[no-]exporter.disable-firewall  
                                Disable the scraping of the firewall (pf)
                                metrics ($OPNSENSE_EXPORTER_DISABLE_FIREWALL)
      --[no-]exporter.disable-firmware  
                                Disable the scraping of the firmware metrics
                                ($OPNSENSE_EXPORTER_DISABLE_FIRMWARE)
      --[no-]exporter.disable-system  
                                Disable the scraping of system resource
                                metrics (memory, uptime, disk, swap)
                                ($OPNSENSE_EXPORTER_DISABLE_SYSTEM)
      --[no-]exporter.disable-temperature  
                                Disable the scraping of temperature metrics
                                ($OPNSENSE_EXPORTER_DISABLE_TEMPERATURE)
      --[no-]exporter.disable-dnsmasq  
                                Disable the scraping of Dnsmasq DHCP leases
                                ($OPNSENSE_EXPORTER_DISABLE_DNSMASQ)
      --[no-]exporter.enable-dnsmasq-details  
                                Enable per-lease detail metrics for Dnsmasq
                                DHCP (high cardinality on large networks)
                                ($OPNSENSE_EXPORTER_ENABLE_DNSMASQ_DETAILS)
      --[no-]exporter.disable-firewall-rules  
                                Disable the scraping of firewall rule statistics
                                ($OPNSENSE_EXPORTER_DISABLE_FIREWALL_RULES)
      --[no-]exporter.enable-firewall-rules-details  
                                Enable per-rule detail metrics for firewall
                                rules (high cardinality on large rulesets)
                                ($OPNSENSE_EXPORTER_ENABLE_FIREWALL_RULES_DETAILS)
      --[no-]exporter.disable-mbuf  
                                Disable the scraping of mbuf statistics
                                ($OPNSENSE_EXPORTER_DISABLE_MBUF)
      --[no-]exporter.disable-ntp  
                                Disable the scraping of NTP peer metrics
                                ($OPNSENSE_EXPORTER_DISABLE_NTP)
      --[no-]exporter.disable-certificates  
                                Disable the scraping of
                                certificate expiry metrics
                                ($OPNSENSE_EXPORTER_DISABLE_CERTIFICATES)
      --[no-]exporter.disable-carp  
                                Disable the scraping of CARP/VIP status metrics
                                ($OPNSENSE_EXPORTER_DISABLE_CARP)
      --[no-]exporter.disable-activity  
                                Disable the scraping of system activity
                                metrics (CPU percentages, thread counts)
                                ($OPNSENSE_EXPORTER_DISABLE_ACTIVITY)
      --[no-]exporter.disable-kea  
                                Disable the scraping of Kea DHCP lease metrics
                                ($OPNSENSE_EXPORTER_DISABLE_KEA)
      --[no-]exporter.enable-kea-details  
                                Enable per-lease detail metrics for Kea
                                DHCP (high cardinality on large networks)
                                ($OPNSENSE_EXPORTER_ENABLE_KEA_DETAILS)
      --[no-]exporter.enable-network-diagnostics  
                                Enable the network diagnostics collector
                                (netisr, sockets, routes). Disabled by default.
                                ($OPNSENSE_EXPORTER_ENABLE_NETWORK_DIAGNOSTICS)
      --[no-]exporter.enable-netflow  
                                Enable the netflow collector (enabled status,
                                service status, cache stats). Disabled by
                                default. ($OPNSENSE_EXPORTER_ENABLE_NETFLOW)
      --[no-]exporter.disable-pf-stats  
                                Disable the scraping of PF statistics (state
                                table, counters, memory limits, timeouts)
                                ($OPNSENSE_EXPORTER_DISABLE_PF_STATS)
      --[no-]exporter.disable-ndp  
                                Disable the scraping of the NDP
                                (IPv6 neighbor discovery) table
                                ($OPNSENSE_EXPORTER_DISABLE_NDP)
      --[no-]exporter.disable-dhcpv4  
                                Disable the scraping of ISC DHCPv4 leases
                                ($OPNSENSE_EXPORTER_DISABLE_DHCPV4)
      --[no-]exporter.enable-dhcpv4-details  
                                Enable per-lease detail metrics for ISC
                                DHCPv4 (high cardinality on large networks)
                                ($OPNSENSE_EXPORTER_ENABLE_DHCPV4_DETAILS)
      --[no-]exporter.disable-acme  
                                Disable the scraping of ACME client
                                certificate renewal status and expiry metrics
                                ($OPNSENSE_EXPORTER_DISABLE_ACME)
      --[no-]exporter.disable-smart  
                                Disable the SMART disk health
                                collector (per-disk POST fanout;
                                silent when the os-smart plugin is absent)
                                ($OPNSENSE_EXPORTER_DISABLE_SMART)
      --[no-]exporter.disable-dyndns  
                                Disable the scraping of DynDNS
                                (ddclient) account update status metrics
                                ($OPNSENSE_EXPORTER_DISABLE_DYNDNS)
      --web.telemetry-path="/metrics"  
                                Path under which to expose metrics.
      --[no-]web.disable-exporter-metrics  
                                Exclude metrics about the exporter
                                itself (promhttp_*, process_*, go_*).
                                ($OPNSENSE_EXPORTER_DISABLE_EXPORTER_METRICS)
      --exporter.instance-label=""  
                                Label to use to identify the instance in
                                every metric. If you have multiple instances
                                of the exporter, you can differentiate them
                                by using different value in this flag, that
                                represents the instance of the target OPNsense.
                                If left empty, it defaults to the OPNsense
                                hostname reported by the API (falling back to
                                the configured OPNsense address if that lookup
                                fails). ($OPNSENSE_EXPORTER_INSTANCE_LABEL)
      --web.listen-address=:8080 ...  
                                Addresses on which to expose metrics and web
                                interface. Repeatable for multiple addresses.
                                Examples: `:9100` or `[::1]:9100` for http,
                                `vsock://:9100` for vsock
      --web.config.file=""      Path to configuration file that can
                                enable TLS or authentication. See:
                                https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md
      --opnsense.protocol=OPNSENSE.PROTOCOL  
                                Protocol to use to connect to
                                OPNsense API. One of: [http, https]
                                ($OPNSENSE_EXPORTER_OPS_PROTOCOL)
      --opnsense.address=OPNSENSE.ADDRESS  
                                Hostname or IP address of OPNsense API
                                ($OPNSENSE_EXPORTER_OPS_API)
      --opnsense.api-key=""     API key to use to connect to OPNsense API.
                                This flag/ENV or the OPS_API_KEY_FILE my be set.
                                ($OPNSENSE_EXPORTER_OPS_API_KEY)
      --opnsense.api-secret=""  API secret to use to connect to OPNsense API.
                                This flag/ENV or the OPS_API_SECRET_FILE my be
                                set. ($OPNSENSE_EXPORTER_OPS_API_SECRET)
      --[no-]opnsense.insecure  Disable TLS certificate verification
                                ($OPNSENSE_EXPORTER_OPS_INSECURE)
      --log.level=info          Only log messages with the given severity or
                                above. One of: [debug, info, warn, error]
      --log.format=logfmt       Output format of log messages. One of: [logfmt,
                                json]

```
