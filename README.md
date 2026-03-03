# OPNsense Prometheus Exporter

> **Fork notice:** This is a fork of [AthennaMind/opnsense-exporter](https://github.com/AthennaMind/opnsense-exporter), the original OPNsense Prometheus exporter. This fork includes significant additions and changes beyond the scope of the upstream project. Full credit to the original AthennaMind authors for building the foundation this work is based on.

![GitHub License](https://img.shields.io/github/license/rknightion/opnsense-exporter)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/rknightion/opnsense-exporter/ci.yml)
![GitHub go.mod Go version (branch)](https://img.shields.io/github/go-mod/go-version/rknightion/opnsense-exporter/main)

## Table of Contents

- **[Changes from Upstream](#changes-from-upstream)**
- **[About](#about)**
- **[Grafana Dashboard](#grafana-dashboard)**
- **[Metrics List](./docs/metrics.md)**
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
- **Dnsmasq DHCP lease collector** — New collector exposing dnsmasq lease metrics: total leases, leases by interface, reserved vs dynamic counts, and optional per-lease detail metrics (enabled via `--exporter.dnsmasq-details`). Includes new `--exporter.disable-dnsmasq` flag.
- **Temperature collector** — New collector exposing hardware temperature readings (`opnsense_temperature_celsius`) with per-device labels (device, type, device_seq). Polls `api/diagnostics/system/systemTemperature`. Includes new `--exporter.disable-temperature` / `OPNSENSE_EXPORTER_DISABLE_TEMPERATURE` flag.
- **Firewall rule statistics collector** — New collector exposing per-rule firewall statistics (evaluations, packets, bytes, active states, PF rule count) with rule metadata labels (UUID, description, action, interface, direction). Fetches 2 API endpoints and joins rule stats with metadata. High-cardinality per-rule detail metrics are opt-in via `--exporter.enable-firewall-rules-details` / `OPNSENSE_EXPORTER_ENABLE_FIREWALL_RULES_DETAILS`. Summary metric (total rules count) is always emitted. Includes new `--exporter.disable-firewall-rules` / `OPNSENSE_EXPORTER_DISABLE_FIREWALL_RULES` flag.
- **Mbuf statistics collector** — New collector exposing FreeBSD network buffer (mbuf) statistics: current/cache/total mbuf counts, cluster counts and max, allocation failures and sleeps by type (mbuf, cluster, packet, jumbop), and memory bytes in use/total. Polls `api/diagnostics/system/systemMbuf`. Includes new `--exporter.disable-mbuf` / `OPNSENSE_EXPORTER_DISABLE_MBUF` flag.
- **NTP collector** — New collector exposing NTP peer metrics: peer info, stratum, seconds since last response, poll interval, reachability register (octal decoded), round-trip delay, clock offset, and jitter (all in milliseconds), plus total peer count. Polls `api/ntpd/service/status`. Includes new `--exporter.disable-ntp` / `OPNSENSE_EXPORTER_DISABLE_NTP` flag.
- **Certificate expiry collector** — New collector exposing certificate validity timestamps (valid_from, valid_to as Unix epoch seconds), certificate info, and total certificate count with description, common name, cert type, and in-use labels. Enables alerting on approaching expiry. Polls `api/trust/cert/search`. Includes new `--exporter.disable-certificates` / `OPNSENSE_EXPORTER_DISABLE_CERTIFICATES` flag.
- **CARP/VIP status collector** — New collector exposing CARP high-availability metrics: demotion counter, allow status, maintenance mode, total VIP count, and per-VIP status (MASTER/BACKUP/INIT), advertisement base interval, and advertisement skew. Polls `api/diagnostics/interface/get_vip_status`. Includes new `--exporter.disable-carp` / `OPNSENSE_EXPORTER_DISABLE_CARP` flag.
- **System activity collector** — New collector exposing CPU usage percentages (user, nice, system, interrupt, idle) and thread counts (total, running, sleeping, waiting) parsed from the activity API headers. Polls `api/diagnostics/activity/get_activity`. Includes new `--exporter.disable-activity` / `OPNSENSE_EXPORTER_DISABLE_ACTIVITY` flag.
- **Kea DHCP lease collector** — New collector exposing Kea DHCPv4 and DHCPv6 lease metrics: total leases, leases by interface, reserved vs dynamic counts, and optional per-lease detail metrics (enabled via `--exporter.enable-kea-details`). Polls both `api/kea/leases4/search` and `api/kea/leases6/search`. Includes new `--exporter.disable-kea` / `OPNSENSE_EXPORTER_DISABLE_KEA` flag.
- **Network diagnostics collector** — New opt-in collector exposing kernel network ISR statistics (dispatched, hybrid dispatched, queued, handled, queue drops, queue length/watermark/limit per protocol), active socket counts by type, UNIX domain socket count, and routing table counts by protocol. Polls 3 API endpoints. Disabled by default; enable with `--exporter.enable-network-diagnostics` / `OPNSENSE_EXPORTER_ENABLE_NETWORK_DIAGNOSTICS=true`.

### Enhanced Collectors

- **Interfaces** — Added 8 new metrics: received/transmitted packet totals, send queue length/max/drops, input queue drops, link state, and line rate.
- **Protocol statistics** — Added 28 new metrics covering CARP (received/sent/dropped), pfsync (received/sent/dropped/errors), IP (received/forwarded/sent/dropped/fragments/reassembled), TCP (connections requested/accepted/established/closed/dropped, retransmit/keepalive timeouts, listen queue overflows, syncache entries), and ARP (sent failures/replies, received replies/packets, dropped no entry, entry timeouts). Additionally added 11 expanded metrics: TCP sent data bytes, retransmitted packets/bytes, received in-sequence/duplicate bytes, segments updated RTT, bad connection attempts, keepalive probes, syncache dropped; IP sent fragments; ARP dropped duplicate address.
- **Unbound DNS** — Comprehensive overhaul adding 26 new metrics: query totals, cache hits/misses, prefetch/expired counts, recursive replies, timed-out/rate-limited queries, DNSSEC secure/bogus answers, queries by type and protocol, answers by rcode, unwanted queries, query flags, EDNS counts, request list stats (avg/max/current/overwritten/exceeded), recursion time (avg/median), cache counts by type, and memory usage by component. Also added TCP usage ratio metric and DNS blocklist enabled status.
- **Firewall PF statistics** — Added 8 byte counter metrics (IPv4/IPv6 pass/block bytes by interface) complementing the existing packet counters. Added PF state table metrics (current states, state limit) for capacity monitoring.
- **Health check** — Added `opnsense_system_status_code` gauge exposing the numeric system status code from the health check API (2 = OK for OPNsense >= 25.1).
- **Unbound DNS / Dnsmasq / IPsec / Wireguard** — Added `service_running` gauge to each collector (1 = running, 0 = stopped/disabled) via per-subsystem service status API endpoints.
- **Firmware** — Reworked metrics to follow Prometheus best practices: consolidated version strings into a single `opnsense_firmware_info` metric with labels, replaced value-in-label anti-patterns with proper numeric gauges (`needs_reboot`, `upgrade_needs_reboot`, `last_check_timestamp_seconds`, `new_packages_count`, `upgrade_packages_count`).

### Bug Fixes

- **Gateway probe_period** — Fixed `probe_period_seconds` metric that was defined but never emitted. Fixed fallback logic that used a `switch` statement (only first match runs) instead of independent `if` blocks, causing empty gateway configuration fields to not be backfilled.
- **Interface line rate** — Fixed parsing of line rate values containing unit suffix (e.g. "64000 bit/s") which caused `strconv.Atoi` to fail and silently return 0.
- **Kea DHCP** — Fixed JSON unmarshal failure when Kea DHCP is not enabled on OPNsense. The API returns `"interfaces": []` (array) instead of `{}` (object) when Kea is disabled, which caused every scrape to log errors.

### Build & Infrastructure

- **Go 1.26** — Upgraded from Go 1.25, gaining Green Tea GC (10-40% less GC overhead), ~2x faster `io.ReadAll` for API responses, and post-quantum TLS by default.
- **Go modernization** — Applied `go fix` modernizers: `interface{}` replaced with `any`, unused loop variables removed with `for range` syntax.
- **Standalone fork** — Module path changed to `github.com/rknightion/opnsense-exporter`. All container images, CI/CD, and deployment manifests updated accordingly.
- **Profiling support** — Enabled Go pprof and godeltaprof (Pyroscope) endpoints at `/debug/pprof/*` for CPU, memory, mutex, block, and goroutine profiling. Supports Grafana Alloy pull-mode scraping out of the box.
- **Dead code removal** — Removed unreachable `opnsense/system.go` (dead `FetchSystemInfo()` with unregistered endpoint), replaced by the new temperature collector using the verified diagnostics API.
- **Release automation** — Migrated from manual tag-triggered releases to [release-please](https://github.com/googleapis/release-please) for automated conventional commit-driven versioning and changelogs. Docker builds use native multi-arch runners (amd64/arm64). All GitHub Actions pinned to commit hashes for supply-chain security.
- **Dockerfile modernization** — Alpine-based builder (smaller pulls), BuildKit cache mounts for faster rebuilds, `-trimpath` and `-mod=vendor` flags for reproducibility, distroless debian13 nonroot runtime image pinned by digest.

### Utilities

- **Safe string parsing** — Added utility functions for safe string-to-number conversion used across the enhanced collectors.

## About

Focusing specifically on OPNsense, this exporter provides metrics about OPNsense, the plugin ecosystem and the services running on the firewall. However, it's recommended to use it with `node_exporter`. You can combine the metrics from both exporters in Grafana and in your Alert System to create a dashboard that displays the full picture of your system.

While the `node_exporter` must be installed on the firewall itself, this exporter can be installed on any machine that has network access to the OPNsense API.

## Grafana Dashboard

**[OPNsense Exporter Dashboard](https://grafana.com/grafana/dashboards/21113)**

![gateways](docs/assets/gateways.png)

Finaly we have a Grafana dashboard to visualize the data from this exporter. The dashboard can be imported into Grafana by using the id `21113` or by importing the `deploy/grafana/dashboard-v1.json` file. Please give a review to the dashboard if you like our work. Thank you!

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
- `--exporter.instance-label` - Label to use to identify the instance in every metric. If you have multiple instances of the exporter, you can differentiate them by using different value in this flag, that represents the instance of the target OPNsense. You must not start more then 1 instance of the exporter with the same value in this flag.

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
| `--exporter.disable-firewall-rules` | `OPNSENSE_EXPORTER_DISABLE_FIREWALL_RULES` | Per-rule firewall statistics (evaluations, packets, bytes, states) |
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

#### Disabled by default (opt-in with flag)

| Flag | Env Var | Description |
|------|---------|-------------|
| `--exporter.enable-network-diagnostics` | `OPNSENSE_EXPORTER_ENABLE_NETWORK_DIAGNOSTICS` | Network diagnostics: kernel netisr stats, socket counts, route counts. Makes 3 API calls per scrape. |

#### High-cardinality detail options

These flags enable per-item detail metrics that can produce a large number of time series on busy networks or complex rulesets. **Evaluate your environment before enabling** — each unique label combination creates a separate time series in Prometheus.

| Flag | Env Var | Description |
|------|---------|-------------|
| `--exporter.enable-dnsmasq-details` | `OPNSENSE_EXPORTER_ENABLE_DNSMASQ_DETAILS` | Emit per-lease detail metrics for Dnsmasq DHCP. One time series per active DHCP lease (address, hostname, MAC, interface). |
| `--exporter.enable-firewall-rules-details` | `OPNSENSE_EXPORTER_ENABLE_FIREWALL_RULES_DETAILS` | Emit per-rule detail metrics for firewall rules. One time series per firewall rule per metric (UUID, description, action, interface, direction). |
| `--exporter.enable-kea-details` | `OPNSENSE_EXPORTER_ENABLE_KEA_DETAILS` | Emit per-lease detail metrics for Kea DHCP. One time series per active DHCP lease (address, hostname, MAC, interface). |

#### Exporter meta-metrics

| Flag | Env Var | Description |
|------|---------|-------------|
| `--web.disable-exporter-metrics` | `OPNSENSE_EXPORTER_DISABLE_EXPORTER_METRICS` | Exclude metrics about the exporter itself (`promhttp_*`, `process_*`, `go_*`). Defaults to `false`. |

### All Options

```
Flags:
  -h, --[no-]help                Show context-sensitive help (also try --help-long and --help-man).

OPNsense connection:
      --opnsense.protocol=OPNSENSE.PROTOCOL
                                 Protocol to use to connect to OPNsense API. One of: [http, https]
                                 ($OPNSENSE_EXPORTER_OPS_PROTOCOL)
      --opnsense.address=OPNSENSE.ADDRESS
                                 Hostname or IP address of OPNsense API ($OPNSENSE_EXPORTER_OPS_API)
      --opnsense.api-key=""      API key to use to connect to OPNsense API. This flag/ENV or the
                                 OPS_API_KEY_FILE must be set. ($OPNSENSE_EXPORTER_OPS_API_KEY)
      --opnsense.api-secret=""   API secret to use to connect to OPNsense API. This flag/ENV or the
                                 OPS_API_SECRET_FILE must be set. ($OPNSENSE_EXPORTER_OPS_API_SECRET)
      --[no-]opnsense.insecure   Disable TLS certificate verification ($OPNSENSE_EXPORTER_OPS_INSECURE)

Collector disable flags (all enabled by default):
      --[no-]exporter.disable-arp-table          Disable the scraping of the ARP table
      --[no-]exporter.disable-cron-table         Disable the scraping of the cron table
      --[no-]exporter.disable-wireguard          Disable the scraping of Wireguard service
      --[no-]exporter.disable-ipsec              Disable the scraping of IPSec service
      --[no-]exporter.disable-unbound            Disable the scraping of Unbound service
      --[no-]exporter.disable-openvpn            Disable the scraping of OpenVPN service
      --[no-]exporter.disable-firewall           Disable the scraping of the firewall (pf) metrics
      --[no-]exporter.disable-firewall-rules     Disable the scraping of per-rule firewall statistics
      --[no-]exporter.disable-firmware           Disable the scraping of the firmware metrics
      --[no-]exporter.disable-system             Disable the scraping of system resource metrics (memory, uptime, disk, swap)
      --[no-]exporter.disable-temperature        Disable the scraping of temperature metrics
      --[no-]exporter.disable-dnsmasq            Disable the scraping of Dnsmasq DHCP leases
      --[no-]exporter.disable-mbuf               Disable the scraping of mbuf statistics
      --[no-]exporter.disable-ntp                Disable the scraping of NTP peer metrics
      --[no-]exporter.disable-certificates       Disable the scraping of certificate expiry metrics
      --[no-]exporter.disable-carp               Disable the scraping of CARP/VIP status metrics
      --[no-]exporter.disable-activity           Disable the scraping of system activity metrics (CPU percentages, thread counts)
      --[no-]exporter.disable-kea                Disable the scraping of Kea DHCP lease metrics

Collector enable flags (all disabled by default):
      --[no-]exporter.enable-network-diagnostics Enable the network diagnostics collector (netisr, sockets, routes)

High-cardinality detail flags (all disabled by default):
      --[no-]exporter.enable-dnsmasq-details     Enable per-lease detail metrics for Dnsmasq DHCP
      --[no-]exporter.enable-firewall-rules-details
                                                 Enable per-rule detail metrics for firewall rules
      --[no-]exporter.enable-kea-details         Enable per-lease detail metrics for Kea DHCP

Web server:
      --web.telemetry-path="/metrics"            Path under which to expose metrics
      --[no-]web.disable-exporter-metrics        Exclude metrics about the exporter itself (promhttp_*, process_*, go_*)
      --web.listen-address=:8080 ...             Addresses on which to expose metrics and web interface. Repeatable for
                                                 multiple addresses.
      --[no-]web.systemd-socket                  Use systemd socket activation listeners instead of port listeners (Linux only)
      --web.config.file=""                       Path to configuration file that can enable TLS or authentication. See:
                                                 https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md

Runtime:
      --exporter.instance-label=EXPORTER.INSTANCE-LABEL
                                                 Label to identify the OPNsense instance in every metric. Required.
                                                 ($OPNSENSE_EXPORTER_INSTANCE_LABEL)
      --runtime.gomaxprocs=2                     Target number of CPUs for the Go runtime (GOMAXPROCS) ($GOMAXPROCS)
      --log.level=info                           Log severity threshold. One of: [debug, info, warn, error]
      --log.format=logfmt                        Log output format. One of: [logfmt, json]
```
