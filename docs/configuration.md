---
title: Configuration
description: Complete reference for all OPNsense Exporter CLI flags, environment variables, and collector switches
tags:
  - Configuration
---

# Configuration

The OPNsense Exporter follows standard Prometheus ecosystem conventions. It can be configured using command-line flags, environment variables, or a combination of both. Environment variables take the prefix `OPNSENSE_EXPORTER_` unless noted otherwise.

## OPNsense connection

These settings control how the exporter connects to the OPNsense API.

| Flag | Env Var | Required | Default | Description |
|------|---------|----------|---------|-------------|
| `--opnsense.protocol` | `OPNSENSE_EXPORTER_OPS_PROTOCOL` | Yes | -- | Protocol to use. One of: `http`, `https` |
| `--opnsense.address` | `OPNSENSE_EXPORTER_OPS_API` | Yes | -- | Hostname or IP address of the OPNsense API |
| `--opnsense.api-key` | `OPNSENSE_EXPORTER_OPS_API_KEY` | Yes[^1] | -- | API key for authentication |
| `--opnsense.api-secret` | `OPNSENSE_EXPORTER_OPS_API_SECRET` | Yes[^1] | -- | API secret for authentication |
| `--opnsense.insecure` | `OPNSENSE_EXPORTER_OPS_INSECURE` | No | `false` | Disable TLS certificate verification |

[^1]: Either the flag/env var or the corresponding file-based secret (`OPS_API_KEY_FILE` / `OPS_API_SECRET_FILE`) must be set. See [Security: File-based secrets](security.md#file-based-secrets).

### File-based secrets

For secure credential management in containers and orchestrated environments, credentials can be read from files:

| Env Var | Description |
|---------|-------------|
| `OPS_API_KEY_FILE` | Path to a file containing the API key (first line is read) |
| `OPS_API_SECRET_FILE` | Path to a file containing the API secret (first line is read) |

!!! note
    These environment variables do **not** use the `OPNSENSE_EXPORTER_` prefix. They are checked first -- if a file-based secret is set and non-empty, it takes precedence over the flag/env var value.

## Exporter settings

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--exporter.instance-label` | `OPNSENSE_EXPORTER_INSTANCE_LABEL` | -- (required) | Label added to every metric to identify this OPNsense instance. Must be unique across multiple exporter instances. |
| `--web.listen-address` | -- | `:8080` | Address(es) on which to expose metrics. Repeatable for multiple addresses. |
| `--web.telemetry-path` | -- | `/metrics` | HTTP path under which to expose metrics |
| `--web.disable-exporter-metrics` | `OPNSENSE_EXPORTER_DISABLE_EXPORTER_METRICS` | `false` | Exclude metrics about the exporter itself (`promhttp_*`, `process_*`, `go_*`) |
| `--web.systemd-socket` | -- | `false` | Use systemd socket activation listeners instead of port listeners (Linux only) |
| `--web.config.file` | -- | -- | Path to a [web configuration file](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md) for TLS or authentication |
| `--log.level` | -- | `info` | Log severity threshold. One of: `debug`, `info`, `warn`, `error` |
| `--log.format` | -- | `logfmt` | Log output format. One of: `logfmt`, `json` |

## Collector switches

All collectors are **enabled by default** unless noted otherwise. Each can be individually disabled or enabled using CLI flags or environment variables.

### Enabled by default (disable with flag)

| Flag | Env Var | Collector |
|------|---------|-----------|
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

### Disabled by default (opt-in with flag)

These collectors are disabled by default because they make additional API calls per scrape. Enable them only if you need the data.

| Flag | Env Var | Collector |
|------|---------|-----------|
| `--exporter.enable-network-diagnostics` | `OPNSENSE_EXPORTER_ENABLE_NETWORK_DIAGNOSTICS` | Network diagnostics: kernel netisr stats, socket counts, route counts. Makes 3 API calls per scrape. |
| `--exporter.enable-netflow` | `OPNSENSE_EXPORTER_ENABLE_NETFLOW` | NetFlow: service status, enabled state, per-interface cache statistics. Makes 3 API calls per scrape. |

### High-cardinality detail options

These flags enable per-item detail metrics that can produce a large number of time series. Each unique label combination creates a separate time series in Prometheus.

!!! warning "Evaluate before enabling"
    On a firewall with hundreds of DHCP leases or firewall rules, enabling detail metrics can produce thousands of time series. Monitor your Prometheus storage and ingestion rate after enabling.

| Flag | Env Var | Description |
|------|---------|-------------|
| `--exporter.enable-dnsmasq-details` | `OPNSENSE_EXPORTER_ENABLE_DNSMASQ_DETAILS` | Per-lease detail metrics for Dnsmasq DHCP. One time series per active lease (address, hostname, MAC, interface). |
| `--exporter.enable-firewall-rules-details` | `OPNSENSE_EXPORTER_ENABLE_FIREWALL_RULES_DETAILS` | Per-rule detail metrics for firewall rules. One time series per rule per metric (UUID, description, action, interface, direction). |
| `--exporter.enable-kea-details` | `OPNSENSE_EXPORTER_ENABLE_KEA_DETAILS` | Per-lease detail metrics for Kea DHCP. One time series per active lease (address, hostname, MAC, interface). |

## Full flag reference

The complete list of flags as output by `--help`:

```text
Flags:
  -h, --[no-]help                Show context-sensitive help (also try
                                 --help-long and --help-man).

OPNsense connection:
      --opnsense.protocol=OPNSENSE.PROTOCOL
                                 Protocol to use to connect to OPNsense API.
                                 One of: [http, https]
                                 ($OPNSENSE_EXPORTER_OPS_PROTOCOL)
      --opnsense.address=OPNSENSE.ADDRESS
                                 Hostname or IP address of OPNsense API
                                 ($OPNSENSE_EXPORTER_OPS_API)
      --opnsense.api-key=""      API key to use to connect to OPNsense API.
                                 This flag/ENV or the OPS_API_KEY_FILE must
                                 be set. ($OPNSENSE_EXPORTER_OPS_API_KEY)
      --opnsense.api-secret=""   API secret to use to connect to OPNsense API.
                                 This flag/ENV or the OPS_API_SECRET_FILE must
                                 be set. ($OPNSENSE_EXPORTER_OPS_API_SECRET)
      --[no-]opnsense.insecure   Disable TLS certificate verification
                                 ($OPNSENSE_EXPORTER_OPS_INSECURE)

Collector disable flags (all enabled by default):
      --[no-]exporter.disable-arp-table
      --[no-]exporter.disable-cron-table
      --[no-]exporter.disable-wireguard
      --[no-]exporter.disable-ipsec
      --[no-]exporter.disable-unbound
      --[no-]exporter.disable-openvpn
      --[no-]exporter.disable-firewall
      --[no-]exporter.disable-firewall-rules
      --[no-]exporter.disable-firmware
      --[no-]exporter.disable-system
      --[no-]exporter.disable-temperature
      --[no-]exporter.disable-dnsmasq
      --[no-]exporter.disable-mbuf
      --[no-]exporter.disable-ntp
      --[no-]exporter.disable-certificates
      --[no-]exporter.disable-carp
      --[no-]exporter.disable-activity
      --[no-]exporter.disable-kea
      --[no-]exporter.disable-pf-stats
      --[no-]exporter.disable-ndp

Collector enable flags (all disabled by default):
      --[no-]exporter.enable-network-diagnostics
      --[no-]exporter.enable-netflow

High-cardinality detail flags (all disabled by default):
      --[no-]exporter.enable-dnsmasq-details
      --[no-]exporter.enable-firewall-rules-details
      --[no-]exporter.enable-kea-details

Web server:
      --web.telemetry-path="/metrics"
      --[no-]web.disable-exporter-metrics
      --web.listen-address=:8080 ...
      --[no-]web.systemd-socket
      --web.config.file=""

Runtime:
      --exporter.instance-label=EXPORTER.INSTANCE-LABEL
                                 ($OPNSENSE_EXPORTER_INSTANCE_LABEL)
      --log.level=info
      --log.format=logfmt
```
