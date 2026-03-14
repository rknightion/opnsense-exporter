---
title: Collectors
description: Overview of all 26 OPNsense Exporter collectors, their auto-registration pattern, and configuration options
tags:
  - Monitoring
  - Configuration
---

# Collectors

The OPNsense Exporter runs 26 sub-collectors concurrently via goroutines, each targeting a specific OPNsense subsystem. On every Prometheus scrape, all enabled collectors fan out in parallel, query the OPNsense REST API, and emit their metrics.

## Scrape flow

```mermaid
graph LR
    A[Prometheus scrape] --> B[Collector.Collect]
    B --> C[Health check]
    C --> D{opnsense_up?}
    D -->|Yes| E[Fan out to sub-collectors]
    D -->|No| F[Return opnsense_up=0]
    E --> G1[ARP table]
    E --> G2[Gateways]
    E --> G3[Interfaces]
    E --> G4[...]
    E --> G5[PF Stats]
    G1 --> H[Merge metrics]
    G2 --> H
    G3 --> H
    G4 --> H
    G5 --> H
    H --> I[Return to Prometheus]
```

## Auto-registration pattern

Sub-collectors register themselves via `init()` functions that append to a global `collectorInstances` slice. Adding a new collector requires only creating the file with an `init()` function -- no manual registration is needed. See [Adding a Collector](../development/adding-collector.md) for details.

## Top-level exporter metrics

These metrics are always emitted regardless of which sub-collectors are enabled:

| Metric | Type | Description |
|--------|------|-------------|
| `opnsense_up` | Gauge | Was the last scrape successful (1 = yes, 0 = no) |
| `opnsense_firewall_status` | Gauge | Firewall health status from system health check (1 = ok, 0 = errors) |
| `opnsense_system_status_code` | Gauge | Numeric system status code from health check (2 = OK for OPNsense >= 25.1) |
| `opnsense_exporter_scrapes_total` | Counter | Total number of scrapes performed |
| `opnsense_exporter_endpoint_errors_total` | Counter | Total API errors by endpoint |

## Collector reference

### Enabled by default

| Collector | Subsystem | Description | Disable flag |
|-----------|-----------|-------------|-------------|
| ARP table | `arp_table` | ARP cache entries | `--exporter.disable-arp-table` |
| Gateways | `gateways` | Gateway status, RTT, loss, configuration | Always enabled |
| Interfaces | `interfaces` | Interface traffic counters, packet totals, queue stats, link state, line rate | Always enabled |
| Protocol stats | `protocol` | CARP, pfsync, IP, TCP, ARP protocol statistics (39+ metrics) | Always enabled |
| Services | `services` | Service running status across all OPNsense services | Always enabled |
| Cron jobs | `cron` | Cron table entries | `--exporter.disable-cron-table` |
| WireGuard | `wireguard` | WireGuard tunnels, peers, transfer stats, service status | `--exporter.disable-wireguard` |
| IPsec | `ipsec` | IPsec tunnels, phase1/phase2 status, service status | `--exporter.disable-ipsec` |
| Unbound DNS | `unbound_dns` | DNS resolver statistics (30+ metrics), blocklist status, service status | `--exporter.disable-unbound` |
| OpenVPN | `openvpn` | OpenVPN instances, sessions, traffic | `--exporter.disable-openvpn` |
| Firewall | `firewall` | PF interface packet/byte counters (IPv4/IPv6 pass/block), state table, per-interface hits | `--exporter.disable-firewall` |
| Firewall rules | `firewall_rule` | Total rule count; opt-in per-rule detail metrics | `--exporter.disable-firewall-rules` |
| Firmware | `firmware` | Firmware version info, update status, reboot flags | `--exporter.disable-firmware` |
| System | `system` | Memory, uptime, load averages, disk/swap usage, system info | `--exporter.disable-system` |
| Temperature | `temperature` | Hardware temperature sensors | `--exporter.disable-temperature` |
| Dnsmasq DHCP | `dnsmasq` | DHCP leases (total, by interface, reserved vs dynamic) | `--exporter.disable-dnsmasq` |
| Mbuf stats | `mbuf` | FreeBSD network buffers, allocation failures, sendfile stats | `--exporter.disable-mbuf` |
| NTP | `ntp` | NTP peer metrics (stratum, delay, offset, jitter) | `--exporter.disable-ntp` |
| Certificates | `certificate` | Certificate validity timestamps, expiry monitoring | `--exporter.disable-certificates` |
| CARP/VIP | `carp` | CARP HA status, demotion counter, per-VIP state | `--exporter.disable-carp` |
| Activity | `activity` | CPU percentages (user/nice/system/interrupt/idle), thread counts | `--exporter.disable-activity` |
| Kea DHCP | `kea` | Kea DHCPv4/v6 leases (total, by interface, reserved vs dynamic) | `--exporter.disable-kea` |
| PF stats | `pf_stats` | PF state table, counters, limit counters, memory limits, timeouts | `--exporter.disable-pf-stats` |
| NDP | `ndp` | IPv6 neighbor discovery table entries | `--exporter.disable-ndp` |

### Disabled by default (opt-in)

| Collector | Subsystem | Description | Enable flag |
|-----------|-----------|-------------|-------------|
| Network diagnostics | `network_diag` | Kernel netisr stats, socket counts, route counts, pfsync HA nodes | `--exporter.enable-network-diagnostics` |
| NetFlow | `netflow` | NetFlow service status, per-interface cache statistics | `--exporter.enable-netflow` |

### High-cardinality detail metrics

These produce one time series per item and should be evaluated carefully before enabling:

| Detail option | Parent collector | Enable flag |
|---------------|-----------------|-------------|
| Dnsmasq per-lease details | Dnsmasq DHCP | `--exporter.enable-dnsmasq-details` |
| Firewall per-rule details | Firewall rules | `--exporter.enable-firewall-rules-details` |
| Kea per-lease details | Kea DHCP | `--exporter.enable-kea-details` |

!!! warning "Cardinality impact"
    Each active DHCP lease or firewall rule generates multiple time series when detail metrics are enabled. On a firewall with 500 DHCP leases, enabling Dnsmasq details creates approximately 500 additional time series. Monitor your Prometheus storage after enabling.

## Service running metrics

Several collectors include a `service_running` gauge (1 = running, 0 = stopped/disabled) for their respective services:

- Unbound DNS: `opnsense_unbound_dns_service_running`
- Dnsmasq: `opnsense_dnsmasq_service_running`
- IPsec: `opnsense_ipsec_service_running`
- WireGuard: `opnsense_wireguard_service_running`
