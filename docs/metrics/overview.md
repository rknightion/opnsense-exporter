---
title: Metrics Overview
description: Naming conventions, common labels, metric types, and PromQL examples for OPNsense Exporter metrics
tags:
  - Prometheus
  - Monitoring
---

# Metrics Overview

This page describes the naming conventions, label schemas, and metric types used by the OPNsense Exporter, along with practical PromQL examples.

## Naming convention

All metrics follow the pattern:

```
opnsense_<subsystem>_<metric_name>
```

Where `<subsystem>` corresponds to a collector (e.g., `gateways`, `firewall`, `unbound_dns`, `system`) and `<metric_name>` describes what is being measured.

Examples:

- `opnsense_gateways_loss_percentage` -- packet loss for a gateway
- `opnsense_firewall_ipv4_pass_packets_total` -- IPv4 pass packet counter per interface
- `opnsense_unbound_dns_queries_total` -- total DNS queries handled by Unbound
- `opnsense_system_memory_used_bytes` -- memory currently in use

## Common labels

### Instance label

Every metric includes the `opnsense_instance` label, set via `--exporter.instance-label`. This identifies which OPNsense firewall the metric came from, enabling multi-instance monitoring.

```promql
opnsense_up{opnsense_instance="primary-fw"}
```

### Subsystem-specific labels

Collectors add labels relevant to their subsystem:

| Subsystem | Common labels |
|-----------|--------------|
| Gateways | `gateway`, `address`, `interface`, `default_gateway` |
| Interfaces | `interface`, `device` |
| Firewall | `interface` |
| Firewall rules | `uuid`, `description`, `action`, `interface`, `direction` |
| WireGuard | `device`, `name`, `public_key` |
| IPsec | `name`, `phase1_id`, `phase2_id` |
| Unbound DNS | Various (query type, protocol, rcode) |
| Temperature | `device`, `type`, `device_seq` |
| DHCP (Dnsmasq/Kea) | `interface`, `address`, `hostname`, `mac` |
| Certificates | `description`, `common_name`, `cert_type`, `in_use` |
| NTP | `peer`, `refid`, `status` |
| CARP/VIP | `interface`, `vhid`, `status` |

## Metric types

### Gauge

Most metrics are gauges representing the current value at scrape time:

- Status indicators (0/1)
- Usage percentages
- Counts (current connections, leases, rules)
- Durations (uptime, RTT)
- Temperatures

### Counter

Counters represent monotonically increasing values and use the `_total` suffix:

- `opnsense_firewall_ipv4_pass_packets_total`
- `opnsense_exporter_scrapes_total`
- `opnsense_exporter_endpoint_errors_total`
- `opnsense_interfaces_received_bytes_total`

Use the `rate()` or `increase()` function to compute per-second rates or interval changes:

```promql
rate(opnsense_firewall_ipv4_pass_packets_total[5m])
```

## Top-level exporter metrics

These metrics are always emitted regardless of collector configuration:

| Metric | Type | Description |
|--------|------|-------------|
| `opnsense_up` | Gauge | Last scrape success (1 = yes, 0 = no) |
| `opnsense_firewall_status` | Gauge | Firewall health (1 = ok, 0 = errors) |
| `opnsense_system_status_code` | Gauge | Numeric health status (2 = OK on OPNsense >= 25.1) |
| `opnsense_exporter_scrapes_total` | Counter | Total scrapes performed |
| `opnsense_exporter_endpoint_errors_total` | Counter | API errors by endpoint |

## High-cardinality metrics

Some collectors offer opt-in detail metrics that produce one time series per item:

- **Dnsmasq details:** One series per DHCP lease (`--exporter.enable-dnsmasq-details`)
- **Kea details:** One series per DHCP lease (`--exporter.enable-kea-details`)
- **Firewall rule details:** One series per firewall rule (`--exporter.enable-firewall-rules-details`)

These are disabled by default. See [Collectors: High-cardinality detail metrics](../collectors/index.md#high-cardinality-detail-metrics) for guidance.

## PromQL examples

### Gateway health

Check if any gateway is down:

```promql
opnsense_gateways_status{opnsense_instance="my-firewall"} != 1
```

Gateway packet loss over time:

```promql
opnsense_gateways_loss_percentage{opnsense_instance="my-firewall"}
```

### Firewall traffic rates

Packets per second through the firewall by interface:

```promql
sum by (interface) (
  rate(opnsense_firewall_ipv4_pass_packets_total{opnsense_instance="my-firewall"}[5m])
)
```

### Memory usage trend

Memory usage percentage:

```promql
opnsense_system_memory_used_bytes{opnsense_instance="my-firewall"}
  /
opnsense_system_memory_total_bytes{opnsense_instance="my-firewall"}
  * 100
```

### Certificate expiry alerting

Certificates expiring within 30 days:

```promql
(opnsense_certificate_valid_to_seconds - time()) / 86400 < 30
```

### Service availability

Check if critical services are running:

```promql
opnsense_unbound_dns_service_running{opnsense_instance="my-firewall"} == 0
  or
opnsense_wireguard_service_running{opnsense_instance="my-firewall"} == 0
  or
opnsense_ipsec_service_running{opnsense_instance="my-firewall"} == 0
```

### DNS query rate

Unbound DNS queries per second:

```promql
rate(opnsense_unbound_dns_queries_total{opnsense_instance="my-firewall"}[5m])
```

### CARP failover detection

Alert on CARP state changes:

```promql
changes(opnsense_carp_vip_status[5m]) > 0
```

### NTP health

NTP peers with high offset (> 100ms):

```promql
abs(opnsense_ntp_offset_milliseconds) > 100
```

### Temperature monitoring

Alert on high CPU temperature:

```promql
opnsense_temperature_celsius{type="cpu"} > 80
```
