---
title: Integration & Dashboards
description: Prometheus scrape configuration, Grafana dashboard setup, and example PromQL queries for the OPNsense Exporter
tags:
  - Prometheus
  - Monitoring
---

# Integration & Dashboards

This guide covers integrating the OPNsense Exporter with Prometheus and Grafana, including scrape configuration, dashboard import, and practical PromQL queries.

## Prometheus scrape configuration

Add the following scrape job to your `prometheus.yml`:

```yaml title="prometheus.yml"
scrape_configs:
  - job_name: opnsense
    scrape_interval: 30s
    scrape_timeout: 10s
    static_configs:
      - targets:
          - "exporter-host:8080"
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
        replacement: "my-firewall"
```

### Multi-instance configuration

If you monitor multiple OPNsense firewalls, add a target for each exporter instance:

```yaml title="prometheus.yml"
scrape_configs:
  - job_name: opnsense
    scrape_interval: 30s
    static_configs:
      - targets:
          - "exporter-primary:8080"
        labels:
          firewall: primary
      - targets:
          - "exporter-secondary:8081"
        labels:
          firewall: secondary
```

### Prometheus Operator

See the [Kubernetes deployment guide](deployment/kubernetes.md) for `ScrapeConfig` and `ServiceMonitor` examples.

## Grafana dashboard

A pre-built Grafana dashboard is available for visualizing OPNsense Exporter metrics.

**[OPNsense Exporter Dashboard on Grafana.com](https://grafana.com/grafana/dashboards/21113)** (ID: `21113`)

### Import the dashboard

1. Open Grafana and navigate to **Dashboards > Import**.
2. Enter the dashboard ID `21113` and click **Load**.
3. Select your Prometheus data source and click **Import**.

Alternatively, import the JSON file directly from the repository:

```
deploy/grafana/dashboard-v1.json
```

### Dashboard panels

The dashboard includes panels for:

![Gateway monitoring](assets/gateways.png)

![Interface statistics](assets/interfaces.png)

![Service status](assets/services.png)

![Firmware and system](assets/firmware.png)

![ARP table](assets/arp.png)

## Example PromQL queries

### Gateway monitoring

**Gateway availability overview:**

```promql
opnsense_gateways_status
```

**Average RTT per gateway over 5 minutes:**

```promql
avg_over_time(opnsense_gateways_rtt_milliseconds[5m])
```

**Gateways with packet loss above 1%:**

```promql
opnsense_gateways_loss_percentage > 1
```

### Firewall traffic analysis

**Total pass packets per second by interface:**

```promql
sum by (interface) (
  rate(opnsense_firewall_ipv4_pass_packets_total[5m])
  + rate(opnsense_firewall_ipv6_pass_packets_total[5m])
)
```

**Block rate by interface:**

```promql
sum by (interface) (
  rate(opnsense_firewall_ipv4_block_packets_total[5m])
  + rate(opnsense_firewall_ipv6_block_packets_total[5m])
)
```

**Firewall state table utilization:**

```promql
opnsense_firewall_states_current / opnsense_firewall_states_limit * 100
```

### System resources

**Memory usage percentage:**

```promql
opnsense_system_memory_used_bytes / opnsense_system_memory_total_bytes * 100
```

**Load average trend (1-min):**

```promql
opnsense_system_load_average_one_minute
```

**Disk usage by device:**

```promql
opnsense_system_disk_used_ratio * 100
```

### Certificate expiry alerting

**Days until certificate expiry:**

```promql
(opnsense_certificate_valid_to_seconds - time()) / 86400
```

**Certificates expiring within 14 days:**

```promql
(opnsense_certificate_valid_to_seconds - time()) / 86400 < 14
  and
(opnsense_certificate_valid_to_seconds - time()) > 0
```

### DNS performance

**Unbound query rate:**

```promql
rate(opnsense_unbound_dns_queries_total[5m])
```

**DNS cache hit ratio:**

```promql
rate(opnsense_unbound_dns_cache_hits_total[5m])
/ (
  rate(opnsense_unbound_dns_cache_hits_total[5m])
  + rate(opnsense_unbound_dns_cache_misses_total[5m])
) * 100
```

### VPN monitoring

**WireGuard peer transfer rates:**

```promql
rate(opnsense_wireguard_peer_received_bytes_total[5m])
```

**IPsec tunnel status:**

```promql
opnsense_ipsec_phase1_status
```

### High-availability

**CARP VIP status (MASTER=1, BACKUP=2, INIT=0):**

```promql
opnsense_carp_vip_status
```

**CARP demotion counter (non-zero indicates issues):**

```promql
opnsense_carp_demotion_counter > 0
```

### NTP health

**NTP offset across all peers:**

```promql
opnsense_ntp_offset_milliseconds
```

**NTP peers with poor reachability:**

```promql
opnsense_ntp_reachability < 255
```

### Temperature alerts

**High temperature alert (above 75C):**

```promql
opnsense_temperature_celsius > 75
```

## Alerting rules

Example Prometheus alerting rules for OPNsense monitoring:

```yaml title="opnsense-alerts.yml"
groups:
  - name: opnsense
    rules:
      - alert: OPNsenseDown
        expr: opnsense_up == 0
        for: 2m
        labels:
          severity: critical
        annotations:
          summary: "OPNsense exporter cannot reach {{ $labels.opnsense_instance }}"

      - alert: OPNsenseGatewayDown
        expr: opnsense_gateways_status != 1
        for: 1m
        labels:
          severity: warning
        annotations:
          summary: "Gateway {{ $labels.gateway }} is down on {{ $labels.opnsense_instance }}"

      - alert: OPNsenseCertExpiringSoon
        expr: (opnsense_certificate_valid_to_seconds - time()) / 86400 < 14
        for: 1h
        labels:
          severity: warning
        annotations:
          summary: "Certificate {{ $labels.description }} expires in {{ $value | humanize }} days"

      - alert: OPNsenseHighMemory
        expr: opnsense_system_memory_used_bytes / opnsense_system_memory_total_bytes > 0.9
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Memory usage above 90% on {{ $labels.opnsense_instance }}"

      - alert: OPNsenseHighTemperature
        expr: opnsense_temperature_celsius > 80
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "Temperature {{ $value }}C on {{ $labels.device }} ({{ $labels.opnsense_instance }})"
```

## Complementary exporters

The OPNsense Exporter focuses on OPNsense-specific metrics. For complete visibility, consider running these alongside it:

- **[node_exporter](https://github.com/prometheus/node_exporter)** -- Install on the OPNsense firewall itself for OS-level metrics (CPU, memory, disk I/O, network). The OPNsense Exporter provides OPNsense-specific views of some of these, but node_exporter offers deeper system-level detail.
- **[blackbox_exporter](https://github.com/prometheus/blackbox_exporter)** -- Probe endpoints through the firewall to verify connectivity and measure latency from the network edge.
