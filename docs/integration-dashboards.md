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

!!! warning "Minimum Grafana version: 13+ — and Grafana 12 fails silently"
    The dashboard uses the v2 dynamic schema (`dashboard.grafana.app/v2`) with `TabsLayout` and `conditionalRendering`, which require **Grafana 13 or later**. There is deliberately no schema-v1 build: the show/hide behaviour is the point of this dashboard, and classic schema cannot express it, so a converted copy would render every plugin-gated tab permanently empty — indistinguishable from a broken exporter.

    Know what an older Grafana does with it before you try, because two of the three routes do not tell you (verified against pinned `grafana/grafana` containers, 2026-07-27):

    | Grafana | route | result |
    | --- | --- | --- |
    | 11.5.0 | `POST /api/dashboards/db` | **400** `Dashboard title cannot be empty` — v2 keeps the title under `spec`, so the error names a symptom, not the cause |
    | 12.4.0 | `POST /api/dashboards/db` | **200**, and the dashboard then renders **0 panels and 0 variables**. The v2 body is stored verbatim and ignored — no error anywhere |
    | 12.4.0 | `POST /apis/dashboard.grafana.app/...` | **400** `no kind "Dashboard" is registered for version "dashboard.grafana.app/v2"` |

    An empty dashboard on Grafana 12 is not a broken export; it is the version. Upgrade to Grafana 13.

A single comprehensive Grafana dashboard covers **all 836 metrics across 41 tabs** (<!-- docgen:begin:dashboard-tabs -->
Overview, System & Resources, Services, Cron & DynDNS, Certificates, UPS, Monit, HA Sync, CARP / HA, Interfaces, Gateways & WAN, DNS - Unbound, DHCP, Routing & Neighbors, Protocol Stats, NTP, Chrony, Traffic Shaper, NetFlow, FRR Routing, Captive Portal, Firewall & PF, Aliases, IDS/IPS, CrowdSec, ClamAV, Q-Feeds, Zenarmor, VPN, Tailscale, NetBird, Tor, Syslog, HAProxy, Relayd, Nginx, Siproxd, Log-derived Events, Flow Volume, Log Shipping, Recording rules, Diagnostics
<!-- docgen:end:dashboard-tabs -->). Tabs and rows auto show/hide based on which metrics your exporter emits, so unused collectors and absent OPNsense plugins disappear automatically.

### Import the dashboard

1. Open Grafana and navigate to **Dashboards > New > Import**.
2. Import the JSON file from the repository: `grafana/dashboard.json`
3. Select your Prometheus data source and click **Import**.

The dashboard uses template variables for `datasource`, `opnsense_instance`, and `interface`. See [`grafana/README.md`](https://github.com/rknightion/opnsense-exporter/blob/main/grafana/README.md) for `gcx`/GitOps deployment and the bundled alert and recording rules.

## Example PromQL queries

### Gateway monitoring

**Gateway availability overview:**

```promql
opnsense_gateways_status
```

**Gateway alarm transitions from `dpinger`:**

```promql
sum by (opnsense_instance, gateway, event) (
  rate(opnsense_log_events_gateway_total{event=~"alarm_started|alarm_cleared"}[5m])
)
```

The Gateways & WAN tab puts this transition rate beside the current gateway-state
timeline. `event` is closed to `alarm_started` (`none -> down`) and
`alarm_cleared` (`down -> none`); the metric has no address, RTT or loss labels.
The Grafana-managed `OPNsenseGatewayAlarmFlapping` warning alerts when one gateway
has three or more `alarm_started` events in 15 minutes. It is transition evidence,
not a claim that the gateway is currently down.

**CARP transitions from the FreeBSD kernel:**

```promql
sum by (opnsense_instance, event, from, to, interface, vhid) (
  rate(opnsense_log_events_carp_total[5m])
)
```

The CARP / HA tab puts this beside the CARP VIP Status timeline: that shows the state
now, this shows the transitions that produced it. `event` is closed to `state_changed`,
`demoted` and `promoted`; `from` and `to` are closed to `master`, `backup` and `init`.
A demotion names neither an interface nor a VHID, so `from`, `to`, `interface` and
`vhid` are empty on those series, and `demoted` versus `promoted` is decided by the
sign of the kernel's demotion delta. The kernel's **cause** is not a label — read it
from `carp.reason` on the shipped log record, with `carp.demotion.delta` and
`carp.demotion.total`. Two Grafana-managed warnings cover it:
`OPNsenseCARPStateFlapping` on four or more state changes for one vhid in 15 minutes
(a clean failover is two, and does not fire), and `OPNsenseCARPUnexpectedDemotion` on
any sustained rate of `event="demoted"`.

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
  rate(opnsense_firewall_in_ipv4_pass_packets_total[5m])
  + rate(opnsense_firewall_out_ipv4_pass_packets_total[5m])
  + rate(opnsense_firewall_in_ipv6_pass_packets_total[5m])
  + rate(opnsense_firewall_out_ipv6_pass_packets_total[5m])
)
```

**Block rate by interface:**

```promql
sum by (interface) (
  rate(opnsense_firewall_in_ipv4_block_packets_total[5m])
  + rate(opnsense_firewall_out_ipv4_block_packets_total[5m])
  + rate(opnsense_firewall_in_ipv6_block_packets_total[5m])
  + rate(opnsense_firewall_out_ipv6_block_packets_total[5m])
)
```

**Firewall state table utilization:**

```promql
opnsense_firewall_pf_states_current / opnsense_firewall_pf_states_limit * 100
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
