---
title: OPNsense Exporter
description: Prometheus and OpenTelemetry exporter for OPNsense firewalls with 920 metrics across 65 collectors, native OTLP metrics and logs, a syslog receiver, and NetFlow and Zenarmor flow shipping
image: assets/social-card.png
---

<div class="hero" markdown>

# OPNsense Exporter

**Prometheus and OpenTelemetry metrics for OPNsense firewalls**

A Prometheus exporter that polls OPNsense REST APIs and exposes 920 metrics across 65 concurrent collectors: firewall statistics, network interfaces, gateways, VPN tunnels, DHCP leases, DNS resolver stats, system resources, hardware temperatures, certificate expiry, and more. It also pushes native OpenTelemetry metrics and logs over OTLP, receives and enriches syslog, and turns NetFlow and Zenarmor records into bounded flow-volume metrics.

<div class="hero-badges" markdown>

[Getting Started](getting-started.md){ .md-button .md-button--primary .md-button--stretch }
[GitHub :fontawesome-brands-github:](https://github.com/rknightion/opnsense-exporter){ .md-button .md-button--primary .md-button--stretch target="_blank" }
[Docker Hub :fontawesome-brands-docker:](https://ghcr.io/rknightion/opnsense-exporter){ .md-button .md-button--primary .md-button--stretch target="_blank" }

</div>
</div>

## Quick navigation

<div class="grid cards" markdown>

-   :material-rocket-launch:{ .lg .middle } **Getting Started**

    ---

    Create an API key, deploy the exporter, and verify metrics in under five minutes.

    [:octicons-arrow-right-24: Quick start](getting-started.md)

-   :material-cog:{ .lg .middle } **Configuration**

    ---

    Complete reference for all CLI flags, environment variables, and collector switches.

    [:octicons-arrow-right-24: Configuration](configuration.md)

-   :material-chart-bar:{ .lg .middle } **Metrics Reference**

    ---

    Browse all 920 Prometheus metrics with types, labels, and PromQL examples.

    [:octicons-arrow-right-24: Metrics](metrics/index.md)

-   :material-puzzle:{ .lg .middle } **Collectors**

    ---

    65 sub-collectors running concurrently, each targeting a specific OPNsense subsystem.

    [:octicons-arrow-right-24: Collectors](collectors/index.md)

-   :material-docker:{ .lg .middle } **Deployment**

    ---

    Deploy with Docker, Docker Compose, Kubernetes, or systemd on any host with API access.

    [:octicons-arrow-right-24: Deployment](deployment.md)

-   :material-monitor-dashboard:{ .lg .middle } **Dashboards**

    ---

    Pre-built Grafana dashboard, Prometheus scrape configs, and example PromQL queries.

    [:octicons-arrow-right-24: Integration](integration-dashboards.md)

</div>

## About

OPNsense Exporter targets OPNsense specifically, covering the firewall, its plugin ecosystem, and the services running on it. It complements `node_exporter`: `node_exporter` has to run on the firewall itself, but this exporter can run on any machine with network access to the OPNsense API.

Key highlights:

- **65 collectors** covering every major OPNsense subsystem
- **Independent background polling** with snapshot replay for fast, API-free scrapes
- **High-availability support** with CARP/VIP monitoring
- **Opt-in high-cardinality metrics** for per-lease DHCP and per-rule firewall detail
- **File-based secrets** for credentials outside plain environment variables
- **Continuous profiling** (opt-in) pushed to Grafana Cloud Pyroscope

## What sets it apart

Most OPNsense exporters scrape a few endpoints and stop at `/metrics`. This one covers all four telemetry paths off the firewall:

- **Native OpenTelemetry** - push metrics *and* logs over OTLP to any collector or to Grafana Cloud, with no Prometheus scrape at all. See [configuration](configuration.md).
- **[Syslog receiver](syslog-receiver.md)** - the firewall pushes logs to the exporter, which parses `filterlog`, sshd, DHCP, HAProxy and Suricata lines and enriches them with rule descriptions, interface names and hostnames from the API. A generic collector can receive those lines; it cannot understand them.
- **[Zenarmor receiver](zenarmor-receiver.md)** - per-connection, DNS, TLS/SNI, HTTP and threat-alert records taken straight from Zenarmor by posing as its Elasticsearch streaming target. The only way to get that data off a Home-tier box, since Zenarmor's syslog export is licence-gated.
- **[NetFlow and flow volume](flow.md)** - a NetFlow v5/v9 receiver and Zenarmor connection records feed one bounded rollup, so traffic-volume questions are answerable from Prometheus for years instead of by scanning GB/day of logs.

The source for all of it is on GitHub at [rknightion/opnsense-exporter](https://github.com/rknightion/opnsense-exporter) under Apache-2.0. Bug reports and questions go to [GitHub issues](https://github.com/rknightion/opnsense-exporter/issues) and [discussions](https://github.com/rknightion/opnsense-exporter/discussions); if the project is useful to you, [a star on the repository](https://github.com/rknightion/opnsense-exporter) helps other OPNsense operators find it.

!!! info "Fork notice"
    This began as a fork of [AthennaMind/opnsense-exporter](https://github.com/AthennaMind/opnsense-exporter) and became a hard fork early on, as its changes quickly grew incompatible with upstream. Credit to the original authors for the foundation this builds on. It now evolves independently; see the [changelog](changelog.md) for release history.
