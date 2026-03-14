---
title: OPNsense Exporter
description: Comprehensive Prometheus exporter for OPNsense firewalls with 320+ metrics across 26 collectors
image: assets/social-card.png
---

<div class="hero" markdown>

# OPNsense Exporter

**Comprehensive Prometheus metrics for OPNsense firewalls**

A production-ready Prometheus exporter that polls OPNsense REST APIs and exposes 320+ metrics across 26 concurrent collectors -- covering firewall statistics, network interfaces, gateways, VPN tunnels, DHCP leases, DNS resolver stats, system resources, hardware temperatures, certificate expiry, and much more.

<div class="hero-badges">

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

    Browse all 320+ Prometheus metrics with types, labels, and PromQL examples.

    [:octicons-arrow-right-24: Metrics](metrics/index.md)

-   :material-puzzle:{ .lg .middle } **Collectors**

    ---

    26 sub-collectors running concurrently, each targeting a specific OPNsense subsystem.

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

OPNsense Exporter focuses specifically on OPNsense, providing deep insight into the firewall, its plugin ecosystem, and the services running on it. It is designed to complement `node_exporter` -- while `node_exporter` must be installed on the firewall itself, this exporter can run on any machine with network access to the OPNsense API.

Key highlights:

- **26 collectors** covering every major OPNsense subsystem
- **Concurrent collection** via goroutines for fast scrapes
- **High-availability support** with CARP/VIP monitoring
- **Opt-in high-cardinality metrics** for per-lease DHCP and per-rule firewall detail
- **File-based secrets** for secure credential management in containers
- **Profiling endpoints** via pprof and godeltaprof for operational visibility

!!! info "Fork notice"
    This is a fork of [AthennaMind/opnsense-exporter](https://github.com/AthennaMind/opnsense-exporter). Full credit to the original authors for building the foundation. This fork includes significant additions -- 14 new collectors, enhanced existing collectors, modernized build infrastructure, and many bug fixes -- that go beyond the scope of the upstream project.
