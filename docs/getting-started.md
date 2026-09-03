---
title: Getting Started
description: Quick start guide for deploying opnsense2otel and scraping your first metrics
tags:
  - Deployment
  - Configuration
---

# Getting Started

Get opnsense2otel up and running in under five minutes.

## Prerequisites

- An OPNsense firewall supported by the [compatibility policy](compatibility.md)
- API access enabled on OPNsense
- Network connectivity from the exporter host to the OPNsense API
- Docker, a Kubernetes cluster, or a Linux host with systemd

## Step 1: Create an OPNsense API key

1. Log in to the OPNsense web UI.
2. Navigate to **System > Access > Users**.
3. Select the user you want to generate an API key for (or create a dedicated monitoring user).
4. Scroll to **API keys** and click the **+** button to generate a new key pair.
5. Save the downloaded `.txt` file: it contains the key and secret.

!!! warning "Least privilege"
    Avoid using the `root` user for API keys. Create a dedicated user and assign only the [required permissions](security.md#opnsense-user-permissions) for the metrics you need.

## Step 2: Deploy the exporter

=== "Docker"

    ```bash
    docker run -p 8080:8080 \
      -e OPN2OTEL_OPS_API_KEY=YOUR_API_KEY \
      -e OPN2OTEL_OPS_API_SECRET=YOUR_API_SECRET \
      ghcr.io/rknightion/opnsense2otel:latest \
      --opnsense.protocol=https \
      --opnsense.address=opnsense.example.com \
      --exporter.instance-label=my-firewall \
      --web.listen-address=:8080
    ```

=== "Docker Compose"

    ```yaml
    services:
      opnsense2otel:
        image: ghcr.io/rknightion/opnsense2otel:latest
        restart: always
        command:
          - --opnsense.protocol=https
          - --opnsense.address=opnsense.example.com
          - --exporter.instance-label=my-firewall
          - --web.listen-address=:8080
        environment:
          OPN2OTEL_OPS_API_KEY: "${OPS_API_KEY}"
          OPN2OTEL_OPS_API_SECRET: "${OPS_API_SECRET}"
        ports:
          - "8080:8080"
    ```

=== "Binary"

    Download the latest release from [GitHub Releases](https://github.com/rknightion/opnsense2otel/releases), then run:

    ```bash
    export OPN2OTEL_OPS_API_KEY=YOUR_API_KEY
    export OPN2OTEL_OPS_API_SECRET=YOUR_API_SECRET

    ./opnsense2otel \
      --opnsense.protocol=https \
      --opnsense.address=opnsense.example.com \
      --exporter.instance-label=my-firewall
    ```

!!! tip "Production credentials"
    Avoid passing credentials as command-line flags: they are visible in the process list. For production, prefer file-based secrets via `OPS_API_KEY_FILE` / `OPS_API_SECRET_FILE` (see [Security: File-based secrets](security.md#file-based-secrets)).

## Step 3: Verify metrics

Once the exporter is running, open your browser or use `curl`:

```bash
curl http://localhost:8080/metrics
```

You should see output containing lines like:

```text
# HELP opnsense_up Whether the OPNsense API was reachable on the last health poll (1 = reachable, 0 = unreachable), updated on --collector.poll-interval independently of scrapes. A reachable box reporting a degraded subsystem stays 1; see opnsense_system_status_code and the per-subsystem status metrics.
# TYPE opnsense_up gauge
opnsense_up{opnsense_instance="my-firewall"} 1
```

`opnsense_up` reflects whether the OPNsense API was reachable on the last health poll, not whether the box is healthy and not the last scrape — scraping replays an in-memory snapshot and makes no API call. If it is `0`, check the exporter logs for connection or authentication errors around the poll interval. A reachable box that OPNsense itself reports as degraded (e.g. a leftover crash report) keeps `opnsense_up=1`. Check `opnsense_system_status_code` (2 = OK, 1 = NOTICE, 0 = WARNING, -1 = ERROR) and `opnsense_crash_reporter_status` / `opnsense_firewall_status` instead.

## Step 4: Configure Prometheus

Add a scrape job to your `prometheus.yml`:

```yaml
scrape_configs:
  - job_name: opnsense
    scrape_interval: 30s
    static_configs:
      - targets:
          - "exporter-host:8080"
    relabel_configs:
      - source_labels: [__address__]
        target_label: instance
        replacement: "my-firewall"
```

## What's next?

- **[Configuration](configuration.md)**: full reference for all CLI flags, environment variables, and collector switches
- **[Deployment](deployment.md)**: production deployment guides for Docker, Kubernetes, and systemd
- **[Security](security.md)**: API key permissions, TLS configuration, and file-based secrets
- **[Collectors](collectors/index.md)**: overview of all 81 collectors and what they monitor
- **[Integration & Dashboards](integration-dashboards.md)**: Grafana dashboard setup and PromQL examples
