---
title: Getting Started
description: Quick start guide for deploying the OPNsense Exporter and scraping your first metrics
tags:
  - Deployment
  - Configuration
---

# Getting Started

Get the OPNsense Exporter up and running in under five minutes.

## Prerequisites

- An OPNsense firewall (any supported version; tested with 24.x and 25.x)
- API access enabled on OPNsense
- Network connectivity from the exporter host to the OPNsense API
- Docker, a Kubernetes cluster, or a Linux host with systemd

## Step 1: Create an OPNsense API key

1. Log in to the OPNsense web UI.
2. Navigate to **System > Access > Users**.
3. Select the user you want to generate an API key for (or create a dedicated monitoring user).
4. Scroll to **API keys** and click the **+** button to generate a new key pair.
5. Save the downloaded `.txt` file -- it contains the key and secret.

!!! warning "Least privilege"
    Avoid using the `root` user for API keys. Create a dedicated user and assign only the [required permissions](security.md#opnsense-user-permissions) for the metrics you need.

## Step 2: Deploy the exporter

=== "Docker"

    ```bash
    docker run -p 8080:8080 ghcr.io/rknightion/opnsense-exporter:latest \
      --opnsense.protocol=https \
      --opnsense.address=opnsense.example.com \
      --opnsense.api-key=YOUR_API_KEY \
      --opnsense.api-secret=YOUR_API_SECRET \
      --exporter.instance-label=my-firewall \
      --web.listen-address=:8080
    ```

=== "Docker Compose"

    ```yaml
    services:
      opnsense-exporter:
        image: ghcr.io/rknightion/opnsense-exporter:latest
        restart: always
        command:
          - --opnsense.protocol=https
          - --opnsense.address=opnsense.example.com
          - --exporter.instance-label=my-firewall
          - --web.listen-address=:8080
        environment:
          OPNSENSE_EXPORTER_OPS_API_KEY: "${OPS_API_KEY}"
          OPNSENSE_EXPORTER_OPS_API_SECRET: "${OPS_API_SECRET}"
        ports:
          - "8080:8080"
    ```

=== "Binary"

    Download the latest release from [GitHub Releases](https://github.com/rknightion/opnsense-exporter/releases), then run:

    ```bash
    ./opnsense-exporter \
      --opnsense.protocol=https \
      --opnsense.address=opnsense.example.com \
      --opnsense.api-key=YOUR_API_KEY \
      --opnsense.api-secret=YOUR_API_SECRET \
      --exporter.instance-label=my-firewall
    ```

## Step 3: Verify metrics

Once the exporter is running, open your browser or use `curl`:

```bash
curl http://localhost:8080/metrics
```

You should see output containing lines like:

```text
# HELP opnsense_up Was the last scrape of OPNsense successful. (1 = yes, 0 = no)
# TYPE opnsense_up gauge
opnsense_up{opnsense_instance="my-firewall"} 1
```

If `opnsense_up` is `0`, check the exporter logs for connection or authentication errors.

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

- **[Configuration](configuration.md)** -- Full reference for all CLI flags, environment variables, and collector switches
- **[Deployment](deployment.md)** -- Production deployment guides for Docker, Kubernetes, and systemd
- **[Security](security.md)** -- API key permissions, TLS configuration, and file-based secrets
- **[Collectors](collectors/index.md)** -- Overview of all 26 collectors and what they monitor
- **[Integration & Dashboards](integration-dashboards.md)** -- Grafana dashboard setup and PromQL examples
