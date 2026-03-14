---
title: Docker & Compose
description: Deploy the OPNsense Exporter using Docker or Docker Compose with environment variables or Docker secrets
tags:
  - Deployment
  - Docker
---

# Docker & Compose

The OPNsense Exporter is published as a multi-architecture container image (amd64/arm64) on GitHub Container Registry.

```
ghcr.io/rknightion/opnsense-exporter:latest
```

## Docker run

The simplest way to start the exporter:

```bash
docker run -p 8080:8080 ghcr.io/rknightion/opnsense-exporter:latest \
  --opnsense.protocol=https \
  --opnsense.address=opnsense.example.com \
  --opnsense.api-key=YOUR_API_KEY \
  --opnsense.api-secret=YOUR_API_SECRET \
  --exporter.instance-label=my-firewall \
  --web.listen-address=:8080 \
  --log.level=info \
  --log.format=json
```

## Docker Compose with environment variables

```yaml title="docker-compose.yml"
services:
  opnsense-exporter:
    image: ghcr.io/rknightion/opnsense-exporter:latest
    container_name: opnsense-exporter
    restart: always
    command:
      - --opnsense.protocol=https
      - --opnsense.address=opnsense.example.com
      - --exporter.instance-label=my-firewall
      - --web.listen-address=:8080
      # Disable collectors you don't need:
      # - --exporter.disable-arp-table
      # - --exporter.disable-cron-table
    environment:
      OPNSENSE_EXPORTER_OPS_API_KEY: "${OPS_API_KEY}"
      OPNSENSE_EXPORTER_OPS_API_SECRET: "${OPS_API_SECRET}"
    ports:
      - "8080:8080"
```

## Docker Compose with file-based secrets

For production deployments, use Docker secrets to avoid storing credentials in environment variables or compose files.

### Create the secrets

```bash
echo "your-api-key" | docker secret create opnsense-api-key -
echo "your-api-secret" | docker secret create opnsense-api-secret -
```

### Compose file

```yaml title="docker-compose.yml"
services:
  opnsense-exporter:
    image: ghcr.io/rknightion/opnsense-exporter:latest
    container_name: opnsense-exporter
    restart: always
    command:
      - --opnsense.protocol=https
      - --opnsense.address=opnsense.example.com
      - --exporter.instance-label=my-firewall
      - --web.listen-address=:8080
    environment:
      OPS_API_KEY_FILE: /run/secrets/opnsense-api-key
      OPS_API_SECRET_FILE: /run/secrets/opnsense-api-secret
    secrets:
      - opnsense-api-key
      - opnsense-api-secret
    ports:
      - "8080:8080"

secrets:
  opnsense-api-key:
    external: true
  opnsense-api-secret:
    external: true
```

!!! tip "Local file secrets"
    If you are not running Docker Swarm, you can use file-based secrets with bind mounts instead:

    ```yaml
    services:
      opnsense-exporter:
        # ...
        volumes:
          - ./secrets/api-key:/run/secrets/opnsense-api-key:ro
          - ./secrets/api-secret:/run/secrets/opnsense-api-secret:ro
        environment:
          OPS_API_KEY_FILE: /run/secrets/opnsense-api-key
          OPS_API_SECRET_FILE: /run/secrets/opnsense-api-secret
    ```

## Health check configuration

Add a health check to your compose file to ensure the container is restarted if the exporter becomes unresponsive:

```yaml
services:
  opnsense-exporter:
    # ...
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:8080/"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
```

## Multi-instance setup

To monitor multiple OPNsense firewalls from a single Docker host, run one exporter per firewall with unique instance labels and port mappings:

```yaml title="docker-compose.yml"
services:
  opnsense-primary:
    image: ghcr.io/rknightion/opnsense-exporter:latest
    restart: always
    command:
      - --opnsense.protocol=https
      - --opnsense.address=primary-fw.example.com
      - --exporter.instance-label=primary
      - --web.listen-address=:8080
    environment:
      OPNSENSE_EXPORTER_OPS_API_KEY: "${PRIMARY_API_KEY}"
      OPNSENSE_EXPORTER_OPS_API_SECRET: "${PRIMARY_API_SECRET}"
    ports:
      - "8080:8080"

  opnsense-secondary:
    image: ghcr.io/rknightion/opnsense-exporter:latest
    restart: always
    command:
      - --opnsense.protocol=https
      - --opnsense.address=secondary-fw.example.com
      - --exporter.instance-label=secondary
      - --web.listen-address=:8080
    environment:
      OPNSENSE_EXPORTER_OPS_API_KEY: "${SECONDARY_API_KEY}"
      OPNSENSE_EXPORTER_OPS_API_SECRET: "${SECONDARY_API_SECRET}"
    ports:
      - "8081:8080"
```

## Container image details

- **Base image:** Distroless Debian 13 (nonroot), pinned by digest
- **User:** Runs as nonroot (UID 65534)
- **Architectures:** `linux/amd64`, `linux/arm64`
- **Build flags:** Static binary with `-trimpath`, `-mod=vendor`, CGO disabled
