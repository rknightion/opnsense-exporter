---
title: Docker & Compose
description: Deploy the OPNsense Exporter using Docker or Docker Compose with environment variables or Docker secrets
tags:
  - Deployment
  - Docker
---

# Docker & Compose

The OPNsense Exporter is published as a multi-architecture container image (amd64/arm64) on GitHub Container Registry.

```text
ghcr.io/rknightion/opnsense-exporter:latest
```

## Docker run

The simplest way to start the exporter:

```bash
docker run -p 8080:8080 \
  -e OPNSENSE_EXPORTER_OPS_API_KEY=YOUR_API_KEY \
  -e OPNSENSE_EXPORTER_OPS_API_SECRET=YOUR_API_SECRET \
  ghcr.io/rknightion/opnsense-exporter:latest \
  --opnsense.protocol=https \
  --opnsense.address=opnsense.example.com \
  --exporter.instance-label=my-firewall \
  --web.listen-address=:8080 \
  --log.level=info \
  --log.format=json
```

For production, prefer the [file-based secrets](#docker-compose-with-file-based-secrets) (`OPS_API_KEY_FILE` / `OPS_API_SECRET_FILE`) shown below over plain environment variables.

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
      # The receivers listen on their own ports and are off by default. Publish
      # one only when you enable its receiver - an unpublished port is the
      # commonest reason a receiver appears to receive nothing.
      #
      # Zenarmor's Elasticsearch stream (--logs.zenarmor.enabled). 9200 is the
      # Elasticsearch convention; nothing requires it, it just has to match the
      # URI you give Zenarmor. See ../zenarmor-receiver.md.
      # - "9200:9200"
      #
      # Syslog (--logs.syslog.enabled). Publish BOTH protocols. See ../syslog-receiver.md.
      # - "5514:5514/udp"
      # - "5514:5514/tcp"
```

## Docker Compose with file-based secrets

For production deployments, keep the API key and secret out of environment variables and out of the compose file. Compose reads each secret from a file on the host and mounts it at `/run/secrets/<name>`; the exporter reads the file paths named by `OPS_API_KEY_FILE` / `OPS_API_SECRET_FILE`.

This is the plain-Compose form and works on a single Docker host with no Swarm.

### Create the secret files

```bash
mkdir -p ./secrets
printf '%s' "your-api-key" > ./secrets/api-key
printf '%s' "your-api-secret" > ./secrets/api-secret
chmod 400 ./secrets/api-key ./secrets/api-secret
sudo chown 65532:65532 ./secrets/api-key ./secrets/api-secret
```

### Compose file

<!-- executable:begin:compose-file-secrets -->
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
    file: ./secrets/api-key
  opnsense-api-secret:
    file: ./secrets/api-secret
```
<!-- executable:end:compose-file-secrets -->

Verify the file renders before deploying it:

```bash
docker compose config
```

The container runs as UID 65532, so both secret files must be readable by that UID. Plain Compose implements file-backed secrets as bind mounts and preserves the host ownership and mode; the `uid`, `gid`, and `mode` fields do not remap a local file. Keep the files private by owning them with UID/GID 65532 and mode `0400`, as shown above.

### Alternative: Swarm external secrets

Only on Docker Swarm. `external: true` means the secret already exists in the Swarm cluster and is not created from a local file:

```bash
echo "your-api-key" | docker secret create opnsense-api-key -
echo "your-api-secret" | docker secret create opnsense-api-secret -
```

```yaml
secrets:
  opnsense-api-key:
    external: true
  opnsense-api-secret:
    external: true
```

The service block is otherwise identical. `docker secret create` fails outside Swarm, so do not mix this form into a plain-Compose file.

### Alternative: plain bind mounts

No `secrets:` section at all — the files are ordinary read-only mounts. Simplest, but the credentials appear in `docker inspect` as mount paths and are subject to the host file's ownership:

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

The runtime image is distroless: it contains the exporter binary and its licence files, and nothing else — no shell, no `curl`, no `wget`. A healthcheck that calls one of those can never run. The binary carries its own probe instead:

```yaml
services:
  opnsense-exporter:
    # ...
    healthcheck:
      test: ["CMD", "/opnsense-exporter", "health"]
      interval: 30s
      timeout: 5s
      retries: 3
      start_period: 10s
```

`CMD` (exec form) runs the binary directly. `CMD-SHELL`, and the bare-string form that implies it, would need `/bin/sh` and will not work in this image.

`health` performs an HTTP GET of `/-/healthy` on `http://127.0.0.1:8080` and exits 0 or 1. It makes no OPNsense API call: it reports whether this process is serving, which is what a liveness check is for. Flags:

| Flag | Default | Purpose |
|------|---------|---------|
| `--url` | `http://127.0.0.1:8080/-/healthy` | Probe target. Change it when `--web.listen-address` is not `:8080`. |
| `--timeout` | `2s` | Bounds the whole probe. |
| `--insecure` | off | Skip certificate verification, for a metrics port secured with a private cert via `--web.config.file`. |

For a non-default listen address:

```yaml
    healthcheck:
      test: ["CMD", "/opnsense-exporter", "health", "--url=http://127.0.0.1:9100/-/healthy"]
```

### What an unhealthy container does and does not do

A failing healthcheck marks the container `unhealthy`. **It does not restart it.** Docker's `restart:` policy reacts to the container's main process *exiting*; a container that is running but unhealthy has not exited, so no restart policy — `always` included — will act on it.

Health status is still worth having: `docker ps` shows it, `depends_on: condition: service_healthy` gates dependent services on it, and Docker emits `health_status` events you can alert on.

Automatic remediation needs something outside plain Docker Compose:

- **Docker Swarm** (`docker stack deploy`) — the orchestrator kills and reschedules a task whose healthcheck fails. This is the only first-party mechanism that acts on health status.
- **Kubernetes** — a `livenessProbe` restarts the container. See [Kubernetes](kubernetes.md).
- **A watchdog container** (for example `willfarrell/autoheal`) — subscribes to Docker health events and restarts unhealthy containers. Third-party, and it needs access to the Docker socket.

## Preflight the configuration

`--config.check` validates the effective configuration and exits: it binds no port, starts no poll scheduler, contacts no OPNsense API and exports no telemetry. It reads the files the configuration names (API key/secret, TLS keypairs) and exits 0 when the configuration is usable, 1 with every problem listed otherwise. Secrets are never printed.

With an env-var-driven configuration:

```bash
docker compose run --rm --no-deps opnsense-exporter --config.check
```

!!! warning "`docker compose run` replaces `command:`"
    Arguments passed to `docker compose run` do not extend the service's `command:` list, they replace it. If your flags live in `command:` rather than in `environment:`, the invocation above drops them and the check fails on missing required flags. Either repeat the flags:

    ```bash
    docker compose run --rm --no-deps opnsense-exporter \
      --opnsense.protocol=https --opnsense.address=opnsense.example.com --config.check
    ```

    or configure the exporter through `OPNSENSE_EXPORTER_*` environment variables, which the check reads through the same parser a real start does.

Deliberately not checked, because a configuration error and an unreachable firewall are different problems: OPNsense API reachability, port binding, and OTLP/Pyroscope endpoint reachability. Runtime reachability is reported by `/-/ready`.

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
- **User:** Runs as nonroot (UID 65532)
- **Architectures:** `linux/amd64`, `linux/arm64`
- **Build flags:** Static binary with `-trimpath`, `-mod=vendor`, CGO disabled

## Custom CA certificates

If your OPNsense web UI uses a certificate from a private CA, mount the CA bundle
and point Go's TLS stack at it with `SSL_CERT_FILE` (the runtime image is distroless,
so there is no `update-ca-certificates`):

```yaml
services:
  opnsense-exporter:
    image: ghcr.io/rknightion/opnsense-exporter:latest
    command:
      - --opnsense.protocol=https
      - --opnsense.address=ops.example.com
    environment:
      SSL_CERT_FILE: /certs/private-ca.pem
    volumes:
      - ./private-ca.pem:/certs/private-ca.pem:ro
```

Avoid `--opnsense.insecure` outside of testing. It disables certificate
verification entirely.
