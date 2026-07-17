---
title: Security
description: Security guide covering OPNsense API key management, TLS configuration, file-based secrets, and user permissions
tags:
  - Configuration
  - Deployment
---

# Security

This guide covers secure configuration of the OPNsense Exporter, including API key management, TLS, and least-privilege access.

## OPNsense API key creation

1. Log in to the OPNsense web UI.
2. Navigate to **System > Access > Users**.
3. Create a dedicated monitoring user (do not use the `root` account).
4. Assign the user to a group with only the [required permissions](#opnsense-user-permissions).
5. Scroll to the **API keys** section and click **+** to generate a new key pair.
6. Save the downloaded file -- it contains the key and secret.

!!! danger "Avoid root API keys"
    API keys generated for the `root` user have full access to all OPNsense APIs, including write operations. Always create a dedicated read-only monitoring user.

## OPNsense user permissions

Create a group (e.g., `monitoring`) with only the following GUI permissions and assign your monitoring user to it:

| Type | Permission |
|------|-----------|
| GUI | Diagnostics: ARP Table |
| GUI | Diagnostics: Firewall statistics |
| GUI | Diagnostics: Netstat |
| GUI | Reporting: Traffic |
| GUI | Services: Unbound (MVC) |
| GUI | Status: DHCP leases |
| GUI | Status: DNS Overview |
| GUI | Status: IPsec |
| GUI | Status: OpenVPN |
| GUI | Status: Services |
| GUI | System: Firmware |
| GUI | System: Gateways |
| GUI | System: Settings: Cron |
| GUI | System: Status |
| GUI | VPN: OpenVPN: Instances |
| GUI | VPN: WireGuard |

!!! note
    Some of the newer collectors (temperature, CARP, NTP, certificates, activity, Kea, network diagnostics, NetFlow, PF stats, NDP) may require additional API endpoint permissions beyond this list. If a collector logs permission errors, grant the corresponding permission in OPNsense.

!!! warning "Page-level ACLs include write endpoints"
    OPNsense ACLs are page-level: each GUI permission grants access to *all* of that page's API endpoints, including its write endpoints -- there is no read-only variant. Use a dedicated monitoring user so a leaked key's blast radius is limited to the pages listed above.

## TLS configuration

### Using OPNsense with HTTPS

The exporter connects to OPNsense via HTTPS by default when `--opnsense.protocol=https` is set. For OPNsense instances using a certificate signed by a public CA, no additional configuration is needed.

### Self-signed or private-CA certificates

If your OPNsense uses a self-signed certificate or one issued by a private CA,
trust the CA where the exporter can see it. The recommended approach depends on
how the exporter runs.

**Host / bare binary (recommended for non-container installs)**

On a normal Linux host the exporter uses the OS trust store. Add the OPNsense CA
to it and refresh the bundle:

```bash
sudo cp opnsense-ca.crt /usr/local/share/ca-certificates/opnsense-ca.crt
sudo update-ca-certificates
```

This works only where `update-ca-certificates` (or your distro's equivalent)
merges that directory into the system bundle. It does **not** apply to the
official container image.

**Container (official distroless image)**

The official runtime image is distroless: it has no `update-ca-certificates` and
does not merge `/usr/local/share/ca-certificates` into Go's trust roots, so
mounting a certificate there leaves it untrusted. Instead mount the CA bundle at
any path and point Go's TLS stack at it with `SSL_CERT_FILE`:

```yaml
services:
  opnsense-exporter:
    image: ghcr.io/rknightion/opnsense-exporter:latest
    environment:
      SSL_CERT_FILE: /certs/opnsense-ca.pem
    volumes:
      - ./opnsense-ca.pem:/certs/opnsense-ca.pem:ro
```

See [Custom CA certificates](deployment/docker.md#custom-ca-certificates) in the
Docker deployment guide for the full example.

**Disable TLS verification (not recommended)**

```bash
--opnsense.insecure
```

Or via environment variable:

```bash
OPNSENSE_EXPORTER_OPS_INSECURE=true
```

!!! warning
    Disabling TLS verification exposes the API key and secret to potential man-in-the-middle attacks. Only use this for testing or on trusted networks. When enabled, the exporter logs a startup warning: `TLS certificate verification disabled (opnsense.insecure); API credentials and data are exposed to MITM risk`.

### Exporter TLS (web config)

The exporter itself can serve metrics over HTTPS using the Prometheus exporter toolkit's [web configuration](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md):

```bash
--web.config.file=/path/to/web-config.yml
```

Example web config:

```yaml title="web-config.yml"
tls_server_config:
  cert_file: /path/to/cert.pem
  key_file: /path/to/key.pem
```

Avoid enabling the exporter toolkit's `rate_limit` option in the web config on listeners reachable by untrusted peers: it is a single pre-authentication global bucket, so any one client can exhaust it and starve legitimate Prometheus scrapes.

## File-based secrets

For production deployments, avoid passing API credentials as command-line flags or plain environment variables. Instead, use file-based secrets:

| Env Var | Description |
|---------|-------------|
| `OPS_API_KEY_FILE` | Path to a file containing the API key |
| `OPS_API_SECRET_FILE` | Path to a file containing the API secret |

The exporter reads the first line of each file. File-based secrets take precedence over flag/env var values when set.

### Docker secrets example

```yaml
services:
  opnsense-exporter:
    image: ghcr.io/rknightion/opnsense-exporter:latest
    environment:
      OPS_API_KEY_FILE: /run/secrets/opnsense-api-key
      OPS_API_SECRET_FILE: /run/secrets/opnsense-api-secret
    secrets:
      - opnsense-api-key
      - opnsense-api-secret
```

### Kubernetes secrets example

```yaml
env:
  - name: OPS_API_KEY_FILE
    value: /etc/opnsense-exporter/creds/api-key
  - name: OPS_API_SECRET_FILE
    value: /etc/opnsense-exporter/creds/api-secret
volumeMounts:
  - name: api-key-vol
    mountPath: /etc/opnsense-exporter/creds
    readOnly: true
```

### Systemd with file permissions

```bash
# Create credential files
echo "your-api-key" | sudo tee /etc/opnsense-exporter/api-key > /dev/null
echo "your-api-secret" | sudo tee /etc/opnsense-exporter/api-secret > /dev/null

# Restrict permissions
sudo chmod 600 /etc/opnsense-exporter/api-key /etc/opnsense-exporter/api-secret
sudo chown root:root /etc/opnsense-exporter/api-key /etc/opnsense-exporter/api-secret
```

## OPNsense settings

One collector needs an extra OPNsense setting enabled:

- **Unbound DNS collector:** Enable **Unbound DNS > Advanced > Extended Statistics** in the OPNsense web UI for full DNS metrics.

## Container security

The official container image is hardened:

- **Distroless base image** -- minimal attack surface with no shell, package manager, or unnecessary binaries
- **Non-root execution** -- runs as UID 65532 (nonroot)
- **Read-only root filesystem** -- supported in Kubernetes and Docker
- **No capabilities** -- all Linux capabilities are dropped in the Kubernetes deployment manifest
- **Static binary** -- no runtime dependencies, CGO disabled

The `/metrics` endpoint requires no authentication by default, so restrict who can reach it at the network layer. On Kubernetes, a sample [NetworkPolicy](deployment/kubernetes.md#restrict-access-with-a-networkpolicy) limiting ingress on the metrics port to Prometheus is provided at [`deploy/k8s/networkpolicy.yaml`](https://github.com/rknightion/opnsense-exporter/blob/main/deploy/k8s/networkpolicy.yaml).
