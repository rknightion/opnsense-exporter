---
title: Systemd
description: Deploy the OPNsense Exporter as a systemd service on Linux hosts
tags:
  - Deployment
---

# Systemd Deployment

Run the OPNsense Exporter as a managed systemd service on a Linux host.

## Step 1: Install the binary

Download a specific release from [GitHub Releases](https://github.com/rknightion/opnsense-exporter/releases). Linux archives are named `opnsense-exporter_Linux_x86_64.tar.gz` and `opnsense-exporter_Linux_arm64.tar.gz`; do not use the old raw-binary URL.

Install [cosign](https://docs.sigstore.dev/cosign/system_config/installation/) on the deployment host, then obtain the verifier from the same repository revision you are deploying. The verifier constrains `--certificate-identity` to `https://github.com/rknightion/.github/.github/workflows/binaries.yml@d1c590b295b9d7f2535fadc7bc5e74f2eddbd512` and `--certificate-oidc-issuer` to `https://token.actions.githubusercontent.com`, verifies the archive checksum, extracts the binary, and runs `--version`.

```bash
# Select a released version and the Linux architecture reported by uname -m.
VERSION=vX.Y.Z # a release tag that includes this verifier and --config.check
ARCH=x86_64 # use arm64 on aarch64 hosts

INSTALL_ROOT=$(mktemp -d)
git clone --depth 1 --branch "$VERSION" https://github.com/rknightion/opnsense-exporter.git "$INSTALL_ROOT/source"
"$INSTALL_ROOT/source/scripts/systemd/verify-release.sh" "$VERSION" "$ARCH" "$INSTALL_ROOT/verified"

# install writes a complete new inode; rename makes the final replacement atomic.
sudo install -o root -g root -m 0755 "$INSTALL_ROOT/verified/opnsense-exporter" /usr/local/bin/opnsense-exporter.new
sudo mv -f /usr/local/bin/opnsense-exporter.new /usr/local/bin/opnsense-exporter
```

Verify the binary:

```bash
/usr/local/bin/opnsense-exporter --version
```

## Step 2: Create a system user

Create a dedicated user with no shell or home directory:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin opnsense-exporter
```

## Step 3: Create the environment file

Store configuration and credentials in an environment file with restricted permissions:

```bash
# The service group may traverse this directory but cannot list it.
sudo install -d -o root -g opnsense-exporter -m 0710 /etc/opnsense-exporter
sudo tee /etc/opnsense-exporter/exporter.env > /dev/null << 'EOF'
OPNSENSE_EXPORTER_OPS_PROTOCOL=https
OPNSENSE_EXPORTER_OPS_API=opnsense.example.com
OPNSENSE_EXPORTER_OPS_API_KEY=your-api-key
OPNSENSE_EXPORTER_OPS_API_SECRET=your-api-secret
OPNSENSE_EXPORTER_INSTANCE_LABEL=my-firewall
EOF

# systemd reads this file before dropping to the service user.
sudo chmod 600 /etc/opnsense-exporter/exporter.env
sudo chown root:root /etc/opnsense-exporter/exporter.env
```

!!! tip "File-based secrets"
    To keep the credentials out of the service's environment, store the API key and secret in separate files and use `OPS_API_KEY_FILE` and `OPS_API_SECRET_FILE`:

    ```bash
    printf '%s\n' 'your-api-key' | sudo install -o root -g opnsense-exporter -m 0640 /dev/stdin /etc/opnsense-exporter/api-key
    printf '%s\n' 'your-api-secret' | sudo install -o root -g opnsense-exporter -m 0640 /dev/stdin /etc/opnsense-exporter/api-secret
    ```

    Then reference them in the environment file:

    ```bash
    OPS_API_KEY_FILE=/etc/opnsense-exporter/api-key
    OPS_API_SECRET_FILE=/etc/opnsense-exporter/api-secret
    ```

## Step 4: Create the systemd unit file

```ini title="/etc/systemd/system/opnsense-exporter.service"
[Unit]
Description=OPNsense Prometheus Exporter
Documentation=https://m7kni.io/opnsense-exporter/
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=opnsense-exporter
Group=opnsense-exporter
EnvironmentFile=/etc/opnsense-exporter/exporter.env
ExecStartPre=/usr/local/bin/opnsense-exporter --config.check
ExecStart=/usr/local/bin/opnsense-exporter \
    --web.listen-address=:8080 \
    --log.level=info \
    --log.format=json

Restart=on-failure
RestartSec=5s

# Security hardening
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectHostname=yes
ProtectClock=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
RestrictAddressFamilies=AF_INET AF_INET6
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
MemoryDenyWriteExecute=yes
LockPersonality=yes

# Read-only access to credential files
ReadOnlyPaths=/etc/opnsense-exporter

[Install]
WantedBy=multi-user.target
```

## Step 5: Enable and start the service

```bash
sudo systemctl daemon-reload
sudo systemctl enable opnsense-exporter
sudo systemctl start opnsense-exporter
sudo systemctl is-active --quiet opnsense-exporter
curl --fail --silent --show-error http://127.0.0.1:8080/-/healthy
```

## Service management

```bash
# Check status
sudo systemctl status opnsense-exporter

# View logs
sudo journalctl -u opnsense-exporter -f

# Restart after configuration changes
sudo systemctl restart opnsense-exporter

# Stop the service
sudo systemctl stop opnsense-exporter
```

## Verify metrics

```bash
curl http://localhost:8080/metrics | head -20
```

You should see Prometheus metrics including `opnsense_up{opnsense_instance="my-firewall"} 1`.

## Upgrading

To upgrade to a new version:

```bash
# Verify and stage the new binary while the current service remains running.
VERSION=vX.Y.Z # replace with the target release tag
ARCH=x86_64 # use arm64 on aarch64 hosts
UPGRADE_ROOT=$(mktemp -d)
git clone --depth 1 --branch "$VERSION" https://github.com/rknightion/opnsense-exporter.git "$UPGRADE_ROOT/source"
"$UPGRADE_ROOT/source/scripts/systemd/verify-release.sh" "$VERSION" "$ARCH" "$UPGRADE_ROOT/verified"
sudo install -o root -g root -m 0755 "$UPGRADE_ROOT/verified/opnsense-exporter" /usr/local/bin/opnsense-exporter.new

# Only stop after verification and staging succeed. The rename is atomic.
sudo systemctl stop opnsense-exporter
sudo mv -f /usr/local/bin/opnsense-exporter.new /usr/local/bin/opnsense-exporter
sudo systemctl start opnsense-exporter
sudo systemctl is-active --quiet opnsense-exporter
curl --fail --silent --show-error http://127.0.0.1:8080/-/healthy
```

## Disabling collectors

Add disable flags to the `ExecStart` line in the unit file, or add environment variables to the environment file:

```bash
# In /etc/opnsense-exporter/exporter.env
OPNSENSE_EXPORTER_DISABLE_CRON_TABLE=true
OPNSENSE_EXPORTER_DISABLE_ARP_TABLE=true
```

Then restart the service:

```bash
sudo systemctl restart opnsense-exporter
```
