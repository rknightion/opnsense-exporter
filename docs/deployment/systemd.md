---
title: Systemd
description: Deploy the OPNsense Exporter as a systemd service on Linux hosts
tags:
  - Deployment
---

# Systemd Deployment

Run the OPNsense Exporter as a managed systemd service on a Linux host.

## Step 1: Install the binary

Download the latest release binary from [GitHub Releases](https://github.com/rknightion/opnsense-exporter/releases):

```bash
# Download the latest release (adjust version and architecture)
curl -LO https://github.com/rknightion/opnsense-exporter/releases/latest/download/opnsense-exporter_linux_amd64

# Make executable and move to a system path
chmod +x opnsense-exporter_linux_amd64
sudo mv opnsense-exporter_linux_amd64 /usr/local/bin/opnsense-exporter
```

Verify the binary:

```bash
opnsense-exporter --help
```

## Step 2: Create a system user

Create a dedicated user with no shell or home directory:

```bash
sudo useradd --system --no-create-home --shell /usr/sbin/nologin opnsense-exporter
```

## Step 3: Create the environment file

Store configuration and credentials in an environment file with restricted permissions:

```bash
sudo mkdir -p /etc/opnsense-exporter
sudo tee /etc/opnsense-exporter/exporter.env > /dev/null << 'EOF'
OPNSENSE_EXPORTER_OPS_PROTOCOL=https
OPNSENSE_EXPORTER_OPS_API=opnsense.example.com
OPNSENSE_EXPORTER_OPS_API_KEY=your-api-key
OPNSENSE_EXPORTER_OPS_API_SECRET=your-api-secret
OPNSENSE_EXPORTER_INSTANCE_LABEL=my-firewall
EOF

# Restrict permissions to root only
sudo chmod 600 /etc/opnsense-exporter/exporter.env
sudo chown root:root /etc/opnsense-exporter/exporter.env
```

!!! tip "File-based secrets"
    For even better security, store the API key and secret in separate files and use `OPS_API_KEY_FILE` and `OPS_API_SECRET_FILE`:

    ```bash
    echo "your-api-key" | sudo tee /etc/opnsense-exporter/api-key > /dev/null
    echo "your-api-secret" | sudo tee /etc/opnsense-exporter/api-secret > /dev/null
    sudo chmod 600 /etc/opnsense-exporter/api-key /etc/opnsense-exporter/api-secret
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
# Download the new binary
curl -LO https://github.com/rknightion/opnsense-exporter/releases/latest/download/opnsense-exporter_linux_amd64

# Replace the binary
sudo systemctl stop opnsense-exporter
chmod +x opnsense-exporter_linux_amd64
sudo mv opnsense-exporter_linux_amd64 /usr/local/bin/opnsense-exporter
sudo systemctl start opnsense-exporter
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
