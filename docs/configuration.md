---
title: Configuration
description: Complete reference for all OPNsense Exporter CLI flags, environment variables, and collector switches
tags:
  - Configuration
---

# Configuration

The OPNsense Exporter follows standard Prometheus ecosystem conventions. It can be configured using command-line flags, environment variables, or a combination of both. Environment variables take the prefix `OPNSENSE_EXPORTER_` unless noted otherwise.

## OPNsense connection

These settings control how the exporter connects to the OPNsense API.

| Flag | Env Var | Required | Default | Description |
|------|---------|----------|---------|-------------|
| `--opnsense.protocol` | `OPNSENSE_EXPORTER_OPS_PROTOCOL` | Yes | -- | Protocol to use. One of: `http`, `https` |
| `--opnsense.address` | `OPNSENSE_EXPORTER_OPS_API` | Yes | -- | Hostname or IP address of the OPNsense API |
| `--opnsense.api-key` | `OPNSENSE_EXPORTER_OPS_API_KEY` | Yes[^1] | -- | API key for authentication |
| `--opnsense.api-secret` | `OPNSENSE_EXPORTER_OPS_API_SECRET` | Yes[^1] | -- | API secret for authentication |
| `--opnsense.insecure` | `OPNSENSE_EXPORTER_OPS_INSECURE` | No | `false` | Disable TLS certificate verification |

[^1]: Either the flag/env var or the corresponding file-based secret (`OPS_API_KEY_FILE` / `OPS_API_SECRET_FILE`) must be set. See [Security: File-based secrets](security.md#file-based-secrets).

### File-based secrets

For secure credential management in containers and orchestrated environments, credentials can be read from files:

| Env Var | Description |
|---------|-------------|
| `OPS_API_KEY_FILE` | Path to a file containing the API key (first line is read) |
| `OPS_API_SECRET_FILE` | Path to a file containing the API secret (first line is read) |

!!! note
    These environment variables do **not** use the `OPNSENSE_EXPORTER_` prefix. They are checked first -- if a file-based secret is set and non-empty, it takes precedence over the flag/env var value.

## Exporter settings

| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--exporter.instance-label` | `OPNSENSE_EXPORTER_INSTANCE_LABEL` | OPNsense hostname (auto-detected) | Label added to every metric to identify this OPNsense instance. If left unset, it defaults to the hostname the OPNsense API reports for itself (falling back to the configured address if that lookup fails). Set it explicitly when running multiple exporters so each has a unique, stable value. |
| `--web.listen-address` | -- | `:8080` | Address(es) on which to expose metrics. Repeatable for multiple addresses. |
| `--web.telemetry-path` | -- | `/metrics` | HTTP path under which to expose metrics |
| `--web.disable-exporter-metrics` | `OPNSENSE_EXPORTER_DISABLE_EXPORTER_METRICS` | `false` | Exclude metrics about the exporter itself (`promhttp_*`, `process_*`, `go_*`) |
| `--web.systemd-socket` | -- | `false` | Use systemd socket activation listeners instead of port listeners (Linux only) |
| `--web.config.file` | -- | -- | Path to a [web configuration file](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md) for TLS or authentication |
| `--log.level` | -- | `info` | Log severity threshold. One of: `debug`, `info`, `warn`, `error` |
| `--log.format` | -- | `logfmt` | Log output format. One of: `logfmt`, `json` |

## Continuous profiling (Pyroscope)

The exporter can push continuous profiles to Grafana Cloud Pyroscope using the
`pyroscope-go` SDK. Profiling is **disabled by default** and activates only when
`--pyroscope.server-address` (env `OPNSENSE_EXPORTER_PYROSCOPE_SERVER_ADDRESS`)
is set. There are no unauthenticated `/debug/pprof/*` endpoints.

| Flag | Env Var | Default | Description |
|---|---|---|---|
| `--pyroscope.server-address` | `OPNSENSE_EXPORTER_PYROSCOPE_SERVER_ADDRESS` | _(empty)_ | Pyroscope endpoint URL. Empty disables profiling. |
| `--pyroscope.auth-user` | `OPNSENSE_EXPORTER_PYROSCOPE_AUTH_USER` | _(empty)_ | Basic auth user (Grafana Cloud stack/instance ID). |
| `--pyroscope.auth-password` | `OPNSENSE_EXPORTER_PYROSCOPE_AUTH_PASSWORD` | _(empty)_ | Basic auth password (Cloud Access Policy token). |
| `--pyroscope.tenant-id` | `OPNSENSE_EXPORTER_PYROSCOPE_TENANT_ID` | _(empty)_ | Tenant ID for multi-tenancy (unused for Grafana Cloud). |
| `--pyroscope.application-name` | `OPNSENSE_EXPORTER_PYROSCOPE_APPLICATION_NAME` | `opnsense-exporter` | Application name profiles report under. |
| `--pyroscope.enable-mutex-block` | `OPNSENSE_EXPORTER_PYROSCOPE_ENABLE_MUTEX_BLOCK` | `false` | Also collect goroutine/mutex/block profiles (minor overhead). |

### File-based secrets

Like the OPNsense API credentials, the auth user and password can be read from
files instead of flags/env vars: set `PYROSCOPE_AUTH_USER_FILE` and/or
`PYROSCOPE_AUTH_PASSWORD_FILE` to a path whose first line holds the value. The
file value takes precedence over the corresponding flag/env var when present
and non-empty.

Profiles are tagged with `instance` (the resolved instance label) and `version`.

## OTLP metrics export

In addition to the `/metrics` pull endpoint, the exporter can **push** the exact
same metrics to an OpenTelemetry (OTLP) endpoint. A Prometheus-bridge producer reads
the existing registry on each export tick, so OTLP metric names, labels and values
are identical to what `/metrics` exposes (no native renaming) — existing dashboards
keep working against either backend. Export is **disabled by default** and activates
only when `--otlp.enabled` (env `OPNSENSE_EXPORTER_OTLP_ENABLED`) is set. The pull
endpoint is unaffected whether or not OTLP is enabled.

Any field left empty falls through to the corresponding **standard OpenTelemetry
environment variable** (`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`,
`OTEL_EXPORTER_OTLP_PROTOCOL`, `OTEL_METRIC_EXPORT_INTERVAL`, `OTEL_SERVICE_NAME`,
`OTEL_RESOURCE_ATTRIBUTES`, …) read natively by the OTEL SDK. Explicit `--otlp.*`
flags take precedence over those env vars.

| Flag | Env Var | Default | Description |
|---|---|---|---|
| `--otlp.enabled` | `OPNSENSE_EXPORTER_OTLP_ENABLED` | `false` | Master switch. When false, no OTLP export occurs. |
| `--otlp.endpoint` | `OPNSENSE_EXPORTER_OTLP_ENDPOINT` | _(empty)_ | OTLP endpoint URL. Empty defers to `OTEL_EXPORTER_OTLP_ENDPOINT`. |
| `--otlp.protocol` | `OPNSENSE_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` | `grpc` or `http/protobuf`. |
| `--otlp.insecure` | `OPNSENSE_EXPORTER_OTLP_INSECURE` | `false` | Disable TLS (plaintext). |
| `--otlp.headers` | `OPNSENSE_EXPORTER_OTLP_HEADERS` | _(empty)_ | Headers as `k=v,k2=v2`. When set, **replaces** `OTEL_EXPORTER_OTLP_HEADERS` entirely; when empty, that env var is used. |
| `--otlp.export-interval` | `OPNSENSE_EXPORTER_OTLP_EXPORT_INTERVAL` | `60s` | Interval between exports (independent of Prometheus scrapes). |
| `--otlp.tls-ca-file` | `OPNSENSE_EXPORTER_OTLP_TLS_CA_FILE` | _(empty)_ | CA certificate file to verify the OTLP server. |
| `--otlp.tls-cert-file` | `OPNSENSE_EXPORTER_OTLP_TLS_CERT_FILE` | _(empty)_ | Client certificate for mutual TLS (requires the key file). |
| `--otlp.tls-key-file` | `OPNSENSE_EXPORTER_OTLP_TLS_KEY_FILE` | _(empty)_ | Client key for mutual TLS (requires the cert file). |
| `--otlp.service-name` | `OPNSENSE_EXPORTER_OTLP_SERVICE_NAME` | `opnsense-exporter` | `service.name` resource attribute. |
| `--otlp.grafana-cloud-instance-id` | `OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_INSTANCE_ID` | _(empty)_ | Grafana Cloud OTLP instance ID (shortcut). |
| `--otlp.grafana-cloud-token` | `OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_TOKEN` | _(empty)_ | Grafana Cloud Access Policy token (shortcut). |
| `--otlp.grafana-cloud-endpoint` | `OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_ENDPOINT` | _(empty)_ | Grafana Cloud OTLP gateway base URL (required to use the shortcut). |

The metric set exported over OTLP is byte-for-byte the same as the Prometheus
catalogue (see the [metrics reference](metrics/metrics.md)); enabling OTLP adds no
new metric names.

### Grafana Cloud shortcut

Setting `--otlp.grafana-cloud-instance-id`, `--otlp.grafana-cloud-token` and
`--otlp.grafana-cloud-endpoint` together synthesizes the
`Authorization: Basic base64(instanceID:token)` header and uses the gateway URL as
the endpoint, so you do not have to assemble the basic-auth header yourself. An
explicit `--otlp.endpoint` or `Authorization` header always wins over the shortcut.
The instance ID and token also support `*_FILE` secret variants
(`OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_INSTANCE_ID_FILE`,
`OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_TOKEN_FILE`), whose file contents take
precedence over the flag/env value, mirroring the OPNsense API credentials.

### Temporality

Exported metrics are always **cumulative**, and this is not configurable. They are
sourced from the Prometheus registry via a bridge producer, so they arrive already
aggregated as cumulative (Prometheus' model) and are exported as-is — exactly the
temporality Grafana Cloud's metrics backend (Mimir) and Prometheus' OTLP ingest
require. An exporter-side temporality selector cannot re-aggregate
producer-supplied metrics, so no delta option is offered.

## Collector switches

All collectors are **enabled by default** unless noted otherwise. Each can be individually disabled or enabled using CLI flags or environment variables.

### Enabled by default (disable with flag)

| Flag | Env Var | Collector |
|------|---------|-----------|
| `--exporter.disable-arp-table` | `OPNSENSE_EXPORTER_DISABLE_ARP_TABLE` | ARP table |
| `--exporter.disable-cron-table` | `OPNSENSE_EXPORTER_DISABLE_CRON_TABLE` | Cron jobs |
| `--exporter.disable-wireguard` | `OPNSENSE_EXPORTER_DISABLE_WIREGUARD` | WireGuard tunnels and peers |
| `--exporter.disable-ipsec` | `OPNSENSE_EXPORTER_DISABLE_IPSEC` | IPsec tunnels and SAs |
| `--exporter.disable-unbound` | `OPNSENSE_EXPORTER_DISABLE_UNBOUND` | Unbound DNS resolver statistics |
| `--exporter.disable-openvpn` | `OPNSENSE_EXPORTER_DISABLE_OPENVPN` | OpenVPN instances and sessions |
| `--exporter.disable-firewall` | `OPNSENSE_EXPORTER_DISABLE_FIREWALL` | Firewall PF interface statistics (packet/byte counters, state table) |
| `--exporter.disable-firewall-rules` | `OPNSENSE_EXPORTER_DISABLE_FIREWALL_RULES` | Firewall rule statistics (total rule count; per-rule details opt-in) |
| `--exporter.disable-firmware` | `OPNSENSE_EXPORTER_DISABLE_FIRMWARE` | Firmware version info, update status, and reboot flags |
| `--exporter.disable-system` | `OPNSENSE_EXPORTER_DISABLE_SYSTEM` | System resources (memory, uptime, load, disk, swap) |
| `--exporter.disable-temperature` | `OPNSENSE_EXPORTER_DISABLE_TEMPERATURE` | Hardware temperature sensors |
| `--exporter.disable-dnsmasq` | `OPNSENSE_EXPORTER_DISABLE_DNSMASQ` | Dnsmasq DHCP leases |
| `--exporter.disable-mbuf` | `OPNSENSE_EXPORTER_DISABLE_MBUF` | FreeBSD mbuf (network buffer) statistics |
| `--exporter.disable-ntp` | `OPNSENSE_EXPORTER_DISABLE_NTP` | NTP peer metrics |
| `--exporter.disable-certificates` | `OPNSENSE_EXPORTER_DISABLE_CERTIFICATES` | Certificate validity and expiry timestamps |
| `--exporter.disable-carp` | `OPNSENSE_EXPORTER_DISABLE_CARP` | CARP/VIP high-availability status |
| `--exporter.disable-activity` | `OPNSENSE_EXPORTER_DISABLE_ACTIVITY` | System activity (CPU percentages, thread counts) |
| `--exporter.disable-kea` | `OPNSENSE_EXPORTER_DISABLE_KEA` | Kea DHCP lease metrics |
| `--exporter.disable-pf-stats` | `OPNSENSE_EXPORTER_DISABLE_PF_STATS` | PF statistics (state table, counters, memory limits, timeouts) |
| `--exporter.disable-ndp` | `OPNSENSE_EXPORTER_DISABLE_NDP` | NDP (IPv6 neighbor discovery) table |
| `--exporter.disable-dhcpv4` | `OPNSENSE_EXPORTER_DISABLE_DHCPV4` | ISC DHCPv4 lease metrics (silent when the legacy ISC DHCP backend is absent) |
| `--exporter.disable-acme` | `OPNSENSE_EXPORTER_DISABLE_ACME` | ACME client certificate renewal status and expiry (silent when `os-acme-client` is absent) |
| `--exporter.disable-smart` | `OPNSENSE_EXPORTER_DISABLE_SMART` | SMART disk health, one `list` + one `info` POST per disk per scrape (silent when `os-smart` is absent) |
| `--exporter.disable-dyndns` | `OPNSENSE_EXPORTER_DISABLE_DYNDNS` | DynDNS (ddclient) account update status (silent when `os-ddclient` is absent) |

### Disabled by default (opt-in with flag)

These collectors are disabled by default because they make additional API calls per scrape. Enable them only if you need the data.

| Flag | Env Var | Collector |
|------|---------|-----------|
| `--exporter.enable-network-diagnostics` | `OPNSENSE_EXPORTER_ENABLE_NETWORK_DIAGNOSTICS` | Network diagnostics: kernel netisr stats, socket counts, route counts. Makes 3 API calls per scrape. |
| `--exporter.enable-netflow` | `OPNSENSE_EXPORTER_ENABLE_NETFLOW` | NetFlow: service status, enabled state, per-interface cache statistics. Makes 3 API calls per scrape. |

### High-cardinality detail options

These flags enable per-item detail metrics that can produce a large number of time series. Each unique label combination creates a separate time series in Prometheus.

!!! warning "Evaluate before enabling"
    On a firewall with hundreds of DHCP leases or firewall rules, enabling detail metrics can produce thousands of time series. Monitor your Prometheus storage and ingestion rate after enabling.

| Flag | Env Var | Description |
|------|---------|-------------|
| `--exporter.enable-dnsmasq-details` | `OPNSENSE_EXPORTER_ENABLE_DNSMASQ_DETAILS` | Per-lease detail metrics for Dnsmasq DHCP. One time series per active lease (address, hostname, MAC, interface). |
| `--exporter.enable-firewall-rules-details` | `OPNSENSE_EXPORTER_ENABLE_FIREWALL_RULES_DETAILS` | Per-rule detail metrics for firewall rules. One time series per rule per metric (UUID, description, action, interface, direction). |
| `--exporter.enable-kea-details` | `OPNSENSE_EXPORTER_ENABLE_KEA_DETAILS` | Per-lease detail metrics for Kea DHCP. One time series per active lease (address, hostname, MAC, interface). |
| `--exporter.enable-dhcpv4-details` | `OPNSENSE_EXPORTER_ENABLE_DHCPV4_DETAILS` | Per-lease detail metrics for ISC DHCPv4. One time series per active lease (address, hostname, MAC, interface). |

## Full flag reference

The complete list of flags as output by `--help`:

```text
usage: opnsense-exporter --opnsense.protocol=OPNSENSE.PROTOCOL --opnsense.address=OPNSENSE.ADDRESS [<flags>]


Flags:
  -h, --[no-]help               Show context-sensitive help (also try
                                --help-long and --help-man).
      --[no-]exporter.disable-arp-table  
                                Disable the scraping of the ARP table
                                ($OPNSENSE_EXPORTER_DISABLE_ARP_TABLE)
      --[no-]exporter.disable-cron-table  
                                Disable the scraping of the cron table
                                ($OPNSENSE_EXPORTER_DISABLE_CRON_TABLE)
      --[no-]exporter.disable-wireguard  
                                Disable the scraping of Wireguard service
                                ($OPNSENSE_EXPORTER_DISABLE_WIREGUARD)
      --[no-]exporter.disable-ipsec  
                                Disable the scraping of IPSec service
                                ($OPNSENSE_EXPORTER_DISABLE_IPSEC)
      --[no-]exporter.disable-unbound  
                                Disable the scraping of Unbound service
                                ($OPNSENSE_EXPORTER_DISABLE_UNBOUND)
      --[no-]exporter.disable-openvpn  
                                Disable the scraping of OpenVPN service
                                ($OPNSENSE_EXPORTER_DISABLE_OPENVPN)
      --[no-]exporter.disable-firewall  
                                Disable the scraping of the firewall (pf)
                                metrics ($OPNSENSE_EXPORTER_DISABLE_FIREWALL)
      --[no-]exporter.disable-firmware  
                                Disable the scraping of the firmware metrics
                                ($OPNSENSE_EXPORTER_DISABLE_FIRMWARE)
      --[no-]exporter.disable-system  
                                Disable the scraping of system resource
                                metrics (memory, uptime, disk, swap)
                                ($OPNSENSE_EXPORTER_DISABLE_SYSTEM)
      --[no-]exporter.disable-temperature  
                                Disable the scraping of temperature metrics
                                ($OPNSENSE_EXPORTER_DISABLE_TEMPERATURE)
      --[no-]exporter.disable-dnsmasq  
                                Disable the scraping of Dnsmasq DHCP leases
                                ($OPNSENSE_EXPORTER_DISABLE_DNSMASQ)
      --[no-]exporter.enable-dnsmasq-details  
                                Enable per-lease detail metrics for Dnsmasq
                                DHCP (high cardinality on large networks)
                                ($OPNSENSE_EXPORTER_ENABLE_DNSMASQ_DETAILS)
      --[no-]exporter.disable-firewall-rules  
                                Disable the scraping of firewall rule statistics
                                ($OPNSENSE_EXPORTER_DISABLE_FIREWALL_RULES)
      --[no-]exporter.enable-firewall-rules-details  
                                Enable per-rule detail metrics for firewall
                                rules (high cardinality on large rulesets)
                                ($OPNSENSE_EXPORTER_ENABLE_FIREWALL_RULES_DETAILS)
      --[no-]exporter.disable-mbuf  
                                Disable the scraping of mbuf statistics
                                ($OPNSENSE_EXPORTER_DISABLE_MBUF)
      --[no-]exporter.disable-ntp  
                                Disable the scraping of NTP peer metrics
                                ($OPNSENSE_EXPORTER_DISABLE_NTP)
      --[no-]exporter.disable-certificates  
                                Disable the scraping of
                                certificate expiry metrics
                                ($OPNSENSE_EXPORTER_DISABLE_CERTIFICATES)
      --[no-]exporter.disable-carp  
                                Disable the scraping of CARP/VIP status metrics
                                ($OPNSENSE_EXPORTER_DISABLE_CARP)
      --[no-]exporter.disable-activity  
                                Disable the scraping of system activity
                                metrics (CPU percentages, thread counts)
                                ($OPNSENSE_EXPORTER_DISABLE_ACTIVITY)
      --[no-]exporter.disable-kea  
                                Disable the scraping of Kea DHCP lease metrics
                                ($OPNSENSE_EXPORTER_DISABLE_KEA)
      --[no-]exporter.enable-kea-details  
                                Enable per-lease detail metrics for Kea
                                DHCP (high cardinality on large networks)
                                ($OPNSENSE_EXPORTER_ENABLE_KEA_DETAILS)
      --[no-]exporter.enable-network-diagnostics  
                                Enable the network diagnostics collector
                                (netisr, sockets, routes). Disabled by default.
                                ($OPNSENSE_EXPORTER_ENABLE_NETWORK_DIAGNOSTICS)
      --[no-]exporter.enable-netflow  
                                Enable the netflow collector (enabled status,
                                service status, cache stats). Disabled by
                                default. ($OPNSENSE_EXPORTER_ENABLE_NETFLOW)
      --[no-]exporter.disable-pf-stats  
                                Disable the scraping of PF statistics (state
                                table, counters, memory limits, timeouts)
                                ($OPNSENSE_EXPORTER_DISABLE_PF_STATS)
      --[no-]exporter.disable-ndp  
                                Disable the scraping of the NDP
                                (IPv6 neighbor discovery) table
                                ($OPNSENSE_EXPORTER_DISABLE_NDP)
      --[no-]exporter.disable-dhcpv4  
                                Disable the scraping of ISC DHCPv4 leases
                                ($OPNSENSE_EXPORTER_DISABLE_DHCPV4)
      --[no-]exporter.enable-dhcpv4-details  
                                Enable per-lease detail metrics for ISC
                                DHCPv4 (high cardinality on large networks)
                                ($OPNSENSE_EXPORTER_ENABLE_DHCPV4_DETAILS)
      --[no-]exporter.disable-acme  
                                Disable the scraping of ACME client
                                certificate renewal status and expiry metrics
                                ($OPNSENSE_EXPORTER_DISABLE_ACME)
      --[no-]exporter.disable-smart  
                                Disable the SMART disk health
                                collector (per-disk POST fanout;
                                silent when the os-smart plugin is absent)
                                ($OPNSENSE_EXPORTER_DISABLE_SMART)
      --[no-]exporter.disable-dyndns  
                                Disable the scraping of DynDNS
                                (ddclient) account update status metrics
                                ($OPNSENSE_EXPORTER_DISABLE_DYNDNS)
      --web.telemetry-path="/metrics"  
                                Path under which to expose metrics.
      --[no-]web.disable-exporter-metrics  
                                Exclude metrics about the exporter
                                itself (promhttp_*, process_*, go_*).
                                ($OPNSENSE_EXPORTER_DISABLE_EXPORTER_METRICS)
      --exporter.instance-label=""  
                                Label to use to identify the instance in
                                every metric. If you have multiple instances
                                of the exporter, you can differentiate them
                                by using different value in this flag, that
                                represents the instance of the target OPNsense.
                                If left empty, it defaults to the OPNsense
                                hostname reported by the API (falling back to
                                the configured OPNsense address if that lookup
                                fails). ($OPNSENSE_EXPORTER_INSTANCE_LABEL)
      --web.listen-address=:8080 ...  
                                Addresses on which to expose metrics and web
                                interface. Repeatable for multiple addresses.
                                Examples: `:9100` or `[::1]:9100` for http,
                                `vsock://:9100` for vsock
      --web.config.file=""      Path to configuration file that can
                                enable TLS or authentication. See:
                                https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md
      --opnsense.protocol=OPNSENSE.PROTOCOL  
                                Protocol to use to connect to
                                OPNsense API. One of: [http, https]
                                ($OPNSENSE_EXPORTER_OPS_PROTOCOL)
      --opnsense.address=OPNSENSE.ADDRESS  
                                Hostname or IP address of OPNsense API
                                ($OPNSENSE_EXPORTER_OPS_API)
      --opnsense.api-key=""     API key to use to connect to OPNsense API.
                                This flag/ENV or the OPS_API_KEY_FILE my be set.
                                ($OPNSENSE_EXPORTER_OPS_API_KEY)
      --opnsense.api-secret=""  API secret to use to connect to OPNsense API.
                                This flag/ENV or the OPS_API_SECRET_FILE my be
                                set. ($OPNSENSE_EXPORTER_OPS_API_SECRET)
      --[no-]opnsense.insecure  Disable TLS certificate verification
                                ($OPNSENSE_EXPORTER_OPS_INSECURE)
      --[no-]otlp.enabled       Enable pushing metrics to an OTLP endpoint (in
                                addition to the /metrics pull endpoint). Off by
                                default. ($OPNSENSE_EXPORTER_OTLP_ENABLED)
      --otlp.endpoint=""        OTLP endpoint URL. When empty, the standard
                                OTEL_EXPORTER_OTLP_ENDPOINT env var is used.
                                ($OPNSENSE_EXPORTER_OTLP_ENDPOINT)
      --otlp.protocol="http/protobuf"  
                                OTLP transport protocol: grpc or http/protobuf.
                                When empty, OTEL_EXPORTER_OTLP_PROTOCOL is used.
                                ($OPNSENSE_EXPORTER_OTLP_PROTOCOL)
      --[no-]otlp.insecure      Disable TLS for the OTLP connection (plaintext).
                                ($OPNSENSE_EXPORTER_OTLP_INSECURE)
      --otlp.headers=""         OTLP headers as comma-separated key=value pairs
                                (e.g. X-Scope-OrgID=1,Authorization=Bearer x).
                                When set, replaces OTEL_EXPORTER_OTLP_HEADERS
                                entirely; when empty, that env var is used.
                                ($OPNSENSE_EXPORTER_OTLP_HEADERS)
      --otlp.export-interval=60s  
                                Interval between OTLP metric exports
                                (independent of Prometheus scrapes).
                                ($OPNSENSE_EXPORTER_OTLP_EXPORT_INTERVAL)
      --otlp.tls-ca-file=""     Path to a CA certificate file
                                used to verify the OTLP server.
                                ($OPNSENSE_EXPORTER_OTLP_TLS_CA_FILE)
      --otlp.tls-cert-file=""   Path to a client certificate file for OTLP
                                mutual TLS (requires --otlp.tls-key-file).
                                ($OPNSENSE_EXPORTER_OTLP_TLS_CERT_FILE)
      --otlp.tls-key-file=""    Path to a client key file for OTLP mutual
                                TLS (requires --otlp.tls-cert-file).
                                ($OPNSENSE_EXPORTER_OTLP_TLS_KEY_FILE)
      --otlp.service-name="opnsense-exporter"  
                                service.name resource attribute for exported
                                metrics. ($OPNSENSE_EXPORTER_OTLP_SERVICE_NAME)
      --otlp.grafana-cloud-instance-id=""  
                                Grafana Cloud OTLP instance ID.
                                With --otlp.grafana-cloud-token,
                                synthesizes basic-auth. This flag/ENV or
                                OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_INSTANCE_ID_FILE
                                may be set.
                                ($OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_INSTANCE_ID)
      --otlp.grafana-cloud-token=""  
                                Grafana Cloud Access Policy
                                token. This flag/ENV or
                                OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_TOKEN_FILE
                                may be set.
                                ($OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_TOKEN)
      --otlp.grafana-cloud-endpoint=""  
                                Grafana Cloud OTLP gateway base URL (required
                                when using the Grafana Cloud shortcut).
                                ($OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_ENDPOINT)
      --pyroscope.server-address=""  
                                Grafana Cloud Pyroscope endpoint URL.
                                When empty, continuous profiling is disabled.
                                ($OPNSENSE_EXPORTER_PYROSCOPE_SERVER_ADDRESS)
      --pyroscope.auth-user=""  HTTP basic auth user for Pyroscope (Grafana
                                Cloud stack/instance ID). This flag/ENV
                                or PYROSCOPE_AUTH_USER_FILE may be set.
                                ($OPNSENSE_EXPORTER_PYROSCOPE_AUTH_USER)
      --pyroscope.auth-password=""  
                                HTTP basic auth password for Pyroscope (Grafana
                                Cloud Access Policy token). This flag/ENV
                                or PYROSCOPE_AUTH_PASSWORD_FILE may be set.
                                ($OPNSENSE_EXPORTER_PYROSCOPE_AUTH_PASSWORD)
      --pyroscope.tenant-id=""  Pyroscope tenant ID (only needed for
                                multi-tenancy; unused for Grafana Cloud).
                                ($OPNSENSE_EXPORTER_PYROSCOPE_TENANT_ID)
      --pyroscope.application-name="opnsense-exporter"  
                                Pyroscope application name
                                profiles are reported under.
                                ($OPNSENSE_EXPORTER_PYROSCOPE_APPLICATION_NAME)
      --[no-]pyroscope.enable-mutex-block  
                                Enable goroutine/mutex/block profiling
                                (adds minor runtime overhead).
                                ($OPNSENSE_EXPORTER_PYROSCOPE_ENABLE_MUTEX_BLOCK)
      --log.level=info          Only log messages with the given severity or
                                above. One of: [debug, info, warn, error]
      --log.format=logfmt       Output format of log messages. One of: [logfmt,
                                json]

```
