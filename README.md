# opnsense2otel: Prometheus and OpenTelemetry monitoring for OPNsense firewalls

[![Documentation](https://img.shields.io/badge/docs-m7kni.io-2563eb)](https://m7kni.io/opnsense2otel/)
[![Release](https://img.shields.io/github/v/release/rknightion/opnsense2otel)](https://github.com/rknightion/opnsense2otel/releases)
[![GitHub License](https://img.shields.io/github/license/rknightion/opnsense2otel)](https://github.com/rknightion/opnsense2otel/blob/main/LICENSE)
[![CI](https://img.shields.io/github/actions/workflow/status/rknightion/opnsense2otel/ci.yml)](https://github.com/rknightion/opnsense2otel/actions)
![Go version](https://img.shields.io/github/go-mod/go-version/rknightion/opnsense2otel/main)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/rknightion/opnsense2otel/badge)](https://scorecard.dev/viewer/?uri=github.com/rknightion/opnsense2otel)

**An observability agent for [OPNsense](https://opnsense.org/) firewalls.** It exposes
Prometheus metrics, pushes native OpenTelemetry metrics and logs over OTLP, receives and
enriches syslog, and turns NetFlow and Zenarmor flow records into bounded traffic-volume
metrics. One binary, one API user, no agent on the firewall.

📖 **[Full documentation: m7kni.io/opnsense2otel](https://m7kni.io/opnsense2otel/)**

## What this does that other OPNsense exporters don't

Most OPNsense exporters scrape a handful of endpoints and stop at `/metrics`. This one covers
all four telemetry paths off the firewall, plus a local console:

| Capability | What you get | Docs |
|---|---|---|
| **Native OpenTelemetry** | Push metrics **and** logs over OTLP to any collector or Grafana Cloud, with no Prometheus scrape involved. Not a sidecar or a translation layer. | [OTLP export](https://m7kni.io/opnsense2otel/configuration/) |
| **Syslog receiver** | OPNsense pushes logs to the exporter, which parses `filterlog`, sshd, DHCP, HAProxy and Suricata lines and enriches them with rule descriptions, interface names and hostnames from the API. A generic collector can receive these lines; it cannot understand them. | [Syslog receiver](https://m7kni.io/opnsense2otel/syslog-receiver/) |
| **Zenarmor receiver** | Per-connection, DNS, TLS/SNI, HTTP and threat-alert records pulled straight out of Zenarmor by posing as its Elasticsearch streaming target. This is the only way to get that data off a Home-tier box, since Zenarmor's syslog export is licence-gated. | [Zenarmor receiver](https://m7kni.io/opnsense2otel/zenarmor-receiver/) |
| **NetFlow and flow volume** | A NetFlow v5/v9 receiver and Zenarmor connection records feed one bounded rollup, so you can answer "how much traffic, which interface, which direction, which application category" from Prometheus for years, instead of scanning GB/day of logs. | [Flow volume](https://m7kni.io/opnsense2otel/flow/) |
| **Operator console** | A built-in web UI at `/` showing collector health, cardinality, effective config and discovered devices, without scraping the firewall to render it. | [Architecture](https://m7kni.io/opnsense2otel/architecture/) |

Underneath that: 1014 metrics across 67 collectors covering firewall and PF statistics,
interfaces, gateways, VPN (WireGuard, OpenVPN, IPsec), DHCP (Kea, Dnsmasq, ISC), Unbound DNS,
certificates and ACME, hardware temperatures, SMART disk health, system resources and more.
Collection is decoupled from scraping: each collector polls on its own volatility tier and
`/metrics` replays the latest snapshot, so a slow firewall API never stalls a scrape.

## Quick start

Create an OPNsense API user (see [permissions](#opnsense-user-permissions) below), then:

```bash
docker run -p 8080:8080 \
      -e OPN2OTEL_OPS_API_KEY=your-api-key \
      -e OPN2OTEL_OPS_API_SECRET=your-api-secret \
      ghcr.io/rknightion/opnsense2otel:latest \
      --opnsense.protocol=https \
      --opnsense.address=ops.example.com
```

Metrics are now at `http://localhost:8080/metrics` and the operator console at
`http://localhost:8080/`. The instance label defaults to the configured OPNsense address; set
`--exporter.instance-use-hostname` to derive it from the hostname the API reports.

For production, prefer file-based secrets over plain environment variables:

```yaml
services:
  opnsense2otel:
    image: ghcr.io/rknightion/opnsense2otel:latest
    restart: always
    command:
      - --opnsense.protocol=https
      - --opnsense.address=ops.example.com
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

Full walkthrough: [Getting started](https://m7kni.io/opnsense2otel/getting-started/). Other
deployment methods: [Docker & Compose](https://m7kni.io/opnsense2otel/deployment/docker/) ·
[Kubernetes](https://m7kni.io/opnsense2otel/deployment/kubernetes/) (manifests in
[`deploy/k8s/`](./deploy/k8s/)) ·
[Systemd](https://m7kni.io/opnsense2otel/deployment/systemd/)

## OpenTelemetry and log shipping

OTLP export and log shipping are independent of each other and both off by default.

```bash
# Push metrics and logs over OTLP instead of (or alongside) a Prometheus scrape
--otlp.enabled --otlp.endpoint=https://otlp-gateway.example.com/otlp

# Receive syslog from the firewall and ship enriched events to Loki
--logs.enabled --logs.syslog.enabled --logs.syslog.listen-udp=0.0.0.0:5140

# Receive Zenarmor flow, DNS, TLS and alert records
--logs.zenarmor.enabled --logs.zenarmor.listen-http=0.0.0.0:9200

# Receive NetFlow v5/v9
--flow.netflow.enabled --flow.netflow.listen=0.0.0.0:2055
```

High-cardinality event data (addresses, ports, Suricata SIDs, domains) ships as log body and
structured metadata, never as a metric label and never as a Loki label. See
[log shipping](https://m7kni.io/opnsense2otel/log-shipping/) and
[flow volume](https://m7kni.io/opnsense2otel/flow/).

## Configuration

Everything is configured with CLI flags or `OPN2OTEL_*` environment variables. Each
collector can be switched off individually (`--exporter.disable-<name>`); a few high-cost or
high-cardinality collectors are opt-in (`--exporter.enable-<name>`). Grafana Cloud Pyroscope
continuous profiling is also available.

The generated flag and collector reference lives in the
[configuration docs](https://m7kni.io/opnsense2otel/configuration/) and the
[collector reference](https://m7kni.io/opnsense2otel/collectors/reference/).

## Grafana dashboard

> **Minimum Grafana version: 13+** - the dashboard uses the v2 dynamic schema
> (`dashboard.grafana.app/v2`) with `TabsLayout` and `conditionalRendering`. There is no
> schema-v1 build, by design. Note that Grafana 12.4 *accepts* this file with HTTP 200 and then
> renders an empty dashboard with no error at all - that is the version, not a broken export.

Two cross-linked dynamic dashboards cover all 1055 metrics across 57 tabs, auto-hiding tabs and rows
for collectors and OPNsense plugins you don't run. Import
[`grafana/dashboard.json`](./grafana/dashboard.json) for the firewall itself and
[`grafana/dashboard-health.json`](./grafana/dashboard-health.json) for the exporter's own health,
via the Grafana UI, `gcx`, or GitOps. Alert
and recording rules ship alongside it in [`grafana/alerts/`](./grafana/alerts/). See
[`grafana/README.md`](./grafana/README.md) and
[integration & dashboards](https://m7kni.io/opnsense2otel/integration-dashboards/).

## OPNsense user permissions

Use the generated [collector-to-ACL matrix](https://m7kni.io/opnsense2otel/security/#generated-collector-to-acl-matrix) to grant only the privileges required by the collectors you enable. It records known, plugin-dependent, and explicitly unknown mappings, including whether an available privilege can also reach write actions.

Required OPNsense settings:

- Unbound collector: *Unbound DNS > Advanced > Extended Statistics* must be enabled.

Details, 401/403 remediation, and ACL caveats: [security](https://m7kni.io/opnsense2otel/security/).

## Compatibility

Supported against the current and previous stable OPNsense releases. Plugin-gated collectors go
silent when the plugin is absent rather than erroring. See
[compatibility](https://m7kni.io/opnsense2otel/compatibility/) and
[upgrading](https://m7kni.io/opnsense2otel/upgrading/).

## Documentation

| | |
|---|---|
| [Getting started](https://m7kni.io/opnsense2otel/getting-started/) | API key, first deploy, verifying metrics |
| [Configuration](https://m7kni.io/opnsense2otel/configuration/) | Every flag and environment variable |
| [Metrics reference](https://m7kni.io/opnsense2otel/metrics/metrics/) | All 1014 metrics with types, labels and PromQL |
| [Collectors](https://m7kni.io/opnsense2otel/collectors/) | What each of the 67 collectors covers |
| [Deployment](https://m7kni.io/opnsense2otel/deployment/) | Docker, Kubernetes, systemd |
| [Log shipping](https://m7kni.io/opnsense2otel/log-shipping/) | Syslog, Zenarmor, NetFlow, Loki |
| [Architecture](https://m7kni.io/opnsense2otel/architecture/) | Poll scheduler, snapshot model, operator console |
| [Troubleshooting](https://m7kni.io/opnsense2otel/troubleshooting/) | Common failures and how to read them |

## Fork notice

This project began as a fork of
[AthennaMind/opnsense-exporter](https://github.com/AthennaMind/opnsense-exporter) and hard-forked
early, once the changes grew incompatible with upstream. Thanks to the AthennaMind authors for the
original exporter this one is built on. See [CHANGELOG.md](./CHANGELOG.md) for release history.

## Contributing

Bug reports, questions and ideas are welcome in
[issues](https://github.com/rknightion/opnsense2otel/issues) and
[discussions](https://github.com/rknightion/opnsense2otel/discussions).

See [CONTRIBUTING.md](./CONTRIBUTING.md) and the
[development docs](https://m7kni.io/opnsense2otel/development/contributing/). Docs for
metrics and configuration are generated from code; run `just docs` after changing flags or
collectors.

## License

[Apache-2.0](./LICENSE)
