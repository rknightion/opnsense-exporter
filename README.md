# OPNsense Prometheus Exporter

![GitHub License](https://img.shields.io/github/license/rknightion/opnsense-exporter)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/rknightion/opnsense-exporter/ci.yml)
![GitHub go.mod Go version (branch)](https://img.shields.io/github/go-mod/go-version/rknightion/opnsense-exporter/main)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/rknightion/opnsense-exporter/badge)](https://scorecard.dev/viewer/?uri=github.com/rknightion/opnsense-exporter)

A Prometheus exporter for [OPNsense](https://opnsense.org/) firewalls. It polls the
OPNsense REST API and exposes 765 metrics across 61 collectors: firewall and PF
statistics, interfaces, gateways, VPN (WireGuard, OpenVPN, IPsec), DHCP (Kea, Dnsmasq,
ISC), Unbound DNS, certificates and ACME, hardware temperatures, SMART disk health,
system resources, and more. Metrics are served at `/metrics` and can optionally be
pushed over OTLP.

> **Fork notice:** this project began as a fork of
> [AthennaMind/opnsense-exporter](https://github.com/AthennaMind/opnsense-exporter) and
> became a hard fork early on, as its changes quickly grew incompatible with upstream.
> Many thanks to the AthennaMind authors for the original exporter this project is
> built on. It now evolves independently. See [CHANGELOG.md](./CHANGELOG.md) for
> release history.

**Full documentation: [m7kni.io/opnsense-exporter](https://m7kni.io/opnsense-exporter/)** —
[getting started](https://m7kni.io/opnsense-exporter/getting-started/) ·
[configuration](https://m7kni.io/opnsense-exporter/configuration/) ·
[metrics reference](https://m7kni.io/opnsense-exporter/metrics/metrics/) ·
[collectors](https://m7kni.io/opnsense-exporter/collectors/) ·
[deployment](https://m7kni.io/opnsense-exporter/deployment/) ·
[security](https://m7kni.io/opnsense-exporter/security/) ·
[troubleshooting](https://m7kni.io/opnsense-exporter/troubleshooting/) ·
[upgrading](https://m7kni.io/opnsense-exporter/upgrading/)

## Quick start

Create an OPNsense API user (see [permissions](#opnsense-user-permissions) below), then:

```bash
docker run -p 8080:8080 \
      -e OPNSENSE_EXPORTER_OPS_API_KEY=your-api-key \
      -e OPNSENSE_EXPORTER_OPS_API_SECRET=your-api-secret \
      ghcr.io/rknightion/opnsense-exporter:latest \
      --opnsense.protocol=https \
      --opnsense.address=ops.example.com
```

Metrics are now available at `http://localhost:8080/metrics`. The instance label
defaults to the hostname the OPNsense API reports for itself, so it does not need
to be configured for a single firewall.

For production, prefer file-based secrets over plain environment variables:

```yaml
services:
  opnsense-exporter:
    image: ghcr.io/rknightion/opnsense-exporter:latest
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

Other deployment methods:
[Docker & Compose](https://m7kni.io/opnsense-exporter/deployment/docker/) ·
[Kubernetes](https://m7kni.io/opnsense-exporter/deployment/kubernetes/) (manifests in
[`deploy/k8s/`](./deploy/k8s/)) ·
[Systemd](https://m7kni.io/opnsense-exporter/deployment/systemd/)

## Configuration

Everything is configured with CLI flags or `OPNSENSE_EXPORTER_*` environment
variables. Each collector can be switched off individually
(`--exporter.disable-<name>`); a few high-cost or high-cardinality collectors are
opt-in (`--exporter.enable-<name>`). Optional integrations include OTLP metrics
push and Grafana Cloud Pyroscope continuous profiling.

The complete, generated flag and collector reference lives in the
[configuration docs](https://m7kni.io/opnsense-exporter/configuration/) and the
[collector reference](https://m7kni.io/opnsense-exporter/collectors/reference/).

## Grafana dashboard

> **Minimum Grafana version: 13+** — the dashboard uses the v2 dynamic schema
> (`dashboard.grafana.app/v2`) with `TabsLayout` and `conditionalRendering`.

A single dynamic dashboard covers all 765 metrics across 39 tabs, auto-hiding
tabs and rows for collectors and OPNsense plugins you don't run. Import
[`grafana/dashboard.json`](./grafana/dashboard.json) via the Grafana UI, `gcx`, or
GitOps. Alert and recording rules ship alongside it in
[`grafana/alerts/`](./grafana/alerts/). See [`grafana/README.md`](./grafana/README.md).

## OPNsense user permissions

The API user needs the following OPNsense privileges:

| Type     |      Name                    |
|----------|:-------------:               |
| GUI |  Diagnostics: ARP Table           |
| GUI |  Diagnostics: Firewall statistics |
| GUI |  Diagnostics: Netstat             |
| GUI |  Reporting: Traffic               |
| GUI |  Services: Unbound (MVC)          |
| GUI |  Status: DHCP leases              |
| GUI |  Status: DNS Overview             |
| GUI |  Status: IPsec                    |
| GUI |  Status: OpenVPN                  |
| GUI |  Status: Services                 |
| GUI |  System: Firmware                 |
| GUI |  System: Gateways                 |
| GUI |  System: Settings: Cron           |
| GUI |  System: Status                   |
| GUI |  VPN: OpenVPN: Instances          |
| GUI |  VPN: WireGuard                   |

Required OPNsense settings:

- Unbound collector: *Unbound DNS > Advanced > Extended Statistics* must be enabled.

## Contributing

See [CONTRIBUTING.md](./CONTRIBUTING.md) and the
[development docs](https://m7kni.io/opnsense-exporter/development/contributing/).
Docs for metrics and configuration are generated from code. Run `make docs` after
changing flags or collectors.

## License

[Apache-2.0](./LICENSE)
