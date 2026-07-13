# OPNsense Exporter — Grafana assets

This folder ships everything you need to visualise and alert on the metrics exposed by the
OPNsense Exporter:

| Path | What it is |
|------|------------|
| `dashboard.json` | The dashboard — a single **Grafana v2 dynamic dashboard** (`dashboard.grafana.app/v2`) with 31 tabs that auto-show/hide based on which metrics your exporter emits. |
| `build_dashboard.py` | Generator for `dashboard.json`. Run `python3 build_dashboard.py`. |
| `builder.py`, `tabs/` | The builder framework and one module per tab. See `tabs/AUTHORING.md`. |
| `alerts/grafana-managed/` | Alert + recording rules as **Grafana-managed** `rules.alerting.grafana.app/v0alpha1` manifests (+ a folder), pushable with `gcx`. |
| `alerts/build_rules.py` | Generator for the Grafana-managed rule manifests from a single source. |

The dashboard is **metrics-only**. It does not include log/Loki panels — those belong in a
separate firewall-logs dashboard.

## Requirements

- **Grafana 13+** (Grafana Cloud or self-hosted). The v2 schema with `TabsLayout` and
  `conditionalRendering` is required for the show/hide behaviour.
- A Prometheus-compatible datasource scraping the exporter.
- For the **Diagnostics** tab's *Build & Collectors* panels you need an exporter build that
  emits `opnsense_exporter_build_info` and `opnsense_exporter_collector_enabled` (added in this
  fork). Older builds simply leave those two panels empty.

## The dashboard

One dashboard, 31 tabs (generated list, do not hand-edit):

<!-- docgen:begin:dashboard-tabs -->
Overview, System & Resources, Interfaces, Firewall & PF, Aliases, Gateways & WAN, DNS — Unbound, DHCP, VPN, Tailscale, Routing & Neighbors, Protocol Stats, NTP, Certificates, ClamAV, Services, Cron & DynDNS, Syslog, Q-Feeds, NetFlow, CARP / HA, HAProxy, Nginx, FRR Routing, Monit, CrowdSec, UPS, Captive Portal, Traffic Shaper, HA Sync, Chrony, Diagnostics
<!-- docgen:end:dashboard-tabs -->

covering **every** metric the exporter emits (a coverage gate in `build_dashboard.py` fails the
build if any catalogue metric is left unreferenced).

### Dynamic show/hide

Tabs and rows for optional collectors / OPNsense plugins **hide automatically when their
metrics are absent**, so the same dashboard adapts to any deployment. This is driven by hidden
sentinel template variables (`label_values(metric, __name__)` → empty when the metric is absent)
plus `conditionalRendering` on the tab/row. A few sections are gated on *data* rather than mere
presence (e.g. a DHCP backend's row only appears when it actually has leases), so a box that
runs Kea but not legacy ISC DHCPv4 only shows the Kea section.

Examples of what hides when unused: NetFlow tab, OpenVPN / WireGuard-peer / IPsec-tunnel rows,
ISC DHCPv4 (when leaseless), CARP VIPs, SMART, ACME, DynDNS, the Go-runtime row, etc.

### Variables

- **Data source** — pick your Prometheus datasource.
- **OPNsense instance** — multi-select over `opnsense_instance` (supports multiple exporters).
- **Interface** — multi-select, scopes the Interfaces tab.

### Deploy the dashboard

**Grafana UI:** Dashboards → New → Import, and upload `dashboard.json` (Grafana 13+).

**gcx (Grafana Cloud / API):**
```bash
gcx dashboards create -f dashboard.json          # first time
gcx dashboards update opnsense-exporter -f dashboard.json   # subsequent updates
# or, for a folder of resources, with the UI staying editable:
gcx resources push -p dashboard.json --omit-manager-fields
```

**GitOps (GitSync):** drop the manifest into your synced repo under the target folder; the
`metadata.name` (`opnsense-exporter`) is the dashboard UID/slug.

### Regenerate

```bash
cd grafana
python3 build_dashboard.py          # writes dashboard.json + prints coverage (NNN/NNN)
python3 build_dashboard.py --check  # coverage gate only (non-zero exit if any metric unreferenced)
```
Set `DASH_NAME=<slug>` to override `metadata.name` (used for scratch/validation copies).

## Alerts & recording rules

`alerts/` contains **20 alert rules** and **8 recording rules**, shipped as **Grafana-managed
alerting** manifests. Grafana-managed is the only supported format — it carries `noDataState`
(so the exporter-down / NoData case actually fires) and Grafana templating, neither of which a
portable Prometheus rule-group file can express. Alerts carry a `severity` label and runbook
annotation; recording rules follow the `instance:opnsense_<subsystem>_<measurement>:<op>`
convention.

### Grafana-managed format

`alerts/grafana-managed/` holds one `rules.alerting.grafana.app/v0alpha1` manifest per rule
plus a `_folder.json`. Push with gcx:
```bash
cd grafana/alerts
python3 build_rules.py --datasource <your-prom-uid>   # default: grafanacloud-prom
gcx resources push -p grafana-managed/_folder.json    # create the folder first
gcx resources push -p grafana-managed/                # then the rules
```

Regenerate with `--stack` to attach an IRM label contract (`domain=infra`, plus `page=true` on
critical rules) for routing through a notification policy / on-call. Use `--folder <uid>` to
target a specific Grafana folder.

### Alerts

| Alert | Severity | Fires when |
|-------|----------|-----------|
| OPNsenseExporterDown | critical | `opnsense_up` 0 (API unreachable / scrape failed) or NoData for 15m |
| OPNsenseFirewallUnhealthy | warning | firewall health check reports errors for 10m |
| OPNsenseCrashReports | warning | crash reports present |
| OPNsenseEndpointErrors | warning | an API endpoint returned errors in 15m |
| OPNsenseGatewayDown | critical | the primary gateway is offline for 5m |
| OPNsenseGatewayDownFailover | warning | a failover/secondary gateway is offline for 15m |
| OPNsenseGatewayHighLoss | warning | gateway loss > 20% for 10m |
| OPNsenseGatewayHighRTT | warning | gateway RTT over its configured high threshold for 10m |
| OPNsensePFStateTableNearLimit | warning | PF state table > 90% of limit for 10m |
| OPNsenseMemoryHigh | warning | memory > 90% for 15m |
| OPNsenseDiskUsageHigh | warning | a filesystem > 90% for 15m |
| OPNsenseHighTemperature | warning | a sensor > 85 °C for 10m |
| OPNsenseSmartHealthFailed | critical | a disk's SMART health is FAILED |
| OPNsenseFirmwareNeedsReboot | warning | a firmware update needs a reboot (30m) |
| OPNsenseCertificateExpiringSoon | warning | a certificate expires within 14 days |
| OPNsenseCertificateExpiringCritical | critical | a certificate expires within 3 days |
| OPNsenseServiceDown | warning | a monitored service is stopped for 10m |
| OPNsenseNTPPeerUnreachable | warning | an NTP peer's reachability register is 0 for 15m |
| OPNsenseUnboundDNSSECBogus | info | > 5 DNSSEC-bogus answers in 15m |

Thresholds are conservative defaults — tune them in `build_rules.py` for your environment.
Note: `OPNsenseEndpointErrors` and `OPNsenseServiceDown` emit one alert per endpoint/service.

**Gateway coverage.** `opnsense_gateways_status` is emitted for every *enabled* gateway using the
API-reported status, including gateways with OPNsense monitoring disabled (a common PPPoE/DHCPv6-PD
default-gateway pattern) — so `OPNsenseGatewayDown` covers them too. The rule's `noDataState` stays
`OK` (a totally-absent series means the exporter itself is down, which `OPNsenseExporterDown`
already pages on); it does not fire for *disabled* gateways, which have no status series by design.

**`opnsense_up` is reachability-only.** It is 1 whenever the exporter reaches and parses the
OPNsense system-status API, and 0 only when that call fails (unreachable / auth / HTTP error).
A reachable box that self-reports a degraded subsystem — e.g. a leftover crash report puts
OPNsense's *own* overall status into ERROR — keeps `opnsense_up = 1`; that state surfaces via
`opnsense_system_status_code` (2 = OK, 1 = NOTICE, 0 = WARNING, -1 = ERROR) and the per-subsystem
`opnsense_firewall_status` / `opnsense_crash_reporter_status` gauges, which drive the
lower-severity warnings above. So `OPNsenseExporterDown` (critical/page) fires only on genuine
unreachability, not on a benign degraded-subsystem notice. **Operators upgrading from an exporter
build before this change:** `opnsense_up` no longer flips to 0 for a degraded-but-reachable box,
so a leftover crash report now pages as a warning (`OPNsenseCrashReports`) instead of a critical
(`OPNsenseExporterDown`).

### Recording rules

`instance:opnsense_interface_rx_bits:rate5m`, `…_tx_bits:rate5m`,
`instance:opnsense_firewall_block_packets:rate5m`, `instance:opnsense_pf_state:utilization`,
`instance:opnsense_unbound_cache:hit_ratio`, `instance:opnsense_unbound_queries:rate5m`,
`instance:opnsense_gateway_loss:ratio`, `instance:opnsense_system_mem:utilization`.
