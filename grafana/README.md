# OPNsense Exporter - Grafana assets

This folder ships everything you need to visualise and alert on the metrics exposed by the
OPNsense Exporter:

| Path | What it is |
|------|------------|
| `dashboard.json` | A **Grafana v2 dynamic dashboard** (`dashboard.grafana.app/v2`) with 7 top-level domains and 41 tabs that render conditionally. |
| `build_dashboard.py` | Generator for `dashboard.json`. Run `python3 build_dashboard.py`. |
| `builder.py`, `tabs/` | The builder framework and one module per tab. See `tabs/AUTHORING.md`. |
| `alerts/grafana-managed/` | Alert + recording rules as **Grafana-managed** `rules.alerting.grafana.app/v0alpha1` manifests (+ a folder), pushable with `gcx`. |
| `alerts/build_rules.py` | Generator for the Grafana-managed rule manifests from a single source. |

The dashboard is **mixed-datasource**: Prometheus metrics plus opt-in **Loki** log panels
(raw Zenarmor/syslog streams, top-talker tables) that auto-hide when no matching log stream
exists. It works fully on a Prometheus datasource alone; the Loki panels light up when a Loki
datasource carrying the exporter's shipped logs is selected.

## Requirements

- **Grafana 13+** (Grafana Cloud or self-hosted). The v2 schema with `TabsLayout` and
  `conditionalRendering` is required for the show/hide behaviour.
- A Prometheus-compatible datasource scraping the exporter.
- For the **Diagnostics** tab's *Build & Collectors* panels you need an exporter build that
  emits `opnsense_exporter_build_info` and `opnsense_exporter_collector_enabled` (added in this
  fork). Older builds simply leave those two panels empty.

## The dashboard

One dashboard, 7 top-level domains and 41 tabs grouped by feature (generated list, do not hand-edit):

<!-- docgen:begin:dashboard-tabs -->
Overview, System & Resources, Services, Cron & DynDNS, Certificates, UPS, Monit, HA Sync, CARP / HA, Interfaces, Gateways & WAN, DNS - Unbound, DHCP, Routing & Neighbors, Protocol Stats, NTP, Chrony, Traffic Shaper, NetFlow, FRR Routing, Captive Portal, Firewall & PF, Aliases, IDS/IPS, CrowdSec, ClamAV, Q-Feeds, Zenarmor, VPN, Tailscale, NetBird, Tor, Syslog, HAProxy, Relayd, Nginx, Siproxd, Log-derived Events, Flow Volume, Log Shipping, Recording rules, Diagnostics
<!-- docgen:end:dashboard-tabs -->

covering **every** metric the exporter emits (a coverage gate in `build_dashboard.py` fails the
build if any catalogue metric is left unreferenced).

### Dynamic show/hide

Feature tabs and rows for optional collectors / OPNsense plugins **hide automatically when their
metrics are absent**, so the same dashboard adapts to any deployment. This is driven by hidden
sentinel template variables (`label_values(metric, __name__)` → empty when the metric is absent)
plus `conditionalRendering` on the tab/row. A few sections are gated on *data* rather than mere
presence (e.g. a DHCP backend's row only appears when it actually has leases), so a box that
runs Kea but not legacy ISC DHCPv4 only shows the Kea section.

Examples of what hides when unused: NetFlow, VPN, UPS, HAProxy, CrowdSec, Zenarmor and recording-rule
tabs; OpenVPN / WireGuard-peer / IPsec-tunnel rows; CARP VIPs, SMART, ACME, DynDNS, and Go-runtime rows.

### Variables

- **Data source** - pick your Prometheus datasource.
- **Loki data source** - pick the Loki datasource carrying the exporter's shipped logs
  (default `grafanacloud-logs`). The Loki panels/rows (Zenarmor, syslog streams) hide when it
  has no matching stream, so a metrics-only deployment is unaffected.
- **OPNsense instance** - multi-select over `opnsense_instance` (supports multiple exporters).
- **Interface** - multi-select, scopes the Interfaces tab.
- **Device (pf/netflow)** - multi-select over kernel interface names used by PF and NetFlow.

### Deploy the dashboard

**Grafana UI:** Dashboards → New → Import, and upload `dashboard.json` (Grafana 13+).

**gcx (standalone / unmanaged dashboard only):**
```bash
gcx dashboards create -f dashboard.json          # first time
gcx dashboards update opnsense-exporter -f dashboard.json   # subsequent updates
# or, for a folder of resources, with the UI staying editable:
gcx resources push -p dashboard.json --omit-manager-fields
```

Do not run those update/push commands against a GitSync-managed production UID. Test a generated
scratch UID first, then publish the canonical manifest only through the synced repository:

```bash
DASH_NAME=opnsense-exporter-review python3 build_dashboard.py
gcx dashboards create -f dashboard.json
gcx dashboards snapshot opnsense-exporter-review --since 6h --width 1920

# Restore the canonical UID, then copy/commit this file in the GitSync repository.
python3 build_dashboard.py
cp dashboard.json /path/to/gitsync-repo/networking/opnsense-exporter.json
```

**GitOps (GitSync):** commit and push the manifest at the target repository path; GitSync performs
the production update and retains manager ownership. The canonical `metadata.name`
(`opnsense-exporter`) is the dashboard UID/slug. Delete the scratch UID after the synced production
dashboard has rendered successfully.

### Regenerate

```bash
cd grafana
python3 build_dashboard.py          # writes dashboard.json + prints coverage (NNN/NNN)
python3 build_dashboard.py --check  # coverage gate only (non-zero exit if any metric unreferenced)
```
Set `DASH_NAME=<slug>` to override `metadata.name` (used for scratch/validation copies).

## Alerts & recording rules

`alerts/` contains **37 alert rules** and **14 recording rules**, shipped as **Grafana-managed
alerting** manifests. Grafana-managed is the only supported format - it carries `noDataState`
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
| OPNsenseEndpointErrors | warning | an API endpoint returned errors in 15m (fast/medium tiers - see below) |
| OPNsenseCollectorDataStale | warning | a collector's retained data is older than 3 of its own poll intervals |
| OPNsenseCollectorDegraded | info | a collector keeps refreshing partial data but has not fully succeeded for 6 intervals |
| OPNsenseCollectorNeverStoredData | warning | a collector has polled for 30m and never once stored data |
| OPNsenseOTLPDeliveryFailing | warning | every OTLP metric export has failed for 15m |
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

Thresholds are conservative defaults - tune them in `build_rules.py` for your environment.
Note: `OPNsenseEndpointErrors` and `OPNsenseServiceDown` emit one alert per endpoint/service.

**Stale-data alerting is tier-aware, and attempt age is not freshness.** Each collector polls on
its own tier (fast 15s / medium 60s / slow 5m / cold 15m, overridable with
`--collector.poll-interval-override`), and a failed poll that produced nothing deliberately
retains the last-good values rather than blanking the dashboard. Two consequences the rules above
encode:

- `opnsense_exporter_collector_last_poll_timestamp_seconds` advances on **every attempt**,
  successful or not, so it measures scheduler liveness and never data age. The dashboard panel is
  titled *Collector Last Attempt Age* for that reason. True data age is
  `opnsense_exporter_collector_snapshot_timestamp_seconds` (buffer last replaced) and
  `opnsense_exporter_collector_last_success_timestamp_seconds` (last fully clean poll).
- `OPNsenseCollectorDataStale` / `OPNsenseCollectorDegraded` express tolerance in **missed poll
  intervals**, dividing the age by `opnsense_exporter_collector_poll_interval_seconds` (plus a
  120s scrape-lag allowance), so one rule covers every tier: a persistent failure fires ~8m into
  the fast tier and ~52m into the cold tier, while a single failed poll followed by recovery peaks
  at ~2 missed intervals on all four tiers and cannot fire. `OPNsenseEndpointErrors` keeps its 2m
  window and stays the fast/medium-tier signal that names the failing *endpoint*; it cannot fire
  for a slow/cold-tier collector (the window is empty between two once-per-tier attempts), and
  widening it would reintroduce the fire-after-recovery bug those windows were tightened to fix.

**`OPNsenseOTLPDeliveryFailing` cannot page a pure-OTLP backend.** The exporter cannot ship its own
failure metric through the path that is failing, so `opnsense_exporter_otlp_*` is a signal for
`/metrics` scrapers, for the passive operator console, and for post-recovery forensics - not an
in-band outage page. On a pure-OTLP backend, the in-band symptom of this failure mode is staleness
of the exporter's data at the backend. `opnsense_exporter_otlp_enabled=1` means the push pipeline
is *running*, not that delivery *works*: the OTLP exporter connects lazily, so it reads 1 from
startup even against a wrong endpoint.

**Gateway coverage.** `opnsense_gateways_status` is emitted for every *enabled* gateway using the
API-reported status, including gateways with OPNsense monitoring disabled (a common PPPoE/DHCPv6-PD
default-gateway pattern) - so `OPNsenseGatewayDown` covers them too. The rule's `noDataState` stays
`OK` (a totally-absent series means the exporter itself is down, which `OPNsenseExporterDown`
already pages on); it does not fire for *disabled* gateways, which have no status series by design.

**`opnsense_up` is reachability-only.** It is 1 whenever the exporter reaches and parses the
OPNsense system-status API, and 0 only when that call fails (unreachable / auth / HTTP error).
A reachable box that self-reports a degraded subsystem - e.g. a leftover crash report puts
OPNsense's *own* overall status into ERROR - keeps `opnsense_up = 1`; that state surfaces via
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
