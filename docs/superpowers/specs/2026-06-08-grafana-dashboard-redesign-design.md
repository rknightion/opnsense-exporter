# OPNsense Exporter — Grafana Dashboard Redesign (v2 dynamic schema)

Date: 2026-06-08
Status: Design (autonomous mode — self-reviewed, not gated on user approval)

## Goal

Replace the legacy 112-panel flat dashboard with a **single comprehensive dashboard**
using the Grafana 13 **v2 dynamic dashboard schema** (`dashboard.grafana.app/v2`,
`TabsLayout` + `conditionalRendering`). It must:

- Touch **all 301 catalogued metrics** across ~30 collectors (incl. exporter self-metrics).
- Use **tabs** as the primary navigation; auto **show/hide tabs and rows** based on whether
  the underlying metrics exist (or carry data), so the same dashboard adapts to any user's
  enabled collectors / installed OPNsense plugins.
- Use a **variety of visualization types** (timeseries, stat, gauge, bar gauge, table,
  state timeline, status history, piechart, heatmap where it adds value).
- Include a **Diagnostics / self-observability** tab.
- Ship from a new **`grafana/`** folder at the repo root (dashboard JSON + builder + alerts +
  recording rules + README), replacing `deploy/grafana/dashboard.json`.

## Deliverables

```
grafana/
  build_dashboard.py        # Python builder -> emits dashboard.json (v2 manifest)
  dashboard.json            # generated v2 manifest (dashboard.grafana.app/v2)
  alerts/
    opnsense-alerts.yaml     # generic Grafana-managed alert rules (portable)
    opnsense-recording.yaml  # generic Grafana-managed recording rules
  README.md                 # how to import/deploy dashboard + rules (gcx, gitsync, UI)
```

`deploy/grafana/dashboard.json` is removed (and the legacy `scripts/generate-dashboard.py`).

## Exporter code change — feature/build info metric

Add two exporter-level metrics (emitted by the top-level `Collector`, which already owns the
`opnsense_exporter_*` family and is constructed in `main.go` where `version` + the
`CollectorsDisableSwitch` are both available):

- `opnsense_exporter_build_info{version, goversion, instance_label}` = 1 — build/version panel
  for Diagnostics; lets dashboards/alerts pin exporter version. Reuse `runtime.Version()`.
- `opnsense_exporter_collector_enabled{collector="<subsystem>"}` = 0|1 — one series per
  collector reflecting the resolved enable/disable switch. Distinguishes "collector disabled"
  from "feature absent / no data", and powers a Diagnostics coverage matrix.

Implementation: pass `version string` and `map[string]bool` (collector -> enabled) into
`collector.New(...)` via two new `Option`s (`WithBuildInfo`, `WithCollectorStates`) or direct
fields; register const `*prometheus.Desc`s; emit in `Collect`. Const label `opnsense_instance`
applies as everywhere else. Full doc/test/changelog updates per CLAUDE.md "Adding a New
Collector" (the docgen maps, README/configuration tables, metrics.md regen, fork changelog).

## Dashboard structure

### Variables (`spec.variables[]`)

- `datasource` — `DatasourceVariable` (prometheus), referenced as `${datasource}`.
- `opnsense_instance` — `QueryVariable` `label_values(opnsense_up, opnsense_instance)`,
  multi+includeAll, default All. Every panel query filters `opnsense_instance=~"$opnsense_instance"`.
- `interface` — `QueryVariable` `label_values(opnsense_interfaces_link_state, interface)`,
  multi+includeAll, used by the Interfaces tab.
- **Hidden sentinel `QueryVariable`s** (`hide: hideVariable`, `skipUrlSync: true`,
  `refresh: onDashboardLoad`, `sort: disabled`) driving conditionalRendering:

  | Sentinel | Query | Gates |
  |---|---|---|
  | `has_firewall_rules` | `label_values(opnsense_firewall_rule_rules_total, __name__)` | Firewall Rules row |
  | `has_unbound` | `label_values(opnsense_unbound_dns_uptime_seconds, __name__)` | DNS tab |
  | `has_ntp` | `label_values(opnsense_ntp_peer_info, __name__)` | NTP tab |
  | `has_acme` | `label_values(opnsense_acme_certificates_total, __name__)` | ACME row |
  | `has_netflow` | `label_values(opnsense_netflow_enabled, __name__)` | NetFlow tab |
  | `has_openvpn` | `label_values(opnsense_openvpn_instances, __name__)` | OpenVPN row |
  | `has_wireguard` | `label_values(opnsense_wireguard_interfaces_status, __name__)` | WireGuard row |
  | `has_ipsec_tunnels` | `label_values(opnsense_ipsec_phase1_status, __name__)` | IPsec detail row |
  | `has_dyndns` | `label_values(opnsense_dyndns_accounts_total, __name__)` | DynDNS row |
  | `has_network_diag` | `label_values(opnsense_network_diag_sockets_unix_total, __name__)` | NetISR/sockets rows |
  | `has_smart` | `label_values(opnsense_smart_device_health, __name__)` | SMART row |
  | `has_temperature` | `label_values(opnsense_temperature_celsius, __name__)` | Temperature row |
  | `has_carp_vips` | `query_result(opnsense_carp_vips_total > 0)` | CARP VIP row |
  | `has_dnsmasq` | `query_result(opnsense_dnsmasq_leases_total > 0)` | dnsmasq DHCP row |
  | `has_kea` | `query_result((opnsense_kea_dhcp4_leases_total + opnsense_kea_dhcp6_leases_total) > 0)` | Kea DHCP row |
  | `has_dhcpv4_isc` | `query_result(opnsense_dhcpv4_leases_total > 0)` | ISC DHCPv4 row |
  | `has_dnsmasq_details` | `label_values(opnsense_dnsmasq_lease_info, __name__)` | dnsmasq lease table |
  | `has_kea_details` | `label_values(opnsense_kea_dhcp6_lease_info, __name__)` / dhcp4 | Kea lease table |

  conditionalRendering form: `ConditionalRenderingGroup{visibility:show, condition:and,
  items:[ConditionalRenderingVariable{variable, operator:matches, value:".+"}]}`.

### Tabs (each a `TabsLayoutTab`, GridLayout or RowsLayout inside)

1. **Overview** (always) — health row (`opnsense_up`, `firewall_status`, `crash_reporter_status`,
   `system_status_code`, `firmware_needs_reboot`) as stat/status-history; WAN status + RTT/loss
   summary; CPU/mem/load gauges; pf states current vs limit gauge; services running/stopped;
   throughput sparkstats per WAN; uptime; worst disk usage; max temperature. Exporter build_info stat.
2. **System & Resources** (system, activity, mbuf, temperature, SMART) — memory used/total/ARC
   (timeseries + gauge), swap, load avg 1/5/15, uptime, config-last-change; CPU user/system/idle/
   nice/interrupt (stacked timeseries), threads total/running/sleeping/waiting; disk per-mount
   table + bar gauge (`usage_ratio`); **Temperature row** (gated) timeseries + stat per sensor;
   **mbuf row** current/cache/total/cluster*/failures/sleeps/sendfile; **SMART row** (gated)
   health state-timeline, temperature, power-on-hours.
3. **Interfaces** (interfaces; `$interface`) — throughput bits in/out (rate*8), packets in/out,
   input/output errors, queue drops (send/input), collisions, multicasts, MTU, line_rate;
   **link_state** state-timeline + table.
4. **Firewall & PF** (firewall, pf_stats; firewall_rule gated row) — pass/block packets & bytes
   by interface & direction (ipv4/ipv6), interface hits; pf states current vs limit (gauge) +
   source tracking; pf_stats counters / limit counters (table + timeseries), memory limits (bar
   gauge), timeouts (table); **Firewall Rules row (gated)**: top-N rules by evaluations/packets/
   bytes (table), rule states, pf_rules.
5. **Gateways & WAN** (gateways) — status state-timeline, RTT + rtt_low/high bands, RTTd, loss %
   + loss_low/high bands, priority, force_down/virtual/dynamic flags, probe interval/period/
   timeout, monitor_info + info tables.
6. **DNS — Unbound** (unbound) [tab gated `has_unbound`] — query rate, cache hit ratio (hits/
   (hits+miss)), prefetch, expired, recursion time avg/median, request list avg/max/current/
   exceeded/overwritten, answers by rcode (piechart), queries by type/protocol/flag (bar/pie),
   edns, DNSSEC secure/bogus + rrset bogus, unwanted, ip_ratelimited, timed_out, tcp_usage_ratio
   (gauge), blocklist_enabled (stat), cache_count, memory by component, uptime, service_running.
7. **DHCP** (dnsmasq, kea, dhcpv4 — rows each gated) — per backend: totals (total/reserved/
   dynamic), leases by interface (bar gauge), service_running; lease tables gated on `_details`.
8. **VPN** (wireguard, openvpn, ipsec) — always: service_running stats for all three; gated rows:
   **WireGuard** interfaces_status, peer_status state-timeline, peer rx/tx bytes rate, handshake
   age; **OpenVPN** instances + sessions tables; **IPsec** phase1 status/bytes/packets/install,
   phase2 bytes/packets/rekey/life tables.
9. **Routing & Neighbors** (arp_table, ndp, network_diag) — ARP entry count by interface/type +
   table; NDP entry count + table; **NetISR rows (gated)** dispatched/queued/handled/drops/queue
   length/watermark/limit by protocol; sockets active/unix, routes by proto, pfsync nodes/info.
10. **Protocol Stats** (protocol) — TCP (conn by state state-timeline/pie, sent/recv packets,
    retransmits & bytes, drops, syncache, established/closed, keepalive, listen overflows), UDP
    (delivered/output/received + dropped by reason), IP (recv/forward/sent/dropped by reason/
    fragments/reassembled), ARP protocol counters, ICMP calls/sent/dropped by reason, CARP &
    pfsync protocol packets/dropped. Mostly rate timeseries + "dropped by reason" tables.
11. **NTP** (ntp) [tab gated `has_ntp`] — peer offset/jitter/delay (timeseries), stratum, poll,
    reach, when (stat/table), peer_info table, peers_total.
12. **Certificates** (certificates, acme) — cert expiry countdown table (sorted by valid_to,
    color thresholds), valid_from/valid_to, info table, total; **ACME row (gated)**
    certificates_total, status_code, enabled, last_update timestamps, info table.
13. **Services, Cron & DynDNS** (services, cron, dyndns) — services_status table + running/stopped
    totals + stopped stat; cron_job_status table; **DynDNS row (gated)** accounts_total,
    account_enabled, last_update, info table, service_running.
14. **NetFlow** (netflow) [tab gated `has_netflow`] — enabled/local/active/collectors_count stats;
    cache packets / unique source / unique dest IPs by interface (timeseries + table).
15. **CARP / HA** (carp) — demotion, allow, maintenance_mode stats; vips_total; **VIP row (gated
    `has_carp_vips`)** vip_status state-timeline, advbase, advskew table.
16. **Diagnostics** (always) — `opnsense_up` timeline; `opnsense_exporter_scrapes_total` rate;
    `opnsense_exporter_endpoint_errors_total` by endpoint (timeseries + table); **build_info**
    table (new); **collector_enabled** coverage matrix (new, table/state-timeline); Go runtime
    self-metrics (`go_goroutines`, `go_memstats_*`, `process_resident_memory_bytes`,
    `process_cpu_seconds_total`) — gated on their presence (DisableExporterMetrics off).

### Visualization variety (mapping)

- **stat** — singletons/flags (up, needs_reboot, service_running, totals).
- **gauge** — utilization (pf states/limit, disk ratio, tcp_usage_ratio, mem%).
- **bar gauge** — per-mount disk, leases by interface, memory by component.
- **timeseries** — all rates/throughput/latency.
- **table** — info metrics, per-entity inventories (gateways, certs, rules, leases, services).
- **state timeline** — link_state, gateway status, carp vip status, wireguard peer status,
  service status over time.
- **status history** — health flags over time (Overview).
- **piechart** — answers by rcode, tcp conn by state, queries by type.
- **heatmap** — (optional) recursion time distribution if useful.

## Alerts (generic, Grafana-managed) — `grafana/alerts/opnsense-alerts.yaml`

Curated, portable (no instance-specific labels in repo). Each: expr, `for`, severity annotation,
summary/description + runbook hint. ~14 rules:

- `OPNsenseExporterDown` — `opnsense_up == 0 or absent(opnsense_up)` 5m — critical.
- `OPNsenseEndpointErrors` — `increase(opnsense_exporter_endpoint_errors_total[15m]) > 0` — warning.
- `OPNsenseGatewayDown` — `opnsense_gateways_status == 0` 5m — critical (per name/address).
- `OPNsenseGatewayHighLoss` — `opnsense_gateways_loss_percentage > 20` 10m — warning.
- `OPNsenseGatewayHighRTT` — `opnsense_gateways_rtt_milliseconds > opnsense_gateways_rtt_high_milliseconds` 10m — warning.
- `OPNsensePFStateTableNearLimit` — `opnsense_firewall_pf_states_current / opnsense_firewall_pf_states_limit > 0.9` 10m — warning.
- `OPNsenseFirmwareNeedsReboot` — `opnsense_firmware_needs_reboot == 1` 30m — warning.
- `OPNsenseCertificateExpiringSoon` — `(opnsense_certificate_valid_to_seconds - time()) < 14*24*3600` — warning; `< 3d` — critical.
- `OPNsenseACMECertExpiring` — analogous (gated by presence at eval).
- `OPNsenseDiskUsageHigh` — `opnsense_system_disk_usage_ratio > 0.9` 15m — warning.
- `OPNsenseHighTemperature` — `opnsense_temperature_celsius > 85` 10m — warning.
- `OPNsenseSmartHealthFailed` — `opnsense_smart_device_health == 0` 5m — critical.
- `OPNsenseMemoryHigh` — `opnsense_system_memory_used_bytes / opnsense_system_memory_total_bytes > 0.9` 15m — warning.
- `OPNsenseCrashReports` — `opnsense_crash_reporter_status == 0` — warning.
- `OPNsenseServiceDown` — `opnsense_services_status == 0` 10m — warning (per name).
- `OPNsenseUnboundDNSSECBogus` — `increase(opnsense_unbound_dns_answers_bogus_total[15m]) > 0` — info.

When pushed to the **m7kni** stack, add label contract `domain="infra"`, `severity`, `page`
(per the grafana CLAUDE.md) so they route through IRM/OnCall. Repo copies stay generic.

## Recording rules (generic) — `grafana/alerts/opnsense-recording.yaml`

~8 high-value precomputes:

- `opnsense:interface:rx_bits:rate5m`, `:tx_bits:rate5m` (by interface).
- `opnsense:firewall:block_packets:rate5m` (by interface, direction, ipver).
- `opnsense:pf:state_utilization` = current/limit.
- `opnsense:unbound:cache_hit_ratio` = hits/(hits+miss).
- `opnsense:gateway:loss_ratio`.
- `opnsense:dns:query:rate5m`.
- `opnsense:system:mem_utilization`.

## Build / validation approach

- Python builder `grafana/build_dashboard.py` modeled on the proven
  `../chat/grafana/build_opnsense_netactivity.py` and `../tailscale2otel` builders: helpers for
  `panel()`, `tab()`, `row()`, `sentinel_var()`, `conditional_show()`, grid layout packing.
- Emit `dashboard.grafana.app/v2` manifest with `metadata.name: opnsense-exporter`.
- Validate with `gcx resources validate -p grafana -o json`; push to a **scratch folder** via
  `gcx dashboards create/update` (or `resources push --omit-manager-fields`) for live testing;
  render `gcx dashboards snapshot` to verify conditional hiding (OpenVPN/WireGuard/NetFlow tabs
  hidden on the live box; present tabs shown). Iterate.

## Deployment

- **Dashboard**: remove `networking/opnsense-exporter.json` from `gc-gitsync-m7kni`, commit+push
  (reconcile deletes the old one). Add the new v2 manifest as `networking/opnsense-exporter.json`
  (same UID `cdmf5fk3ip4aob`? — NO: new build, new metadata.name; keep slug `opnsense-exporter`
  to preserve URL). Commit+push to GitHub `rknightion/gc-gitsync-m7kni` (nested repo, manual push).
- **Alerts/recording rules**: gitsync doesn't manage alerts — push to the m7kni stack via gcx
  (with IRM labels). Repo ships the generic YAML + README instructions.
- **Exporter repo**: new `grafana/` folder, Go info-metric change, docs/changelog. Branch + PR
  (real fork with CI/release-please) — final commit/PR is a user-preference gate.

## Non-goals

- The other 4 OPNsense dashboards (`opnsense.json`, `opnsense-network-activity.json`,
  `opnsense-firewall-logs.json`, `opnsense-sfp-and-port-monitor.json`) are untouched.
- No Loki/log panels (this dashboard is metrics-only; firewall logs have their own dashboard).
```
