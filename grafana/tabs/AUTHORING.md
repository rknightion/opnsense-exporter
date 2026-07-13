# Tab module authoring guide (READ FIRST)

Each tab is a Python module `grafana/tabs/<name>.py` exposing **one** function:

```python
from builder import Builder, sel, RATE, UPDOWN, RUNSTOP, OKERR, YESNO, ENABLED, GW_STATUS

def build(b: Builder):
    ...
    b.tab("Title", [ b.row("Row title", [panel, panel, ...], present="has_x"), ... ])
```

`build(b)` adds panels (via `b.<viz>(...)`, each returns an element-name string) and then
calls `b.tab(...)` exactly once (or more, but normally once per module). Do NOT build the
manifest, write files, or define variables other than sentinels.

The orchestrator (`build_dashboard.py`) imports each module in a fixed order and calls
`build(b)`. The canonical worked examples are `build_overview()` and `build_diagnostics()`
in `build_dashboard.py` — mirror their style. The full API is in `builder.py` (read it).

## Hard rules

1. **Instance filter on every query.** Use `sel("opnsense_metric")` →
   `opnsense_metric{opnsense_instance=~"$opnsense_instance"}`. Extra matchers:
   `sel("opnsense_x", 'interface=~"$interface"')`. Never write a bare metric without `sel`
   (except `go_*`/`process_*` which use `{job="opnsense-exporter"}`).
2. **Datasource** is always `${datasource}` — handled by the helpers, never hard-code a UID.
3. **conditionalRendering is TAB/ROW level only** (never per-panel). Gate a tab with
   `b.tab(..., present="sentinel")`; gate a row with `b.row(..., present="sentinel")`.
   Register the sentinel first with `b.sentinel("name", "<grafana variable query>")`.
4. **Counters → rate.** Metrics whose name ends `_total` AND that are true cumulative
   counters must be charted as `rate(sel("..._total")[{RATE}])` (use the `RATE` constant).
   EXCEPTIONS — these are named `_total` but are *instantaneous* (current value); show RAW,
   never rate: `opnsense_services_running_total`, `opnsense_services_stopped_total`,
   `opnsense_carp_vips_total`, `opnsense_*_leases_total/_reserved_total/_dynamic_total`,
   `opnsense_*_peers_total`, `opnsense_acme_certificates_total`, `opnsense_mbuf_cluster_total`,
   `opnsense_mbuf_bytes_total`, `opnsense_activity_threads_total`, `opnsense_dyndns_accounts_total`,
   `opnsense_network_diag_*_total` socket/route/pfsync counts, `opnsense_firewall_rule_rules_total`,
   `opnsense_qfeeds_feeds_total`, `opnsense_alias_tables_total`, `opnsense_certificate_ca_total`
   (`opnsense_tailscale_peers_total` is covered by the `opnsense_*_peers_total` pattern above).
   When unsure, treat a "current count" as RAW and a "things-that-happened" as rate.
5. **Firewall pass/block packet & byte metrics** (`opnsense_firewall_in/out_ipv4/6_*`) are
   cumulative pf counters → use `rate(...[{RATE}])` for pps / throughput (×8 for bits).
   **⚠ Two disjoint `interface` label spaces — pick the matching variable (#98).** The same
   `interface` label name is populated from *different* identifiers by different collectors:
   * **description space** — `LAN`, `IOT`, `MGMT` (the configured description). Used by the
     `opnsense_interfaces_*` family and `opnsense_firewall_interface_log_entries_recent`.
     Filter these with **`$interface`**.
   * **device-name space** — `igb0`, `ixl0_vlan25`, `pppoe0` (the kernel device). Used by the
     pf-traffic counters (`opnsense_firewall_in/out_ipv4/6_{pass,block}_{packets,bytes_total}`)
     and the netflow cache metrics (`opnsense_netflow_cache_*`). Filter these with **`$device`**
     (module constant `DEV = 'interface=~"$device"'` in firewall.py).
   The two value sets never overlap, so applying `$interface` to a device-space metric silently
   blanks the panel whenever a specific interface is selected. Never cross the spaces.
6. **Cardinality.** For high-series metrics use `topk(20, ...)` in tables/timeseries and put
   detail tables in their own row gated behind a `*_details`/presence sentinel. Known big ones:
   arp_table (~106), ndp (~67), firewall_rule (~129), dnsmasq lease_info (~91). For "count"
   stats use `count by (label)(sel("..."))`, NOT the raw info-metric value.
7. **info metrics** (`*_info`, value always 1) → `table` with `excludes=["Value","__name__","job","instance"]`
   and friendly `renames`. Never put them on a timeseries.
8. **Coverage.** Every metric assigned to your tab MUST appear in at least one panel query.
   The orchestrator's coverage gate fails if any catalogue metric is unreferenced.

## Builder viz helpers (all return an element-name string)

- `b.ts(title, series, unit="short", w=12, h=8, stack=False, desc="", overrides=None, decimals=None)`
  — timeseries. `series = [(expr, "legend {{label}}"), ...]`.
- `b.stat(title, expr, unit="short", w=4, h=4, mappings=None, thresholds=None, color_mode="value", graph="area", decimals=None, instant=False, desc="")`
  — single stat. `mappings=UPDOWN` etc. `thresholds=[{"color":"green","value":None},{"color":"red","value":90}]`.
- `b.gauge(title, expr, unit="percent", w=4, h=6, mn=0, mx=100, thresholds=None)` — radial gauge.
- `b.bargauge(title, series, unit="short", w=8, h=8, orient="horizontal", mx=None)` — per-series bars (instant).
- `b.table(title, exprs, w=24, h=10, excludes=[...], renames={...}, unit_overrides={field:unit}, sort_by="Field", sort_desc=True)`
  — `exprs` is a list of instant PromQL strings; multiple are merged by labels.
- `b.statetimeline(title, series, mappings, w=24, h=8, unit="short")` — discrete state over time
  (link/gateway/peer/service status). `mappings=UPDOWN`/`GW_STATUS`/custom.
- `b.statushistory(title, series, mappings, w=24, h=6)` — discrete state squares over time.
- `b.piechart(title, series, unit="short", w=8, h=8, pie="donut")` — distribution (instant).
- `b.text(title, markdown, w=24, h=4)` — markdown note.

Grid is 24 cols; widths in a row should sum to ≤24 (helper auto-wraps). Common widths: 24 (full),
12 (half), 8 (third), 6 (quarter), 4 (sixth), 3 (eighth). Pick heights 4 (stat) / 6 (gauge) /
7–9 (ts/table).

## Value-mapping constants (import from builder)

`UPDOWN` {0:Down/red,1:Up/green} · `RUNSTOP` {0:Stopped,1:Running} · `OKERR` {0:Error,1:OK} ·
`YESNO` {0:No/green,1:Yes/orange} · `ENABLED` {0:Disabled,1:Enabled} ·
`GW_STATUS` {0:Offline,1:Online,2:Unknown,3:Pending,4:Packetloss,5:Latency,6:Offline (forced)}. Build a custom one as a dict
`{"value": ("Text", "color"), ...}` and pass to `mappings=`.

## Sentinel queries (use EXACTLY these — corrected for real emission behaviour)

Register with `b.sentinel(name, query)` then gate the tab/row with `present=name`.

| name | query |
|---|---|
| has_smart | `label_values(opnsense_smart_device_health, __name__)` |
| has_temperature | `label_values(opnsense_temperature_celsius, __name__)` |
| has_firewall_rules | `label_values(opnsense_firewall_rule_rules_total, __name__)` |
| has_carp | `label_values(opnsense_carp_allow, __name__)` |
| has_carp_vips | `query_result(opnsense_carp_vips_total > 0)` |
| has_unbound | `label_values(opnsense_unbound_dns_uptime_seconds, __name__)` |
| has_unbound_qstats | `label_values(opnsense_unbound_dns_qstats_enabled, __name__)` |
| has_ntp | `label_values(opnsense_ntp_peer_info, __name__)` |
| has_acme | `label_values(opnsense_acme_certificates_total, __name__)` |
| has_netflow | `label_values(opnsense_netflow_active, __name__)` |
| has_openvpn | `label_values(opnsense_openvpn_instances, __name__)` |
| has_wireguard | `label_values(opnsense_wireguard_service_running, __name__)` |
| has_wireguard_ifaces | `label_values(opnsense_wireguard_interfaces_status, __name__)` |
| has_wireguard_peers | `label_values(opnsense_wireguard_peer_status, __name__)` |
| has_ipsec | `label_values(opnsense_ipsec_service_running, __name__)` |
| has_ipsec_tunnels | `label_values(opnsense_ipsec_phase1_status, __name__)` |
| has_dyndns | `label_values(opnsense_dyndns_accounts_total, __name__)` |
| has_network_diag | `label_values(opnsense_network_diag_sockets_unix_total, __name__)` |
| has_dnsmasq | `query_result(opnsense_dnsmasq_leases_total > 0)` |
| has_kea | `query_result((opnsense_kea_dhcp4_leases_total + opnsense_kea_dhcp6_leases_total) > 0)` |
| has_dhcpv4_isc | `query_result(opnsense_dhcpv4_leases_total > 0)` |
| has_dnsmasq_details | `label_values(opnsense_dnsmasq_lease_info, __name__)` |
| has_kea4_details | `label_values(opnsense_kea_dhcp4_lease_info, __name__)` |
| has_kea6_details | `label_values(opnsense_kea_dhcp6_lease_info, __name__)` |
| has_dhcpv4_details | `label_values(opnsense_dhcpv4_lease_info, __name__)` |
| has_firmware_details | `label_values(opnsense_firmware_plugin_installed, __name__)` |
| has_syslog | `label_values(opnsense_syslog_service_running, __name__)` |
| has_qfeeds | `label_values(opnsense_qfeeds_feeds_total, __name__)` |
| has_tailscale | `label_values(opnsense_tailscale_service_running, __name__)` |
| has_tailscale_peers | `label_values(opnsense_tailscale_peer_session_active, __name__)` |
| has_netbird | `label_values(opnsense_netbird_service_running, __name__)` |
| has_netbird_peers | `label_values(opnsense_netbird_peer_connected, __name__)` |
| has_alias | `label_values(opnsense_alias_tables_total, __name__)` |
| has_alias_details | `label_values(opnsense_alias_table_packets_total, __name__)` |

## Self-test before finishing

Run from `grafana/`:
```bash
python3 - <<'PY'
import builder, importlib
b = builder.Builder()
importlib.import_module("tabs.<your_module>").build(b)
print("panels", len(b.elements), "tabs", len(b.tabs), "vars", [v['spec']['name'] for v in b.variables])
PY
```
It must run without exception. Then validate the schema for your tab only:
```bash
python3 - <<'PY'
import builder, importlib, json
b = builder.Builder()
# add a dummy instance/datasource var is not needed for schema validation
importlib.import_module("tabs.<your_module>").build(b)
json.dump(b.manifest("t","d",["x"]), open("/tmp/<your_module>.json","w"), indent=2)
PY
gcx resources validate -p /tmp/<your_module>.json
```
Expect `{"failures":[]}`. Fix anything it reports. Do not push.
