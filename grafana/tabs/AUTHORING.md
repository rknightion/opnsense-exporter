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

The orchestrator (`build_dashboard.py`) imports each module in a fixed order, calls `build(b)`,
then moves every leaf into one top-level domain through `TAB_GROUPS`. Add a new leaf title to that
map or the build fails as unassigned. The canonical worked examples are `build_overview()` and
`build_diagnostics()` in `build_dashboard.py` — mirror their style. The full API is in `builder.py`.

## Hard rules

1. **Instance filter on every query.** Use `sel("opnsense_metric")` →
   `opnsense_metric{opnsense_instance=~"$opnsense_instance"}`. Extra matchers:
   `sel("opnsense_x", 'interface=~"$interface"')`. Never write a bare metric without `sel`
   (except `go_*`/`process_*`, which carry no appliance label and use `{job=~"opnsense.*"}`).
   On the Loki side the equivalent chokepoint is `loki_sel(matchers)` — see *Loki panels*.
   **Instance identity must also survive every aggregation (#468).** `sel()` decides which
   data enters a panel; this decides whether the panel can still tell two firewalls apart.
   Build the group-by clause, never write it: `f'sum {grp("protocol")} (...)'` →
   `sum by (opnsense_instance, protocol)`, and `f'topk {grp()} (20, ...)'` →
   `topk by (opnsense_instance) (20, ...)`. On the Loki side use `loki_grp()`, which names
   `service_instance_id` instead.
   - Where `topk` wraps an inner aggregation, **both** clauses need the label: the inner one
     has already fused the boxes before `topk` ranks them.
   - `topk` without a clause does not merge rows, it **drops** them — one firewall's series can
     push another's out of the panel entirely, with nothing on screen to say so.
   - Tables **rename** `opnsense_instance` to `"Instance"`; never `excludes` it.
   - A panel that is genuinely a fleet total must say so in its description and be listed in
     `tests/test_instance_identity.py`, which fails on any unlisted merge.
2. **Datasource** is always `${datasource}` — handled by the helpers, never hard-code a UID.
3. **conditionalRendering is TAB/ROW level only** (never per-panel). Gate a tab with
   `b.tab(..., present="sentinel")`; gate a row with `b.row(..., present="sentinel")`.
   Register the sentinel first with `b.sentinel("name", metric="opnsense_x")` — see *Sentinels*
   below for the scope modes. A list such as `present=["has_nut", "has_apcupsd"]` is an OR
   condition. Add optional leaves to `OPTIONAL_TAB_PRESENCE` so Grafana hides the tab itself
   when every implementation is absent.
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
     pf-traffic counters (`opnsense_firewall_in/out_ipv4/6_{pass,block}_{packets,bytes_total}`),
     the netflow cache metrics (`opnsense_netflow_cache_*`) and `opnsense_vnstat_*`, and carried
     in a separate `device` label by `opnsense_interfaces_info`/`_admin_up`/`_lagg_*`/`_sfp_*` and
     `opnsense_flow_interface_info`. Filter these with **`$device`** (module constant
     `DEV = 'interface=~"$device"'` in firewall.py).
   The two value sets never overlap, so applying `$interface` to a device-space metric silently
   blanks the panel whenever a specific interface is selected. Never cross the spaces.
   **`$device` is filtered on the `interface` label, never on `device`.** The variable's five
   *sources* (`DEVICE_SOURCES_*` in build_dashboard.py, #424) include two that own a real `device`
   label — that is how the picker survives a disabled firewall collector — but every *consumer*
   still filters `interface=~"$device"`. A panel filtering `device=~"$device"` is a bug, and
   `grafana/tests/test_device_variable.py` fails on it.
6. **Cardinality.** For high-series metrics use `topk {grp()} (20, ...)` in tables/timeseries and put
   detail tables in their own row gated behind a `*_details`/presence sentinel. Known big ones:
   arp_table (~106), ndp (~67), firewall_rule (~129), dnsmasq lease_info (~91). For "count"
   stats use `count {grp("label")} (sel("..."))`, NOT the raw info-metric value.
7. **info metrics** (`*_info`, value always 1) → `table` with `excludes=["Value","__name__","job","instance"]`
   and friendly `renames` including `"opnsense_instance": "Instance"`. Never put them on a
   timeseries, and never exclude the instance column (#468).
8. **Coverage.** Every metric assigned to your tab MUST appear in at least one panel query.
   The orchestrator's coverage gate fails if any catalogue metric is unreferenced.
9. **A tab module never adds an annotation.** The event timeline is dashboard-wide and lives in
   `annotations.py` (#421); annotations carry no `conditionalRendering`, so there is nothing
   tab-scoped about them. If your subsystem emits an instant-valued metric
   (`*_timestamp_seconds`), `tests/test_annotations.py` will fail until it is either added to
   `ANNOTATIONS` or listed in `NOT_ANNOTATED` with a reason — a heartbeat, a future-dated value
   or an upstream-authored timestamp is an exclusion, a discrete event is a layer. Tag keys may
   never carry an address, hostname or raw log body.

## Builder viz helpers (all return an element-name string)

- `b.ts(title, series, unit="short", w=12, h=8, stack=False, desc="", overrides=None, decimals=None)`
  — timeseries. `series = [(expr, "legend {{label}}"), ...]`.
- `b.stat(title, expr, unit="short", w=4, h=4, mappings=None, thresholds=None, color_mode="value", graph="area", decimals=None, instant=True, desc="")`
  — current-value stat by default. Set `instant=False` only when a range reduction or sparkline is
  deliberate. `mappings=UPDOWN` etc. `thresholds=[{"color":"green","value":None},{"color":"red","value":90}]`.
- `b.gauge(title, expr, unit="percent", w=4, h=6, mn=0, mx=100, thresholds=None)` — radial gauge.
- `b.bargauge(title, series, unit="short", w=8, h=8, orient="horizontal", mx=None)` — per-series bars (instant).
  Both `gauge()` and `bargauge()` render **neutrally** when `thresholds=` is omitted — neither invents
  a severity boundary (#415, #467). Pass an explicit list only for a bounded scale where the boundary
  means something, say what it means at the call site, and add the panel title to the matching
  allowlist in `tests/test_threshold_defaults.py`, which fails otherwise.
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

Prometheus panel queries are wrapped in `max without (instance, job, service_instance_id,
service_name, service_version)` by the builder. This removes scrape/OTel deployment identities while
preserving `opnsense_instance` and feature labels, so redeployments do not create duplicate logical
series in range panels.

## Loki panels (mixed datasource)

The dashboard is mixed Prometheus + Loki. Loki panels reference `${loki_datasource}`
(default `grafanacloud-logs`) and are gated on a Loki presence sentinel so they auto-hide
when no log stream exists. Helpers (all return an element name; LogQL is kept OUT of the
Prometheus coverage gate via a separate `_loki_exprs` list):

**Build every stream selector with `loki_sel(matchers)` (#413).** It is the LogQL chokepoint,
the exact counterpart of `sel()`:

```python
from builder import loki_sel
ZEN_BLOCKED = loki_sel('opnsense_source="zenarmor", opnsense_action="block"')
# -> {service_instance_id=~"$opnsense_instance",opnsense_source="zenarmor", opnsense_action="block"}
```

`service_instance_id`, not `opnsense_instance`: a shipped stream's complete label set is
`opnsense_action`, `opnsense_source`, `opnsense_subsystem`, `service_instance_id`,
`service_name`, and `service_instance_id` holds the same value space as Prometheus
`opnsense_instance` (both verified live). Hoist the selector to a module constant so a tab's
panels cannot drift apart. The matcher MUST sit in the stream selector rather than after the
`|`: a `topk` over `count_over_time` ranks whatever the selector admitted, so a late matcher
would still have summed every appliance's records before ranking them.

- `b.logs(title, expr, desc="", w=24, h=10)` — raw log-line viz. `expr` is a LogQL stream
  selector, e.g. `loki_sel('opnsense_source="zenarmor"')`.
- `b.loki_ts(title, series, unit="short", w=12, h=8)` — timeseries from LogQL metric queries.
  `series=[(logql, legend)]`, e.g. `f'sum by (opnsense_subsystem) (rate({SYSLOG_STREAM} [$__auto]))'`.
- `b.loki_stat(title, expr, ...)` — single stat; sets `noValue:"0"` (Loki returns no series,
  not a zero series, so an un-annotated stat reads "No data" when the answer is 0).
- `b.loki_table(title, exprs, field_title, sort_by="Total", ...)` — top-N tables. THE
  cardinality-safe path: range query + 5m interval. `exprs` is a ONE-element list (a second
  query would have its values summed into the first one's rows without saying so, so the
  helper refuses it). Renders exactly three columns: the ranked label titled `field_title`
  (`"Application"`, `"Query"`, `"Host"`, …), `Instance`, and `Total`.
  **You do not name the ranked label** — the helper reads it back out of the query's own
  `loki_grp("app_name")` clause, so the key column cannot drift away from what is actually
  ranked (#471); a query whose group-by leaves none or several labels besides
  `service_instance_id` is refused rather than guessed at.
- `b.loki_sentinel(name, matchers=..., label=...)` — hidden Loki presence variable, scoped
  through `loki_sel()`; gate a row/tab with `present=name`, exactly like `b.sentinel`.
**Self-metric selectors.** Use the ordinary `sel()` for any `opnsense_exporter_*` family
registered through the instance-stamping wrapper (`logship.SelfMetricsRegisterer`) — logs,
annotations, the `/metrics` handler and, since #466, OTLP delivery. There is no separate
`sel_pipeline()` helper: it existed as a pure alias of `sel()` and expressed an intent it did
not implement, so #466 deleted it.

The failure it was meant to prevent is real and is now caught in Go instead: registering a
family **bare** onto the self-metrics registry and then filtering on `opnsense_instance`
anyway gives panels that are structurally empty, because `=~` never matches an absent label.
`main_test.go`'s `TestSelfMetricsRegistryIsNeverRegisteredOnBare` fails on that shape. The one
family that genuinely cannot carry an appliance label is the client library's `go_*`/`process_*`,
which is scoped with `scope="target_join"` and a bare selector.

**LogQL label rule (load-bearing):** ONLY these labels are indexed and may appear inside `{}` —
`opnsense_source`, `opnsense_subsystem`, `opnsense_action`, `service_name`, `service_instance_id`.
Everything else (`device_name`, `server_name`, `ja3`, `dst_nbytes`, `dst_geoip_*`, `app_name`,
`host`, `program`, …) is **structured metadata** — use only after `|` (`| key="value"`,
`| key!=""`, `| unwrap key`). Select exporter-shipped logs on `opnsense_source`, never on
`service_name` (ambiguous on Grafana Cloud).

**Cardinality guard (hard):** never `topk(N, sum by (<structured-metadata-key>) (...))` as an
instant query — it materializes one series per distinct value before `topk` and blows Loki's
~500-series cap. Always use `b.loki_table` (range query + 5m interval).

**Four v2 Loki render traps** (validate clean, render wrong — a `gcx dashboards snapshot`
render-check is MANDATORY, `gcx resources validate` does not catch them): (1) transforms use
`{kind:"Transformation", group:"<id>", spec:{options}}`, not the v1 `{id, options}` shape;
(2) table `sortBy.displayName` is the DISPLAY name (`Total`), never the reducer id or the
raw field name; (3) **never reduce a LogQL metric query with `mode:"seriesToRows"`** — a Loki
metric frame carries its labels on the value FIELD, so the reduce names every row after the
serialised label set and the table ships `{app_name="STUN", service_instance_id="opnsense"}`
as its key column (#471). Split the labels out instead:
`labelsToFields{mode:"columns"}` → `merge` → `groupBy{<label>,service_instance_id: groupby;
Value: sum}` → `organize` to title and order the columns; (4) a stat over a Loki query needs
`noValue:"0"`. `b.loki_table`/`b.loki_stat` bake all four in — use the helpers, don't hand-roll.

## Links and drilldowns (import from uids)

Never write a URL or a dashboard UID at a call site — `uids.py` owns both (#419), and
`tests/test_links.py` fails the build on a link that drops context, targets a reserved or
retired UID, or templates a label the panel does not return.

```python
from uids import focus_device, focus_interface, to_tab

b.field_links(panel, [focus_interface()])          # click a series -> set $interface
b.field_links(panel, [focus_device("interface")])  # pf/device-space label -> set $device
b.panel_links(panel, [to_tab("Firewall verdicts for this selection",
                             "Security", "Firewall & PF")])
b.panel_links(panel, [to_tab("Raw syslog", "Services", "Syslog", loki=True)])
```

Two rules that are easy to get wrong:

* `field_links` is the ONLY place `${__field.labels.x}` resolves — a panel-header link has no
  series context, so `panel_links` raises if you pass one.
* `$interface` (LAN, IOT) and `$device` (igb0, ixl0_vlan25) are disjoint label spaces (#98).
  Pick the helper that matches the metric family the panel queries, or the link navigates to a
  selection matching nothing.

## Value-mapping constants (import from builder)

`UPDOWN` {0:Down/red,1:Up/green} · `RUNSTOP` {0:Stopped,1:Running} · `OKERR` {0:Error,1:OK} ·
`YESNO` {0:No/green,1:Yes/orange} · `ENABLED` {0:Disabled,1:Enabled} ·
`GW_STATUS` {0:Offline,1:Online,2:Unknown,3:Pending,4:Packetloss,5:Latency,6:Offline (forced)}. Build a custom one as a dict
`{"value": ("Text", "color"), ...}` and pass to `mappings=`.

## Sentinels

A sentinel is a hidden presence variable that drives `conditionalRendering`. You declare
WHAT it probes and HOW it is scoped; `b.sentinel` builds the query, so there is no raw
query string to get wrong (#414). This section used to be a table of ~40 hand-written
queries; two of its rows had rotted into prescribing exactly what the build now rejects.

```python
b.sentinel("has_thing", metric="opnsense_thing_service_running")   # the common case
b.sentinel("has_family", name_regex="opnsense_thing_.+")           # "any metric in this family"
b.sentinel("has_thing", metric="opnsense_thing_x", more='kind="a"') # extra matchers
```

Then gate with `present="has_thing"` on `b.tab(...)` / `b.row(...)`, and add optional
leaves to `OPTIONAL_TAB_PRESENCE` in `build_dashboard.py`.

**`scope=` — every sentinel declares one; default `"collector"`.** The instance matcher is
injected accordingly, and `tests/test_sentinel_scoping.py` fails the build if one is missing.

| scope | when | how it is scoped |
|---|---|---|
| `collector` | domain metric (`opnsense_*`, `instance:opnsense_*`) | `opnsense_instance=~"$opnsense_instance"` in the selector |
| `self_labeled` | exporter self-metric that DOES carry `opnsense_instance` — the `opnsense_exporter_logs_*` family, via `logship.SelfMetricsRegisterer` | same matcher; the distinct mode records *why* it is available |
| `target_join` | metric with NO appliance label: `go_*`, `process_*`, and the raw-registry `opnsense_exporter_otlp_*` | `query_result(<metric> * on(job, instance) group_left() max by (job, instance) (opnsense_up{...}))` — the co-scrape identity |
| `global` | deliberately fleet-wide | not scoped; requires `reason=` AND an entry in the guard's `GLOBAL_SENTINEL_ALLOWLIST`. Currently empty — prefer one of the above |

**Two hard rules:**

1. **Test existence, not value — the rule is about the METRIC, not about taste.**

   > Use existence when the series only appears if the feature is **deployed**; use a value
   > test (`nonzero=True`) only when the series is emitted **unconditionally**.

   `label_values(...)` is the default because for a plugin-gated metric the series already
   *is* the presence signal, so a `> 0` on top conflates "absent" with "present but zero" and
   blanks the health panel that answers "is it up?" (#114 — a dedicated gate in
   `build_dashboard.py` fails the build on a count-gated DHCP sentinel). Where the collector
   goes silent when the feature is absent, plain existence is both correct and simpler.

   `nonzero=True` has exactly **one** justified user: `opnsense_carp_vips_total`. CARP status
   is core rather than a plugin, so every readable box emits it — including as a literal `0`
   — which means existence conveys nothing and the value test is the only presence test
   available. Read the comment at that call site before touching it — converting it for
   consistency with its neighbours is exactly what that comment exists to stop.
2. **Names are unique, and a collision RAISES.** It used to be silently deduped, which is
   how `has_netflow` came to be registered twice with two different queries — three rows in
   the module that lost the race were gated on an unrelated collector's metric.

Loki sentinels take the same shape, scoped through `loki_sel()` by construction:

```python
b.loki_sentinel("has_thing_logs", matchers='opnsense_source="thing"', label="opnsense_source")
```

## Generated sentinel contract (#417)

The table below is generated from the live registry, not hand-maintained — the table this
section replaced was a ~40-row manual inventory that had drifted so far it prescribed exactly
the DHCP `leases_total > 0` query the #114 build guard exists to reject. `grafana/sentinel_contract.py`
reads the same `Builder` instance `build_dashboard.build_all()` produces and lists, for every
hidden presence sentinel: its declared scope mode (`collector` / `self_labeled` / `target_join` /
`global`, or the single Loki `stream_selector` mode), whether it presence-tests series
**existence** or a nonzero **value** (the #114/#417 rule above — `has_carp_vips` is the one
justified exception), every tab/row it gates, and its built query.

Regenerate with `make dashboard` — never hand-edit between the markers. The same data is also
written machine-readably to `grafana/sentinel-contract.json`; `make grafana-check` fails the
build if either drifts from the registry (`git diff --exit-code`), and
`tests/test_sentinel_contract.py` catches the same drift without needing a Make run.

<!-- sentinelgen:begin -->
### Prometheus sentinels — 106 total (collector 101 / self_labeled 4 / target_join 1 / global 0)

| Sentinel | Scope | Presence test | Gates (tab/row) | Query |
|---|---|---|---|---|
| `has_acme` | `collector` | existence (series presence) | OPNsense Exporter > System > Certificates > ACME Client | `label_values(opnsense_acme_certificates_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_alias` | `collector` | existence (series presence) | OPNsense Exporter > Security > Aliases; OPNsense Exporter > Security > Aliases > Alias Tables | `label_values(opnsense_alias_tables_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_alias_details` | `collector` | existence (series presence) | OPNsense Exporter > Security > Aliases > Alias pf Counters (details flag) | `label_values(opnsense_alias_table_packets_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_annotations` | `self_labeled` | existence (series presence) | OPNsense Exporter Health > Delivery > Metrics & OTLP > Grafana Annotation Writing | `label_values(opnsense_exporter_annotations_written_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_apcupsd` | `collector` | existence (series presence) | OPNsense Exporter > System > UPS; OPNsense Exporter > System > UPS > APC UPS (apcupsd) | `label_values(opnsense_apcupsd_ups_info{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_bridge` | `collector` | existence (series presence) | OPNsense Exporter > Network > Interfaces > Bridge Membership | `label_values(opnsense_interfaces_bridge_member{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_captiveportal` | `collector` | existence (series presence) | OPNsense Exporter > Network > Captive Portal; OPNsense Exporter > Network > Captive Portal > Captive Portal Overview; OPNsense Exporter > Network > Captive Portal > Per-Zone Sessions | `label_values(opnsense_captiveportal_zones_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_captiveportal_vouchers` | `collector` | existence (series presence) | OPNsense Exporter > Network > Captive Portal > Voucher Expiry; OPNsense Exporter > Network > Captive Portal > Voucher Inventory | `label_values(opnsense_captiveportal_vouchers{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_carp` | `collector` | existence (series presence) | OPNsense Exporter > System > CARP / HA | `label_values(opnsense_carp_allow{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_carp_vips` | `collector` | value (nonzero threshold) | OPNsense Exporter > System > CARP / HA > VIP Status & Advertisement | `query_result(opnsense_carp_vips_total{opnsense_instance=~"$opnsense_instance"} > 0)` |
| `has_chrony` | `collector` | existence (series presence) | OPNsense Exporter > Network > Chrony; OPNsense Exporter > Network > Chrony > Service & Sync; OPNsense Exporter > Network > Chrony > Source Statistics; OPNsense Exporter > Network > Chrony > Sources; OPNsense Exporter > Network > Chrony > Tracking | `label_values(opnsense_chrony_stratum{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_clamav` | `collector` | existence (series presence) | OPNsense Exporter > Security > ClamAV; OPNsense Exporter > Security > ClamAV > Engine & Signatures; OPNsense Exporter > Security > ClamAV > Signature Databases | `label_values(opnsense_clamav_version_info{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_crowdsec` | `collector` | existence (series presence) | OPNsense Exporter > Security > CrowdSec; OPNsense Exporter > Security > CrowdSec > Bouncer Details; OPNsense Exporter > Security > CrowdSec > CrowdSec Overview; OPNsense Exporter > Security > CrowdSec > Machine Details | `label_values(opnsense_crowdsec_service_running{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_crowdsec_hub_items` | `collector` | existence (series presence) | OPNsense Exporter > Security > CrowdSec > Hub Component Health | `label_values(opnsense_crowdsec_hub_items{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_crowdsec_version` | `collector` | existence (series presence) | OPNsense Exporter > Security > CrowdSec > Engine Version | `label_values(opnsense_crowdsec_version_info{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_debug_capture` | `self_labeled` | existence (series presence) | OPNsense Exporter Health > Delivery > Log Shipping > Debug Capture | `label_values(opnsense_exporter_logs_debug_captured_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_dhcpv4_details` | `collector` | existence (series presence) | OPNsense Exporter > Network > DHCP > ISC DHCPv4 Lease Details | `label_values(opnsense_dhcpv4_lease_info{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_dhcpv4_isc` | `collector` | existence (series presence) | OPNsense Exporter > Network > DHCP; OPNsense Exporter > Network > DHCP > ISC DHCPv4 | `label_values(opnsense_dhcpv4_leases_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_dhcpv6_details` | `collector` | existence (series presence) | OPNsense Exporter > Network > DHCP > ISC DHCPv6 Lease Details | `label_values(opnsense_dhcpv6_lease_info{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_dhcpv6_isc` | `collector` | existence (series presence) | OPNsense Exporter > Network > DHCP; OPNsense Exporter > Network > DHCP > ISC DHCPv6 | `label_values(opnsense_dhcpv6_leases_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_dnsmasq` | `collector` | existence (series presence) | OPNsense Exporter > Network > DHCP; OPNsense Exporter > Network > DHCP > Dnsmasq DHCP | `label_values(opnsense_dnsmasq_service_running{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_dnsmasq_details` | `collector` | existence (series presence) | OPNsense Exporter > Network > DHCP > Dnsmasq Lease Details | `label_values(opnsense_dnsmasq_lease_info{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_dyndns` | `collector` | existence (series presence) | OPNsense Exporter > System > Services, Cron & DynDNS > DynDNS | `label_values(opnsense_dyndns_accounts_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_firewall_nat_counts` | `collector` | existence (series presence) | OPNsense Exporter > Security > Firewall & PF > NAT Rule Inventory (details flag) | `label_values(opnsense_firewall_nat_rules{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_firewall_rules` | `collector` | existence (series presence) | OPNsense Exporter > Security > Firewall & PF > Firewall Rules (top 20) | `label_values(opnsense_firewall_rule_rules_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_firmware_details` | `collector` | existence (series presence) | OPNsense Exporter > System > System & Resources > Firmware Packages | `label_values(opnsense_firmware_plugin_installed{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_flow` | `collector` | existence (series presence) | OPNsense Exporter Health > Delivery > Flow Pipeline | `label_values({__name__=~"opnsense_flow_.+",opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_flow_country` | `collector` | existence (series presence) | OPNsense Exporter > Network > Flow Volume > Geography | `label_values(opnsense_flow_bytes_total{opnsense_instance=~"$opnsense_instance",country!=""}, __name__)` |
| `has_flow_geoip` | `collector` | existence (series presence) | OPNsense Exporter Health > Delivery > Flow Pipeline > GeoIP Enrichment | `label_values(opnsense_flow_geoip_lookups_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_flow_netflow` | `collector` | existence (series presence) | OPNsense Exporter Health > Delivery > Flow Pipeline > NetFlow Receiver; OPNsense Exporter Health > Delivery > Flow Pipeline > NetFlow Repairs & Topology | `label_values(opnsense_flow_netflow_datagrams_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_flow_volume` | `collector` | existence (series presence) | OPNsense Exporter > Network > Flow Volume; OPNsense Exporter > Network > Flow Volume > Breakdown; OPNsense Exporter > Network > Flow Volume > Records & Packets; OPNsense Exporter > Network > Flow Volume > Volume | `label_values(opnsense_flow_bytes_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_frr` | `collector` | existence (series presence) | OPNsense Exporter > Network > FRR Routing; OPNsense Exporter > Network > FRR Routing > BFD; OPNsense Exporter > Network > FRR Routing > BGP Peer Session Detail; OPNsense Exporter > Network > FRR Routing > BGP Peers; OPNsense Exporter > Network > FRR Routing > FRR Service & Summary; OPNsense Exporter > Network > FRR Routing > OSPF; OPNsense Exporter > Network > FRR Routing > OSPF Interface Detail; OPNsense Exporter > Network > FRR Routing > OSPFv3 (ospf6) Parity | `label_values(opnsense_frr_service_running{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_frr_routes` | `collector` | existence (series presence) | OPNsense Exporter > Network > FRR Routing > Routing-State Volume (opt-in: --exporter.enable-frr-routes) | `label_values(opnsense_frr_route_count{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_go_runtime` | `target_join` | existence (series presence) | OPNsense Exporter Health > Exporter Runtime > Go Runtime (client metrics) | `query_result(go_goroutines{job=~"opnsense.*"} * on(job, instance) group_left() max by (job, instance) (opnsense_up{opnsense_instance=~"$opnsense_instance"}))` |
| `has_haproxy` | `collector` | existence (series presence) | OPNsense Exporter > Services; OPNsense Exporter > Services > HAProxy; OPNsense Exporter > Services > HAProxy > Backend Traffic; OPNsense Exporter > Services > HAProxy > Frontend Traffic; OPNsense Exporter > Services > HAProxy > HAProxy Overview; OPNsense Exporter > Services > HAProxy > Server Details | `label_values(opnsense_haproxy_frontend_status{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_haproxy_stick_tables` | `collector` | existence (series presence) | OPNsense Exporter > Services > HAProxy > Stick Tables | `label_values(opnsense_haproxy_stick_table_size{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_hardware_dmi` | `collector` | existence (series presence) | OPNsense Exporter > System > System & Resources > Hardware Identity | `label_values(opnsense_hardware_dmi_info{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_hardware_psu` | `collector` | existence (series presence) | OPNsense Exporter > System > System & Resources > Hardware Power Supply | `label_values(opnsense_hardware_psu_status{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_hasync` | `collector` | existence (series presence) | OPNsense Exporter > System > HA Sync; OPNsense Exporter > System > HA Sync > HA Sync Status; OPNsense Exporter > System > HA Sync > Remote Services | `label_values(opnsense_hasync_remote_reachable{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_ids` | `collector` | existence (series presence) | OPNsense Exporter > Security > IDS/IPS; OPNsense Exporter > Security > IDS/IPS > Rulesets; OPNsense Exporter > Security > IDS/IPS > Suricata Overview; OPNsense Exporter > Security > IDS/IPS > eve Log Files | `label_values(opnsense_ids_status{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_ids_alerts` | `collector` | existence (series presence) | OPNsense Exporter > Security > IDS/IPS > Alert Activity | `label_values(opnsense_ids_recent_alerts{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_ipsec` | `collector` | existence (series presence) | OPNsense Exporter > VPN & remote access; OPNsense Exporter > VPN & remote access > VPN; OPNsense Exporter > VPN & remote access > VPN > IPsec Config State | `label_values(opnsense_ipsec_service_running{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_ipsec_pools` | `collector` | existence (series presence) | OPNsense Exporter > VPN & remote access > VPN > IPsec Mode-CFG Pools | `label_values(opnsense_ipsec_pool_size{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_ipsec_sad` | `collector` | existence (series presence) | OPNsense Exporter > VPN & remote access > VPN > IPsec Kernel (SAD/SPD) | `label_values(opnsense_ipsec_sad_entries{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_ipsec_tunnels` | `collector` | existence (series presence) | OPNsense Exporter > VPN & remote access > VPN > IPsec Phase 1; OPNsense Exporter > VPN & remote access > VPN > IPsec Phase 2 | `label_values(opnsense_ipsec_phase1_status{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_kea` | `collector` | existence (series presence) | OPNsense Exporter > Network > DHCP; OPNsense Exporter > Network > DHCP > Kea DHCP | `label_values(opnsense_kea_service_running{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_kea4_details` | `collector` | existence (series presence) | OPNsense Exporter > Network > DHCP > Kea DHCPv4 Lease Details | `label_values(opnsense_kea_dhcp4_lease_info{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_kea6_details` | `collector` | existence (series presence) | OPNsense Exporter > Network > DHCP > Kea DHCPv6 Lease Details | `label_values(opnsense_kea_dhcp6_lease_info{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_kea_pd_pools` | `collector` | existence (series presence) | OPNsense Exporter > Network > DHCP > Kea DHCPv6 Prefix Delegation | `label_values(opnsense_kea_dhcp6_pd_pool_size{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_lagg` | `collector` | existence (series presence) | OPNsense Exporter > Network > Interfaces > LAGG (Link Aggregation) | `label_values(opnsense_interfaces_lagg_info{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_lldp` | `collector` | existence (series presence) | OPNsense Exporter > Network > Routing & Neighbors > LLDP Neighbors | `label_values(opnsense_lldp_neighbors{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_log_events` | `collector` | existence (series presence) | OPNsense Exporter Health > Delivery > Log Shipping > Derived Metric Budget | `label_values({__name__=~"opnsense_log_events_.+",opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_log_events_arp_moves` | `collector` | existence (series presence) | OPNsense Exporter > Network > Routing & Neighbors > ARP Address Moves (log-derived) | `label_values(opnsense_log_events_arp_address_moves_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_log_events_audit` | `collector` | existence (series presence) | OPNsense Exporter > Security > Authentication & Audit; OPNsense Exporter > Security > Authentication & Audit > Config / Audit | `label_values(opnsense_log_events_audit_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_log_events_carp` | `collector` | existence (series presence) | OPNsense Exporter > System > CARP / HA > Transition Events (from syslog) | `label_values(opnsense_log_events_carp_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_log_events_dhcp` | `collector` | existence (series presence) | OPNsense Exporter > Network > DHCP > Lease Events (log-derived) | `label_values(opnsense_log_events_dhcp_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_log_events_dhcp_client` | `collector` | existence (series presence) | OPNsense Exporter > Network > DHCP > WAN DHCP Client (log-derived) | `label_values(opnsense_log_events_dhcp_client_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_log_events_firewall` | `collector` | existence (series presence) | OPNsense Exporter > Security > Firewall & PF > Firewall Events (log-derived) | `label_values(opnsense_log_events_firewall_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_log_events_haproxy` | `collector` | existence (series presence) | OPNsense Exporter > Services > HAProxy > HAProxy Events (log-derived) | `label_values(opnsense_log_events_haproxy_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_log_events_ids` | `collector` | existence (series presence) | OPNsense Exporter > Security > IDS/IPS > IDS Events (log-derived) | `label_values(opnsense_log_events_ids_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_log_events_netmap` | `collector` | existence (series presence) | OPNsense Exporter > Network > Interfaces > Netmap Datapath (log-derived) | `label_values(opnsense_log_events_netmap_ring_full_events_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_log_events_radius` | `collector` | existence (series presence) | OPNsense Exporter > Security > Authentication & Audit; OPNsense Exporter > Security > Authentication & Audit > RADIUS Authentication | `label_values(opnsense_log_events_radius_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_log_events_sshd` | `collector` | existence (series presence) | OPNsense Exporter > Security > Authentication & Audit; OPNsense Exporter > Security > Authentication & Audit > SSH Authentication | `label_values(opnsense_log_events_sshd_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_log_events_upnp` | `collector` | existence (series presence) | OPNsense Exporter > Security > Firewall & PF > UPnP / NAT-PMP Mappings | `label_values(opnsense_log_events_upnp_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_log_events_vpn` | `collector` | existence (series presence) | OPNsense Exporter > VPN & remote access > VPN > Tunnel Lifecycle (log-derived) | `label_values(opnsense_log_events_vpn_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_logs` | `self_labeled` | existence (series presence) | OPNsense Exporter Health > Delivery > Log Shipping; OPNsense Exporter Health > Delivery > Log Shipping > Cursor; OPNsense Exporter Health > Delivery > Log Shipping > Enrichment; OPNsense Exporter Health > Delivery > Log Shipping > Queue & Errors; OPNsense Exporter Health > Delivery > Log Shipping > Receivers; OPNsense Exporter Health > Delivery > Log Shipping > Throughput; OPNsense Exporter Health > Overview > Log Shipping | `label_values(opnsense_exporter_logs_queue_capacity{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_monit` | `collector` | existence (series presence) | OPNsense Exporter > System > Monit; OPNsense Exporter > System > Monit > Check Status Detail; OPNsense Exporter > System > Monit > Filesystem Check Resources; OPNsense Exporter > System > Monit > Host Check Resources; OPNsense Exporter > System > Monit > Monit Overview; OPNsense Exporter > System > Monit > Process Check Resources; OPNsense Exporter > System > Monit > System Check Resources | `label_values(opnsense_monit_status_ok{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_netbird` | `collector` | existence (series presence) | OPNsense Exporter > VPN & remote access; OPNsense Exporter > VPN & remote access > NetBird; OPNsense Exporter > VPN & remote access > NetBird > NetBird Node | `label_values(opnsense_netbird_service_running{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_netbird_peers` | `collector` | existence (series presence) | OPNsense Exporter > VPN & remote access > NetBird > NetBird Peers (details flag) | `label_values(opnsense_netbird_peer_connected{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_netflow` | `collector` | existence (series presence) | OPNsense Exporter > Network > NetFlow | `label_values(opnsense_netflow_active{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_network_diag` | `collector` | existence (series presence) | OPNsense Exporter > Network > Routing & Neighbors > NetISR (Network Interrupt Subsystem); OPNsense Exporter > Network > Routing & Neighbors > NetISR Per-CPU Distribution; OPNsense Exporter > Network > Routing & Neighbors > Sockets & Routes; OPNsense Exporter > Network > Routing & Neighbors > pfsync | `label_values(opnsense_network_diag_sockets_unix_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_nginx` | `collector` | existence (series presence) | OPNsense Exporter > Services; OPNsense Exporter > Services > Nginx; OPNsense Exporter > Services > Nginx > Config Reload & Autoblock; OPNsense Exporter > Services > Nginx > Nginx Overview; OPNsense Exporter > Services > Nginx > Server Zone Cache Status & Latency; OPNsense Exporter > Services > Nginx > Server Zones; OPNsense Exporter > Services > Nginx > Shared Memory; OPNsense Exporter > Services > Nginx > Upstream Servers | `label_values(opnsense_nginx_connections_active{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_nginx_cache` | `collector` | existence (series presence) | OPNsense Exporter > Services > Nginx > Cache Zones | `label_values(opnsense_nginx_cache_zone_max_bytes{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_ntp` | `collector` | existence (series presence) | OPNsense Exporter > Network > NTP | `label_values(opnsense_ntp_peer_info{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_ntp_gps` | `collector` | existence (series presence) | OPNsense Exporter > Network > NTP > GPS (experimental) | `label_values(opnsense_ntp_gps_ok{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_nut` | `collector` | existence (series presence) | OPNsense Exporter > System > UPS; OPNsense Exporter > System > UPS > NUT (Network UPS Tools) | `label_values(opnsense_nut_ups_info{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_openvpn` | `collector` | existence (series presence) | OPNsense Exporter > VPN & remote access; OPNsense Exporter > VPN & remote access > VPN; OPNsense Exporter > VPN & remote access > VPN > OpenVPN | `label_values(opnsense_openvpn_instances{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_otlp` | `self_labeled` | existence (series presence) | OPNsense Exporter Health > Delivery > Metrics & OTLP > OTLP Delivery Health; OPNsense Exporter Health > Overview > OTLP Delivery | `label_values(opnsense_exporter_otlp_enabled{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_qfeeds` | `collector` | existence (series presence) | OPNsense Exporter > Security > Q-Feeds; OPNsense Exporter > Security > Q-Feeds > Q-Feeds Activity; OPNsense Exporter > Security > Q-Feeds > Q-Feeds Overview | `label_values(opnsense_qfeeds_feeds_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_recording_flow` | `collector` | existence (series presence) | OPNsense Exporter Health > Recording rules > Flow Volume | `label_values(instance:opnsense_flow_bytes:rate5m{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_recording_gateway_loss` | `collector` | existence (series presence) | OPNsense Exporter Health > Recording rules > Gateway Health | `label_values(instance:opnsense_gateway_loss:ratio{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_recording_haproxy` | `collector` | existence (series presence) | OPNsense Exporter Health > Recording rules > HAProxy | `label_values(instance:opnsense_haproxy_5xx:ratio5m{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_recording_ids` | `collector` | existence (series presence) | OPNsense Exporter Health > Recording rules > IDS / IPS | `label_values(instance:opnsense_ids_alerts:active{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_recording_ipsec` | `collector` | existence (series presence) | OPNsense Exporter Health > Recording rules > IPsec Health | `label_values(instance:opnsense_ipsec_tunnels_down:count{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_recording_rules` | `collector` | existence (series presence) | OPNsense Exporter Health > Recording rules | `label_values({__name__=~"instance:opnsense_.+",opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_recording_unbound` | `collector` | existence (series presence) | OPNsense Exporter Health > Recording rules > Unbound DNS | `label_values(instance:opnsense_unbound_queries:rate5m{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_recording_wireguard` | `collector` | existence (series presence) | OPNsense Exporter Health > Recording rules > WireGuard Health | `label_values(instance:opnsense_wireguard_peers_down:count{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_recording_zenarmor` | `collector` | existence (series presence) | OPNsense Exporter Health > Recording rules > Zenarmor | `label_values(instance:opnsense_zenarmor_block:ratio5m{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_relayd` | `collector` | existence (series presence) | OPNsense Exporter > Services; OPNsense Exporter > Services > Relayd; OPNsense Exporter > Services > Relayd > Host Health; OPNsense Exporter > Services > Relayd > Relayd Overview; OPNsense Exporter > Services > Relayd > Virtual Server & Table Status | `label_values(opnsense_relayd_virtualserver_status{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_sfp` | `collector` | existence (series presence) | OPNsense Exporter > Network > Interfaces > SFP / Optics (DOM) | `label_values(opnsense_interfaces_sfp_info{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_siproxd` | `collector` | existence (series presence) | OPNsense Exporter > Services; OPNsense Exporter > Services > Siproxd; OPNsense Exporter > Services > Siproxd > Registrations | `label_values(opnsense_siproxd_registrations{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_smart` | `collector` | existence (series presence) | OPNsense Exporter > System > System & Resources > SMART; OPNsense Exporter > System > System & Resources > SMART Attributes & NVMe | `label_values(opnsense_smart_device_health{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_syslog` | `collector` | existence (series presence) | OPNsense Exporter > Services; OPNsense Exporter > Services > Syslog; OPNsense Exporter > Services > Syslog > Syslog-ng Overview; OPNsense Exporter > Services > Syslog > Syslog-ng Throughput | `label_values(opnsense_syslog_service_running{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_tailscale` | `collector` | existence (series presence) | OPNsense Exporter > VPN & remote access; OPNsense Exporter > VPN & remote access > Tailscale; OPNsense Exporter > VPN & remote access > Tailscale > Tailscale Node | `label_values(opnsense_tailscale_service_running{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_tailscale_peers` | `collector` | existence (series presence) | OPNsense Exporter > VPN & remote access > Tailscale > Tailscale Peers (details flag) | `label_values(opnsense_tailscale_peer_session_active{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_temperature` | `collector` | existence (series presence) | OPNsense Exporter > System > System & Resources > Temperature | `label_values(opnsense_temperature_celsius{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_tor` | `collector` | existence (series presence) | OPNsense Exporter > VPN & remote access; OPNsense Exporter > VPN & remote access > Tor; OPNsense Exporter > VPN & remote access > Tor > Circuits; OPNsense Exporter > VPN & remote access > Tor > Hidden Services; OPNsense Exporter > VPN & remote access > Tor > Streams; OPNsense Exporter > VPN & remote access > Tor > Tor Overview | `label_values(opnsense_tor_control_port_up{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_trafficshaper` | `collector` | existence (series presence) | OPNsense Exporter > Network > Traffic Shaper; OPNsense Exporter > Network > Traffic Shaper > Pipes; OPNsense Exporter > Network > Traffic Shaper > Queues; OPNsense Exporter > Network > Traffic Shaper > Rules; OPNsense Exporter > Network > Traffic Shaper > Summary | `label_values(opnsense_trafficshaper_pipes_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_unbound` | `collector` | existence (series presence) | OPNsense Exporter > Network > DNS - Unbound | `label_values(opnsense_unbound_dns_uptime_seconds{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_unbound_infra` | `collector` | existence (series presence) | OPNsense Exporter > Network > DNS - Unbound > Upstream Infra Cache | `label_values(opnsense_unbound_dns_infra_rtt_seconds{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_unbound_qstats` | `collector` | existence (series presence) | OPNsense Exporter > Network > DNS - Unbound > DNSBL / Query Stats | `label_values(opnsense_unbound_dns_qstats_enabled{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_vnstat` | `collector` | existence (series presence) | OPNsense Exporter > Network > Interfaces > Vnstat Traffic Accounting | `label_values(opnsense_vnstat_bytes_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_wireguard` | `collector` | existence (series presence) | OPNsense Exporter > VPN & remote access; OPNsense Exporter > VPN & remote access > VPN | `label_values(opnsense_wireguard_service_running{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_wireguard_ifaces` | `collector` | existence (series presence) | OPNsense Exporter > VPN & remote access > VPN > WireGuard Interfaces | `label_values(opnsense_wireguard_interfaces_status{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_wireguard_peers` | `collector` | existence (series presence) | OPNsense Exporter > VPN & remote access > VPN > WireGuard Peers | `label_values(opnsense_wireguard_peer_status{opnsense_instance=~"$opnsense_instance"}, __name__)` |
| `has_zenarmor_metrics` | `collector` | existence (series presence) | OPNsense Exporter > Security > Zenarmor; OPNsense Exporter > Security > Zenarmor > Overview | `label_values(opnsense_log_events_zenarmor_total{opnsense_instance=~"$opnsense_instance"}, __name__)` |

### Loki sentinels — 2 total (scope: `stream_selector`)

| Sentinel | Scope | Presence test | Gates (tab/row) | Query |
|---|---|---|---|---|
| `has_syslog_logs` | `stream_selector` | existence (series presence) | OPNsense Exporter > Services; OPNsense Exporter > Services > Syslog; OPNsense Exporter > Services > Syslog > Shipped Syslog Logs | `label_values({service_instance_id=~"$opnsense_instance",opnsense_source="syslog"}, opnsense_source)` |
| `has_zenarmor_logs` | `stream_selector` | existence (series presence) | OPNsense Exporter > Security > Zenarmor; OPNsense Exporter > Security > Zenarmor > Applications & Destinations; OPNsense Exporter > Security > Zenarmor > DNS Detail; OPNsense Exporter > Security > Zenarmor > Live Records & Rates; OPNsense Exporter > Security > Zenarmor > Security Detail; OPNsense Exporter > Security > Zenarmor > Web / HTTP Detail | `label_values({service_instance_id=~"$opnsense_instance",opnsense_source="zenarmor"}, opnsense_source)` |
<!-- sentinelgen:end -->

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
