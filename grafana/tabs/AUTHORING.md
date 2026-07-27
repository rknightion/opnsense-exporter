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
- `b.stat(title, expr, unit="short", w=4, h=4, mappings=None, thresholds=None, color_mode="value", graph="area", decimals=None, instant=True, desc="")`
  — current-value stat by default. Set `instant=False` only when a range reduction or sparkline is
  deliberate. `mappings=UPDOWN` etc. `thresholds=[{"color":"green","value":None},{"color":"red","value":90}]`.
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
- `b.loki_table(title, exprs, sort_by="Total", ...)` — top-N tables. THE cardinality-safe
  path: range query + reduce(sum, seriesToRows) + 5m interval. Column display name is `Total`.
- `b.loki_sentinel(name, matchers=..., label=...)` — hidden Loki presence variable, scoped
  through `loki_sel()`; gate a row/tab with `present=name`, exactly like `b.sentinel`.
- `b.sel_pipeline(metric, more="")` — a pure **alias of `sel()`**, kept for the log-pipeline
  panels. **It is NOT a bare selector**, despite its name and a long-standing comment in
  `build_dashboard.py` that claimed otherwise: it injects `opnsense_instance` exactly like
  `sel()`. Correct for the `opnsense_exporter_logs_*` (internal/logship) family, which DOES
  carry that label via `SelfMetricsRegisterer` — but **wrong for anything on the raw
  self-metrics registry**, which is why the four `opnsense_exporter_otlp_*` delivery panels
  are currently always empty (**tracked in #466** — do not fix in passing). For a self-metric
  with no appliance label, scope the *sentinel* with `scope="target_join"` and give the panel
  a genuinely bare selector.

**LogQL label rule (load-bearing):** ONLY these labels are indexed and may appear inside `{}` —
`opnsense_source`, `opnsense_subsystem`, `opnsense_action`, `service_name`, `service_instance_id`.
Everything else (`device_name`, `server_name`, `ja3`, `dst_nbytes`, `dst_geoip_*`, `app_name`,
`host`, `program`, …) is **structured metadata** — use only after `|` (`| key="value"`,
`| key!=""`, `| unwrap key`). Select exporter-shipped logs on `opnsense_source`, never on
`service_name` (ambiguous on Grafana Cloud).

**Cardinality guard (hard):** never `topk(N, sum by (<structured-metadata-key>) (...))` as an
instant query — it materializes one series per distinct value before `topk` and blows Loki's
~500-series cap. Always use `b.loki_table` (range + reduce + 5m interval).

**Four v2 Loki render traps** (validate clean, render wrong — a `gcx dashboards snapshot`
render-check is MANDATORY, `gcx resources validate` does not catch them): (1) transforms use
`{kind:"Transformation", group:"reduce", spec:{options}}`, not the v1 `{id, options}` shape;
(2) table `sortBy.displayName` is the DISPLAY name (`Total` for a reduced sum), never the
reducer id; (3) `reduce` needs `mode:"seriesToRows"`; (4) a stat over a Loki query needs
`noValue:"0"`. `b.loki_table`/`b.loki_stat` bake all four in — use the helpers, don't hand-roll.

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
