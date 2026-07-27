"""
Grafana v2 dynamic-dashboard builder framework for the OPNsense Exporter.

Emits a `dashboard.grafana.app/v2` manifest (TabsLayout + conditionalRendering).
Tab modules call the helper methods on a `Builder` instance; each helper registers
a panel in the shared `elements` map and returns its element name. Layout packing
is automatic (24-column grid, wrapping at column 24).

This file is the FROZEN API used by every tab module under `tabs/`. See
`grafana/README.md` (Authoring) for the contract. Conventions:

* Every panel query is filtered by the instance selector. Use `b.sel(metric, more)`
  to build `metric{opnsense_instance=~"$opnsense_instance"<more>}`.
* Every LogQL query is filtered by `loki_sel(matchers)`, which builds the stream
  selector `{service_instance_id=~"$opnsense_instance",<matchers>}` (#413).
* Datasources are referenced as `${datasource}` — never a hard-coded UID.
* conditionalRendering lives on TABS and ROWS only (never panels): pass `present=`
  a sentinel-variable name to `b.tab(...)` / `b.row(...)`.
* Sentinels are declared STRUCTURALLY (`b.sentinel(name, metric=..., scope=...)`),
  never as a raw query string, so a presence variable cannot be written fleet-wide
  by accident (#414).
"""

from __future__ import annotations

import re

INSTANCE_LABEL = "opnsense_instance"
INSTANCE_SEL = f'{INSTANCE_LABEL}=~"$opnsense_instance"'
# Loki's equivalent of INSTANCE_SEL. A shipped log stream carries NO
# `opnsense_instance` label — its complete label set is opnsense_action,
# opnsense_source, opnsense_subsystem, service_instance_id, service_name — and
# `service_instance_id` holds the SAME value space as Prometheus
# `opnsense_instance` (both verified live, 2026-07-26). So `$opnsense_instance`
# selects correctly on either side, and multi-select/All stay regex-based.
LOKI_INSTANCE_LABEL = "service_instance_id"
LOKI_INSTANCE_SEL = f'{LOKI_INSTANCE_LABEL}=~"$opnsense_instance"'
RATE = "$__rate_interval"
DS = {"name": "${datasource}"}
LOKI_DS = {"name": "${loki_datasource}"}
VIZ_VERSION = "v11.5.0"
TRANSPORT_LABELS = (
    "job", "service_instance_id", "service_name", "service_version",
)


# ---- sentinel scope modes ------------------------------------------------
# Every presence sentinel declares HOW it is scoped to the selected appliance. A
# sentinel drives conditionalRendering on a tab/row, so an unscoped one asks "does
# ANY box in the fleet export this?" while every panel behind it asks "does the
# SELECTED box?" — the tab lights up because a different firewall runs the plugin
# and every panel inside reads No data (#414).
SCOPE_COLLECTOR = "collector"          # domain metric carrying opnsense_instance
SCOPE_SELF_LABELED = "self_labeled"    # exporter self-metric that carries it too
SCOPE_TARGET_JOIN = "target_join"      # no appliance label; join to opnsense_up
SCOPE_GLOBAL = "global"                # deliberately fleet-wide; needs a reason
SENTINEL_SCOPES = (SCOPE_COLLECTOR, SCOPE_SELF_LABELED, SCOPE_TARGET_JOIN, SCOPE_GLOBAL)

# `go_*` / `process_*` and the raw-registry `opnsense_exporter_otlp_*` family have
# no appliance label at all, but they ARE scraped from the same target as
# opnsense_up, so the co-scrape identity (job, instance) scopes them. `max by
# (job, instance)` makes the right-hand side unique — group_left() errors on
# duplicate match-group entries, and opnsense_up is one series per appliance.
TARGET_JOIN_TEMPLATE = (
    "{left} * on(job, instance) group_left() "
    "max by (job, instance) (opnsense_up{{{instance_sel}}})"
)


def sel(metric: str, more: str = "") -> str:
    """Return metric{opnsense_instance=~"$opnsense_instance"<more>}."""
    inner = INSTANCE_SEL + (("," + more) if more else "")
    return f"{metric}{{{inner}}}"


def grp(*labels: str) -> str:
    """Render a group-by clause that always retains exporter-instance identity.

    `sum by (protocol) (...)` fuses two firewalls' protocol counts into one number
    the moment `$opnsense_instance` selects more than one box, and NOTHING on the
    panel says so: the legend still reads "tcp", the axis still has a unit, and the
    value is simply the sum of two unrelated appliances (#468, from #425's audit).

    So the group-by is built rather than written. `f'sum {grp("protocol")} (...)'`
    yields `sum by (opnsense_instance, protocol) (...)`, and the instance label
    cannot be forgotten because the helper is the only way to write the clause.
    `tests/test_instance_identity.py` fails on any built query whose aggregation
    drops it without an allowlist entry, so the correct form is also the easy one.

    Duplicates are collapsed, so `grp("opnsense_instance", "x")` is safe — a few
    call sites (carp, gateways, netflow) already wrote the label by hand.
    """
    out = [INSTANCE_LABEL]
    for label in labels:
        label = label.strip()
        if label and label not in out:
            out.append(label)
    return "by (" + ", ".join(out) + ")"


# Ranking needs the clause for a DIFFERENT and worse reason than a `sum` does. An
# unqualified `topk(20, ...)` ranks every selected appliance's series in one pool, so
# if one firewall's series dominate, the other firewall's rows are not merged into the
# result — they are ABSENT from it, with nothing on screen suggesting a second box
# exists (#425). Write it as `topk {grp()} (20, <expr>)`; where the ranked expression
# is itself an aggregation, ITS clause needs the label too, because an inner
# `sum by (host)` has already fused the two boxes before `topk` ever runs.


def loki_sel(matchers: str = "") -> str:
    """Return the Loki stream selector {service_instance_id=~"$opnsense_instance"<,matchers>}.

    The ONE LogQL chokepoint, mirroring `sel()` on the Prometheus side (#413).
    Putting the matcher in the STREAM SELECTOR rather than appending a label
    filter is what makes it correct under aggregation: a `topk` over
    `count_over_time` ranks whatever the selector admitted, so a matcher applied
    after the `|` would already have summed every appliance's lines.

    `matchers` may only use Loki's INDEXED labels (opnsense_source,
    opnsense_subsystem, opnsense_action). Everything else on the wire
    (device_name, server_name, ja3, ...) is structured metadata, usable only
    after a `|` filter/unwrap.
    """
    inner = LOKI_INSTANCE_SEL + (("," + matchers) if matchers else "")
    return f"{{{inner}}}"


def loki_grp(*labels: str) -> str:
    """`grp()` for LogQL, whose instance label is `service_instance_id` (#468).

    A shipped log stream carries no `opnsense_instance` label — see LOKI_INSTANCE_SEL
    — so the Prometheus helper would name a label that does not exist and group
    everything into one empty-valued series, which looks correct and is not.

    #413 scoped the stream SELECTORS, so the lines reaching these aggregations are
    already the right lines; the merge this fixes happens after that filter.

    The prefix form (`sum by (...) (expr)`) is live-verified against the deployed
    Loki, including on `topk`, whose reference syntax documents only the postfix
    form: `topk by (service_instance_id) (5, sum by (service_instance_id, ...) (...))`
    returned correctly-labelled per-instance series on 2026-07-27.
    """
    out = [LOKI_INSTANCE_LABEL]
    for label in labels:
        label = label.strip()
        if label and label not in out:
            out.append(label)
    return "by (" + ", ".join(out) + ")"


def epoch_ms(expr: str) -> str:
    """Scale an epoch-*seconds* PromQL expression to milliseconds for Grafana's
    dateTime* value formats, which interpret the raw number as epoch ms. Without
    this an epoch-seconds gauge renders as a ~1970 date (#78). The `* 1000`
    suffix is also what the dateTimeAsIso build guard checks for."""
    return f"({expr}) * 1000"


def stable(expr: str) -> str:
    """Collapse scrape/OTel identities into one logical OPNsense series.

    Grafana Cloud resource labels change when the exporter is redeployed. They
    are useful for transport diagnostics but must not split dashboard series for
    the same ``opnsense_instance``. The scrape ``instance`` remains part of the
    exporter identity; all domain labels are preserved by ``without``.
    """
    return f"max without ({', '.join(TRANSPORT_LABELS)}) ({expr})"


# Shared value-mapping dictionaries: state value -> (display text, colour).
UPDOWN = {"0": ("Down", "red"), "1": ("Up", "green")}
# Interface link state is tri-state: unknown ("2") is reported for carrier-less
# pseudo-devices (PPPoE, tun/tailscale) and is not a fault, so map it distinctly
# from a genuine down rather than folding it into UPDOWN (#86).
LINK_STATE = {"0": ("Down", "red"), "1": ("Up", "green"), "2": ("Unknown", "yellow")}
RUNSTOP = {"0": ("Stopped", "red"), "1": ("Running", "green")}
OKERR = {"0": ("Error", "red"), "1": ("OK", "green")}
YESNO = {"0": ("No", "green"), "1": ("Yes", "orange")}
ENABLED = {"0": ("Disabled", "red"), "1": ("Enabled", "green")}
GW_STATUS = {"0": ("Offline", "red"), "1": ("Online", "green"),
             "2": ("Unknown", "orange"), "3": ("Pending", "yellow"),
             "4": ("Packetloss", "orange"), "5": ("Latency", "yellow"),
             "6": ("Offline (forced)", "red")}


class Builder:
    def __init__(self):
        self.elements: dict = {}
        self.tabs: list = []
        self.variables: list = []
        self.annotations: list = []            # v2 AnnotationQuery envelopes (#421)
        self._sentinels: set = set()          # every claimed sentinel name (both datasources)
        self._sentinel_scopes: dict = {}      # prometheus sentinel name -> declared scope mode
        self._id = 0
        self.size: dict = {}      # element name -> (w, h)
        self._exprs: list = []    # every PromQL string emitted (for coverage)
        self._loki_exprs: list = []  # every LogQL string emitted (kept SEPARATE from
                                      # _exprs — LogQL must never reach the Prometheus
                                      # metric-coverage gate)
        self._ts_violations: list = []  # dateTimeAsIso fields fed unscaled epoch seconds (#78)
        self._table_key_violations: list = []  # dead metric-name/Value renames+units on multi-expr tables (#97)
        self._table_exclude_conflicts: list = []  # a rename/unit key that is also excluded (#112)

    # ---- expression recorders -------------------------------------------
    # Panels record their own queries as a side effect of being built. The
    # annotation layer has no panel, so it records through these instead — which is
    # what puts annotation queries inside the existing coverage, promqlcheck,
    # instance-identity and Loki-scoping gates rather than outside them (#421).
    def record_expr(self, expr: str) -> None:
        """Record a PromQL string that is emitted somewhere other than a panel."""
        self._exprs.append(expr)

    def record_loki_expr(self, expr: str) -> None:
        """Record a LogQL string that is emitted somewhere other than a panel."""
        self._loki_exprs.append(expr)

    # ---- low-level -------------------------------------------------------
    def _next(self) -> tuple[str, int]:
        self._id += 1
        return f"panel-{self._id}", self._id

    def _query(self, expr: str, ref: str = "A", instant: bool = False,
               legend: str | None = None, dedupe: bool = True) -> dict:
        self._exprs.append(expr)
        panel_expr = stable(expr) if dedupe else expr
        spec: dict = {"expr": panel_expr, "refId": ref}
        if legend is not None:
            spec["legendFormat"] = legend
        if instant:
            spec.update({"instant": True, "range": False, "format": "table"})
        else:
            spec.update({"instant": False, "range": True})
        return {
            "kind": "PanelQuery",
            "spec": {
                "refId": ref,
                "hidden": False,
                "datasource": {"type": "prometheus", "uid": "${datasource}"},
                "query": {
                    "kind": "DataQuery", "version": "v0", "group": "prometheus",
                    "datasource": DS, "spec": spec,
                },
            },
        }

    def _loki_query(self, expr: str, ref: str = "A", instant: bool = False,
                     legend: str | None = None) -> dict:
        """Like `_query` but for LogQL against the Loki datasource. Appends to
        `_loki_exprs`, NOT `_exprs` — LogQL must never reach the Prometheus
        metric-coverage gate."""
        self._loki_exprs.append(expr)
        spec: dict = {"expr": expr, "refId": ref}
        if legend is not None:
            spec["legendFormat"] = legend
        if instant:
            spec.update({"queryType": "instant", "instant": True, "range": False})
        else:
            spec.update({"queryType": "range", "instant": False, "range": True})
        return {
            "kind": "PanelQuery",
            "spec": {
                "refId": ref,
                "hidden": False,
                "datasource": {"type": "loki", "uid": "${loki_datasource}"},
                "query": {
                    "kind": "DataQuery", "version": "v0", "group": "loki",
                    "datasource": LOKI_DS, "spec": spec,
                },
            },
        }

    def _panel(self, title, group, viz_spec, queries, desc="",
               transformations=None, interval="30s", max_dp=None) -> str:
        name, pid = self._next()
        qopts = {"interval": interval}
        if max_dp:
            qopts["maxDataPoints"] = max_dp
        self.elements[name] = {
            "kind": "Panel",
            "spec": {
                "id": pid, "title": title, "description": desc, "links": [],
                "data": {"kind": "QueryGroup", "spec": {
                    "queries": queries,
                    "queryOptions": qopts,
                    "transformations": transformations or [],
                }},
                "vizConfig": {"kind": "VizConfig", "group": group,
                              "version": VIZ_VERSION, "spec": viz_spec},
            },
        }
        return name

    @staticmethod
    def _thresholds(steps):
        return {"mode": "absolute", "steps": steps}

    @staticmethod
    def _value_mappings(mapping: dict) -> list:
        """mapping: {"0": ("Down","red"), "1": ("Up","green")}."""
        opts = {}
        for i, (k, (text, color)) in enumerate(mapping.items()):
            opts[k] = {"text": text, "color": color, "index": i}
        return [{"type": "value", "options": opts}]

    # ---- viz helpers (return element name) -------------------------------
    def ts(self, title, series, unit="short", desc="", w=12, h=8,
           stack=False, decimals=None, overrides=None, fill=18,
           min0=True, legend_calcs=("mean", "max", "lastNotNull"),
           dedupe=True) -> str:
        """Timeseries. series = list of (expr, legend)."""
        queries = [self._query(e, ref=chr(65 + i), legend=lg, dedupe=dedupe)
                   for i, (e, lg) in enumerate(series)]
        defaults = {
            "unit": unit,
            "custom": {
                "axisCenteredZero": False, "fillOpacity": fill,
                "gradientMode": "opacity", "lineInterpolation": "smooth",
                "lineWidth": 2, "showPoints": "never",
                "scaleDistribution": {"type": "linear"},
                "stacking": {"mode": "normal" if stack else "none"},
            },
        }
        if decimals is not None:
            defaults["decimals"] = decimals
        if min0:
            defaults["min"] = 0
        spec = {"fieldConfig": {"defaults": defaults, "overrides": overrides or []},
                "options": {
                    "legend": {"calcs": list(legend_calcs), "displayMode": "table",
                               "placement": "bottom"},
                    "tooltip": {"mode": "multi", "sort": "desc"}}}
        n = self._panel(title, "timeseries", spec, queries, desc=desc)
        self.size[n] = (w, h)
        return n

    def stat(self, title, expr, unit="short", desc="", w=4, h=4, decimals=None,
             mappings=None, thresholds=None, color="thresholds",
             color_mode="value", graph="area", text_mode="auto",
             instant=None, legend=None, reducer="lastNotNull", dedupe=True) -> str:
        """Single-value panel with an optional sparkline.

        Query mode follows the visual by default: area graphs receive range data,
        while ``graph="none"`` cards receive one instant value. Callers may still
        override ``instant`` explicitly for exceptional panels.
        """
        defaults = {"unit": unit, "color": {"mode": color}}
        if decimals is not None:
            defaults["decimals"] = decimals
        if thresholds:
            defaults["thresholds"] = self._thresholds(thresholds)
        else:
            defaults["thresholds"] = self._thresholds([{"color": "blue", "value": None}])
        if mappings:
            defaults["mappings"] = self._value_mappings(mappings)
        spec = {"fieldConfig": {"defaults": defaults, "overrides": []},
                "options": {"colorMode": color_mode, "graphMode": graph,
                            "justifyMode": "auto", "orientation": "auto",
                            "reduceOptions": {"calcs": [reducer], "fields": "", "values": False},
                            "textMode": text_mode, "wideLayout": True}}
        if unit == "dateTimeAsIso" and "* 1000" not in expr:
            self._ts_violations.append(f"stat {title!r}")
        query_instant = graph == "none" if instant is None else instant
        q = [self._query(expr, instant=query_instant, legend=legend, dedupe=dedupe)]
        n = self._panel(title, "stat", spec, q, desc=desc)
        self.size[n] = (w, h)
        return n

    def gauge(self, title, expr, unit="short", desc="", w=4, h=6, mn=0, mx=None,
              thresholds=None, decimals=None, instant=True, legend=None,
              dedupe=True) -> str:
        """Radial gauge.

        `thresholds` is neutral by default, for the same reason as `bargauge()`
        (#415, extended here by #467): this helper used to inject a fabricated
        green/yellow(70)/red(90) triple into every caller that omitted
        `thresholds=`, so a gauge on a count, a byte figure or an unbounded rate
        silently acquired a severity boundary nobody chose. Pass an explicit
        `thresholds=` list for a panel that genuinely owns a bounded scale, and
        say at the call site what the boundary means.

        `legend` exists for the same reason `stat()` has one: a gauge grouped by
        `opnsense_instance` (#468) renders one dial per box, and without a legend
        template the dials are unlabelled.
        """
        defaults = {"unit": unit, "color": {"mode": "thresholds"},
                    "min": mn,
                    "thresholds": self._thresholds(
                        thresholds or [{"color": "blue", "value": None}])}
        if mx is not None:
            defaults["max"] = mx
        if decimals is not None:
            defaults["decimals"] = decimals
        spec = {"fieldConfig": {"defaults": defaults, "overrides": []},
                "options": {"orientation": "auto", "showThresholdLabels": False,
                            "showThresholdMarkers": True,
                            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}}}
        n = self._panel(title, "gauge", spec,
                        [self._query(expr, instant=instant, legend=legend,
                                     dedupe=dedupe)], desc=desc)
        self.size[n] = (w, h)
        return n

    def bargauge(self, title, series, unit="short", desc="", w=8, h=8,
                 mode="gradient", orient="horizontal", thresholds=None,
                 instant=True, mx=None, dedupe=True) -> str:
        """Per-series bar gauge.

        `thresholds` is neutral by default (#415): most bar gauges are counts,
        bytes, rates, versions, or categorical values with no severity boundary,
        so an omitted `thresholds=` renders as a single, un-colored step rather
        than inheriting a fabricated 0-100-style 70/90 boundary. Pass an explicit
        `thresholds=` list only for a panel that genuinely owns a normalized
        percentage/ratio scale with a defensible boundary (e.g. a percent
        utilization gauge with `mx=100`), and document why at the call site.
        """
        queries = [self._query(e, ref=chr(65 + i), instant=instant, legend=lg,
                               dedupe=dedupe)
                   for i, (e, lg) in enumerate(series)]
        defaults = {"unit": unit, "color": {"mode": "thresholds"},
                    "thresholds": self._thresholds(
                        thresholds or [{"color": "blue", "value": None}])}
        if mx is not None:
            defaults["max"] = mx
        spec = {"fieldConfig": {"defaults": defaults, "overrides": []},
                "options": {"reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                            "orientation": orient, "displayMode": mode, "showUnfilled": True}}
        n = self._panel(title, "bargauge", spec, queries, desc=desc)
        self.size[n] = (w, h)
        return n

    def table(self, title, exprs, desc="", w=24, h=10, excludes=None,
              renames=None, unit_overrides=None, sort_by=None, sort_desc=True,
              footer=False, dedupe=True) -> str:
        """exprs = list of PromQL strings (instant). excludes/renames operate on field names.
        unit_overrides = {field_name: unit}. sort_by = field name."""
        queries = [self._query(e, ref=chr(65 + i), instant=True, dedupe=dedupe)
                   for i, e in enumerate(exprs)]
        excl = {"Time": True, "__name__": True}
        for x in (excludes or []):
            excl[x] = True
        org = {"kind": "Transformation", "group": "organize", "spec": {"options": {
            "excludeByName": excl, "renameByName": renames or {}, "indexByName": {}}}}
        transformations = [{"kind": "Transformation", "group": "merge", "spec": {"options": {}}}, org]
        overrides = []
        for field, unit in (unit_overrides or {}).items():
            overrides.append({"matcher": {"id": "byName", "options": field},
                              "properties": [{"id": "unit", "value": unit}]})
            # A dateTimeAsIso column must be fed epoch *milliseconds* (#78). Resolve
            # the display field back to its query expr and require the *1000 scaling.
            if unit == "dateTimeAsIso":
                orig = next((o for o, disp in (renames or {}).items() if disp == field), field)
                idx = 0 if orig == "Value" else (
                    ord(orig.split("#", 1)[1].strip()) - ord("A") if orig.startswith("Value #") else None)
                if idx is None or not (0 <= idx < len(exprs)) or "* 1000" not in exprs[idx]:
                    self._ts_violations.append(f"table {title!r} column {field!r}")
        # Regression guard (#112): a field listed in `excludes` is dropped from the table, so a
        # renameByName/unit_override keyed on that same field is dead — the classic exclude "Value"
        # + unit_override "Value" contradiction that silently hid the lease-expiry column.
        excluded = set(excludes or [])
        for key in list((renames or {}).keys()) + list((unit_overrides or {}).keys()):
            if key in excluded:
                self._table_exclude_conflicts.append(f"table {title!r} key {key!r} is both excluded and renamed/unit-overridden")
        # Regression guard (#97): with multiple exprs the merge transform names the value
        # columns "Value #A".."Value #N" — keying renames/unit_overrides on a metric name (or on
        # bare "Value", or an out-of-range "Value #X") silently matches nothing, leaving unlabeled,
        # unit-less columns. Flag such dead keys so the build fails instead of shipping them.
        if len(exprs) > 1:
            referenced = set()
            for e in exprs:
                referenced.update(re.findall(r"opnsense_[a-z0-9_]+", e))
            referenced.discard("opnsense_instance")  # a real label, legitimately renamable
            valid_value_cols = {f"Value #{chr(65 + i)}" for i in range(len(exprs))}
            for key in list((renames or {}).keys()) + list((unit_overrides or {}).keys()):
                if key in referenced or key == "Value" or (
                        key.startswith("Value #") and key not in valid_value_cols):
                    self._table_key_violations.append(f"table {title!r} key {key!r}")
        opts = {"showHeader": True, "cellHeight": "sm",
                "footer": {"show": footer, "reducer": ["sum"], "countRows": False, "fields": ""}}
        if sort_by:
            opts["sortBy"] = [{"displayName": sort_by, "desc": sort_desc}]
        spec = {"fieldConfig": {"defaults": {"custom": {
                    "align": "auto", "cellOptions": {"type": "auto"},
                    "inspect": False, "filterable": True}}, "overrides": overrides},
                "options": opts}
        n = self._panel(title, "table", spec, queries, desc=desc, transformations=transformations)
        self.size[n] = (w, h)
        return n

    def statetimeline(self, title, series, mappings, unit="short", desc="",
                      w=24, h=8, thresholds=None, dedupe=True) -> str:
        """series = list of (expr, legend). mappings = {"0":("Down","red"),...}."""
        queries = [self._query(e, ref=chr(65 + i), legend=lg, dedupe=dedupe)
                   for i, (e, lg) in enumerate(series)]
        defaults = {"unit": unit, "color": {"mode": "thresholds"},
                    "mappings": self._value_mappings(mappings),
                    "thresholds": self._thresholds(
                        thresholds or [{"color": "red", "value": None}, {"color": "green", "value": 1}])}
        spec = {"fieldConfig": {"defaults": defaults, "overrides": []},
                "options": {"showValue": "never", "alignValue": "left", "rowHeight": 0.9,
                            "fillOpacity": 80, "mergeValues": True,
                            "legend": {"displayMode": "list", "placement": "bottom"},
                            "tooltip": {"mode": "single", "sort": "none"}}}
        n = self._panel(title, "state-timeline", spec, queries, desc=desc,
                        interval="1m", max_dp=300)
        self.size[n] = (w, h)
        return n

    def statushistory(self, title, series, mappings, desc="", w=24, h=6,
                      thresholds=None, dedupe=True) -> str:
        queries = [self._query(e, ref=chr(65 + i), legend=lg, dedupe=dedupe)
                   for i, (e, lg) in enumerate(series)]
        defaults = {"color": {"mode": "thresholds"},
                    "mappings": self._value_mappings(mappings),
                    "thresholds": self._thresholds(
                        thresholds or [{"color": "red", "value": None}, {"color": "green", "value": 1}])}
        spec = {"fieldConfig": {"defaults": defaults, "overrides": []},
                "options": {"showValue": "never", "colWidth": 0.9, "rowHeight": 0.9,
                            "legend": {"displayMode": "list", "placement": "bottom"}}}
        n = self._panel(title, "status-history", spec, queries, desc=desc,
                        interval="1m", max_dp=200)
        self.size[n] = (w, h)
        return n

    def piechart(self, title, series, unit="short", desc="", w=8, h=8,
                 pie="donut", dedupe=True) -> str:
        queries = [self._query(e, ref=chr(65 + i), instant=True, legend=lg,
                               dedupe=dedupe)
                   for i, (e, lg) in enumerate(series)]
        spec = {"fieldConfig": {"defaults": {"unit": unit}, "overrides": []},
                "options": {"legend": {"displayMode": "table", "placement": "right",
                                       "values": ["value", "percent"]},
                            "pieType": pie,
                            "reduceOptions": {"calcs": ["lastNotNull"], "values": False},
                            "tooltip": {"mode": "single", "sort": "desc"}}}
        n = self._panel(title, "piechart", spec, queries, desc=desc)
        self.size[n] = (w, h)
        return n

    # ---- Loki viz helpers (return element name) --------------------------
    def logs(self, title, expr, desc="", w=24, h=10) -> str:
        """Raw log lines panel. One LogQL range query."""
        q = [self._loki_query(expr)]
        spec = {"fieldConfig": {"defaults": {"color": {"mode": "palette-classic"}}, "overrides": []},
                "options": {"dedupStrategy": "none", "showTime": True, "sortOrder": "Descending",
                            "wrapLogMessage": False, "prettifyLogMessage": False,
                            "enableLogDetails": True, "showControls": False,
                            "showLabels": False, "enableInfiniteScrolling": True}}
        n = self._panel(title, "logs", spec, q, desc=desc)
        self.size[n] = (w, h)
        return n

    def loki_ts(self, title, series, unit="short", desc="", w=12, h=8, stack=False,
                legend_calcs=("mean", "max", "lastNotNull")) -> str:
        """LogQL timeseries. series = list of (logql, legend). Reuses the `ts()` viz
        spec exactly, built with `_loki_query` (range) instead of `_query`."""
        queries = [self._loki_query(e, ref=chr(65 + i), legend=lg)
                   for i, (e, lg) in enumerate(series)]
        defaults = {
            "unit": unit,
            "min": 0,
            "custom": {
                "axisCenteredZero": False, "fillOpacity": 18,
                "gradientMode": "opacity", "lineInterpolation": "smooth",
                "lineWidth": 2, "showPoints": "never",
                "scaleDistribution": {"type": "linear"},
                "stacking": {"mode": "normal" if stack else "none"},
            },
        }
        spec = {"fieldConfig": {"defaults": defaults, "overrides": []},
                "options": {
                    "legend": {"calcs": list(legend_calcs), "displayMode": "table",
                               "placement": "bottom"},
                    "tooltip": {"mode": "multi", "sort": "desc"}}}
        n = self._panel(title, "timeseries", spec, queries, desc=desc)
        self.size[n] = (w, h)
        return n

    def loki_stat(self, title, expr, unit="short", desc="", w=4, h=4,
                  thresholds=None, color_mode="value") -> str:
        """LogQL single stat. Reuses the `stat()` viz spec, but CRITICALLY sets
        fieldConfig.defaults.noValue = "0" — Loki returns no series (not a zero
        series) when nothing matched, so an un-annotated stat shows "No data"
        when the true answer is 0."""
        defaults = {"unit": unit, "color": {"mode": "thresholds"}, "noValue": "0"}
        if thresholds:
            defaults["thresholds"] = self._thresholds(thresholds)
        else:
            defaults["thresholds"] = self._thresholds([{"color": "blue", "value": None}])
        spec = {"fieldConfig": {"defaults": defaults, "overrides": []},
                "options": {"colorMode": color_mode, "graphMode": "area",
                            "justifyMode": "auto", "orientation": "auto",
                            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
                            "textMode": "auto", "wideLayout": True}}
        q = [self._loki_query(expr)]
        n = self._panel(title, "stat", spec, q, desc=desc)
        self.size[n] = (w, h)
        return n

    def loki_table(self, title, exprs, desc="", w=24, h=10, sort_by="Total",
                   sort_desc=True) -> str:
        """exprs = list of LogQL strings, queried as RANGE queries and reduced
        (sum, seriesToRows) into table rows — the standard "topk over range"
        shape for high-cardinality log fields. `queryOptions.interval="5m"` is a
        cardinality guard on wide time ranges."""
        queries = [self._loki_query(e, ref=chr(65 + i), instant=False)
                   for i, e in enumerate(exprs)]
        transformations = [{"kind": "Transformation", "group": "reduce", "spec": {"options": {
            "reducers": ["sum"], "mode": "seriesToRows"}}}]
        opts = {"showHeader": True, "cellHeight": "sm",
                "footer": {"show": False, "reducer": ["sum"], "countRows": False, "fields": ""},
                "sortBy": [{"displayName": sort_by, "desc": sort_desc}]}
        spec = {"fieldConfig": {"defaults": {
                    "color": {"mode": "palette-classic"},
                    "custom": {"align": "auto", "cellOptions": {"type": "auto"},
                               "inspect": False, "filterable": True}},
                    "overrides": []},
                "options": opts}
        n = self._panel(title, "table", spec, queries, desc=desc,
                        transformations=transformations, interval="5m")
        self.size[n] = (w, h)
        return n

    def text(self, title, content, w=24, h=4) -> str:
        name, pid = self._next()
        self.elements[name] = {"kind": "Panel", "spec": {
            "id": pid, "title": title, "description": "", "links": [],
            "data": {"kind": "QueryGroup", "spec": {"queries": [], "queryOptions": {}, "transformations": []}},
            "vizConfig": {"kind": "VizConfig", "group": "text", "version": VIZ_VERSION,
                          "spec": {"fieldConfig": {"defaults": {}, "overrides": []},
                                   "options": {"mode": "markdown", "content": content}}}}}
        self.size[name] = (w, h)
        return name

    # ---- variables / sentinels ------------------------------------------
    def _claim_sentinel_name(self, name: str):
        """Reserve a sentinel name, or raise if it is already taken.

        This used to `return` silently, which made a duplicate registration a
        no-op: `has_netflow` was declared twice with two DIFFERENT queries and
        whichever tab module imported first won, so three rows in the loser were
        silently gated on somebody else's metric (#414). A presence variable is a
        navigation element — the collision has to be loud.
        """
        if name in self._sentinels:
            raise ValueError(
                f"sentinel {name!r} is already registered; two presence variables "
                "cannot share a name (give the second one its own)")
        self._sentinels.add(name)

    @staticmethod
    def _sentinel_query(name: str, metric: str, name_regex: str, scope: str,
                        more: str, nonzero: bool, reason: str) -> str:
        """Build a sentinel's PromQL from its declared scope. See SENTINEL_SCOPES."""
        if scope not in SENTINEL_SCOPES:
            raise ValueError(
                f"sentinel {name!r}: unknown scope {scope!r} "
                f"(pick one of {', '.join(SENTINEL_SCOPES)})")
        if bool(metric) == bool(name_regex):
            raise ValueError(
                f"sentinel {name!r}: pass exactly one of metric= or name_regex=")
        if scope == SCOPE_GLOBAL and not reason:
            raise ValueError(
                f"sentinel {name!r}: scope={SCOPE_GLOBAL!r} must state reason=... "
                "(a fleet-wide presence variable lights a tab up for the wrong box)")
        if scope == SCOPE_TARGET_JOIN:
            if name_regex:
                raise ValueError(
                    f"sentinel {name!r}: scope={SCOPE_TARGET_JOIN!r} needs a concrete "
                    "metric= — a join has no series to attach to a __name__ regex")
            if nonzero:
                raise ValueError(
                    f"sentinel {name!r}: scope={SCOPE_TARGET_JOIN!r} is already a "
                    "query_result join; nonzero= would compare the join's product")
            # query_result(), not label_values(): Grafana's label_values() takes a
            # selector, which cannot hold a vector match.
            left = f"{metric}{{{more}}}" if more else metric
            joined = TARGET_JOIN_TEMPLATE.format(left=left, instance_sel=INSTANCE_SEL)
            return f"query_result({joined})"

        scoped = scope in (SCOPE_COLLECTOR, SCOPE_SELF_LABELED)
        if name_regex:
            parts = [f'__name__=~"{name_regex}"']
            if scoped:
                parts.append(INSTANCE_SEL)
            if more:
                parts.append(more)
            selector = f"{{{','.join(parts)}}}"
        else:
            parts = ([INSTANCE_SEL] if scoped else []) + ([more] if more else [])
            selector = f"{metric}{{{','.join(parts)}}}" if parts else metric
        if nonzero:
            return f"query_result({selector} > 0)"
        return f"label_values({selector}, __name__)"

    def sentinel(self, name: str, *, metric: str = "", name_regex: str = "",
                 scope: str = SCOPE_COLLECTOR, more: str = "",
                 nonzero: bool = False, reason: str = ""):
        """Register a hidden Prometheus presence variable, scoped by construction.

        Structured rather than raw-query on purpose (#414): the instance matcher is
        injected here, so no call site can forget it and no reviewer has to check 96
        hand-written strings. Pass exactly one of:

          metric=      a concrete metric name.
          name_regex=  a `__name__=~` family probe, for "any metric in this family".

        and optionally:

          scope=       one of SENTINEL_SCOPES; defaults to `collector`.
          more=        extra label matchers, inside the same selector.
          nonzero=     emit `query_result(<selector> > 0)` instead of
                       `label_values(...)`. Presence should test SERIES EXISTENCE,
                       not value (#114 hid a live-but-idle DHCP backend that way),
                       so this is only for metrics a collector emits as a literal 0
                       when the feature is present but empty.
          reason=      mandatory justification for scope='global'.
        """
        query = self._sentinel_query(name, metric, name_regex, scope, more,
                                     nonzero, reason)
        self._claim_sentinel_name(name)
        self._sentinel_scopes[name] = scope
        self.variables.append({"kind": "QueryVariable", "spec": {
            "name": name, "label": name, "hide": "hideVariable",
            "query": {"kind": "DataQuery", "version": "v0", "group": "prometheus",
                      "datasource": DS, "spec": {"query": query, "refId": name}},
            "current": {"text": "", "value": ""}, "options": [], "multi": False,
            "includeAll": False, "allowCustomValue": False,
            "refresh": "onDashboardLoad", "regex": "", "skipUrlSync": True,
            "sort": "disabled"}})

    def loki_sentinel(self, name: str, *, label: str, matchers: str = ""):
        """Register a hidden Loki presence variable, scoped through `loki_sel()`.

        Mirrors `sentinel()` but against the Loki datasource, and the query spec
        shape matches a Grafana-authored Loki QueryVariable (a bare
        `__legacyStringValue` string, e.g. `label_values(...)`), not the prometheus
        `{"query": ..., "refId": ...}` shape.

        There is one scope mode on this side, so it is applied rather than declared:
        the stream selector always comes from `loki_sel()` (#413).
        """
        query = f"label_values({loki_sel(matchers)}, {label})"
        self._claim_sentinel_name(name)
        self.variables.append({"kind": "QueryVariable", "spec": {
            "name": name, "label": name, "hide": "hideVariable",
            "query": {"kind": "DataQuery", "version": "v0", "group": "loki",
                      "datasource": LOKI_DS, "spec": {"__legacyStringValue": query}},
            "current": {"text": "", "value": ""}, "options": [], "multi": False,
            "includeAll": False, "allowCustomValue": False,
            "refresh": "onDashboardLoad", "regex": "", "skipUrlSync": True,
            "sort": "disabled"}})

    @staticmethod
    def sel_pipeline(metric: str, more: str = "") -> str:
        """Return a log-pipeline selector scoped to the stable instance identity."""
        return sel(metric, more)

    # ---- layout ----------------------------------------------------------
    def _place(self, names: list) -> dict:
        items, x, y, rowh = [], 0, 0, 0
        for nm in names:
            w, h = self.size[nm]
            if x + w > 24:
                x = 0
                y += rowh
                rowh = 0
            items.append({"kind": "GridLayoutItem", "spec": {
                "x": x, "y": y, "width": w, "height": h,
                "element": {"kind": "ElementReference", "name": nm}}})
            x += w
            rowh = max(rowh, h)
        return {"kind": "GridLayout", "spec": {"items": items}}

    @staticmethod
    def _cond(present=None, absent=None):
        items = []
        present_vars = ([present] if isinstance(present, str) else list(present or []))
        absent_vars = ([absent] if isinstance(absent, str) else list(absent or []))
        if len(present_vars) > 1 and absent_vars:
            raise ValueError("OR presence conditions cannot be combined with absence conditions")
        for variable in present_vars:
            items.append({"kind": "ConditionalRenderingVariable",
                          "spec": {"variable": variable, "operator": "matches", "value": ".+"}})
        for variable in absent_vars:
            items.append({"kind": "ConditionalRenderingVariable",
                          "spec": {"variable": variable, "operator": "notMatches", "value": ".+"}})
        if not items:
            return None
        return {"kind": "ConditionalRenderingGroup",
                "spec": {"visibility": "show",
                         "condition": "or" if len(present_vars) > 1 else "and",
                         "items": items}}

    def row(self, title, names, present=None, absent=None, collapse=False) -> dict:
        spec = {"title": title, "collapse": collapse, "layout": self._place(names)}
        c = self._cond(present, absent)
        if c:
            spec["conditionalRendering"] = c
        return {"kind": "RowsLayoutRow", "spec": spec}

    def tab(self, title, rows, present=None, absent=None):
        """rows: list of row-dicts (from b.row) OR a flat list of panel names
        (auto-wrapped in a single header-less row)."""
        if rows and isinstance(rows[0], str):
            rows = [self.row("", rows)]
            rows[0]["spec"]["hideHeader"] = True
        spec = {"title": title, "layout": {"kind": "RowsLayout", "spec": {"rows": rows}}}
        c = self._cond(present, absent)
        if c:
            spec["conditionalRendering"] = c
        self.tabs.append({"kind": "TabsLayoutTab", "spec": spec})

    def tab_group(self, title, tabs, present=None, absent=None):
        """Append a top-level tab whose content is a nested tab layout.

        ``tabs`` are complete ``TabsLayoutTab`` dictionaries previously built
        through :meth:`tab`; their own conditional rendering is retained.
        """
        spec = {"title": title,
                "layout": {"kind": "TabsLayout", "spec": {"tabs": tabs}}}
        c = self._cond(present, absent)
        if c:
            spec["conditionalRendering"] = c
        self.tabs.append({"kind": "TabsLayoutTab", "spec": spec})

    # ---- manifest --------------------------------------------------------
    def manifest(self, title, description, tags, name="opnsense-exporter") -> dict:
        return {
            "apiVersion": "dashboard.grafana.app/v2",
            "kind": "Dashboard",
            "metadata": {"name": name, "annotations": {}},
            "spec": {
                "title": title, "description": description, "tags": tags,
                "cursorSync": "Crosshair", "editable": True, "liveNow": False,
                "preload": False,
                "timeSettings": {"from": "now-6h", "to": "now", "autoRefresh": "1m",
                                 "autoRefreshIntervals": ["30s", "1m", "5m", "15m", "30m", "1h"],
                                 "timezone": "browser", "fiscalYearStartMonth": 0,
                                 "hideTimepicker": False},
                "links": [], "annotations": self.annotations,
                "variables": self.variables,
                "elements": self.elements,
                "layout": {"kind": "TabsLayout", "spec": {"tabs": self.tabs}},
            },
        }
