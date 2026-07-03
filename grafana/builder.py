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
* Datasources are referenced as `${datasource}` — never a hard-coded UID.
* conditionalRendering lives on TABS and ROWS only (never panels): pass `present=`
  a sentinel-variable name to `b.tab(...)` / `b.row(...)`.
"""

from __future__ import annotations

import re

INSTANCE_SEL = 'opnsense_instance=~"$opnsense_instance"'
RATE = "$__rate_interval"
DS = {"name": "${datasource}"}
VIZ_VERSION = "v11.5.0"


def sel(metric: str, more: str = "") -> str:
    """Return metric{opnsense_instance=~"$opnsense_instance"<more>}."""
    inner = INSTANCE_SEL + (("," + more) if more else "")
    return f"{metric}{{{inner}}}"


def epoch_ms(expr: str) -> str:
    """Scale an epoch-*seconds* PromQL expression to milliseconds for Grafana's
    dateTime* value formats, which interpret the raw number as epoch ms. Without
    this an epoch-seconds gauge renders as a ~1970 date (#78). The `* 1000`
    suffix is also what the dateTimeAsIso build guard checks for."""
    return f"({expr}) * 1000"


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
        self._sentinels: set = set()
        self._id = 0
        self.size: dict = {}      # element name -> (w, h)
        self._exprs: list = []    # every PromQL string emitted (for coverage)
        self._ts_violations: list = []  # dateTimeAsIso fields fed unscaled epoch seconds (#78)
        self._table_key_violations: list = []  # dead metric-name/Value renames+units on multi-expr tables (#97)

    # ---- low-level -------------------------------------------------------
    def _next(self) -> tuple[str, int]:
        self._id += 1
        return f"panel-{self._id}", self._id

    def _query(self, expr: str, ref: str = "A", instant: bool = False,
               legend: str | None = None) -> dict:
        self._exprs.append(expr)
        spec: dict = {"expr": expr, "refId": ref}
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
           min0=True, legend_calcs=("mean", "max", "lastNotNull")) -> str:
        """Timeseries. series = list of (expr, legend)."""
        queries = [self._query(e, ref=chr(65 + i), legend=lg)
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
             instant=False, legend=None, reducer="lastNotNull") -> str:
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
        q = [self._query(expr, instant=instant, legend=legend)]
        n = self._panel(title, "stat", spec, q, desc=desc)
        self.size[n] = (w, h)
        return n

    def gauge(self, title, expr, unit="short", desc="", w=4, h=6, mn=0, mx=None,
              thresholds=None, decimals=None, instant=False) -> str:
        defaults = {"unit": unit, "color": {"mode": "thresholds"},
                    "min": mn,
                    "thresholds": self._thresholds(
                        thresholds or [{"color": "green", "value": None},
                                       {"color": "yellow", "value": 70},
                                       {"color": "red", "value": 90}])}
        if mx is not None:
            defaults["max"] = mx
        if decimals is not None:
            defaults["decimals"] = decimals
        spec = {"fieldConfig": {"defaults": defaults, "overrides": []},
                "options": {"orientation": "auto", "showThresholdLabels": False,
                            "showThresholdMarkers": True,
                            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False}}}
        n = self._panel(title, "gauge", spec, [self._query(expr, instant=instant)], desc=desc)
        self.size[n] = (w, h)
        return n

    def bargauge(self, title, series, unit="short", desc="", w=8, h=8,
                 mode="gradient", orient="horizontal", thresholds=None,
                 instant=True, mx=None) -> str:
        queries = [self._query(e, ref=chr(65 + i), instant=instant, legend=lg)
                   for i, (e, lg) in enumerate(series)]
        defaults = {"unit": unit, "color": {"mode": "thresholds"},
                    "thresholds": self._thresholds(
                        thresholds or [{"color": "green", "value": None},
                                       {"color": "yellow", "value": 70},
                                       {"color": "red", "value": 90}])}
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
              footer=False) -> str:
        """exprs = list of PromQL strings (instant). excludes/renames operate on field names.
        unit_overrides = {field_name: unit}. sort_by = field name."""
        queries = [self._query(e, ref=chr(65 + i), instant=True)
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
                      w=24, h=8, thresholds=None) -> str:
        """series = list of (expr, legend). mappings = {"0":("Down","red"),...}."""
        queries = [self._query(e, ref=chr(65 + i), legend=lg)
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
                      thresholds=None) -> str:
        queries = [self._query(e, ref=chr(65 + i), legend=lg)
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
                 pie="donut") -> str:
        queries = [self._query(e, ref=chr(65 + i), instant=True, legend=lg)
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
    def sentinel(self, name: str, query: str):
        """Hidden presence variable: label_values(...) or query_result(...)."""
        if name in self._sentinels:
            return
        self._sentinels.add(name)
        self.variables.append({"kind": "QueryVariable", "spec": {
            "name": name, "label": name, "hide": "hideVariable",
            "query": {"kind": "DataQuery", "version": "v0", "group": "prometheus",
                      "datasource": DS, "spec": {"query": query, "refId": name}},
            "current": {"text": "", "value": ""}, "options": [], "multi": False,
            "includeAll": False, "allowCustomValue": False,
            "refresh": "onDashboardLoad", "regex": "", "skipUrlSync": True,
            "sort": "disabled"}})

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
        if present:
            items.append({"kind": "ConditionalRenderingVariable",
                          "spec": {"variable": present, "operator": "matches", "value": ".+"}})
        if absent:
            items.append({"kind": "ConditionalRenderingVariable",
                          "spec": {"variable": absent, "operator": "notMatches", "value": ".+"}})
        if not items:
            return None
        return {"kind": "ConditionalRenderingGroup",
                "spec": {"visibility": "show", "condition": "and", "items": items}}

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
                "links": [], "annotations": [], "variables": self.variables,
                "elements": self.elements,
                "layout": {"kind": "TabsLayout", "spec": {"tabs": self.tabs}},
            },
        }
