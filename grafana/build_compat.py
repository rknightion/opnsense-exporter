#!/usr/bin/env python3
"""Generate the Grafana 11/12 compatibility dashboard (#420, from the #22 report).

The canonical artifact is `dashboard.json`: `dashboard.grafana.app/v2`, Grafana 13+.
Grafana 11 and 12 cannot read that schema at all — 12.4 rejects it outright — so an
operator who cannot upgrade has no supported route. This produces one:
`dashboard-compat.json`, classic schema v1, importable through
`POST /api/dashboards/db` on pinned Grafana 11.5.0 and 12.4.0.

## It is CONVERTED, never authored

Every panel, query, unit, threshold and variable here comes from the v2 artifact the
tab modules already produce. There is no second panel source to keep in step — the
#420 acceptance bar is explicit that 700+ panels must not be copied into a
hand-edited file. Run `make compat`; `make grafana-check` fails if the output is
stale, exactly like `dashboard.json` itself.

## What degrades, and why it is a DROP rather than a downgrade

Classic schema has no TabsLayout and no conditionalRendering. Those are not cosmetic
on this dashboard: 31 of the 41 leaf tabs and 154 of the rows are gated on a feature
sentinel, so that a box without the CrowdSec plugin never sees a CrowdSec tab. Copied
into classic, every one of those becomes permanently visible and permanently empty —
a worse artifact than none, because "No data" on a plugin you do not run is
indistinguishable from a broken exporter.

So the compat dashboard carries exactly the UNCONDITIONAL panels: the tabs and rows
that render on every OPNsense box regardless of installed plugins. Tabs become
classic rows, in the same order, with the domain prefixed into the row title since
classic has no nesting. Anything gated is omitted, and `docs/` says so in as many
words rather than leaving an operator to discover a missing tab.
"""

from __future__ import annotations

import json
import os
import sys


HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.join(HERE, "dashboard.json")
OUT = os.path.join(HERE, "dashboard-compat.json")

# Pinned in the artifact and asserted by CI against these exact container tags.
SUPPORTED_VERSIONS = ("11.5.0", "12.4.0")

# Classic schemaVersion. 39 is Grafana 11.x's, and 12.4 migrates it forward on
# import without complaint; claiming a higher number would make 11.5 run migrations
# it does not have.
SCHEMA_VERSION = 39

COMPAT_UID = "opnsense-exporter-compat"

# v2 vizConfig.group -> classic panel type. Identical strings today, but stated
# rather than assumed: a v2 group rename would otherwise silently emit a panel type
# Grafana 11 has never heard of, and an unknown type renders as an error card.
PANEL_TYPES = {
    "timeseries": "timeseries",
    "stat": "stat",
    "gauge": "gauge",
    "bargauge": "bargauge",
    "table": "table",
    "piechart": "piechart",
    "state-timeline": "state-timeline",
    "status-history": "status-history",
    "logs": "logs",
    "text": "text",
}

# v2 transformation group -> classic transformation id.
TRANSFORM_IDS = {
    "merge": "merge",
    "organize": "organize",
    "reduce": "reduce",
}

# v2 refresh enums -> classic integer codes.
REFRESH = {"never": 0, "onDashboardLoad": 1, "onTimeRangeChanged": 2}
# v2 sort enums -> classic integer codes.
SORT = {"disabled": 0, "alphabeticalAsc": 1, "alphabeticalDesc": 2,
        "numericalAsc": 3, "numericalDesc": 4}
# v2 hide enums -> classic integer codes (0 = show, 1 = label only, 2 = hidden).
HIDE = {"dontHide": 0, "hideLabel": 1, "hideVariable": 2}


def datasource_ref(spec: dict) -> dict:
    """Classic panels take {type, uid}; the v2 query carries the same two facts in
    two places. Keep `${datasource}` as the uid so the picker still drives it."""
    outer = spec.get("datasource") or {}
    return {"type": outer.get("type", "prometheus"),
            "uid": outer.get("uid", "${datasource}")}


def convert_target(query: dict) -> dict:
    spec = query["spec"]
    inner = spec["query"]["spec"]
    target = {
        "refId": inner.get("refId", spec.get("refId", "A")),
        "expr": inner["expr"],
        "datasource": datasource_ref(spec),
        "instant": bool(inner.get("instant")),
        "range": bool(inner.get("range")),
    }
    for key in ("legendFormat", "format", "queryType"):
        if inner.get(key):
            target[key] = inner[key]
    if spec.get("hidden"):
        target["hide"] = True
    return target


def convert_panel(element: dict, panel_id: int, grid: dict) -> dict:
    spec = element["spec"]
    viz = spec["vizConfig"]
    group = viz["group"]
    if group not in PANEL_TYPES:
        raise SystemExit(f"unmapped viz group {group!r} on panel {spec['title']!r} — "
                         f"add it to PANEL_TYPES in build_compat.py")
    data = spec["data"]["spec"]
    panel = {
        "id": panel_id,
        "type": PANEL_TYPES[group],
        "title": spec["title"],
        "gridPos": grid,
        "datasource": {"type": "prometheus", "uid": "${datasource}"},
        "targets": [convert_target(q) for q in data["queries"]],
        "fieldConfig": viz["spec"].get("fieldConfig", {"defaults": {}, "overrides": []}),
        "options": viz["spec"].get("options", {}),
    }
    if spec.get("description"):
        panel["description"] = spec["description"]
    # A Loki panel's datasource comes from the other picker; take it from the first
    # target rather than assuming Prometheus, or the panel queries the wrong store.
    if panel["targets"]:
        panel["datasource"] = panel["targets"][0]["datasource"]
    options = data.get("queryOptions") or {}
    if options.get("interval"):
        panel["interval"] = options["interval"]
    if options.get("maxDataPoints"):
        panel["maxDataPoints"] = options["maxDataPoints"]
    transformations = []
    for transform in data.get("transformations", []):
        group_id = transform["group"]
        if group_id not in TRANSFORM_IDS:
            raise SystemExit(f"unmapped transformation {group_id!r} — add it to "
                             f"TRANSFORM_IDS in build_compat.py")
        transformations.append({"id": TRANSFORM_IDS[group_id],
                                "options": transform["spec"].get("options", {})})
    if transformations:
        panel["transformations"] = transformations
    return panel


def convert_variable(variable: dict) -> dict | None:
    spec = variable["spec"]
    kind = variable["kind"]
    common = {
        "name": spec["name"],
        "label": spec.get("label"),
        "hide": HIDE.get(spec.get("hide", "dontHide"), 0),
        "skipUrlSync": bool(spec.get("skipUrlSync")),
        "current": spec.get("current", {}),
        "options": [],
    }
    if kind == "DatasourceVariable":
        return {**common, "type": "datasource", "query": spec["pluginId"],
                "regex": spec.get("regex", ""), "multi": bool(spec.get("multi")),
                "includeAll": bool(spec.get("includeAll")),
                "refresh": REFRESH.get(spec.get("refresh", "never"), 1)}
    if kind == "QueryVariable":
        query = spec["query"]["spec"]
        # Classic takes the query as an object for Prometheus/Loki. The string form
        # also parses, but 12.x's schema validation is stricter about the object,
        # which is what #22 reported hitting from the other direction.
        return {**common, "type": "query",
                "datasource": {"type": spec["query"]["group"],
                               "uid": spec["query"]["datasource"]["name"]},
                "definition": query.get("query", ""),
                "query": {"qryType": 1, "query": query.get("query", ""),
                          "refId": query.get("refId", spec["name"])},
                "refresh": REFRESH.get(spec.get("refresh", "onDashboardLoad"), 1),
                "sort": SORT.get(spec.get("sort", "disabled"), 0),
                "regex": spec.get("regex", ""),
                "multi": bool(spec.get("multi")),
                "includeAll": bool(spec.get("includeAll")),
                "allValue": spec.get("allValue") or None}
    # An interval/constant/custom variable would need its own mapping. Refuse rather
    # than silently dropping it: a missing variable leaves every panel that
    # interpolates it querying a literal "$name".
    raise SystemExit(f"unmapped variable kind {kind!r} ({spec['name']}) — add it to "
                     f"convert_variable() in build_compat.py")


def leaf_tabs(tabs, path=()):
    """(domain-qualified title, rows) for every UNCONDITIONAL leaf tab, in order."""
    for tab in tabs:
        spec = tab["spec"]
        if "conditionalRendering" in spec:
            continue
        layout = spec["layout"]
        if layout["kind"] == "TabsLayout":
            yield from leaf_tabs(layout["spec"]["tabs"], path + (spec["title"],))
            continue
        rows = [row for row in layout["spec"]["rows"]
                if "conditionalRendering" not in row["spec"]]
        if rows:
            yield " / ".join(path + (spec["title"],)), rows


def build(source: dict) -> dict:
    spec = source["spec"]
    elements = spec["elements"]
    panels: list[dict] = []
    panel_id = 1
    y = 0
    sections = 0
    for title, rows in leaf_tabs(spec["layout"]["spec"]["tabs"]):
        sections += 1
        first_row = True
        for row in rows:
            row_spec = row["spec"]
            # Classic row header. The tab name goes on the FIRST row of each tab, so
            # a reader can still see which tab a row came from once nesting is gone.
            heading = f"{title} — {row_spec['title']}" if first_row else row_spec["title"]
            first_row = False
            panels.append({"id": panel_id, "type": "row", "title": heading,
                           "collapsed": False, "panels": [],
                           "gridPos": {"h": 1, "w": 24, "x": 0, "y": y}})
            panel_id += 1
            y += 1
            max_h = 0
            for item in row_spec["layout"]["spec"]["items"]:
                item_spec = item["spec"]
                name = item_spec["element"]["name"]
                grid = {"h": item_spec["height"], "w": item_spec["width"],
                        "x": item_spec["x"], "y": y + item_spec["y"]}
                panels.append(convert_panel(elements[name], panel_id, grid))
                panel_id += 1
                max_h = max(max_h, item_spec["y"] + item_spec["height"])
            y += max_h

    time_settings = spec["timeSettings"]
    return {
        "uid": COMPAT_UID,
        "title": f"{spec['title']} (Grafana 11/12 compatibility)",
        "description": (
            f"{spec['description']} — COMPATIBILITY BUILD, generated from the "
            f"canonical Grafana 13 schema-v2 dashboard for Grafana "
            f"{' and '.join(SUPPORTED_VERSIONS)}. Carries only the panels that are "
            f"unconditional on every OPNsense box: classic schema has no "
            f"conditional rendering, so a plugin-gated tab would show permanently "
            f"empty panels here. Use grafana/dashboard.json on Grafana 13+."
        ),
        "tags": list(spec["tags"]) + ["compat"],
        "editable": bool(spec.get("editable", True)),
        "graphTooltip": 1 if spec.get("cursorSync") == "Crosshair" else 0,
        "schemaVersion": SCHEMA_VERSION,
        "version": 1,
        "refresh": time_settings.get("autoRefresh", ""),
        "time": {"from": time_settings["from"], "to": time_settings["to"]},
        "timezone": time_settings.get("timezone", "browser"),
        "fiscalYearStartMonth": time_settings.get("fiscalYearStartMonth", 0),
        "timepicker": {"refresh_intervals": list(time_settings.get("autoRefreshIntervals", []))},
        "annotations": {"list": []},
        "links": [],
        "templating": {"list": [v for v in (convert_variable(x) for x in spec["variables"])
                                if v is not None]},
        "panels": panels,
        # Not a Grafana field — a provenance marker so a reader of the file, or a
        # support thread, can tell instantly what produced it and what it is for.
        "__opnsenseExporterCompat": {
            "generatedFrom": "grafana/dashboard.json",
            "generator": "grafana/build_compat.py",
            "supportedGrafanaVersions": list(SUPPORTED_VERSIONS),
            "canonicalArtifact": "grafana/dashboard.json (Grafana 13+, schema v2)",
            "sections": sections,
            "degradation": [
                "no tabs: each tab's rows are flattened in order, tab name on the first row",
                "no conditional rendering: plugin-gated tabs and rows are OMITTED, not shown empty",
            ],
        },
    }


def main() -> int:
    check = "--check" in sys.argv
    with open(SRC) as handle:
        source = json.load(handle)
    built = json.dumps(build(source), indent=2) + "\n"
    if check:
        with open(OUT) as handle:
            if handle.read() != built:
                print(f"{OUT} is stale — run `make compat`", file=sys.stderr)
                return 1
        print(f"compat: {OUT} current", file=sys.stderr)
        return 0
    with open(OUT, "w") as handle:
        handle.write(built)
    dashboard = json.loads(built)
    rows = sum(1 for p in dashboard["panels"] if p["type"] == "row")
    print(f"wrote {OUT}", file=sys.stderr)
    print(f"compat: {len(dashboard['panels']) - rows} panels in {rows} rows across "
          f"{dashboard['__opnsenseExporterCompat']['sections']} sections, "
          f"{len(dashboard['templating']['list'])} variables, "
          f"schemaVersion {SCHEMA_VERSION}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
