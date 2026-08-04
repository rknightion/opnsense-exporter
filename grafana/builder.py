"""
Grafana v2 dynamic-dashboard builder framework for the opnsense2otel.

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

import json
import re


def _references_variable(blob: str, name: str) -> bool:
    """Does `blob` interpolate the Grafana variable `name`?

    Both spellings, and the word boundary matters in both: `$has_dhcp` must not
    match a reference to `$has_dhcpv6_isc`, or a variable gets pinned to the union
    of two unrelated tabs and quietly hoisted to the dashboard.
    """
    return re.search(r"\$\{" + re.escape(name) + r"[:}]", blob) is not None or \
        re.search(r"\$" + re.escape(name) + r"(?![0-9A-Za-z_])", blob) is not None


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

# Sentinel: "let `_panel` derive the min step from the queries" — distinct from an
# explicit `interval=None`, which means "emit no min step at all".
_DERIVE_INTERVAL = object()

# The min step for a Loki RANGE panel, and the one place a panel still pins one.
#
# Prometheus panels deliberately pin NOTHING (#650): the exporter exports every
# `--otlp.export-interval` (60s by default) whatever poll tier a collector is on, and
# the Prometheus datasource already declares that same 60s as its scrape interval, so
# `$__interval` and `$__rate_interval` derive correctly with no help from us. A panel
# `interval` does not ask for data more often — it OVERRIDES the datasource's figure,
# and every panel here overrode 60s down to 30s, which is how 737 panels ended up
# computing `$__rate_interval` from a scrape interval that was half the real one.
#
# Loki gets a floor because there is nothing to inherit: the logs datasource declares
# no interval, so an unpinned Loki range query takes its step from panel width alone
# and a narrow time range collapses `[$__auto]` to a couple of seconds. Log arrival is
# continuous rather than tied to the exporter's export tick, so this is a rendering
# floor, not a statement about data rate — which is exactly why it does not follow the
# Prometheus rule.
LOKI_MIN_STEP = "30s"
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
# Inverse polarity: for metrics where 1 is the *fault* ("..._down"), not the healthy
# state. Using UPDOWN on one of those paints a healthy box solid red and a real
# outage green (#511).
DOWNUP = {"0": ("Up", "green"), "1": ("Down", "red")}
# A configuration flag, not a health flag: "not monitored" is a deliberate setting,
# so it must not borrow UPDOWN's red (#511).
MONITORED = {"0": ("Unmonitored", "text"), "1": ("Monitored", "green")}
# A connection to a remote service, as distinct from a local daemon (RUNSTOP) (#514).
CONNDISC = {"0": ("Disconnected", "red"), "1": ("Connected", "green")}
# Capability flags where 1 means "supported". YESNO is the "is this a problem?"
# polarity (1 = orange) and must not be reused for these (#511).
YESNO_GOOD = {"0": ("No", "red"), "1": ("Yes", "green")}
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
        self.links: list = []                  # dashboard-level DashboardLinks (#419)
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

    @staticmethod
    def _min_step(queries) -> str | None:
        """The panel's `queryOptions.interval`, derived from its own queries (#650).

        Derived rather than passed so the rule cannot be forgotten at a call site and
        a new helper inherits it: the answer depends only on which datasource the
        panel reads and whether it reads it as a range, both of which are already in
        `queries`. See `LOKI_MIN_STEP` for why the two datasources differ.

        Instant queries are excluded on purpose — an instant query has no step, so a
        min step on one is inert config that reads as intent to the next author.
        """
        groups = {q["spec"]["query"].get("group") for q in queries}
        ranged = any(q["spec"]["query"]["spec"].get("range") for q in queries)
        if groups == {"loki"} and ranged:
            return LOKI_MIN_STEP
        return None

    def _panel(self, title, group, viz_spec, queries, desc="",
               transformations=None, interval=_DERIVE_INTERVAL, max_dp=None,
               time_from=None) -> str:
        name, pid = self._next()
        if interval is _DERIVE_INTERVAL:
            interval = self._min_step(queries)
        qopts = {} if interval is None else {"interval": interval}
        if max_dp:
            qopts["maxDataPoints"] = max_dp
        if time_from:
            qopts["timeFrom"] = time_from
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
        """Normalise threshold steps to the shape Grafana's v2 schema accepts.

        Accepts {"value": ..., "color": ...} or the shorthand 2-tuple (value, color).

        Same failure as Builder._overrides, in a second field and found the same way:
        one call site used the shorthand, JSON has no tuple, and Grafana rejected the
        whole dashboard with

            cannot unmarshal array into Go struct field
            ...fieldConfig.defaults.thresholds.steps of type v2.DashboardThreshold

        This one only surfaced AFTER the overrides fix landed, because GitSync reports
        the first validation failure it hits and stops. Assume neither is the last of
        its kind: grafana/tests/test_field_overrides.py has a generic sweep that fails
        on a raw list anywhere under vizConfig, which catches the shape rather than the
        field name.
        """
        out = []
        for step in steps or []:
            if isinstance(step, dict):
                if "color" not in step:
                    raise ValueError(f"threshold step needs a 'color': {step!r}")
                out.append(step)
                continue
            if isinstance(step, (tuple, list)) and len(step) == 2:
                value, color = step
                out.append({"value": value, "color": color})
                continue
            raise ValueError(
                "threshold step must be {'value':...,'color':...} or a 2-tuple "
                f"(value, color); got {step!r}")
        return {"mode": "absolute", "steps": out}

    @staticmethod
    def _overrides(overrides) -> list:
        """Normalise fieldConfig.overrides to the shape Grafana's v2 schema accepts.

        Accepts either the full form — {"matcher": {...}, "properties": [...]} — or the
        shorthand 3-tuple (regex, property_id, value), which expands to a byRegexp
        matcher setting one property.

        This exists because the shorthand was ALREADY in use at one call site and was
        being emitted verbatim. `overrides or []` passed a list of tuples straight into
        dashboard-health.json, and JSON has no tuple, so it serialised as a list of
        lists. Grafana's GitSync then refused the whole dashboard:

            Dashboard in version "v2" cannot be handled as a Dashboard: json: cannot
            unmarshal array into Go struct field
            DashboardSpec.spec.elements.spec.vizConfig.spec.fieldConfig.overrides
            of type v2.DashboardV2FieldConfigSourceOverrides

        Nothing surfaced that. The repository status sat at CompletedWithWarnings, the
        sync workflow reported success because it only checks the push to the GitSync
        repo, and the live dashboard silently froze 12 panels behind for two days (#616).

        Anything that is neither shape raises, so a bad override fails the build here
        rather than at a stack that reports it in a place no one reads.
        """
        out = []
        for ov in overrides or []:
            if isinstance(ov, dict):
                if "matcher" not in ov or "properties" not in ov:
                    raise ValueError(
                        f"override dict needs both 'matcher' and 'properties': {ov!r}")
                out.append(ov)
                continue
            if isinstance(ov, (tuple, list)) and len(ov) == 3:
                regex, prop_id, value = ov
                out.append({"matcher": {"id": "byRegexp", "options": regex},
                            "properties": [{"id": prop_id, "value": value}]})
                continue
            raise ValueError(
                "override must be {'matcher':...,'properties':[...]} or a 3-tuple "
                f"(regex, property_id, value); got {ov!r}")
        return out

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
        spec = {"fieldConfig": {"defaults": defaults,
                                "overrides": self._overrides(overrides)},
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

        `mx` is MANDATORY on a percent/percentunit gauge (#649). Without a max the
        radial arc auto-scales to whatever the data happens to be, so a drive at 4%
        spare and one at 96% can paint identical arcs and the threshold markers land
        at meaningless positions on the dial — the exact opposite of what a gauge is
        for. This is not the #467 case in reverse: a max on a bounded unit is the
        unit's own domain, not a fabricated severity boundary, and omitting it is
        always a defect. Passing something other than 100 is fine and sometimes right
        (the two SMART wear gauges use 120 so a drive past its rated endurance is
        legible rather than pinned) — the requirement is only that the call site
        chooses.
        """
        if unit in ("percent", "percentunit") and mx is None:
            raise ValueError(
                f"gauge({title!r}): unit={unit!r} needs an explicit mx= — a percentage "
                f"gauge with an auto-scaling arc renders its thresholds meaningless "
                f"(#649). Pass mx=100 (or mx=1 for percentunit), or a documented "
                f"higher ceiling where overshoot is expected.")
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
        # Every sel() expr carries an opnsense_instance filter, so the label reaches the
        # table as a column. Half the tables used to rename it and half shipped the raw
        # Prometheus label name as a header (54 vs 58 at the time of #514) — neither was a
        # convention, just drift. Rename it here so no call site has to remember.
        renames = dict(renames or {})
        if ("opnsense_instance" not in renames and not excl.get("opnsense_instance")
                and any("opnsense_instance" in e for e in exprs)):
            renames["opnsense_instance"] = "Instance"
        org = {"kind": "Transformation", "group": "organize", "spec": {"options": {
            "excludeByName": excl, "renameByName": renames, "indexByName": {}}}}
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
            for key in list(renames.keys()) + list((unit_overrides or {}).keys()):
                if key in referenced or key == "Value" or (
                        key.startswith("Value #") and key not in valid_value_cols):
                    self._table_key_violations.append(f"table {title!r} key {key!r}")
        else:
            # Mirror image of the #97 guard, and the hole it left (#509). With a SINGLE expr
            # the merge transform names the value column bare "Value" — the "Value #A"
            # spelling is the *Loki* table convention (LOKI_TABLE_VALUE_FIELD) and on a
            # Prometheus table can only ever match nothing. panel-146 excluded "Value" and
            # renamed "Value #A", so it rendered a table with no value column at all: valid
            # manifest, passing tests, passing coverage gate, nothing on screen.
            for key in list(renames.keys()) + list((unit_overrides or {}).keys()):
                if key.startswith("Value #"):
                    self._table_key_violations.append(
                        f"table {title!r} key {key!r} (single-expr table: the value column is bare \"Value\")")
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
                      w=24, h=8, thresholds=None, dedupe=True,
                      series_mappings=None, color_mode=None) -> str:
        """series = list of (expr, legend). mappings = {"0":("Down","red"),...}.

        series_mappings = {legend: mapping} overrides the panel-wide mapping for one
        row. Needed whenever a panel stacks flags of opposite polarity — a UPS panel
        plots `online` (1 = good) beside `on_battery` (1 = bad), and a single mapping
        has to paint one of them the wrong colour (#511).
        """
        queries = [self._query(e, ref=chr(65 + i), legend=lg, dedupe=dedupe)
                   for i, (e, lg) in enumerate(series)]
        # A census timeline (a count per state) has no two states to paint, so threshold
        # colouring gives it one bit per row. A continuous palette makes the band shade
        # track the count, which is the only thing such a panel has to say (#510).
        defaults = {"unit": unit, "color": {"mode": color_mode or "thresholds"},
                    # An empty dict used to emit a bare {"type":"value","options":{}} into
                    # the shipped JSON — dead config that reads as intent (#510).
                    "mappings": self._value_mappings(mappings) if mappings else [],
                    "thresholds": self._thresholds(
                        thresholds or [{"color": "red", "value": None}, {"color": "green", "value": 1}])}
        if not mappings and thresholds is None and color_mode is None:
            # The default [red@base, green@1] is a two-state DOWN/UP mapping, which is
            # right for a binary metric and wrong for anything else. panel-323 plots a TCP
            # connection-state census with no mapping at all, so every state that happened
            # to be at zero painted solid red and a healthy firewall rendered two-thirds
            # alarm-coloured (#510). An unmapped timeline must say what its colours mean.
            self._table_key_violations.append(
                f"statetimeline {title!r} has no value mappings, so the default red@0/green@1 "
                "would colour it as an up/down flag — pass explicit thresholds")
        legends = {lg for _, lg in series}
        overrides = []
        for legend, mapping in (series_mappings or {}).items():
            if legend not in legends:
                self._table_key_violations.append(
                    f"statetimeline {title!r} series_mappings key {legend!r} matches no series legend")
            overrides.append({"matcher": {"id": "byName", "options": legend},
                              "properties": [{"id": "mappings",
                                              "value": self._value_mappings(mapping)}]})
        spec = {"fieldConfig": {"defaults": defaults, "overrides": overrides},
                "options": {"showValue": "never", "alignValue": "left", "rowHeight": 0.9,
                            "fillOpacity": 80, "mergeValues": True,
                            "legend": {"displayMode": "list", "placement": "bottom"},
                            "tooltip": {"mode": "single", "sort": "none"}}}
        # `max_dp` stays, the `interval="1m"` pin does not (#650): it was exactly the
        # Prometheus datasource's own 60s scrape interval, so pinning it changed
        # nothing except making the panel stop tracking the datasource. The bucket
        # cap is the real guard here — a state timeline is unreadable long before it
        # is slow.
        n = self._panel(title, "state-timeline", spec, queries, desc=desc, max_dp=300)
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
        n = self._panel(title, "status-history", spec, queries, desc=desc, max_dp=200)
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

    # The field `merge` produces for a one-query Loki table: the datasource names
    # the value field "Value" and merge appends the refId, which loki_table pins to
    # "A" by refusing more than one expression.
    LOKI_TABLE_VALUE_FIELD = "Value #A"

    # The column name every Loki table gives the appliance-identity label, matching
    # the project's convention on the Prometheus tables (Build Info, NTP peers).
    LOKI_TABLE_INSTANCE_COLUMN = "Instance"
    # The column name for the ranked value. `sort_by` defaults to it.
    LOKI_TABLE_VALUE_COLUMN = "Total"

    @staticmethod
    def _ranked_loki_label(expr: str, title: str) -> str:
        """The label a `loki_table()` query ranks by, read out of the query itself.

        DERIVED rather than passed in on purpose (#471). The call site already
        names the label once, inside `loki_grp("app_name")`; taking it a second
        time as an argument lets the column key drift away from what is actually
        ranked, and a mislabelled key column is exactly the class of bug this
        helper is being fixed for. Reading it back from the built expression makes
        that drift impossible.

        Every clause is unioned, so the outer `topk by (service_instance_id)` and
        the inner `sum by (service_instance_id, app_name)` both contribute; the
        instance label is then dropped because it gets its own column. Anything
        other than exactly one remaining label is refused — a two-label ranking
        has no single key column, and picking one silently would mislabel rows.
        """
        labels = set()
        for match in re.finditer(r"\bby\s*\(([^)]*)\)", expr):
            labels.update(x.strip() for x in match.group(1).split(",") if x.strip())
        labels.discard(LOKI_INSTANCE_LABEL)
        if len(labels) != 1:
            raise ValueError(
                f"loki_table {title!r}: expected exactly one ranked label besides "
                f"{LOKI_INSTANCE_LABEL}, found {sorted(labels) or 'none'} — a table "
                "keyed on none or several has no single key column; build the "
                "group-by with loki_grp(\"<label>\")")
        return labels.pop()

    def loki_table(self, title, exprs, field_title, desc="", w=24, h=10,
                   sort_by="Total", sort_desc=True, time_from=None,
                   value_unit=None) -> str:
        """exprs = a one-element list holding the LogQL string, evaluated as an
        INSTANT query over `[$__range]` — the standard "topk over range" shape for
        high-cardinality log fields. `field_title` titles the ranked-label column
        ("Application", "DNS Query", ...).

        These panels carried `queryOptions.interval="5m"`, described here as a
        cardinality guard on wide time ranges. It was inert (#650): #471 converted
        them from range queries to instant ones, and an instant query has no step for
        a min interval to raise. The window has been `[$__range]` ever since — which
        `test_no_loki_table_uses_the_step_derived_auto_interval` is what pins — so the
        guard the comment described was already doing the work. Removed rather than
        left as config that reads as a live control.

        The transform chain, and why it is not the obvious one (#471):

        A LogQL metric query returns one frame per output series, and the series'
        labels sit on the value FIELD, not in the rows. `reduce{seriesToRows}` —
        what this helper used to do — therefore names each row after the frame's
        display name, which for such a frame is the serialised label set. Every
        table shipped `{app_name="STUN", service_instance_id="opnsense"}` as its
        key column: correct data, unreadable, and with the instance repeated
        inside every key rather than standing as a column of its own.

        So instead:

        1. `labelsToFields` (mode: columns) turns each frame's labels into real
           string fields and merges the frames into one table.
        2. `merge` is belt-and-braces: labelsToFields documents an internal merge,
           and this is a no-op on the single frame that leaves it. Without a merge
           a per-frame `groupBy` would emit 20 one-row frames.
        3. `organize` titles the three columns, fixes their order, and drops Time.

        There is deliberately NO aggregation step (#479). An earlier version ran
        `groupBy` here to re-sum the value, which a RANGE query needed because it
        returns many points per series. An instant query returns exactly one, so
        the aggregation is redundant — and it actively broke the table: `groupBy`
        looks its target field up by display name, and the Loki datasource stamps
        `displayNameFromDS` with the serialised label set, so it found no field
        called "Value" and silently dropped the value column. The table rendered
        with its key and instance columns and no number at all.
        """
        if len(exprs) != 1:
            raise ValueError(
                f"loki_table {title!r}: takes exactly one expression, got {len(exprs)} "
                "— the label-to-field split merges every query's frames into one "
                "table, so a second query's values would be summed into the first "
                "query's rows without saying so")
        label = self._ranked_loki_label(exprs[0], title)
        # INSTANT, not range (#479). Loki enforces max_query_series (default 500)
        # on the series a query RETURNS, and for a range query that is the UNION
        # across every step — so `topk(N, ...)` returns every value that entered
        # the top N in ANY step, not N. Measured at 82 distinct DNS names over 1h
        # and past 500 over 6h, which is why three of these panels returned a
        # query error and rendered "No data". `topk` cannot fix it, because the
        # union is taken after topk has run per step. An instant query returns
        # exactly N regardless of the window, and is what a top-N table wants
        # anyway: one aggregate over the selected range, not a time series.
        queries = [self._loki_query(e, ref=chr(65 + i), instant=True)
                   for i, e in enumerate(exprs)]
        transformations = [
            {"kind": "Transformation", "group": "labelsToFields",
             "spec": {"options": {"mode": "columns"}}},
            {"kind": "Transformation", "group": "merge", "spec": {"options": {}}},
            {"kind": "Transformation", "group": "organize", "spec": {"options": {
                # Time carries nothing for an instant query — one point per series,
                # all stamped identically — and rendering it wastes a column.
                "excludeByName": {"Time": True},
                # `merge` suffixes the value field with its refId, so the field is
                # "Value #A", not "Value" — renaming only "Value" leaves the column
                # titled "Value #A" AND breaks the sort, which targets "Total" by
                # display name and silently falls back to alphabetical when it does
                # not resolve. Both spellings are listed so neither can regress.
                "renameByName": {
                    label: field_title,
                    LOKI_INSTANCE_LABEL: self.LOKI_TABLE_INSTANCE_COLUMN,
                    self.LOKI_TABLE_VALUE_FIELD: self.LOKI_TABLE_VALUE_COLUMN,
                    "Value": self.LOKI_TABLE_VALUE_COLUMN,
                },
                "indexByName": {label: 0, LOKI_INSTANCE_LABEL: 1,
                                self.LOKI_TABLE_VALUE_FIELD: 2, "Value": 2},
            }}},
        ]
        opts = {"showHeader": True, "cellHeight": "sm",
                "footer": {"show": False, "reducer": ["sum"], "countRows": False, "fields": ""},
                "sortBy": [{"displayName": sort_by, "desc": sort_desc}]}
        spec = {"fieldConfig": {"defaults": {
                    "color": {"mode": "palette-classic"},
                    "custom": {"align": "auto", "cellOptions": {"type": "auto"},
                               "inspect": False, "filterable": True}},
                    "overrides": [
                        # Most of these tables count records, where a bare integer is right.
                        # The ones that sum a byte field are not: unset, they rendered an
                        # 11-digit number that read as a connection count (#513).
                        {"matcher": {"id": "byName", "options": self.LOKI_TABLE_VALUE_COLUMN},
                         "properties": [{"id": "unit", "value": value_unit}]},
                    ] if value_unit else []},
                "options": opts}
        n = self._panel(title, "table", spec, queries, desc=desc,
                        transformations=transformations, time_from=time_from)
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

    # ---- navigation (#419) ----------------------------------------------
    # Links are attached AFTER a panel is built rather than passed through every
    # viz helper's signature: a drilldown is a property of what the panel means,
    # not of how it is drawn, and threading a `links=` parameter through eleven
    # helpers would put the same optional argument on panels that can never use
    # one (a text panel has no field context). Both setters take the element name
    # a viz helper returned, so a typo is an immediate KeyError.
    #
    # The two are NOT interchangeable, and choosing wrong is a silent failure:
    #
    #   panel_links()  -> spec.links, the panel header menu. No field context, so
    #                     `${__field.labels.x}` interpolates to nothing here.
    #   field_links()  -> fieldConfig.defaults.links, reached by clicking a series
    #                     or a table cell. This is the only place a label-scoped
    #                     drilldown works.
    def panel_links(self, name: str, links: list) -> str:
        """Attach header links to a panel (no field/series context available)."""
        spec = self.elements[name]["spec"]
        for link in links:
            if "${__field." in link["url"]:
                raise ValueError(
                    f"panel link {link['title']!r} on {spec['title']!r} templates a "
                    "field value, which a panel-header link has no context for — use "
                    "field_links()")
        spec["links"] = spec.get("links", []) + links
        return name

    def field_links(self, name: str, links: list) -> str:
        """Attach data links to a panel's fields (clicking a series or cell)."""
        viz = self.elements[name]["spec"]["vizConfig"]["spec"]
        defaults = viz.setdefault("fieldConfig", {"defaults": {}, "overrides": []})["defaults"]
        defaults["links"] = defaults.get("links", []) + links
        return name

    def dashboard_links(self, links: list) -> None:
        """Append dashboard-level links (rendered above the tab bar)."""
        self.links.extend(links)

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

    def textbox(self, name: str, *, label: str, default: str, description: str,
                placement: str | None = None):
        """Register a free-text (TextVariable) filter.

        For a field that CANNOT be enumerated. Loki structured metadata is the case
        this exists for (#435): `device_name`, `server_name`, `ja3` and friends are
        not indexed labels, so `label_values()` returns null for them and a query
        variable renders an empty picker that looks broken rather than saying so. A
        textbox is honest about it, costs no cold-load query (#422), and still does
        the operator's job — the value is used as a regex in a `|` filter.

        `default` should match everything, so an untouched dashboard filters nothing.
        """
        spec = {"name": name, "label": label, "query": default,
                "current": {"text": default, "value": default},
                "hide": "dontHide", "skipUrlSync": False, "description": description}
        if placement:
            spec["placement"] = placement
        self.variables.append({"kind": "TextVariable", "spec": spec})

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

    def _autogrid(self, names: list) -> dict:
        """A responsive row: Grafana sizes and reflows the panels itself.

        Shape taken verbatim from a live-deployed v2 dashboard rather than derived
        from the schema — `columnWidthMode`/`rowHeightMode`/`fillScreen` are all
        required, and a v2 push that omits one 422s with a CUE disjunction error
        naming `layout.kind`, which points nowhere near the real cause.
        """
        return {"kind": "AutoGridLayout", "spec": {
            "items": [{"kind": "AutoGridLayoutItem",
                       "spec": {"element": {"kind": "ElementReference", "name": nm}}}
                      for nm in names],
            "columnWidthMode": "standard",
            "rowHeightMode": "standard",
            "fillScreen": False}}

    def autogrid_row(self, title, names, present=None, absent=None,
                     collapse=False) -> dict:
        """A row of N interchangeable panels, laid out responsively (#619).

        Use where a row is N same-size panels and the arrangement carries no
        meaning. `row()` packs those into a fixed 24-column grid, so at a narrow
        viewport they clip instead of reflowing.

        It takes NAMES ONLY, and that is the whole point: a helper that still took
        (name, width, height) would be `row()` with extra steps. Sizes are not
        stated because stating them is what prevents reflowing.

        Keep `row()` wherever the geometry MEANS something — a wide timeseries
        beside two stat tiles says "this is the main chart and these annotate it",
        and AutoGrid would flatten that into three equal boxes.
        """
        spec = {"title": title, "collapse": collapse,
                "layout": self._autogrid(names)}
        c = self._cond(present, absent)
        if c:
            spec["conditionalRendering"] = c
        return {"kind": "RowsLayoutRow", "spec": spec}

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

    # ---- grouping-level variable placement (#619) ------------------------
    #
    # `RowsLayoutRowSpec` and `TabsLayoutTabSpec` both accept their own
    # `variables: [...]`, and a variable declared on a tab only runs its query when
    # that tab is OPENED. This repo declares 98 hidden presence sentinels, every one
    # of which currently fires on cold load whether or not the operator ever visits
    # the tab it gates.
    #
    # Placement is DERIVED here rather than declared at the 127 call sites. The rule
    # that makes derivation worth it is the awkward one:
    #
    #   A TAB CANNOT GATE ITSELF ON A VARIABLE SCOPED TO ITSELF.
    #
    # The variable does not exist until the tab renders, so the gate evaluates
    # against nothing and the tab is hidden forever — on screen indistinguishable
    # from a tab correctly hidden for want of data. A variable that gates a tab
    # therefore belongs to that tab's PARENT, while a variable merely USED inside a
    # tab belongs to the tab. Getting that backwards is silent, and hand-writing it
    # 86 times is 86 chances to get it backwards. Computing it is one.
    #
    # Everything else falls out of one rule: a variable lives at the DEEPEST
    # grouping level that encloses every reference to it. Referenced from two
    # sibling leaves, or from anywhere outside the layout, and the deepest common
    # level is the dashboard, which is where it stays.

    # Reference positions are tuples of enclosing tab titles; () is the dashboard.
    _DASHBOARD_LEVEL: tuple = ()

    @staticmethod
    def _condition_variables(spec: dict) -> list:
        """Variable names a row/tab spec gates its own visibility on."""
        cond = spec.get("conditionalRendering")
        if not cond:
            return []
        return [item["spec"]["variable"] for item in cond["spec"]["items"]
                if item.get("kind") == "ConditionalRenderingVariable"]

    def _variable_references(self) -> dict:
        """Map each sentinel name to the set of layout positions that reference it.

        A position is the tuple of tab titles enclosing the reference. Walking is
        GENERIC — dispatch on `kind`, recurse into everything else — rather than
        against a typed list of layout kinds. A typed reader that meets a layout
        kind it does not know returns no panels for it and every check underneath
        passes vacuously, reporting success while covering less.
        """
        refs = {name: set() for name in self._sentinels}
        panel_positions: dict = {}

        def note(name, position):
            if name in refs:
                refs[name].add(position)

        def walk(node, position):
            if isinstance(node, dict):
                kind = node.get("kind")
                if kind == "TabsLayoutTab":
                    spec = node["spec"]
                    inner = position + (spec["title"],)
                    # A tab's own gate resolves in the PARENT, not in the tab.
                    for name in self._condition_variables(spec):
                        note(name, position)
                    walk(spec.get("layout"), inner)
                    return
                if kind == "RowsLayoutRow":
                    spec = node["spec"]
                    for name in self._condition_variables(spec):
                        note(name, position)
                    walk(spec.get("layout"), position)
                    return
                if kind == "GridLayoutItem":
                    panel_positions.setdefault(
                        node["spec"]["element"]["name"], set()).add(position)
                    return
                if kind == "AutoGridLayoutItem":
                    panel_positions.setdefault(
                        node["spec"]["element"]["name"], set()).add(position)
                    return
                for value in node.values():
                    walk(value, position)
            elif isinstance(node, list):
                for value in node:
                    walk(value, position)

        walk({"kind": "TabsLayout", "spec": {"tabs": self.tabs}}, self._DASHBOARD_LEVEL)

        # Panel queries. Matched against the serialised element so a reference is
        # caught wherever it hides — a query, a title, a legend, a link URL, a
        # transformation, a threshold — rather than only in the places a targeted
        # reader thought to look.
        for element_name, positions in panel_positions.items():
            element = self.elements.get(element_name)
            if element is None:
                continue
            blob = json.dumps(element)
            for name in self._sentinels:
                if _references_variable(blob, name):
                    refs[name].update(positions)

        # Anything referencing a sentinel from OUTSIDE the layout — another
        # variable's query, an annotation, a dashboard link — pins it to the
        # dashboard, because there is no grouping level enclosing those at all.
        outside = json.dumps([self.variables, self.annotations, self.links])
        for name in self._sentinels:
            if _references_variable(outside, name):
                refs[name].add(self._DASHBOARD_LEVEL)

        return refs

    @staticmethod
    def _common_level(positions: set) -> tuple:
        """Deepest grouping level enclosing every position (their common prefix)."""
        if not positions:
            return Builder._DASHBOARD_LEVEL
        common = min(positions, key=len)
        for position in positions:
            while common != position[:len(common)]:
                common = common[:-1]
        return common

    def place_variables(self) -> dict:
        """Move each sentinel onto the deepest grouping level that encloses its uses.

        Returns {variable name: level path} for every sentinel, so the caller (and
        the tests) can assert placement without re-deriving it.

        A sentinel referenced by NOTHING is left at dashboard level rather than
        dropped. Dropping it would delete a variable somebody is about to use and
        turn an unused declaration into a mystery; leaving it costs one cold-load
        query and shows up in the budget test, which is the loud version.
        """
        refs = self._variable_references()
        levels = {name: self._common_level(positions)
                  for name, positions in refs.items()}

        # Index the tab specs by their full path so a level can be resolved to the
        # spec that will carry the variable.
        by_path: dict = {}

        def index(node, position):
            if isinstance(node, dict):
                if node.get("kind") == "TabsLayoutTab":
                    spec = node["spec"]
                    path = position + (spec["title"],)
                    by_path[path] = spec
                    index(spec.get("layout"), path)
                    return
                for value in node.values():
                    index(value, position)
            elif isinstance(node, list):
                for value in node:
                    index(value, position)

        index({"kind": "TabsLayout", "spec": {"tabs": self.tabs}},
              self._DASHBOARD_LEVEL)

        # Rebuild the dashboard-level list in declaration order, moving the rest.
        # Order is preserved rather than regrouped: the variable list is what the
        # cold-load fan-out is read from, and a stable order keeps the artifact diff
        # legible when one variable moves.
        remaining = []
        for variable in self.variables:
            name = variable["spec"]["name"]
            level = levels.get(name, self._DASHBOARD_LEVEL)
            if level == self._DASHBOARD_LEVEL:
                remaining.append(variable)
                continue
            spec = by_path.get(level)
            if spec is None:  # unreachable via _common_level, but never guess
                remaining.append(variable)
                levels[name] = self._DASHBOARD_LEVEL
                continue
            spec.setdefault("variables", []).append(variable)
        self.variables = remaining
        return levels

    def all_variables(self) -> list:
        """Every variable this dashboard declares, at any grouping level.

        `self.variables` is the DASHBOARD-level list, and after `place_variables`
        that is 18 of 104. Anything asking "what does this dashboard declare?" —
        the sentinel contract, the scoping inventory, coverage checks — has to ask
        here instead, or it silently starts governing a sixth of what it used to
        while still reporting success (#619).

        The one caller that must NOT use this is the cold-load budget: its whole
        subject is which variables fire on load, and a tab-scoped one does not.
        """
        found = list(self.variables)

        def walk(node):
            if isinstance(node, dict):
                if node.get("kind") in ("TabsLayoutTab", "RowsLayoutRow"):
                    found.extend(node["spec"].get("variables", []))
                for value in node.values():
                    walk(value)
            elif isinstance(node, list):
                for value in node:
                    walk(value)

        walk(self.tabs)
        return found

    # ---- manifest --------------------------------------------------------
    def manifest(self, title, description, tags, name="opnsense2otel") -> dict:
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
                "links": self.links, "annotations": self.annotations,
                "variables": self.variables,
                "elements": self.elements,
                "layout": {"kind": "TabsLayout", "spec": {"tabs": self.tabs}},
            },
        }
