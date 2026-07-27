"""A model of Grafana's alert-rule state machine, run against our own manifests (#429).

## Why this exists, and why it is not promtool

`tools/promqlcheck` already parses every alert and recording expression with
Prometheus' own parser, so syntax is covered. What no syntax check can reach — and
what promtool structurally cannot model, because it evaluates Prometheus rules and
this project ships **Grafana-managed** rules — is the behaviour *around* the query:

* the **pending period** (`for`), which decides whether a two-minute blip pages;
* **`noDataState`**, which decides what happens when the query returns nothing at all;
* **`execErrState`**, the same for a failed evaluation;
* **MissingSeries**, which is Grafana-only and is the subtle one: when ONE series
  disappears while others keep reporting, the instance does NOT go through
  `noDataState`. It keeps its last state for two evaluation intervals and is then
  resolved with `grafana_state_reason: MissingSeries`. A rule set to
  `noDataState: Alerting` in the belief that it will page when a firewall vanishes
  will therefore stay silent if any other firewall is still reporting — which is
  exactly the gap #427's `OPNsenseExporterInstanceMissing` rule exists to close.

## What this models, and what it deliberately does not

It models the STATE MACHINE, fed with query *results*. It does not evaluate PromQL:
a caller supplies the timeline of values the query would return, and this decides the
resulting alert states. That boundary is deliberate. Reimplementing `increase()` and
`unless` in Python would be a second, worse Prometheus whose disagreements with the
real one would show up as confident wrong answers, and the interesting failures here
are all on the Grafana side of the query anyway.

## Semantics, and where they come from

Verified against the Grafana 13.1 / Grafana Cloud alerting documentation on
2026-07-28 (`alerting/fundamentals/alert-rule-evaluation`,
`alerting/fundamentals/alert-rule-evaluation/stale-alert-instances`,
`alerting/best-practices/missing-data`), not from memory:

* An instance is `Normal`, `Pending`, `Alerting`, `NoData` or `Error`. `Pending`
  means the condition is met but the pending period has not elapsed.
* `NoData` and `Error` also honour the pending period before resolving to their
  configured state.
* A stale instance — query returns data, but one previously-present dimension is
  gone for two consecutive evaluation intervals — keeps its last state for those
  two intervals, then transitions to `Normal` with reason `MissingSeries` and is
  evicted. This is distinct from `NoData`, which is "no dimensions at all".
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# Alert instance states.
NORMAL = "Normal"
PENDING = "Pending"
ALERTING = "Alerting"
NODATA = "NoData"
ERROR = "Error"

# Reason annotations Grafana attaches when Normal was reached other than by the
# condition clearing. Only MissingSeries is modelled; it is the one that changes
# whether a responder is told anything.
REASON_MISSING_SERIES = "MissingSeries"

# Grafana marks a missing dimension stale after this many consecutive evaluation
# intervals, holding its last state in the meantime.
MISSING_SERIES_INTERVALS = 2

# Timeline sentinels. A tick is one of these, or a {series: value} mapping.
NO_DATA = "__no_data__"      # query ran, returned no dimensions at all
EVAL_ERROR = "__error__"     # query failed / timed out


class Unsupported(Exception):
    """A manifest shape this model has never seen.

    Raised rather than guessed. A silent skip here would produce a harness that
    reports every rule as healthy while checking none of them — the exact failure
    `tools/promqlcheck` already shipped once (#435) and must not be reintroduced.
    """


_DURATION = re.compile(r"^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$")


def parse_duration(text: str) -> int:
    """Grafana durations as seconds. `"0s"`, `"15m"`, `"1h30m"`."""
    m = _DURATION.match(text or "")
    if not m or not any(m.groups()):
        raise Unsupported(f"unparseable duration {text!r}")
    h, mi, s = (int(g or 0) for g in m.groups())
    return h * 3600 + mi * 60 + s


# Grafana threshold evaluator types, as they appear in
# `spec.expressions.C.model.conditions[0].evaluator.type`. `params` is the
# evaluator's own list; `gt`/`lt` read params[0], the range types read both.
_EVALUATORS = {
    "gt": lambda v, p: v > p[0],
    "lt": lambda v, p: v < p[0],
    "gte": lambda v, p: v >= p[0],
    "lte": lambda v, p: v <= p[0],
    "within_range": lambda v, p: p[0] < v < p[1],
    "outside_range": lambda v, p: v < p[0] or v > p[1],
}


@dataclass
class Rule:
    """The evaluation-relevant slice of one generated AlertRule manifest."""

    title: str
    evaluator: str
    params: list
    for_seconds: int
    interval_seconds: int
    no_data_state: str
    exec_err_state: str
    folder: str = ""

    def breaches(self, value) -> bool:
        """Does one series value satisfy the alert condition?

        `None` is not a breach: Grafana treats a null reduction as no value for
        that series rather than as zero, and reading it as zero would invent
        firing states for every `lt`-type rule.
        """
        if value is None:
            return False
        fn = _EVALUATORS.get(self.evaluator)
        if fn is None:
            raise Unsupported(
                f"{self.title}: evaluator {self.evaluator!r} is not modelled; add it "
                "to _EVALUATORS rather than letting the rule pass unchecked")
        return fn(value, self.params)


def rule_from_manifest(doc: dict) -> Rule:
    """Extract a `Rule` from a generated AlertRule manifest.

    Reads the SHIPPED artifact rather than `build_rules.py`'s source dicts on
    purpose: the manifest is what Grafana evaluates, so a bug in the emit path is
    in scope for this harness.
    """
    if doc.get("kind") != "AlertRule":
        raise Unsupported(f"not an AlertRule manifest: kind={doc.get('kind')!r}")
    spec = doc["spec"]
    conditions = spec["expressions"]["C"]["model"]["conditions"]
    if len(conditions) != 1:
        raise Unsupported(
            f"{spec['title']}: {len(conditions)} threshold conditions; this model "
            "assumes the single-condition shape build_rules.py emits")
    evaluator = conditions[0]["evaluator"]
    return Rule(
        title=spec["title"],
        evaluator=evaluator["type"],
        params=list(evaluator["params"]),
        for_seconds=parse_duration(spec["for"]),
        interval_seconds=parse_duration(spec["trigger"]["interval"]),
        no_data_state=spec.get("noDataState", "NoData"),
        exec_err_state=spec.get("execErrState", "Error"),
        folder=doc.get("metadata", {}).get("labels", {}).get("grafana.app/folder", ""),
    )


@dataclass
class _Instance:
    state: str = NORMAL
    reason: str = ""
    breaching_since: int | None = None   # tick index of the first consecutive breach
    missing_for: int = 0                 # consecutive intervals absent
    evicted: bool = False


@dataclass
class Evaluation:
    """One tick's outcome, per series plus the rule-level state."""

    tick: int
    states: dict = field(default_factory=dict)   # series -> state
    reasons: dict = field(default_factory=dict)  # series -> reason (only if set)

    def firing(self) -> set:
        return {s for s, st in self.states.items() if st == ALERTING}


def evaluate(rule: Rule, timeline: list) -> list:
    """Run `rule` over `timeline` and return one `Evaluation` per tick.

    Each timeline entry is `NO_DATA`, `EVAL_ERROR`, or a `{series: value}` mapping.
    Series keys stand in for the label sets Grafana would produce — in practice
    `opnsense_instance`, sometimes with a second dimension.

    Rule-level states (`NoData`, `Error`) are reported under the reserved series key
    `""`, because that is what they are: a property of the rule, not of a dimension.
    """
    instances: dict = {}
    out = []
    rule_level = _Instance()

    for tick, sample in enumerate(timeline):
        ev = Evaluation(tick=tick)

        if sample is EVAL_ERROR or sample == EVAL_ERROR:
            _advance_rule_level(rule, rule_level, tick, rule.exec_err_state, ERROR)
            ev.states[""] = rule_level.state
            # Grafana holds existing instances through an errored evaluation rather
            # than resolving them; nothing about the series changed, the query did.
            for name, inst in instances.items():
                if not inst.evicted:
                    ev.states[name] = inst.state
            out.append(ev)
            continue

        if sample is NO_DATA or sample == NO_DATA:
            _advance_rule_level(rule, rule_level, tick, rule.no_data_state, NODATA)
            ev.states[""] = rule_level.state
            out.append(ev)
            continue

        rule_level.state, rule_level.breaching_since = NORMAL, None

        for name in set(instances) | set(sample):
            inst = instances.setdefault(name, _Instance())
            if inst.evicted and name not in sample:
                continue
            if name in sample:
                inst.evicted = False
                inst.missing_for = 0
                inst.reason = ""
                _advance_series(rule, inst, tick, rule.breaches(sample[name]))
            else:
                # MissingSeries: the query returned data, this dimension did not.
                # Last state is held for MISSING_SERIES_INTERVALS, then resolved.
                inst.missing_for += 1
                if inst.missing_for > MISSING_SERIES_INTERVALS:
                    inst.state = NORMAL
                    inst.reason = REASON_MISSING_SERIES
                    inst.breaching_since = None
                    inst.evicted = True
            # An evicted instance is reported ONCE, on the tick it is evicted, and
            # then disappears — Grafana removes it from the UI at that point, and a
            # model that kept emitting Normal forever would suggest a responder can
            # still see it.
            if not inst.evicted:
                ev.states[name] = inst.state
            elif inst.reason and inst.missing_for == MISSING_SERIES_INTERVALS + 1:
                ev.states[name] = inst.state
                ev.reasons[name] = inst.reason
        out.append(ev)

    return out


def _advance_series(rule: Rule, inst: _Instance, tick: int, breaching: bool) -> None:
    if not breaching:
        inst.state, inst.breaching_since = NORMAL, None
        return
    if inst.breaching_since is None:
        inst.breaching_since = tick
    elapsed = (tick - inst.breaching_since) * rule.interval_seconds
    inst.state = ALERTING if elapsed >= rule.for_seconds else PENDING


def _advance_rule_level(rule: Rule, inst: _Instance, tick: int,
                        configured: str, transient: str) -> None:
    """NoData/Error honour the pending period before settling on their configured
    state, so a single failed evaluation on a rule with a long `for` does not page."""
    # `build_rules.py` emits Grafana's own spelling, "Ok". "OK"/"Normal" are
    # accepted too rather than silently falling through to the Alerting branch.
    if configured in ("Ok", "OK", "Normal"):
        inst.state, inst.breaching_since = NORMAL, None
        return
    if configured == "KeepLast":
        inst.breaching_since = None
        return
    if inst.breaching_since is None:
        inst.breaching_since = tick
    elapsed = (tick - inst.breaching_since) * rule.interval_seconds
    if elapsed < rule.for_seconds:
        inst.state = PENDING if configured == ALERTING else transient
    else:
        inst.state = configured
