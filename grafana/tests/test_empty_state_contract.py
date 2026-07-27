"""Gate: a zero-filled panel must be gated by its OWN collector (#478).

## The defect class

A stat-like panel may zero-fill with `or vector(0)` so an empty result reads as a
clean `0` instead of "No data". That is only honest if the panel is inside
something gated by a sentinel fed by the **same collector** as the panel's query.

If they come from different collectors, the row renders because collector A is
present while the panel's metric comes from collector B — which may be absent —
and the panel shows a green **0**. An operator reads that as "checked, nothing
found". The truth is "never checked". A silently wrong zero on a failure-count or
security panel is worse than a blank one: a blank panel prompts a question, a
green zero ends the conversation.

**Metric-name identity is not the test. Collector identity is.** Two metrics from
one collector always co-exist; two metrics from different collectors do not.

## Ownership is derived, never listed

Two generated artifacts already carry the answer, so nothing here is a per-panel
or per-metric list that can rot:

* `docs/metrics/metrics.md` is generated per collector subsystem, one `##` section
  per collector, so a metric name maps back to its owning collector.
* `docs/metrics/self-metrics.md` (#428) covers the exporter's own metrics, which
  are cross-cutting by construction.
* `sentinel-contract.json` (#417) maps each sentinel to the metric it probes.

A metric found in exactly one collector section is owned by that collector.
Anything in `## General`, in the self-metric inventory, or in more than one
section is **shared** — cross-cutting signals that co-exist with every collector,
which is exactly the case the contract must stay silent on.

Ported from `tailscale2otel`'s `test_empty_state_contract.py`. Its
ownership-derivation approach transfers; its collector layout does not.
"""

import json
import re
import sys
import unittest
from pathlib import Path

GRAFANA_DIR = Path(__file__).resolve().parents[1]
REPO = GRAFANA_DIR.parent
sys.path.insert(0, str(GRAFANA_DIR))

import build_dashboard  # noqa: E402

METRICS_MD = REPO / "docs" / "metrics" / "metrics.md"
SELF_METRICS_MD = REPO / "docs" / "metrics" / "self-metrics.md"
CONTRACT = GRAFANA_DIR / "sentinel-contract.json"

ZERO_FILL = "or vector(0)"
SHARED = "<shared>"

# Sections of metrics.md that are not one collector's output. "General" holds the
# exporter's own meta metrics plus `opnsense_up` and the health-check gauges, all
# of which are emitted whatever else is enabled.
SHARED_SECTIONS = {"General", "Summary"}

# Panels whose zero-fill is deliberate despite a provenance mismatch. Each entry
# must say WHY the zero is true rather than convenient — in the style of
# `NOT_ANNOTATED` in `grafana/annotations.py`. Empty is the goal.
ZERO_FILL_EXEMPT: dict = {}

_METRIC_ROW = re.compile(r"^\|\s*`?(opnsense_[a-z0-9_]+)`?\s*\|")
_SECTION = re.compile(r"^##\s+(.*?)\s*$")
# A metric name in a PromQL expression, and nothing else. Two things in every
# selector look like one and are not: the LABEL `opnsense_instance=~...` (excluded
# by the lookahead for a comparison operator) and the Grafana VARIABLE
# `$opnsense_instance` interpolated as its value (excluded by the lookbehind for
# `$`). Without both, every panel appears to chart a metric named
# "opnsense_instance" and the whole gate resolves to `<unknown>`.
_METRIC_IN_EXPR = re.compile(
    r"(?<![$\w])(opnsense_[a-z0-9_]+)\b(?!\s*(?:=|!=|=~|!~))")


def metric_owners() -> dict:
    """metric name -> owning collector display name, or SHARED."""
    owners: dict = {}
    section = ""
    for line in METRICS_MD.read_text().splitlines():
        heading = _SECTION.match(line)
        if heading:
            section = heading.group(1)
            continue
        row = _METRIC_ROW.match(line)
        if not row:
            continue
        name, owner = row.group(1), (SHARED if section in SHARED_SECTIONS else section)
        # Seen under two collectors -> cross-cutting, so it co-exists with both.
        owners[name] = SHARED if owners.get(name, owner) != owner else owner
    for line in SELF_METRICS_MD.read_text().splitlines():
        row = _METRIC_ROW.match(line)
        if row:
            owners[row.group(1)] = SHARED
    return owners


OWNERS = metric_owners()


def owner_of(metric: str) -> str:
    """Owning collector for a metric name, tolerating histogram/counter suffixes."""
    if metric in OWNERS:
        return OWNERS[metric]
    for suffix in ("_bucket", "_count", "_sum"):
        if metric.endswith(suffix) and metric[: -len(suffix)] in OWNERS:
            return OWNERS[metric[: -len(suffix)]]
    # Not in either generated inventory. The coverage gate (#428) already fails on
    # an uncharted metric, so this means a metric charted under a name the docs do
    # not know — treat as unknown rather than shared, so it cannot pass silently.
    return f"<unknown:{metric}>"


def sentinel_metrics() -> dict:
    """sentinel name -> the metric it probes, from the generated contract."""
    contract = json.loads(CONTRACT.read_text())
    out = {}
    for entry in contract["prometheus"]["sentinels"]:
        found = _METRIC_IN_EXPR.findall(entry["query"])
        if found:
            out[entry["name"]] = found[0]
    return out


SENTINEL_METRIC = sentinel_metrics()


def _gate_variables(spec: dict) -> list:
    """Sentinels whose presence this level GUARANTEES.

    An `or` group with more than one item guarantees nothing about any single
    member — a VPN domain gated on `has_wireguard OR ... OR has_tor` renders when
    WireGuard alone is present, so reading `has_tor` out of it as proof that the
    Tor collector is running would be exactly the unproven-zero this file exists to
    catch. Only `and` groups (which `Builder._cond` emits for a single presence
    variable) contribute. `notMatches` items are absence assertions and prove
    nothing about presence either.
    """
    cond = spec.get("conditionalRendering")
    if not cond:
        return []
    group = cond.get("spec", {})
    items = group.get("items", [])
    if group.get("condition") == "or" and len(items) > 1:
        return []
    return [item["spec"]["variable"] for item in items
            if item.get("spec", {}).get("variable")
            and item["spec"].get("operator") != "notMatches"]


def zero_fill_panels() -> list:
    """Every `or vector(0)` panel across the family, with the sentinels gating it.

    Yields `(dashboard_uid, panel_title, [metric...], [sentinel...], path)`. Gates
    accumulate down the tree — tab-group, tab and row all have to be satisfied for
    the panel to render, so any one of them proving the collector present makes the
    zero honest.
    """
    found = []
    for spec, builder in build_dashboard.build_family():
        for tab in builder.tabs:
            _walk(spec.uid, builder, tab["spec"], [], found)
    return found


def _walk(uid, builder, spec, gates, found):
    gates = gates + _gate_variables(spec)
    path = spec.get("title", "")
    layout = spec["layout"]
    if layout["kind"] == "TabsLayout":
        for child in layout["spec"]["tabs"]:
            _walk(uid, builder, child["spec"], gates, found)
        return
    for row in layout["spec"]["rows"]:
        rspec = row["spec"]
        row_gates = gates + _gate_variables(rspec)
        for item in rspec["layout"]["spec"]["items"]:
            name = item["spec"]["element"]["name"]
            panel = builder.elements[name]["spec"]
            exprs = [q["spec"]["query"]["spec"].get("expr", "")
                     for q in panel["data"]["spec"]["queries"]]
            zero = [e for e in exprs if ZERO_FILL in e]
            if not zero:
                continue
            metrics = sorted({m for e in zero for m in _METRIC_IN_EXPR.findall(e)})
            found.append((uid, panel["title"], metrics, row_gates,
                          f"{path} > {rspec.get('title') or '(unnamed row)'}"))


def violations(panels) -> list:
    """The contract, as a pure function of the scan output, so the gate and the
    prove-it-goes-red test below run the SAME code rather than two similar copies."""
    out = []
    for uid, title, metrics, gates, path in panels:
        if title in ZERO_FILL_EXEMPT:
            continue
        panel_owners = {owner_of(m) for m in metrics} - {SHARED}
        if not panel_owners:
            continue  # cross-cutting metric: co-exists with every collector
        gate_owners = {owner_of(SENTINEL_METRIC[g])
                       for g in gates if g in SENTINEL_METRIC}
        if gate_owners & panel_owners:
            continue
        gated_by = (str(sorted(gate_owners)) if gate_owners
                    else "nothing that proves that collector is running")
        out.append(
            f"{uid} :: {path} :: {title!r} zero-fills {sorted(panel_owners)} data "
            f"but is gated by {gated_by} — if that collector is disabled the panel "
            "shows a green 0 meaning 'never checked'")
    return out


class OwnershipDerivationTest(unittest.TestCase):
    """The derivation has to be right before the gate built on it means anything."""

    def test_a_single_collector_metric_resolves_to_that_collector(self):
        self.assertEqual(owner_of("opnsense_tor_circuits"), "Tor")
        self.assertEqual(owner_of("opnsense_crowdsec_hub_items"), "CrowdSec")

    def test_cross_cutting_metrics_resolve_to_shared(self):
        for metric in ("opnsense_up", "opnsense_system_status_code",
                       "opnsense_exporter_scrapes_total"):
            with self.subTest(metric=metric):
                self.assertEqual(owner_of(metric), SHARED)

    def test_an_unknown_metric_does_not_quietly_resolve_to_shared(self):
        """Otherwise a typo'd metric name would pass the gate by looking harmless."""
        self.assertTrue(owner_of("opnsense_not_a_real_metric").startswith("<unknown:"))

    def test_every_sentinel_in_the_contract_resolves_to_a_metric(self):
        contract = json.loads(CONTRACT.read_text())
        named = {e["name"] for e in contract["prometheus"]["sentinels"]}
        # Two sentinels legitimately name no `opnsense_` metric, and both are
        # unusable as provenance rather than broken:
        #   has_go_runtime   probes `go_goroutines`, client-library owned and
        #                    deliberately outside the opnsense_ namespace;
        #   has_recording_rules probes a NAME REGEX (`instance:opnsense_.+`) over the
        #                    recording-rule namespace, so it names no single metric
        #                    and belongs to no collector.
        unresolved = named - set(SENTINEL_METRIC) - {"has_go_runtime",
                                                     "has_recording_rules"}
        self.assertEqual(unresolved, set(),
                         "a sentinel's query names no opnsense_ metric, so its "
                         "provenance cannot be checked")


class ZeroFillProvenanceTest(unittest.TestCase):
    """The gate itself."""

    @classmethod
    def setUpClass(cls):
        cls.panels = zero_fill_panels()

    def test_the_scan_finds_the_zero_filled_panels(self):
        """Control. A scan that found nothing would pass the gate vacuously."""
        self.assertGreaterEqual(
            len(self.panels), 5,
            "the zero-fill scan found almost nothing; `or vector(0)` is still in "
            "the tab sources, so the tree walk is broken rather than the tree clean")

    def test_every_zero_fill_is_gated_by_its_own_collector(self):
        found = violations(self.panels)
        self.assertEqual(found, [], "\n" + "\n".join(found))


class GateFailsOnAMismatchTest(unittest.TestCase):
    """#478's last criterion: prove the gate can go red.

    Driven through `violations()` — the same function the gate above calls — rather
    than by re-deriving ownership, so a gate that had stopped comparing anything
    would fail here too.
    """

    MISMATCH = ("opnsense-exporter", "Built Circuits", ["opnsense_tor_circuits"],
                ["has_crowdsec"], "Security > CrowdSec")
    MATCH = ("opnsense-exporter", "Built Circuits", ["opnsense_tor_circuits"],
             ["has_tor"], "VPN & remote access > Tor")

    def test_a_tor_panel_gated_by_a_crowdsec_sentinel_is_a_violation(self):
        found = violations([self.MISMATCH])
        self.assertEqual(len(found), 1, found)
        self.assertIn("Tor", found[0])
        self.assertIn("CrowdSec", found[0])

    def test_the_same_panel_gated_by_its_own_sentinel_is_not(self):
        """The control: without it, a `violations()` that flagged everything would
        satisfy the test above."""
        self.assertEqual(violations([self.MATCH]), [])

    def test_a_zero_fill_gated_by_nothing_at_all_is_a_violation(self):
        ungated = ("opnsense-exporter", "Built Circuits", ["opnsense_tor_circuits"],
                   [], "Overview > Health")
        self.assertEqual(len(violations([ungated])), 1)

    def test_an_exemption_suppresses_the_failure(self):
        ZERO_FILL_EXEMPT["Built Circuits"] = "test fixture"
        try:
            self.assertEqual(violations([self.MISMATCH]), [])
        finally:
            del ZERO_FILL_EXEMPT["Built Circuits"]


if __name__ == "__main__":
    unittest.main()
