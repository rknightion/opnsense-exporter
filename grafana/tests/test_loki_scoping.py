"""Guard: every LogQL query is scoped to the selected appliance (#413).

The Prometheus side has one chokepoint (`sel()`), so a panel cannot forget the
instance matcher. LogQL had none — every stream selector was hand-written — and
all nine Loki panel targets plus both Loki presence sentinels queried the whole
fleet's logs regardless of the `$opnsense_instance` picker.

Two facts fix the shape of this guard, both verified live against the real stack:

* A syslog stream's COMPLETE label set is `opnsense_action`, `opnsense_source`,
  `opnsense_subsystem`, `service_instance_id`, `service_name`. `opnsense_instance`
  is NOT a Loki label, so the Prometheus matcher cannot be reused verbatim.
* `service_instance_id` and Prometheus `opnsense_instance` hold IDENTICAL value
  spaces (both `opnsense` on the reference box), so `$opnsense_instance` selects
  correctly on either side and multi-select/All stay regex-based.

The matcher therefore has to live INSIDE the stream selector, which is what
`loki_sel()` guarantees. Position matters as much as presence: a `topk` over
`count_over_time` aggregates whatever the stream selector admitted, so a matcher
appended after the `|` line filter (or bolted onto the aggregation) would still
have summed every box's records before ranking them.
"""

import sys
import unittest
from pathlib import Path


GRAFANA_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GRAFANA_DIR))

import build_dashboard  # noqa: E402


# LogQL targets deliberately left fleet-wide, each with the reason. Empty by
# design: every shipped log stream carries service_instance_id, so there is no
# structural reason for an exception. An entry here means a panel knowingly reads
# other appliances' logs — say why.
LOKI_SCOPE_EXCEPTIONS: dict[str, str] = {}

# The label, not the whole matcher: an exception could legitimately pin a literal
# value rather than the variable, and the point of the check is that the stream
# is narrowed to an appliance identity at all.
INSTANCE_LABEL = "service_instance_id"
# Spelled out rather than imported from builder on purpose: this is the contract
# the dashboard owes Loki, and a test that imports the constant it is checking
# cannot fail when that constant changes.
EXPECTED_MATCHER = 'service_instance_id=~"$opnsense_instance"'


def stream_selector(expr: str) -> str:
    """Return the leading `{...}` stream selector of a LogQL expression, or ""."""
    start = expr.find("{")
    if start == -1:
        return ""
    depth = 0
    quoted = False
    for i in range(start, len(expr)):
        char = expr[i]
        if char == '"' and expr[i - 1] != "\\":
            quoted = not quoted
            continue
        if quoted:
            continue
        if char == "{":
            depth += 1
        elif char == "}":
            depth -= 1
            if depth == 0:
                return expr[start:i + 1]
    return ""


def loki_panel_targets(builder) -> list[tuple[str, str]]:
    """[(label, logql)] for every Loki query on every panel, as shipped."""
    targets = []
    for element in builder.elements.values():
        if element["kind"] != "Panel":
            continue
        title = element["spec"]["title"]
        for query in element["spec"]["data"]["spec"]["queries"]:
            spec = query["spec"]
            if spec["datasource"].get("type") != "loki":
                continue
            targets.append((f"panel {title!r} ref {spec['refId']}",
                            spec["query"]["spec"]["expr"]))
    return targets


def loki_sentinel_targets(builder) -> list[tuple[str, str]]:
    """[(label, logql)] for every hidden Loki presence variable, as shipped."""
    targets = []
    for variable in builder.variables:
        spec = variable["spec"]
        if variable["kind"] != "QueryVariable" or spec["hide"] != "hideVariable":
            continue
        query = spec["query"]
        if query["group"] != "loki":
            continue
        targets.append((f"sentinel {spec['name']!r}",
                        query["spec"]["__legacyStringValue"]))
    return targets


def loki_annotation_targets(builder) -> list:
    """LogQL emitted by the annotation layer (#421). Annotations have no panel, so
    they reach `_loki_exprs` through `Builder.record_loki_expr` instead."""
    targets = []
    for annotation in builder.annotations:
        spec = annotation["spec"]
        if spec["query"]["group"] != "loki":
            continue
        targets.append((f"annotation {spec['name']!r}", spec["legacyOptions"]["expr"]))
    return targets


# ---- the five streams #591 item 5 found unread ---------------------------
# Of seven registered `opnsense.source` emitters, the generated LogQL referenced
# only `syslog` and `zenarmor`. These five shipped detail nothing on the dashboard
# could read. Each maps to the stream-selector matcher its owning tab must use.
#
# This is deliberately NOT the generic log-stream coverage gate (that lives in
# `build_dashboard.py` and asks "does every registered source appear somewhere?").
# It pins the SPECIFIC selectors, because the way to satisfy a generic gate while
# still shipping blank panels is to select on the wrong label — see
# `SUBSYSTEMLESS_LANES` below, which is the exact trap #591 called out.
UNREAD_STREAMS = {
    "unbound": 'opnsense_source="unbound"',
    "ids": 'opnsense_source="ids"',
    "crowdsec": 'opnsense_source="crowdsec"',
    # The two flow-log lanes share one selector: they are the same record schema
    # (internal/flow Record.LogAttributes), differing only in whether a Zenarmor
    # conn document was correlated in, so splitting them across panels would ask an
    # operator to know which lane produced a connection before they can look it up.
    "netflow": 'opnsense_source=~"netflow|merged"',
    "merged": 'opnsense_source=~"netflow|merged"',
}

# The lanes that never stamp `opnsense.subsystem`, checked against the emitters
# themselves rather than asserted. A panel selecting one of these on
# `opnsense_subsystem` matches NOTHING and reports no error — it renders as a quiet
# empty panel, which is why this is checked at the source rather than trusted.
SUBSYSTEMLESS_LANES = {
    "unbound": "internal/logship/unbound.go",
    "ids": "internal/logship/ids.go",
    "crowdsec": "internal/logship/crowdsec.go",
}

# The synthetic self-observability record the IDS lane emits when the query_alerts
# window saturated before reaching the prior cursor (internal/logship/ids.go's
# idsGapEvent). It is accepted, bounded alert loss — the point of emitting it is
# that the loss is visible rather than silent, which needs a panel reading it.
IDS_GAP_FILTER = 'event="gap_detected"'


class UnreadStreamCoverageTest(unittest.TestCase):
    """#591 item 5: every registered log stream is read by at least one panel.

    A log stream's absence from the dashboard is invisible in exactly the way an
    annotation's is — there is no empty panel to notice, only a question nobody
    thought to ask. The exporter was shipping per-query DNS dispositions, per-alert
    Suricata signatures, CrowdSec decision detail and ~24 attributes per correlated
    flow, and the estate could read none of it.
    """

    @classmethod
    def setUpClass(cls):
        cls.builder = build_dashboard.build_all()
        cls.panels = loki_panel_targets(cls.builder)

    def test_every_previously_unread_stream_now_has_a_panel(self):
        missing = sorted(
            source for source, matcher in UNREAD_STREAMS.items()
            if not any(matcher in stream_selector(expr) for _, expr in self.panels)
        )
        self.assertEqual(
            [], missing,
            f"these registered opnsense.source lanes are read by no panel: {missing}")

    def test_the_subsystemless_lanes_are_selected_on_source_not_subsystem(self):
        """The trap, checked at BOTH ends.

        First against the emitters: these three lanes build their Record.Attributes
        without `logship.AttrSubsystem`, so their records carry no
        `opnsense_subsystem` label at all. Then against the panels: no stream
        selector may name one of these lanes on the subsystem label, because such a
        selector matches nothing and says nothing about it.
        """
        repo = GRAFANA_DIR.parent
        for lane, path in SUBSYSTEMLESS_LANES.items():
            with self.subTest(lane=lane, source=path):
                self.assertNotIn(
                    "AttrSubsystem", (repo / path).read_text(),
                    f"{path} now stamps a subsystem — re-check whether the {lane} "
                    "panels should select on it, and update this guard")
        for label, expr in self.panels:
            selector = stream_selector(expr)
            for lane in SUBSYSTEMLESS_LANES:
                with self.subTest(panel=label, lane=lane):
                    self.assertNotIn(f'opnsense_subsystem="{lane}"', selector)

    def test_the_ids_gap_record_has_a_consumer(self):
        """`gap_detected` is the IDS lane's own admission that it lost alerts. It was
        emitted and read by nothing, which makes the admission as silent as the loss
        it reports."""
        self.assertTrue(
            any(IDS_GAP_FILTER in expr for _, expr in self.panels),
            f"no panel filters on {IDS_GAP_FILTER}; the synthetic IDS gap record is "
            "emitted and read by nothing")


class LokiScopingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = build_dashboard.build_all()
        cls.panels = loki_panel_targets(cls.builder)
        cls.sentinels = loki_sentinel_targets(cls.builder)
        cls.annotations = loki_annotation_targets(cls.builder)
        cls.everything = cls.panels + cls.sentinels + cls.annotations

    def test_the_target_inventory_covers_every_emitted_logql_string(self):
        """Guards the guard: `_loki_exprs` is the builder's own tally of LogQL it
        emitted, so a panel helper that stopped registering its datasource type
        would otherwise drop out of this file silently. Annotation queries are in
        that tally too, and are counted here so adding one cannot make the panel
        arithmetic drift instead of failing."""
        self.assertTrue(self.panels, "no Loki panel targets found at all")
        self.assertTrue(self.sentinels, "no Loki sentinels found at all")
        self.assertTrue(self.annotations, "no Loki annotations found at all")
        self.assertEqual(
            len(self.builder._loki_exprs), len(self.panels) + len(self.annotations),
            "Loki targets found by this test disagree with Builder._loki_exprs",
        )

    def test_logql_never_reaches_the_prometheus_coverage_gate(self):
        """`_exprs` feeds the metric-coverage gate; a LogQL string in there would
        both corrupt coverage and hide a missing panel."""
        leaked = [expr for expr in self.builder._exprs if "$__auto" in expr]
        self.assertEqual([], leaked, f"LogQL leaked into Builder._exprs: {leaked}")

    def test_every_logql_stream_selector_is_scoped_to_an_appliance(self):
        unscoped = []
        for label, expr in self.everything:
            if label in LOKI_SCOPE_EXCEPTIONS:
                continue
            selector = stream_selector(expr)
            self.assertNotEqual("", selector, f"{label}: no stream selector in {expr}")
            if INSTANCE_LABEL not in selector:
                unscoped.append(f"{label} -> {selector}")
        self.assertEqual(
            [], sorted(unscoped),
            f"{len(unscoped)} LogQL target(s) query the whole fleet's logs:\n  "
            + "\n  ".join(sorted(unscoped)),
        )

    def test_the_instance_matcher_precedes_every_filter_and_aggregation(self):
        """A matcher that lands after the `|` or inside the range/aggregation has
        already let other appliances' lines into the sum."""
        late = []
        for label, expr in self.everything:
            if label in LOKI_SCOPE_EXCEPTIONS:
                continue
            at = expr.find(INSTANCE_LABEL)
            if at == -1:
                continue  # reported by the presence test above
            for construct, token in (("line filter", "|"), ("range selector", "[")):
                pos = expr.find(token)
                if pos != -1 and pos < at:
                    late.append(f"{label}: matcher follows the {construct} -> {expr}")
        self.assertEqual(
            [], sorted(late),
            "LogQL target(s) filter by appliance too late:\n  " + "\n  ".join(sorted(late)),
        )

    def test_the_shared_seam_is_what_produced_the_matcher(self):
        """Every scoped target should carry the exact matcher `loki_sel()` emits;
        a hand-rolled variant is how the seam gets bypassed next time."""
        offbrand = [
            f"{label} -> {stream_selector(expr)}"
            for label, expr in self.everything
            if label not in LOKI_SCOPE_EXCEPTIONS
            and EXPECTED_MATCHER not in stream_selector(expr)
        ]
        self.assertEqual(
            [], sorted(offbrand),
            f"LogQL target(s) not built through loki_sel():\n  " + "\n  ".join(sorted(offbrand)),
        )

    def test_stale_exception_entries_are_removed(self):
        labels = {label for label, _ in self.everything}
        stale = sorted(set(LOKI_SCOPE_EXCEPTIONS) - labels)
        self.assertEqual([], stale, f"stale LOKI_SCOPE_EXCEPTIONS entries: {stale}")


if __name__ == "__main__":
    unittest.main()
