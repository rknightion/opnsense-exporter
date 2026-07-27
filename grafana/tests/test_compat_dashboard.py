"""Guard: the Grafana 11/12 compatibility artifact is classic, complete and derived (#420).

`verify_compat_import.sh` is the real acceptance test — it imports into pinned
Grafana 11.5.0 and 12.4.0 containers and reads the result back — but it needs docker,
so CI runs it in its own workflow. This file holds everything checkable without one,
and it is the part that runs on every commit:

* the artifact is CLASSIC schema, with no v2-only construct that Grafana 11 would
  choke on (that is the whole failure #22 reported);
* it is DERIVED from `dashboard.json` and not drifting — every panel title, query and
  variable in it exists in the canonical artifact;
* the bounded inventory is exactly the unconditional panels, and the omission is
  intentional rather than a converter that quietly dropped something.
"""

import json
import subprocess
import sys
import unittest
from pathlib import Path


GRAFANA_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GRAFANA_DIR))

import build_compat  # noqa: E402

CANONICAL = GRAFANA_DIR / "dashboard.json"
COMPAT = GRAFANA_DIR / "dashboard-compat.json"

# v2-only keys. Any of these in the classic artifact means the converter leaked a
# construct Grafana 11/12 cannot interpret.
V2_ONLY_KEYS = {"elements", "layout", "vizConfig", "timeSettings", "cursorSync",
                "conditionalRendering", "variables", "queryOptions"}
V2_ONLY_KINDS = {"TabsLayout", "RowsLayout", "GridLayout", "Panel", "VizConfig",
                 "QueryGroup", "PanelQuery", "DataQuery", "ElementReference",
                 "GridLayoutItem", "RowsLayoutRow", "TabsLayoutTab", "Transformation"}


def walk(node):
    if isinstance(node, dict):
        yield node
        for value in node.values():
            yield from walk(value)
    elif isinstance(node, list):
        for value in node:
            yield from walk(value)


class CompatArtifactTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.canonical = json.loads(CANONICAL.read_text())
        cls.compat = json.loads(COMPAT.read_text())
        cls.rows = [p for p in cls.compat["panels"] if p["type"] == "row"]
        cls.leaves = [p for p in cls.compat["panels"] if p["type"] != "row"]

    def test_the_committed_artifact_matches_the_generator(self):
        """The staleness gate `make grafana-check` also runs, but a failing unit test
        names the cause; a bare `git diff --exit-code` does not."""
        result = subprocess.run(
            [sys.executable, str(GRAFANA_DIR / "build_compat.py"), "--check"],
            capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_it_is_classic_schema_and_carries_no_v2_construct(self):
        self.assertEqual(self.compat["schemaVersion"], build_compat.SCHEMA_VERSION)
        self.assertIn("panels", self.compat)
        self.assertIn("templating", self.compat)
        for node in walk(self.compat):
            leaked = V2_ONLY_KEYS & set(node)
            self.assertEqual(leaked, set(), f"v2-only key(s) {leaked} in {node.get('title')!r}")
            self.assertNotIn(node.get("kind"), V2_ONLY_KINDS,
                             f"v2 kind {node.get('kind')!r} leaked into the classic artifact")

    def test_every_panel_has_a_recognised_classic_type(self):
        allowed = set(build_compat.PANEL_TYPES.values()) | {"row"}
        types = {p["type"] for p in self.compat["panels"]}
        self.assertEqual(types - allowed, set())

    def test_every_leaf_panel_keeps_its_targets_and_a_unique_id(self):
        ids = [p["id"] for p in self.compat["panels"]]
        self.assertEqual(len(ids), len(set(ids)), "duplicate panel ids")
        for panel in self.leaves:
            with self.subTest(title=panel["title"]):
                self.assertTrue(panel["targets"], "panel lost its query")
                for target in panel["targets"]:
                    self.assertIn("expr", target)
                    self.assertIn("uid", target["datasource"])

    def test_a_loki_panel_keeps_the_loki_datasource(self):
        """The converter defaults to Prometheus; a Loki panel pointed at the
        Prometheus picker would render an error rather than logs. There are only two
        of them in the unconditional set at most, so assert on whichever exist."""
        loki = [p for p in self.leaves
                if any(t["datasource"]["type"] == "loki" for t in p["targets"])]
        for panel in loki:
            with self.subTest(title=panel["title"]):
                self.assertEqual(panel["datasource"]["type"], "loki")

    def test_it_is_derived_from_the_canonical_artifact(self):
        """Every title and every query text must exist in dashboard.json. This is what
        makes 'converted, never authored' checkable instead of a claim in a docstring."""
        canonical_titles = {e["spec"]["title"]
                            for e in self.canonical["spec"]["elements"].values()}
        canonical_exprs = {q["spec"]["query"]["spec"]["expr"]
                           for e in self.canonical["spec"]["elements"].values()
                           for q in e["spec"]["data"]["spec"]["queries"]}
        for panel in self.leaves:
            with self.subTest(title=panel["title"]):
                self.assertIn(panel["title"], canonical_titles)
                for target in panel["targets"]:
                    self.assertIn(target["expr"], canonical_exprs)

    def test_the_bounded_inventory_is_exactly_the_unconditional_panels(self):
        """The boundary is principled, not a taste call: classic has no conditional
        rendering, so anything gated on a feature sentinel would render permanently
        empty. Recomputing it here means a newly-gated tab leaves the compat artifact
        automatically, and a newly-ungated one joins it."""
        expected = 0
        for _title, rows in build_compat.leaf_tabs(
                self.canonical["spec"]["layout"]["spec"]["tabs"]):
            for row in rows:
                expected += len(row["spec"]["layout"]["spec"]["items"])
        self.assertEqual(len(self.leaves), expected)
        self.assertGreater(len(self.leaves), 150, "the bounded set has collapsed")
        self.assertLess(len(self.leaves), len(self.canonical["spec"]["elements"]),
                        "nothing was bounded — gated panels leaked in")

    def test_no_gated_panel_leaked_in(self):
        """Direct check of the failure the boundary exists to prevent: a panel that
        only exists behind a sentinel must not appear in the classic artifact."""
        # A title can be reused by an ungated panel elsewhere, so compare on the
        # (title, expr) pair to avoid a false failure on a duplicate name.
        gated_pairs = set()
        def pairs(tabs, gated=False):
            for tab in tabs:
                spec = tab["spec"]
                is_gated = gated or "conditionalRendering" in spec
                layout = spec["layout"]
                if layout["kind"] == "TabsLayout":
                    pairs(layout["spec"]["tabs"], is_gated)
                    continue
                for row in layout["spec"]["rows"]:
                    row_gated = is_gated or "conditionalRendering" in row["spec"]
                    for item in row["spec"]["layout"]["spec"]["items"]:
                        name = item["spec"]["element"]["name"]
                        element = self.canonical["spec"]["elements"][name]
                        for query in element["spec"]["data"]["spec"]["queries"]:
                            key = (element["spec"]["title"],
                                   query["spec"]["query"]["spec"]["expr"])
                            if row_gated:
                                gated_pairs.add(key)
                            else:
                                gated_pairs.discard(key)
        pairs(self.canonical["spec"]["layout"]["spec"]["tabs"])
        self.assertTrue(gated_pairs, "no gated panels found — the check is vacuous")
        leaked = sorted({(p["title"], t["expr"]) for p in self.leaves
                         for t in p["targets"]} & gated_pairs)
        self.assertEqual(leaked, [])

    def test_variables_are_converted_completely_and_classically(self):
        canonical_vars = self.canonical["spec"]["variables"]
        compat_vars = self.compat["templating"]["list"]
        self.assertEqual(len(compat_vars), len(canonical_vars))
        self.assertEqual([v["name"] for v in compat_vars],
                         [v["spec"]["name"] for v in canonical_vars])
        for variable in compat_vars:
            with self.subTest(name=variable["name"]):
                self.assertIn(variable["type"], ("query", "datasource"))
                # #22's report was an interval variable's kind/refresh failing
                # 12.4 validation. `refresh` must be the classic INTEGER code here,
                # not v2's enum string, or the same class of failure returns.
                self.assertIsInstance(variable["refresh"], int)
                self.assertIn(variable["hide"], (0, 1, 2))

    def test_the_hidden_sentinels_stay_hidden(self):
        """106 variables include ~100 presence sentinels. If those lost hide=2 the
        dashboard would show a hundred pickers, which is a usability failure severe
        enough to make the artifact worthless."""
        hidden = [v for v in self.compat["templating"]["list"] if v["hide"] == 2]
        self.assertGreater(len(hidden), 90)

    def test_it_declares_what_it_is_and_what_it_dropped(self):
        marker = self.compat["__opnsenseExporterCompat"]
        self.assertEqual(marker["generatedFrom"], "grafana/dashboard.json")
        self.assertEqual(list(marker["supportedGrafanaVersions"]),
                         list(build_compat.SUPPORTED_VERSIONS))
        self.assertTrue(marker["degradation"])
        self.assertIn("compat", self.compat["tags"])
        self.assertIn("COMPATIBILITY BUILD", self.compat["description"])
        self.assertNotEqual(self.compat["uid"], self.canonical["metadata"]["name"],
                            "the compat artifact must not collide with the canonical uid")


if __name__ == "__main__":
    unittest.main()
