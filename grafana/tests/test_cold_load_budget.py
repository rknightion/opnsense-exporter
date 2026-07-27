"""Guard: the dashboard's cold-load query fan-out stays within a measured budget (#422).

## What was measured, and what it showed

Every cold-load query was enumerated from the generated manifest and executed
read-only against the live stack on 2026-07-27 (Prometheus `grafanacloud-prom`, Loki
`grafanacloud-logs`, one instance selected, absolute 6h window). 134 measurable
queries, none of which errored, all landing in a 604–1066 ms band with a mean of
794 ms — and a control pair proved that band is almost entirely per-request overhead
rather than backend work: a trivial `up` query averaged ~0.8 s while a deliberately
heavy 44,525-series match averaged ~1.5 s.

So **no single query is expensive, and cold-load cost is a function of how many
queries are issued.** That is what this file bounds. Optimising a query's PromQL
would move nothing; adding forty more sentinels would.

The census at the time these budgets were set:

* 102 variables refreshing `onDashboardLoad` (100 presence sentinels + the instance
  picker), plus `$interface` and `$device` which refresh on time-range change and so
  also run on the initial load;
* 12 of 16 annotation layers enabled by default (8 Prometheus, 2 Loki, 2 built-in
  store); the other 4 are default-off and cost nothing until enabled;
* 20 panel queries on the Overview tab. The other 984 panel queries across the 41
  leaf tabs are deferred until a tab is opened, which is what makes a 739-panel
  dashboard loadable at all — and is exactly the property a careless layout change
  could destroy.

## Why budgets rather than exact counts

An exact count fails on every added panel, which trains people to bump the number
without reading it. These are ceilings with deliberate headroom: crossing one means
the cold-load contract changed materially, so re-measure and move the budget on
purpose. `test_budgets_have_headroom_but_not_a_licence` keeps the headroom honest in
the other direction — a budget quietly raised to double the real figure stops being
a guard.
"""

import sys
import unittest
from collections import Counter
from pathlib import Path

GRAFANA_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GRAFANA_DIR))

import build_dashboard  # noqa: E402


# Ceilings, measured 2026-07-27 (see module docstring). Raise only with a fresh
# measurement, and say in the commit what it showed.
MAX_LOAD_VARIABLES = 112          # measured 104 (102 onDashboardLoad + 2 onTimeRangeChanged)
MAX_ENABLED_ANNOTATIONS = 16      # measured 12 enabled of 16 layers
MAX_COLD_TAB_QUERIES = 26         # measured 20 on Overview
MAX_COLD_LOAD_QUERIES = 145       # measured 136 in total

# Panel queries that are deliberately issued twice on the cold tab. Each entry is
# (panel title, panel title, metric) — the pair of panels that share one query.
#
# These three are REAL duplication and are kept knowingly: the Overview's three
# health stat tiles and the Health History status-history panel below them read the
# same three series over the same window, because one answers "what is it now" as a
# coloured tile and the other "what has it been" as a timeline. Grafana can share a
# query set within a panel but not across panels, so removing the duplication means
# deleting one of the two visualisations. Measured cost of keeping it: 3 extra round
# trips of the same ~800 ms per-request overhead every query here pays, under
# browser-side parallelism — which #422 judged not worth a worse Overview.
KNOWN_COLD_TAB_DUPLICATES = {
    ("Exporter scrape", "Health History", "opnsense_up"),
    ("Firewall health", "Health History", "opnsense_firewall_status"),
    ("Crash reports", "Health History", "opnsense_crash_reporter_status"),
}


def spec():
    return build_dashboard.build_all().manifest("t", "d", [])["spec"]


def load_variables(dash):
    """Variables whose query runs on a cold load.

    `onTimeRangeChanged` is included deliberately: applying the initial time range
    IS a change, so `$interface` and `$device` execute on load like everything else.
    Excluding them would have understated the census by two.
    """
    out = []
    for variable in dash["variables"]:
        vspec = variable["spec"]
        if variable["kind"] == "DatasourceVariable":
            continue
        if vspec.get("refresh") in ("onDashboardLoad", "onTimeRangeChanged"):
            out.append(vspec["name"])
    return out


def enabled_annotations(dash):
    return [a["spec"]["name"] for a in dash["annotations"] if a["spec"]["enable"]]


def cold_tab(dash):
    """The tab rendered on a cold load: the first top-level tab.

    It is unconditional by construction (Overview has no `conditionalRendering`), so
    it is the one tab whose panel queries are guaranteed to run before an operator
    clicks anything.
    """
    return dash["layout"]["spec"]["tabs"][0]


def cold_tab_queries(dash):
    tab = cold_tab(dash)
    layout = tab["spec"]["layout"]
    if layout["kind"] != "RowsLayout":
        raise AssertionError(
            f"cold tab {tab['spec']['title']!r} is no longer a RowsLayout; the cold-load "
            "census walks rows and must be updated with the layout")
    out = []
    for row in layout["spec"]["rows"]:
        for item in row["spec"]["layout"]["spec"]["items"]:
            name = item["spec"]["element"]["name"]
            panel = dash["elements"][name]["spec"]
            for query in panel["data"]["spec"]["queries"]:
                out.append((panel["title"], query["spec"]["query"]["spec"]["expr"]))
    return out


class ColdLoadBudgetTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.dash = spec()
        cls.variables = load_variables(cls.dash)
        cls.annotations = enabled_annotations(cls.dash)
        cls.queries = cold_tab_queries(cls.dash)

    def test_load_variable_count_is_within_budget(self):
        self.assertLessEqual(
            len(self.variables), MAX_LOAD_VARIABLES,
            f"{len(self.variables)} variables refresh on load, budget "
            f"{MAX_LOAD_VARIABLES}. This is the dominant cold-load cost (76% of "
            "queries when measured) and it is a COUNT problem: each is cheap, and "
            "they add up one round trip at a time. Consider a combined "
            "`__name__=~` family probe, as has_flow and has_log_events already do.")

    def test_enabled_annotation_count_is_within_budget(self):
        self.assertLessEqual(
            len(self.annotations), MAX_ENABLED_ANNOTATIONS,
            f"{len(self.annotations)} annotation layers are enabled by default, budget "
            f"{MAX_ENABLED_ANNOTATIONS}. A layer is a query on every load; a new one "
            "that is not needed by most operators should ship `enable=False`.")

    def test_cold_tab_query_count_is_within_budget(self):
        self.assertLessEqual(
            len(self.queries), MAX_COLD_TAB_QUERIES,
            f"the cold tab issues {len(self.queries)} queries, budget "
            f"{MAX_COLD_TAB_QUERIES}. Panels on other tabs are deferred until opened; "
            "panels added to Overview are not.")

    def test_total_cold_load_fan_out_is_within_budget(self):
        total = len(self.variables) + len(self.annotations) + len(self.queries)
        self.assertLessEqual(
            total, MAX_COLD_LOAD_QUERIES,
            f"cold load issues {total} queries, budget {MAX_COLD_LOAD_QUERIES}")

    def test_deferred_panels_stay_deferred(self):
        """The 41 leaf tabs must keep their panels off the cold path.

        This is the property that makes the dashboard loadable: 984 of the 1004 panel
        queries only run when their tab is opened. A layout change that hoisted them
        (flattening the tab layout, or `preload: true`) would multiply cold load by
        fifty, and every count above would still pass.
        """
        self.assertFalse(self.dash["preload"],
                         "preload:true loads EVERY tab's panels on open")
        total_queries = sum(len(e["spec"]["data"]["spec"]["queries"])
                            for e in self.dash["elements"].values())
        self.assertGreater(
            total_queries, 10 * len(self.queries),
            "the cold tab now carries a large share of all panel queries — either the "
            "tab layout was flattened or Overview grew a lot; re-measure cold load")

    def test_cold_tab_duplicate_queries_are_the_known_deliberate_ones(self):
        by_expr = {}
        for title, expr in self.queries:
            by_expr.setdefault(expr, []).append(title)
        found = set()
        for expr, titles in by_expr.items():
            if len(titles) < 2:
                continue
            metric = next((tok for tok in expr.replace("(", " ").replace("{", " ").split()
                           if tok.startswith("opnsense_")), expr[:40])
            found.add((titles[0], titles[1], metric))
        self.assertEqual(
            found, KNOWN_COLD_TAB_DUPLICATES,
            "the set of duplicated cold-load queries changed. Each duplicate is an "
            "extra round trip on every load; add it to KNOWN_COLD_TAB_DUPLICATES with "
            "the reason it is worth keeping, or collapse it.")

    def test_budgets_have_headroom_but_not_a_licence(self):
        """A budget more than 50% above the real figure is not a guard any more."""
        for name, actual, budget in (
                ("load variables", len(self.variables), MAX_LOAD_VARIABLES),
                ("enabled annotations", len(self.annotations), MAX_ENABLED_ANNOTATIONS),
                ("cold tab queries", len(self.queries), MAX_COLD_TAB_QUERIES)):
            self.assertLess(
                budget, actual * 1.5 + 2,
                f"the {name} budget ({budget}) is far above the actual figure "
                f"({actual}); tighten it or it will never fire")

    def test_the_census_counts_query_variables_and_nothing_else(self):
        """Sanity: the census must count round trips, not variables.

        Two variable kinds issue no datasource query and so cost nothing on load:
        `DatasourceVariable` lists installed datasources, and `TextVariable` is a
        textbox (#435 uses one for a Loki structured-metadata field that cannot be
        enumerated at all). Counting either would inflate the budget and make this
        guard measure something other than fan-out — which is the one thing the #422
        measurements identified as the real cost.
        """
        kinds = Counter(v["kind"] for v in self.dash["variables"])
        self.assertEqual(kinds["DatasourceVariable"], 2)
        free = kinds["DatasourceVariable"] + kinds["TextVariable"]
        self.assertEqual(len(self.variables), len(self.dash["variables"]) - free)
        self.assertEqual(kinds["QueryVariable"], len(self.variables))


if __name__ == "__main__":
    unittest.main()
