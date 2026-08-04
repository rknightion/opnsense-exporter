import ast
import sys
import unittest
from pathlib import Path


GRAFANA_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GRAFANA_DIR))

import build_dashboard  # noqa: E402
from builder import Builder, sel  # noqa: E402


STABLE_PREFIX = (
    "max without (job, service_instance_id, service_name, service_version) ("
)


def query_model(panel):
    return panel["spec"]["data"]["spec"]["queries"][0]["spec"]["query"]["spec"]


class QuerySemanticsTest(unittest.TestCase):
    def test_pipeline_queries_follow_the_stable_opnsense_instance_identity(self):
        """The logship self-metric family carries opnsense_instance, so the ordinary
        selector is correct for it. This used to assert the same thing about a
        `sel_pipeline()` alias; #466 removed the alias, which was a pure alias of
        `sel()` expressing an intent it did not implement."""

        self.assertEqual(
            sel("opnsense_exporter_logs_queue_length"),
            'opnsense_exporter_logs_queue_length{opnsense_instance=~"$opnsense_instance"}',
        )
        self.assertEqual(
            sel("opnsense_exporter_logs_dropped_total", 'reason="overflow"'),
            'opnsense_exporter_logs_dropped_total{opnsense_instance=~"$opnsense_instance",reason="overflow"}',
        )

    def test_prometheus_query_preserves_exporter_instance_while_removing_deployment_labels(self):
        builder = Builder()

        query = builder._query(
            'opnsense_up{opnsense_instance="edge",instance="exporter-a"}'
        )

        model = query["spec"]["query"]["spec"]
        self.assertEqual(
            model["expr"],
            STABLE_PREFIX
            + 'opnsense_up{opnsense_instance="edge",instance="exporter-a"})',
        )
        self.assertNotIn("without (instance,", model["expr"])

    def test_stat_query_mode_follows_whether_the_panel_has_a_sparkline(self):
        builder = Builder()
        default_area = builder.stat("Default sparkline", "opnsense_load")
        explicit_area = builder.stat(
            "Explicit sparkline", "opnsense_temperature", graph="area"
        )
        current_card = builder.stat(
            "Current status", "opnsense_up", graph="none"
        )

        for name in (default_area, explicit_area):
            model = query_model(builder.elements[name])
            self.assertFalse(model["instant"])
            self.assertTrue(model["range"])

        model = query_model(builder.elements[current_card])
        self.assertTrue(model["instant"])
        self.assertFalse(model["range"])

    def test_non_stat_current_value_visualizations_remain_instant_by_default(self):
        builder = Builder()
        gauge = builder.gauge("Pressure", "opnsense_pressure")

        model = query_model(builder.elements[gauge])
        self.assertTrue(model["instant"])
        self.assertFalse(model["range"])

    def test_every_prometheus_visualization_supports_dedupe_opt_out(self):
        builder = Builder()
        raw_expr = 'opnsense_up{instance="exporter-a"}'
        panels = [
            builder.ts("Timeseries", [(raw_expr, "up")], dedupe=False),
            builder.stat("Stat", raw_expr, dedupe=False),
            builder.gauge("Gauge", raw_expr, dedupe=False),
            builder.bargauge("Bar gauge", [(raw_expr, "up")], dedupe=False),
            builder.table("Table", [raw_expr], dedupe=False),
            builder.statetimeline(
                "State timeline", [(raw_expr, "up")], {"1": ("Up", "green")},
                dedupe=False,
            ),
            builder.statushistory(
                "Status history", [(raw_expr, "up")], {"1": ("Up", "green")},
                dedupe=False,
            ),
            builder.piechart("Pie", [(raw_expr, "up")], dedupe=False),
        ]

        for panel in panels:
            queries = builder.elements[panel]["spec"]["data"]["spec"]["queries"]
            for query in queries:
                model = query["spec"]["query"]["spec"]
                self.assertEqual(model["expr"], raw_expr)

    def test_tab_stat_calls_do_not_request_instant_data_for_sparklines(self):
        violations = []
        for path in sorted((GRAFANA_DIR / "tabs").glob("*.py")):
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if not (
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and node.func.attr == "stat"
                ):
                    continue
                keywords = {
                    keyword.arg: ast.literal_eval(keyword.value)
                    for keyword in node.keywords
                    if keyword.arg in {"graph", "instant"}
                }
                if (
                    keywords.get("graph", "area") == "area"
                    and keywords.get("instant") is True
                ):
                    violations.append(f"{path.name}:{node.lineno}")

        self.assertEqual(violations, [])

    def test_state_timelines_remain_range_queries(self):
        builder = Builder()
        panel = builder.statetimeline(
            "Status history",
            [("opnsense_up", "{{opnsense_instance}}")],
            {"0": ("Down", "red"), "1": ("Up", "green")},
        )

        model = query_model(builder.elements[panel])
        self.assertFalse(model["instant"])
        self.assertTrue(model["range"])


class NestedLayoutTest(unittest.TestCase):
    def test_tab_group_nests_leaf_tabs_without_losing_conditions(self):
        builder = Builder()
        builder.sentinel("has_feature", metric="opnsense_feature")
        panel = builder.stat("Feature", "opnsense_feature")
        builder.tab("Feature", [panel], present="has_feature")
        leaf = builder.tabs.pop()

        self.assertTrue(hasattr(builder, "tab_group"))
        builder.tab_group("Services", [leaf])

        parent = builder.tabs[0]
        child = parent["spec"]["layout"]["spec"]["tabs"][0]
        self.assertEqual(parent["spec"]["title"], "Services")
        self.assertEqual(parent["spec"]["layout"]["kind"], "TabsLayout")
        self.assertEqual(child["spec"]["title"], "Feature")
        self.assertIn("conditionalRendering", child["spec"])

    def test_multiple_presence_variables_form_an_or_condition(self):
        condition = Builder._cond(present=["has_nut", "has_apcupsd"])

        self.assertEqual(condition["spec"]["condition"], "or")
        self.assertEqual(
            [item["spec"]["variable"] for item in condition["spec"]["items"]],
            ["has_nut", "has_apcupsd"],
        )


if __name__ == "__main__":
    unittest.main()


class TableValueColumnKeyTest(unittest.TestCase):
    """#509: the value column's field name depends on how many exprs the table has,
    and the two spellings are correct in exactly opposite cases. A single-expr
    Prometheus table names it bare "Value"; multi-expr names them "Value #A"..
    "Value #N". `panel-146` renamed "Value #A" on a single-expr table AND excluded
    "Value", so the timestamp it existed to show was dropped and the rename matched
    nothing — a table that rendered one column, with a valid manifest, passing tests
    and a passing coverage gate."""

    def test_single_expr_table_rejects_the_loki_value_column_spelling(self):
        b = Builder()
        b.table("Bad", [sel("opnsense_up")], renames={"Value #A": "When"})
        self.assertTrue(
            any("Value #A" in v for v in b._table_key_violations),
            "a 'Value #A' rename on a single-expr table matches nothing and must fail the build",
        )

    def test_single_expr_table_accepts_the_bare_value_column(self):
        b = Builder()
        b.table("Good", [sel("opnsense_up")], renames={"Value": "When"})
        self.assertEqual(b._table_key_violations, [])

    def test_multi_expr_table_still_rejects_the_bare_value_column(self):
        """The #97 guard, kept honest while its mirror image was added."""
        b = Builder()
        b.table("Bad", [sel("opnsense_up"), sel("opnsense_up")], renames={"Value": "When"})
        self.assertTrue(any("Value" in v for v in b._table_key_violations))

    def test_instance_label_is_titled_without_the_call_site_asking(self):
        """#514: half the tables shipped the raw Prometheus label name as a column
        header because each call site had to remember the rename."""
        b = Builder()
        name = b.table("T", [sel("opnsense_up")], renames={"Value": "V"})
        org = next(t for t in b.elements[name]["spec"]["data"]["spec"]["transformations"]
                   if t["group"] == "organize")
        self.assertEqual(org["spec"]["options"]["renameByName"]["opnsense_instance"], "Instance")


class StateTimelinePolarityTest(unittest.TestCase):
    """#511: one panel-wide mapping cannot serve two polarities. A UPS panel plots
    `online` (1 = good) beside `on_battery` (1 = bad), so whichever polarity the
    panel-wide mapping encodes, the other rows are painted the wrong colour — and on
    a state timeline the colour is the whole signal."""

    def test_per_series_mapping_overrides_the_panel_wide_one(self):
        b = Builder()
        name = b.statetimeline(
            "UPS", [(sel("opnsense_nut_status_online"), "online"),
                    (sel("opnsense_nut_status_on_battery"), "on battery")],
            {"0": ("No", "green"), "1": ("Yes", "orange")},
            series_mappings={"online": {"0": ("No", "red"), "1": ("Yes", "green")}},
        )
        ov = b.elements[name]["spec"]["vizConfig"]["spec"]["fieldConfig"]["overrides"]
        self.assertEqual(len(ov), 1)
        self.assertEqual(ov[0]["matcher"]["options"], "online")
        opts = ov[0]["properties"][0]["value"][0]["options"]
        self.assertEqual(opts["1"]["color"], "green")

    def test_a_series_mapping_for_a_legend_that_does_not_exist_fails_the_build(self):
        b = Builder()
        b.statetimeline("UPS", [(sel("opnsense_nut_status_online"), "online")],
                        {"0": ("No", "green"), "1": ("Yes", "orange")},
                        series_mappings={"typo": {"0": ("No", "red")}})
        self.assertTrue(b._table_key_violations)

    def test_an_empty_mapping_emits_no_dead_mapping_object(self):
        """#510: `mappings={}` shipped a bare {"type":"value","options":{}} into the
        JSON — dead config that reads as intent to the next author."""
        b = Builder()
        name = b.statetimeline("Census", [(sel("opnsense_up"), "{{state}}")], {})
        defaults = b.elements[name]["spec"]["vizConfig"]["spec"]["fieldConfig"]["defaults"]
        self.assertEqual(defaults["mappings"], [])


class CoverageSourceTest(unittest.TestCase):
    """`coverage()` must see PANEL queries and nothing else (#619).

    The sibling project's every-signal-reaches-a-panel gate counted a hidden
    sentinel's `label_values()` call as coverage, so a metric could satisfy it while
    appearing on no panel (rknightion/tailscale2otel#527). This repo does not have
    that bug — `sentinel()` appends to `variables`, never to `_exprs` — but nothing
    enforced it, and a comment saying so is not a guard.
    """

    def test_a_sentinel_does_not_count_as_panel_coverage(self):
        b = Builder()
        b.sentinel("has_thing", metric="opnsense_thing_present")
        self.assertNotIn(
            "opnsense_thing_present", "\n".join(b._exprs),
            "a presence sentinel's query reached _exprs, which is what coverage() "
            "reads — the metric now satisfies the coverage gate without appearing "
            "on any panel an operator can look at")
        self.assertTrue(
            any("opnsense_thing_present" in str(v) for v in b.variables),
            "the sentinel was not registered at all, so this test proves nothing")

    def test_a_loki_sentinel_does_not_count_as_panel_coverage(self):
        b = Builder()
        b.loki_sentinel("has_stream", label="opnsense_subsystem",
                        matchers='opnsense_subsystem="thing"')
        self.assertNotIn("opnsense_subsystem", "\n".join(b._exprs))
        self.assertNotIn("opnsense_subsystem", "\n".join(b._loki_exprs),
                         "a Loki sentinel reached _loki_exprs; the log-stream "
                         "coverage gate would then be satisfied by the probe for a "
                         "stream rather than by a panel selecting it")

    def test_a_panel_query_does_count(self):
        """The control. Without it the two tests above pass on an empty builder."""
        b = Builder()
        b.ts("T", [(sel("opnsense_thing_present"), "x")])
        self.assertIn("opnsense_thing_present", "\n".join(b._exprs))


class PercentGaugeBoundTest(unittest.TestCase):
    """#649: a percent gauge without `mx` auto-scales its arc, so its thresholds land
    at meaningless positions on the dial.

    Four gauges shipped this way — two raw SMART percentages and two `100 * used /
    limit` ratios, all four carrying real severity boundaries. A drive at 4% spare
    and one at 96% painted arcs of the same length, and the 10/50 markers sat wherever
    the observed range put them. The class fix is a build-time refusal rather than an
    injected default: `mx` is not always 100 (the two SMART wear gauges use 120 so a
    drive past its rated endurance stays legible rather than pinning), so the call
    site has to choose. This is deliberately NOT the #467 case in reverse — a max on
    a bounded unit is that unit's own domain, while a threshold is a severity claim
    the caller alone can make.
    """

    def test_percent_gauge_without_a_max_fails_the_build(self):
        for unit in ("percent", "percentunit"):
            with self.subTest(unit=unit):
                with self.assertRaises(ValueError):
                    Builder().gauge("Utilization", "m", unit=unit)

    def test_an_explicit_max_is_honoured_including_deliberate_overshoot(self):
        for unit, mx in (("percent", 100), ("percent", 120), ("percentunit", 1)):
            with self.subTest(unit=unit, mx=mx):
                b = Builder()
                name = b.gauge("Utilization", "m", unit=unit, mx=mx)
                defaults = b.elements[name]["spec"]["vizConfig"]["spec"]["fieldConfig"]["defaults"]
                self.assertEqual(defaults["max"], mx)

    def test_unbounded_units_are_untouched(self):
        """The rule is about units with a domain, not about gauges in general — a
        gauge on bytes or a rate has no max to state and must not be forced to."""
        for unit in ("short", "bytes", "reqps", "celsius"):
            with self.subTest(unit=unit):
                b = Builder()
                name = b.gauge("Count", "m", unit=unit)
                defaults = b.elements[name]["spec"]["vizConfig"]["spec"]["fieldConfig"]["defaults"]
                self.assertNotIn("max", defaults)

    def test_every_shipped_percent_gauge_is_bounded(self):
        """The build-time guard covers `gauge()`; this covers the generated result,
        so a percent gauge arriving through some other helper cannot slip past."""
        unbounded = []
        for _, b in build_dashboard.build_family():
            for el in b.elements.values():
                if el["kind"] != "Panel":
                    continue
                viz = el["spec"]["vizConfig"]
                if viz["group"] != "gauge":
                    continue
                defaults = viz["spec"]["fieldConfig"]["defaults"]
                if defaults.get("unit") in ("percent", "percentunit") and "max" not in defaults:
                    unbounded.append(el["spec"]["title"])
        self.assertEqual(sorted(unbounded), [])
