import importlib.util
import re
import sys
import unittest
from pathlib import Path


GRAFANA_DIR = Path(__file__).resolve().parents[1]
ALERTS_DIR = GRAFANA_DIR / "alerts"
sys.path.insert(0, str(GRAFANA_DIR))
sys.path.insert(0, str(ALERTS_DIR))

from alerts.build_rules import RECORDING  # noqa: E402
from builder import INSTANCE_SEL, Builder, sel  # noqa: E402


METRIC_NAME = re.compile(r"instance:opnsense_[a-z0-9_:]+")


class RecordingRulesTabTest(unittest.TestCase):
    @staticmethod
    def build_leaf():
        module_path = GRAFANA_DIR / "tabs" / "recording_rules.py"
        if not module_path.exists():
            raise AssertionError("the Recording rules leaf has not been implemented")

        spec = importlib.util.spec_from_file_location("recording_rules", module_path)
        module = importlib.util.module_from_spec(spec)
        assert spec.loader is not None
        spec.loader.exec_module(module)

        builder = Builder()
        module.build(builder)
        return builder

    def test_leaf_covers_generated_recording_metrics_and_is_presence_gated(self):
        builder = self.build_leaf()

        expected_metrics = {rule["metric"] for rule in RECORDING}
        queried_metrics = {
            metric
            for expression in builder._exprs
            for metric in METRIC_NAME.findall(expression)
        }
        self.assertEqual(queried_metrics, expected_metrics)

        sentinel = next(
            variable
            for variable in builder.variables
            if variable["spec"]["name"] == "has_recording_rules"
        )
        # Scoped to the selected appliance like every other sentinel (#414): the
        # recording rules all preserve opnsense_instance, so the derived series are
        # per-box and the family probe has to be too.
        self.assertEqual(
            sentinel["spec"]["query"]["spec"]["query"],
            f'label_values({{__name__=~"instance:opnsense_.+",{INSTANCE_SEL}}}, __name__)',
        )

        self.assertEqual(len(builder.tabs), 1)
        leaf = builder.tabs[0]
        self.assertEqual(leaf["spec"]["title"], "Recording rules")
        condition = leaf["spec"]["conditionalRendering"]
        self.assertEqual(
            condition["spec"]["items"],
            [
                {
                    "kind": "ConditionalRenderingVariable",
                    "spec": {
                        "variable": "has_recording_rules",
                        "operator": "matches",
                        "value": ".+",
                    },
                }
            ],
        )

    def test_optional_signal_families_have_sentinels_and_conditional_rows(self):
        builder = self.build_leaf()
        variables = {
            variable["spec"]["name"]: variable["spec"]["query"]["spec"]["query"]
            for variable in builder.variables
        }
        # Which recording-rule metric each row's sentinel probes. The query is built
        # from `sel()` rather than spelled out so this test stays about the mapping;
        # the scoping FORMAT is pinned by tests/test_sentinel_scoping.py (#414).
        expected_sentinel_metrics = {
            "has_recording_gateway_loss": "instance:opnsense_gateway_loss:ratio",
            "has_recording_ipsec": "instance:opnsense_ipsec_tunnels_down:count",
            "has_recording_wireguard": "instance:opnsense_wireguard_peers_down:count",
            "has_recording_unbound": "instance:opnsense_unbound_queries:rate5m",
            "has_recording_zenarmor": "instance:opnsense_zenarmor_block:ratio5m",
            "has_recording_haproxy": "instance:opnsense_haproxy_5xx:ratio5m",
            "has_recording_ids": "instance:opnsense_ids_alerts:active",
        }
        for name, metric in expected_sentinel_metrics.items():
            with self.subTest(sentinel=name):
                self.assertEqual(variables.get(name), f"label_values({sel(metric)}, __name__)")

        rows = builder.tabs[0]["spec"]["layout"]["spec"]["rows"]
        rows_by_title = {row["spec"]["title"]: row for row in rows}
        expected_conditions = {
            "Gateway Health": "has_recording_gateway_loss",
            "IPsec Health": "has_recording_ipsec",
            "WireGuard Health": "has_recording_wireguard",
            "Unbound DNS": "has_recording_unbound",
            "Zenarmor": "has_recording_zenarmor",
            "HAProxy": "has_recording_haproxy",
            "IDS / IPS": "has_recording_ids",
        }
        for title, variable in expected_conditions.items():
            with self.subTest(row=title):
                condition = rows_by_title[title]["spec"]["conditionalRendering"]
                self.assertEqual(
                    condition["spec"]["items"][0]["spec"]["variable"], variable
                )

        self.assertNotIn(
            "conditionalRendering", rows_by_title["Resource Pressure"]["spec"]
        )
        self.assertNotIn("conditionalRendering", rows_by_title["Traffic"]["spec"])


class RecordingRuleDashboardPlacementTest(unittest.TestCase):
    """#523: the Recording rules tab lives on the EXPORTER HEALTH dashboard, whole.

    This reverses #431's per-rule sort, and the reversal is the owner's, not a
    refactor. #431's rule was "a recording rule relating to self-observability may
    move, the rest stay on the main dashboard, because they generate data used for
    monitoring OPNsense". All 14 bundled rules are firewall-derived, so that rule
    produced an empty move set and the tab stayed put — and the tab it stayed on was
    then the problem #523 found: every panel of it restates a raw System, Interfaces
    or Firewall panel in precomputed form, so on the operational dashboard it was a
    second place to read the same figure. On the health dashboard it answers a
    question nothing else does — are the bundled rules actually evaluating?

    So placement is no longer per rule and there is no classifier any more. What this
    test still guarantees is the thing that mattered in #431: no recording rule is
    silently uncharted, and a new one has to be given a panel.
    """

    @classmethod
    def setUpClass(cls):
        import build_dashboard
        cls.by_uid = {spec.uid: b for spec, b in build_dashboard.build_family()}
        cls.uids = __import__("uids")

    def _dashboards_charting(self, metric):
        return {uid for uid, b in self.by_uid.items()
                if any(metric in expr for expr in b._exprs)}

    def test_every_recording_rule_is_charted_on_the_health_dashboard(self):
        for rule in RECORDING:
            with self.subTest(metric=rule["metric"]):
                charted = self._dashboards_charting(rule["metric"])
                self.assertIn(
                    self.uids.HEALTH_UID, charted,
                    f"{rule['metric']} is charted on {sorted(charted) or 'no dashboard'}; "
                    "every bundled recording rule belongs on the Recording rules tab, "
                    "which lives on the exporter health dashboard since #523")

    def test_the_precomputed_series_are_not_also_charted_on_the_main_dashboard(self):
        """The reason the tab moved. A recording rule's output appearing on the
        operational dashboard means an operator has two panels for one figure — the
        raw one and the precomputed one — and no way to tell which is authoritative."""
        for rule in RECORDING:
            with self.subTest(metric=rule["metric"]):
                self.assertNotIn(self.uids.MAIN_UID,
                                 self._dashboards_charting(rule["metric"]))


if __name__ == "__main__":
    unittest.main()
