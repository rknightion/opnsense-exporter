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


if __name__ == "__main__":
    unittest.main()
