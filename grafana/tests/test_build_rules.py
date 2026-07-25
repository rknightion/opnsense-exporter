import json
import sys
import tempfile
import unittest
from pathlib import Path


ALERTS_DIR = Path(__file__).resolve().parents[1] / "alerts"
sys.path.insert(0, str(ALERTS_DIR))

import build_rules  # noqa: E402


class GrafanaManagedRuleGenerationTest(unittest.TestCase):
    def test_vpn_down_counts_preserve_zero_for_healthy_configured_instances(self):
        expressions = {
            rule["metric"]: rule["expr"] for rule in build_rules.RECORDING
        }

        self.assertEqual(
            expressions["instance:opnsense_ipsec_tunnels_down:count"],
            "sum by (opnsense_instance) "
            "(opnsense_ipsec_phase1_status == bool 0)",
        )
        self.assertEqual(
            expressions["instance:opnsense_wireguard_peers_down:count"],
            "sum by (opnsense_instance) "
            "(opnsense_wireguard_peer_status == bool 0)",
        )

    def test_recording_rules_use_instant_queries_without_changing_rule_inventory(self):
        with tempfile.TemporaryDirectory() as tmp:
            original_here = build_rules.HERE
            try:
                build_rules.HERE = tmp
                outdir, written = build_rules.emit_grafana_managed(
                    "test-prometheus", "test-opnsense-alerts", stack=False
                )
            finally:
                build_rules.HERE = original_here

            manifests = [json.loads(Path(path).read_text()) for path in written]

        alerts = [manifest for manifest in manifests if manifest["kind"] == "AlertRule"]
        recordings = [
            manifest for manifest in manifests if manifest["kind"] == "RecordingRule"
        ]

        # One manifest per source rule, no more and no fewer. This used to pin
        # literal counts (29 and 13) and simply rotted: adding a rule failed a
        # test that had nothing to say about the new rule, which trains people to
        # bump the number. The invariant worth holding is that emit_grafana_managed
        # neither drops nor invents rules; the floors below keep an accidentally
        # emptied RULES/RECORDING from passing trivially.
        self.assertEqual(len(alerts), len(build_rules.RULES))
        self.assertEqual(len(recordings), len(build_rules.RECORDING))
        self.assertGreaterEqual(len(build_rules.RULES), 25)
        self.assertGreaterEqual(len(build_rules.RECORDING), 12)
        self.assertEqual(Path(outdir).name, "grafana-managed")

        expected_expressions = {
            rule["metric"]: rule["expr"] for rule in build_rules.RECORDING
        }
        actual_expressions = {
            manifest["spec"]["metric"]: manifest["spec"]["expressions"]["A"][
                "model"
            ]["expr"]
            for manifest in recordings
        }
        self.assertEqual(actual_expressions, expected_expressions)

        invalid_modes = []
        for manifest in recordings:
            model = manifest["spec"]["expressions"]["A"]["model"]
            if (
                model["instant"] is not True
                or model["range"] is not False
                or model.get("format") != "table"
            ):
                invalid_modes.append(
                    (
                        manifest["spec"]["metric"],
                        model["instant"],
                        model["range"],
                        model.get("format"),
                    )
                )
        self.assertEqual(invalid_modes, [])


if __name__ == "__main__":
    unittest.main()
