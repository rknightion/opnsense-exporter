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

        self.assertEqual(len(build_rules.RULES), 29)
        self.assertEqual(len(alerts), 29)
        self.assertEqual(len(build_rules.RECORDING), 13)
        self.assertEqual(len(recordings), 13)
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
