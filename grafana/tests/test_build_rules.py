import json
import re
import sys
import tempfile
import unittest
from pathlib import Path


ALERTS_DIR = Path(__file__).resolve().parents[1] / "alerts"
sys.path.insert(0, str(ALERTS_DIR))

import build_rules  # noqa: E402


# The four poll tiers from internal/collector/interval_tiers.go, in seconds.
POLL_TIERS = {"fast": 15, "medium": 60, "slow": 300, "cold": 900}
# A Prometheus scrape interval, i.e. how stale the timestamp SAMPLE can be at
# alert-evaluation time. This is on top of the collector's own poll interval and is
# what the scrape-lag allowance in the rule exists to absorb.
SCRAPE_INTERVAL = 60


def rule_by_title(title):
    for rule in build_rules.RULES:
        if rule["title"] == title:
            return rule
    raise AssertionError(f"no rule titled {title}")


def missed_intervals(age, interval, slack):
    """Mirror of the staleness rules' PromQL, in Python.

    PromQL: (time() - <clock> - <slack>) / opnsense_exporter_collector_poll_interval_seconds
    """
    return (age - slack) / interval


class TierAwareStalenessToleranceTest(unittest.TestCase):
    """#382: staleness tolerance must be MISSED POLL INTERVALS, not a fixed window.

    These assert the behavioural contract rather than the literal numbers, so
    retuning the threshold or the scrape-lag allowance keeps the test meaningful:
    whatever the constants, a healthy collector and a single failed-then-recovered
    poll must not fire on ANY tier, and a persistent failure must fire on EVERY tier.
    """

    def setUp(self):
        self.rule = rule_by_title("OPNsenseCollectorDataStale")
        self.threshold = self.rule["params"][0]
        slack = re.search(r"- (\d+)\)\s*/", self.rule["A"])
        self.assertIsNotNone(slack, "data-stale rule lost its scrape-lag allowance")
        self.slack = int(slack.group(1))

    def test_expression_divides_by_the_collectors_own_poll_interval(self):
        # The whole point: tolerance scales per collector. A fixed window here is the
        # bug this rule exists to avoid.
        self.assertIn("opnsense_exporter_collector_poll_interval_seconds", self.rule["A"])
        self.assertIn("opnsense_exporter_collector_snapshot_timestamp_seconds", self.rule["A"])
        # last_poll advances on every FAILED attempt too, so it can never express
        # staleness — it must not appear in a staleness rule.
        self.assertNotIn("collector_last_poll_timestamp_seconds", self.rule["A"])

    def test_healthy_collector_never_fires_on_any_tier(self):
        for tier, interval in POLL_TIERS.items():
            with self.subTest(tier=tier):
                # Worst case healthy: data one poll old when scraped, evaluated one
                # scrape interval later.
                age = interval + SCRAPE_INTERVAL
                self.assertLess(missed_intervals(age, interval, self.slack), self.threshold)

    def test_one_failed_poll_followed_by_recovery_never_fires_on_any_tier(self):
        for tier, interval in POLL_TIERS.items():
            with self.subTest(tier=tier):
                # One poll skipped => data two polls old, plus the scrape lag.
                age = 2 * interval + SCRAPE_INTERVAL
                self.assertLess(missed_intervals(age, interval, self.slack), self.threshold)

    def test_persistent_failure_fires_on_every_tier_including_slow_and_cold(self):
        # The gap OPNsenseEndpointErrors structurally cannot cover: a collector that
        # only gets to fail once every 5m or 15m.
        for tier, interval in POLL_TIERS.items():
            with self.subTest(tier=tier):
                fires_at = self.threshold * interval + self.slack
                self.assertGreater(
                    missed_intervals(fires_at + 1, interval, self.slack), self.threshold)
                # And it must be reachable in bounded time, not "eventually".
                self.assertLess(fires_at, 60 * 60)

    def test_degraded_rule_is_suppressed_by_the_data_stale_rule(self):
        degraded = rule_by_title("OPNsenseCollectorDegraded")
        # A totally failed collector freezes BOTH clocks; without the `unless` it
        # would alert twice for one fault.
        self.assertIn("unless on(opnsense_instance, collector)", degraded["A"])
        self.assertIn("collector_last_success_timestamp_seconds", degraded["A"])
        # Looser than the data-stale rule: partial data IS still refreshing.
        self.assertGreater(degraded["params"][0], self.threshold)

    def test_never_stored_rule_covers_the_absent_until_first_set_blind_spot(self):
        # Both data clocks are absent until first set, so a collector broken since
        # boot produces no series for the staleness rules to measure.
        never = rule_by_title("OPNsenseCollectorNeverStoredData")
        self.assertIn("collector_last_poll_timestamp_seconds", never["A"])
        self.assertIn(
            "unless on(opnsense_instance, collector) "
            "opnsense_exporter_collector_snapshot_timestamp_seconds", never["A"])

    def test_endpoint_errors_window_stays_short(self):
        # #94: an increase() window as long as `for` keeps the condition true for a
        # full window after recovery, firing ~15m AFTER the fault cleared. Slow/cold
        # tiers are covered by the staleness rules instead of by widening this.
        endpoint = rule_by_title("OPNsenseEndpointErrors")
        self.assertIn("[2m]", endpoint["A"])
        self.assertEqual(endpoint["for_min"], 15)


class OTLPDeliveryAlertTest(unittest.TestCase):
    def test_alerts_on_consecutive_failures_not_an_error_rate(self):
        rule = rule_by_title("OPNsenseOTLPDeliveryFailing")
        # consecutive_failures resets to 0 on the next success and counts from the
        # very first attempt, so it covers never-worked-since-boot (wrong endpoint /
        # bad credential), which last-success staleness cannot: that gauge is 0 until
        # something lands, and time() - 0 is a meaningless 56-year age.
        self.assertEqual(rule["A"], "opnsense_exporter_otlp_consecutive_failures")
        self.assertNotIn("last_success", rule["A"])

    def test_documents_that_it_cannot_reach_a_pure_otlp_backend(self):
        # The exporter cannot ship its own failure metric through the failing path.
        # An operator must not read this rule as an in-band outage page.
        description = rule_by_title("OPNsenseOTLPDeliveryFailing")["description"]
        self.assertIn("CANNOT REACH A PURE-OTLP BACKEND", description)
        self.assertIn("/metrics", description)


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
