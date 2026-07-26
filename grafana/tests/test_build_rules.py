import json
import re
import sys
import tempfile
import unittest
from pathlib import Path


ALERTS_DIR = Path(__file__).resolve().parents[1] / "alerts"
REPO_ROOT = ALERTS_DIR.parent.parent
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


class LogShippingAlertTest(unittest.TestCase):
    def test_queue_pressure_covers_count_and_enabled_byte_bounds(self):
        rule = rule_by_title("OPNsenseLogShipQueueNearCapacity")

        self.assertIn("opnsense_exporter_logs_queue_length", rule["A"])
        self.assertIn("opnsense_exporter_logs_queue_capacity", rule["A"])
        self.assertIn("opnsense_exporter_logs_queue_bytes", rule["A"])
        self.assertIn("opnsense_exporter_logs_queue_max_bytes", rule["A"])
        self.assertIn(" or ", rule["A"])
        # The two ratios have the same instance labels. Plain `left or right`
        # would keep the count ratio and hide a higher byte ratio, so the rule
        # must make the bounds distinct before reducing to their maximum.
        self.assertIn("max by (opnsense_instance)", rule["A"])
        self.assertEqual(rule["A"].count("label_replace("), 2)

    def test_counted_loss_is_reason_labelled_and_distinct_from_retry_degradation(self):
        loss = rule_by_title("OPNsenseLogShipCountedLoss")
        self.assertIn("increase(opnsense_exporter_logs_dropped_total[", loss["A"])
        self.assertIn("sum by (opnsense_instance, source, reason)", loss["A"])
        self.assertIn("{{ $labels.reason }}", loss["summary"])
        self.assertEqual(loss["severity"], "warning")

        sink = rule_by_title("OPNsenseLogShipSinkErrors")
        self.assertIn("opnsense_instance", sink["A"])
        self.assertIn("retry", sink["description"].lower())
        self.assertNotIn("records are being lost", sink["description"].lower())


class GatewayAlarmFlapAlertTest(unittest.TestCase):
    def test_repeated_dpinger_alarm_starts_alert_per_gateway(self):
        rule = rule_by_title("OPNsenseGatewayAlarmFlapping")

        self.assertEqual(
            rule["A"],
            'sum by (opnsense_instance, gateway) '
            '(increase(opnsense_log_events_gateway_total{event="alarm_started"}[15m]))',
        )
        # Grafana's strict greater-than comparator with 2 means three or more
        # starts in the 15-minute window. Keep the operator-facing threshold in
        # the description too, rather than hiding it in the condition encoding.
        self.assertEqual(rule["op"], "gt")
        self.assertEqual(rule["params"], [2, 0])
        self.assertEqual(rule["for_min"], 0)
        self.assertEqual(rule["severity"], "warning")
        self.assertIn("three or more", rule["description"])
        self.assertIn("15m", rule["description"])


def _flow_doc_dead_hook_query():
    """Extract the fenced ```promql block for the #368 dead-hook detector straight out
    of docs/flow.md ("Joining the two label spaces"), so a future edit to either the
    doc or the rule that lets them drift apart fails loudly instead of silently."""
    text = (REPO_ROOT / "docs" / "flow.md").read_text()
    match = re.search(
        r"```promql\n(max by \(opnsense_instance, interface, device\) \(.*?"
        r"opnsense_netflow_capture_active_timeout_seconds < 2700\))\n```",
        text, re.DOTALL,
    )
    if not match:
        raise AssertionError(
            "docs/flow.md no longer contains the #368 dead-hook detector query in the "
            "expected form - update this extractor or restore the doc")
    return match.group(1)


def _dead_hook_clauses(capture_expected, has_interface_info, packets_increase_45m,
                        firewall_bytes_increase_45m, active_timeout_seconds):
    """Python mirror of the four `and`-chained PromQL clauses (no Prometheus engine is
    available to this test suite - see the tier-aware staleness tests above for the
    established pattern). Returns whether a row would exist for the candidate
    (opnsense_instance, interface, device) series at one evaluation instant.

    Clause 1: interface configured for capture AND joined to a device via
              opnsense_flow_interface_info (absent join = inactive/no receiver).
    Clause 2: that device's OWN ng_netflow node counted zero packets over 45m.
    Clause 3: pf confirms real traffic crossed the same device over 45m (rules out
              a legitimately idle interface, whose cache node is flat for the same
              reason a dead hook's is).
    Clause 4: honesty guard - withdrawn once the box's own configured NetFlow active
              timeout is at least the 45m observation window.
    """
    clause1 = capture_expected == 1 and has_interface_info
    clause2 = packets_increase_45m == 0
    clause3 = firewall_bytes_increase_45m > 0
    clause4 = active_timeout_seconds < 2700
    return clause1 and clause2 and clause3 and clause4


def _simulate_for_duration(conditions, for_minutes):
    """Mirror of Grafana's for-duration state machine (Normal -> Pending -> Alerting),
    driven by one boolean per 1-minute evaluation tick for a SINGLE alert instance
    (one fixed opnsense_instance/interface/device label set throughout - the state
    machine never starts a new instance mid-timeline). A false tick clears the
    pending clock immediately, matching Grafana's default (no keep-firing-for)."""
    states = []
    pending_since = None
    for i, cond in enumerate(conditions):
        if not cond:
            pending_since = None
            states.append("Normal")
            continue
        if pending_since is None:
            pending_since = i
        states.append("Alerting" if i - pending_since >= for_minutes else "Pending")
    return states


class NetFlowHookDeadAlertTest(unittest.TestCase):
    """#402: managed alert for the #368 four-clause dead-hook detector."""

    def setUp(self):
        self.rule = rule_by_title("OPNsenseNetFlowHookDead")
        self.for_min = self.rule["for_min"]

    def test_query_is_byte_identical_to_docs_flow_md(self):
        # #402 scope: copy the exact live-verified query, never simplify it.
        self.assertEqual(self.rule["A"], _flow_doc_dead_hook_query())

    def test_all_four_clauses_present(self):
        a = self.rule["A"]
        self.assertIn("opnsense_netflow_capture_expected == 1", a)
        self.assertIn("group_left (device) opnsense_flow_interface_info", a)
        self.assertIn(
            'label_join(increase(opnsense_netflow_cache_packets_total[45m]), '
            '"device", "", "interface") == 0', a)
        self.assertIn(
            'label_join(increase(opnsense_firewall_in_ipv4_pass_bytes_total[45m]), '
            '"device", "", "interface") > 0', a)
        self.assertIn("opnsense_netflow_capture_active_timeout_seconds < 2700", a)

    def test_never_infers_loss_from_netflow_source_id(self):
        # #402 dependency: source_id=0 is not a sequence counter.
        self.assertNotIn("source_id", self.rule["A"])
        self.assertNotIn("source_id", self.rule["description"])

    def test_severity_is_warning_not_a_page(self):
        # Visibility loss, not a firewall/service outage - matches the other
        # NetFlow/flow-lane rules (correlator-evicting, logs-truncated).
        self.assertEqual(self.rule["severity"], "warning")

    def test_pppoe0_live_failure_reaches_pending_then_alerting(self):
        # The exact #368 finding: AAISP/pppoe0 configured, joined, its own cache node
        # flat, pf still passing bytes, default 1800s active timeout.
        cond = _dead_hook_clauses(
            capture_expected=1, has_interface_info=True,
            packets_increase_45m=0, firewall_bytes_increase_45m=100_000,
            active_timeout_seconds=1800)
        self.assertTrue(cond)
        states = _simulate_for_duration([cond] * (self.for_min + 5), self.for_min)
        self.assertEqual(states[0], "Pending")
        self.assertEqual(states[-1], "Alerting")
        self.assertIn("Alerting", states)

    def test_idle_interface_stays_normal(self):
        # Configured and joined, own cache node flat too - but pf shows nothing
        # crossed the device either, so it's quiet, not dead.
        cond = _dead_hook_clauses(
            capture_expected=1, has_interface_info=True,
            packets_increase_45m=0, firewall_bytes_increase_45m=0,
            active_timeout_seconds=1800)
        self.assertFalse(cond)
        states = _simulate_for_duration([cond] * (self.for_min + 5), self.for_min)
        self.assertTrue(all(s == "Normal" for s in states))

    def test_disabled_hook_stays_normal(self):
        # Not configured for capture at all - clause 1 excludes it up front.
        cond = _dead_hook_clauses(
            capture_expected=0, has_interface_info=True,
            packets_increase_45m=0, firewall_bytes_increase_45m=100_000,
            active_timeout_seconds=1800)
        self.assertFalse(cond)
        states = _simulate_for_duration([cond] * (self.for_min + 5), self.for_min)
        self.assertTrue(all(s == "Normal" for s in states))

    def test_inactive_receiver_stays_normal(self):
        # No NetFlow receiver/lane running at all, so opnsense_flow_interface_info
        # never gets published and the group_left join has nothing to match -
        # clause 1 drops the series before the rest of the chain ever runs.
        cond = _dead_hook_clauses(
            capture_expected=1, has_interface_info=False,
            packets_increase_45m=0, firewall_bytes_increase_45m=100_000,
            active_timeout_seconds=1800)
        self.assertFalse(cond)
        states = _simulate_for_duration([cond] * (self.for_min + 5), self.for_min)
        self.assertTrue(all(s == "Normal" for s in states))

    def test_long_active_timeout_withdraws_the_alert(self):
        # Same dead-hook shape as the pppoe0 case, but the box's own configured
        # active timeout (here 3600s) is at least the 45m/2700s observation window,
        # so clause 4 withdraws the query rather than call 45m of silence proven.
        cond = _dead_hook_clauses(
            capture_expected=1, has_interface_info=True,
            packets_increase_45m=0, firewall_bytes_increase_45m=100_000,
            active_timeout_seconds=3600)
        self.assertFalse(cond)
        states = _simulate_for_duration([cond] * (self.for_min + 5), self.for_min)
        self.assertTrue(all(s == "Normal" for s in states))

    def test_recovery_resolves_the_same_labelled_alert_instance(self):
        # One fixed (opnsense_instance, interface, device) timeline throughout -
        # _simulate_for_duration never changes labels mid-run, so "resolves" here
        # is the SAME alert instance clearing, not a different one going quiet.
        dead = _dead_hook_clauses(
            capture_expected=1, has_interface_info=True,
            packets_increase_45m=0, firewall_bytes_increase_45m=100_000,
            active_timeout_seconds=1800)
        recovered = _dead_hook_clauses(
            capture_expected=1, has_interface_info=True,
            packets_increase_45m=500, firewall_bytes_increase_45m=100_000,
            active_timeout_seconds=1800)
        self.assertTrue(dead)
        self.assertFalse(recovered)

        timeline = [dead] * (self.for_min + 3) + [recovered] * 5
        states = _simulate_for_duration(timeline, self.for_min)
        self.assertEqual(states[self.for_min], "Alerting")
        self.assertEqual(states[-1], "Normal")


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
