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


class CARPTransitionAlertTest(unittest.TestCase):
    """#405's acceptance requires alerting on repeated CARP state changes for one vhid
    and on unexpected demotion. Both are TRANSITION evidence from syslog, so both are
    window-relative (increase / rate) and never a bare cumulative total."""

    def test_repeated_state_changes_alert_per_vhid(self):
        rule = rule_by_title("OPNsenseCARPStateFlapping")

        # Grouped by vhid AND interface: a vhid number is only unique within an
        # interface, so grouping by vhid alone would merge two independent VIPs.
        self.assertEqual(
            rule["A"],
            'sum by (opnsense_instance, interface, vhid) '
            '(increase(opnsense_log_events_carp_total{event="state_changed"}[15m]))',
        )
        # Strict >3 means four or more state changes in the window. A single clean
        # failover is INIT->BACKUP->MASTER, i.e. two changes, so the threshold has to
        # sit above that or every planned failover pages.
        self.assertEqual(rule["op"], "gt")
        self.assertEqual(rule["params"], [3, 0])
        self.assertEqual(rule["for_min"], 0)
        self.assertEqual(rule["severity"], "warning")
        self.assertIn("four or more", rule["description"].lower())
        self.assertIn("15m", rule["description"])

    def test_unexpected_demotion_alerts_above_routine_pfsync_churn(self):
        rule = rule_by_title("OPNsenseCARPUnexpectedDemotion")

        self.assertEqual(
            rule["A"],
            'sum by (opnsense_instance) '
            '(increase(opnsense_log_events_carp_total{event="demoted"}[15m]))',
        )
        # Strict >3 means four or more demotions in the window. NOT >0: the #405 capture
        # recorded 11 pfsync-bulk-start demotions, so demotion during bulk transfer is
        # routine and >0 would page on a healthy cluster.
        self.assertEqual(rule["op"], "gt")
        self.assertEqual(rule["params"], [3, 0])
        self.assertEqual(rule["for_min"], 0)
        self.assertEqual(rule["severity"], "warning")
        self.assertIn("pfsync", rule["description"])

    def test_a_count_threshold_is_never_applied_to_a_per_second_rate(self):
        """THE DEAD-ALERT TRAP. rate() is per-second, so four events in 15m is 0.0044/s;
        any threshold >= 1 on a bare rate() of a rare transition event can never fire and
        the alert is silently dead forever. A count-over-window threshold must therefore
        use increase(). Guards both CARP rules and the dpinger sibling they were modelled on."""
        for title in ("OPNsenseCARPStateFlapping",
                      "OPNsenseCARPUnexpectedDemotion",
                      "OPNsenseGatewayAlarmFlapping"):
            rule = rule_by_title(title)
            if rule["params"][0] >= 1:
                self.assertIn(
                    "increase(", rule["A"],
                    f"{title} applies a threshold of {rule['params'][0]} to an expression "
                    "that is not an increase() over the window; a per-second rate of a rare "
                    "event never reaches 1, so this alert could never fire",
                )

    def test_neither_carp_rule_uses_a_bare_cumulative_total(self):
        for title in ("OPNsenseCARPStateFlapping", "OPNsenseCARPUnexpectedDemotion"):
            expr = rule_by_title(title)["A"]
            self.assertTrue(
                "rate(" in expr or "increase(" in expr,
                f"{title} reads opnsense_log_events_carp_total without rate()/increase(); "
                "a bare counter total only ever grows and would latch on forever",
            )

    def test_neither_carp_rule_selects_on_the_kernel_cause(self):
        """The cause is never a label, so no rule may match on one. A rule written
        against reason=/reason_class= would silently never fire."""
        for title in ("OPNsenseCARPStateFlapping", "OPNsenseCARPUnexpectedDemotion"):
            expr = rule_by_title(title)["A"]
            for forbidden in ("reason", "reason_class", "cause", "delta"):
                self.assertNotIn(f'{forbidden}=', expr)


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
    # The timeout clause stays the ANCHOR that identifies this block among the
    # doc's other promql fences, but the capture runs on to the closing fence so a
    # clause appended after it (the #521 PPPoE suppression) is compared too rather
    # than silently trimmed off before the equality check.
    match = re.search(
        r"```promql\n(max by \(opnsense_instance, interface, device\) \(.*?"
        r"opnsense_netflow_capture_active_timeout_seconds < 2700\).*?)\n```",
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
                    "test-prometheus", "test-opnsense2otel-alerts", stack=False,
        health_folder="test-opnsense-health-alerts"
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


class ExporterDisappearanceTest(unittest.TestCase):
    """#427: one exporter vanishing while others still report must still page.

    Grafana treats these as two different situations, and the distinction is the
    whole issue:

    - **No Data** — the rule's query returns no series at all. `noDataState` governs
      it, so `OPNsenseExporterDown` with `noDataState: Alerting` covers a total
      fleet loss.
    - **MissingSeries** — the query still returns series, but one dimension has
      disappeared from the result. Grafana retains that alert instance briefly and
      then *evicts* it as stale. It never passes through `noDataState`.

    So with exporters `edge-a` and `edge-b`, losing `edge-a` entirely leaves
    `opnsense_up{opnsense_instance="edge-b"}` returning happily, the `edge-a` alert
    instance is quietly evicted, and nothing pages. The bare `opnsense_up` vector
    cannot detect its own absence — something has to assert what SHOULD be there.
    """

    def test_a_missing_instance_rule_exists(self):
        rule = rule_by_title("OPNsenseExporterInstanceMissing")
        self.assertEqual(rule["name"], "opnsense2otel-instance-missing")

    def test_it_compares_recent_history_against_the_present(self):
        """The detector must name instances seen recently but absent NOW.

        `present_over_time` over a lookback yields one series per instance that
        reported at any point in the window; `unless` removes the ones still
        reporting. What survives is exactly the set that has vanished — which a bare
        `opnsense_up` selector can never produce, because a series that does not
        exist cannot match.
        """
        expr = rule_by_title("OPNsenseExporterInstanceMissing")["A"]
        self.assertIn("present_over_time(opnsense_up[", expr)
        self.assertIn("unless", expr)
        self.assertIn("opnsense_instance", expr,
                      "the surviving series must be keyed on instance, or the alert "
                      "cannot say WHICH exporter went away")

    def test_it_raises_one_alert_per_instance_not_per_historical_label_set(self):
        """present_over_time yields one series per distinct LABEL SET, not per
        instance. Any label churn inside the lookback — a version label removed, a
        relabel, a scrape-config edit — therefore leaves several historical series
        for one box, and without aggregation one missing exporter would page once
        per label set.

        Not hypothetical: verified live 2026-07-27, the unaggregated form returned
        two series for the single real instance, differing only by a service_version
        label removed earlier that day (#472).
        """
        expr = rule_by_title("OPNsenseExporterInstanceMissing")["A"]
        self.assertIn("max by (opnsense_instance) (present_over_time(opnsense_up[", expr)

    def test_it_does_not_duplicate_the_total_loss_rule(self):
        """Total fleet loss belongs to OPNsenseExporterDown, not here.

        If every exporter disappears, this rule's own query returns nothing, so it
        would be NoData — and if it were `Alerting` on NoData, both rules would fire
        for the same event. `OPNsenseExporterDown` already carries
        `noDataState: Alerting` for exactly that case, so this one must not.
        """
        rule = rule_by_title("OPNsenseExporterInstanceMissing")
        self.assertEqual(rule.get("nodata", "Ok"), "Ok")
        self.assertEqual(rule_by_title("OPNsenseExporterDown")["nodata"], "Alerting")

    def test_it_pages(self):
        """A firewall that has silently stopped reporting is a critical event."""
        self.assertEqual(rule_by_title("OPNsenseExporterInstanceMissing")["severity"], "critical")

    def test_the_summary_names_the_missing_instance(self):
        rule = rule_by_title("OPNsenseExporterInstanceMissing")
        self.assertIn("$labels.opnsense_instance", rule["summary"])

    def test_the_decommission_horizon_is_stated(self):
        """A historical baseline necessarily alerts for a while after a planned
        removal. That is a real operational cost, so the description must state the
        window rather than leaving an operator to discover it from a page."""
        desc = rule_by_title("OPNsenseExporterInstanceMissing")["description"]
        lookback = re.search(r"present_over_time\(opnsense_up\[(\w+)\]", 
                             rule_by_title("OPNsenseExporterInstanceMissing")["A"]).group(1)
        self.assertIn(lookback, desc,
                      "the description must name the same lookback the expression uses, "
                      "so the decommission behaviour is discoverable without reading PromQL")


class SelfHealthFolderRoutingTest(unittest.TestCase):
    """#431 step 4: exporter-health rules live in their own Grafana folder.

    The point is the 3am read. An `OPNsenseFirewallUnhealthy` page means go look at
    the firewall; an `OPNsenseLogShipSinkErrors` page means the firewall is probably
    fine and the monitoring is not. In one folder a responder has to read every
    title to tell which they have.

    Membership is declared per rule rather than inferred, because two members cannot
    be inferred — `OPNsenseExporterDown` and `OPNsenseExporterInstanceMissing` fire
    on `opnsense_up`, which is not an `opnsense_exporter_*` metric but is entirely a
    statement about the exporter. The declaration is cross-checked below so it
    cannot fall behind the expressions.
    """

    OPS = "opnsense2otel-alerts"
    HEALTH = "opnsense2otel-health-alerts"

    def _folder(self, rule):
        return build_rules.rule_folder(rule, self.OPS, self.HEALTH)

    def test_a_rule_built_only_from_self_metrics_must_be_declared_self_health(self):
        """The cross-check that keeps the declaration honest."""
        for rule in build_rules.RULES:
            if build_rules.is_self_health_expr(rule["A"]):
                with self.subTest(rule=rule["title"]):
                    self.assertEqual(
                        self._folder(rule), self.HEALTH,
                        f"{rule['title']} reads only exporter self-metrics but is "
                        "routed to the firewall folder")

    def test_the_two_opnsense_up_rules_are_declared_self_health(self):
        by_title = {r["title"]: r for r in build_rules.RULES}
        for title in ("OPNsenseExporterDown", "OPNsenseExporterInstanceMissing"):
            with self.subTest(title=title):
                self.assertEqual(self._folder(by_title[title]), self.HEALTH,
                                 f"{title} is about the exporter, not the firewall")

    def test_firewall_rules_stay_in_the_firewall_folder(self):
        """The control. Without it, a `rule_folder` that always returned HEALTH
        would satisfy every assertion above."""
        by_title = {r["title"]: r for r in build_rules.RULES}
        for title in ("OPNsenseFirewallUnhealthy", "OPNsenseCrashReports"):
            with self.subTest(title=title):
                self.assertEqual(self._folder(by_title[title]), self.OPS)

    def test_no_recording_rule_is_self_health_today(self):
        """Recording rules are sorted by the same rule; all 14 derive from firewall
        metrics, so the health folder holds none. If that changes, this fails and
        the new rule needs a deliberate decision rather than a default."""
        moved = [r["metric"] for r in build_rules.RECORDING
                 if self._folder(r) == self.HEALTH]
        self.assertEqual(moved, [])

    def test_both_folders_are_emitted_and_every_rule_resolves_to_one(self):
        import glob
        import json
        import os
        manifest_dir = os.path.join(ALERTS_DIR, "grafana-managed")
        folders, rule_folders = set(), set()
        for path in glob.glob(os.path.join(manifest_dir, "*.json")):
            with open(path) as f:
                doc = json.load(f)
            if doc["kind"] == "Folder":
                folders.add(doc["metadata"]["name"])
            else:
                rule_folders.add(doc["metadata"]["labels"]["grafana.app/folder"])
        self.assertEqual(folders, {self.OPS, self.HEALTH})
        self.assertTrue(rule_folders <= folders,
                        f"rules reference folders with no manifest: {rule_folders - folders}")
        self.assertIn(self.HEALTH, rule_folders,
                      "the health folder manifest ships but no rule is routed to it")


class StackRebootToleranceTest(unittest.TestCase):
    """--stack floors the pending window at 10m so a 10-15 minute firewall reboot,
    which takes the whole monitoring path down with it on this deployment, cannot
    storm IRM. #629."""

    def _emit(self, stack):
        with tempfile.TemporaryDirectory() as tmp:
            original_here = build_rules.HERE
            try:
                build_rules.HERE = tmp
                _, written = build_rules.emit_grafana_managed(
                    "test-prometheus", "test-ops", stack=stack,
                    health_folder="test-health",
                )
                manifests = [json.loads(Path(p).read_text()) for p in written]
            finally:
                build_rules.HERE = original_here
        return [m for m in manifests if m["kind"] == "AlertRule"]

    @staticmethod
    def _minutes(value):
        match = re.fullmatch(r"(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?", value)
        hours, minutes, seconds = (int(g or 0) for g in match.groups())
        return hours * 60 + minutes + seconds / 60

    def test_stack_floors_every_nonzero_pending_window_at_ten_minutes(self):
        # The 10 is written out rather than read from build_rules.STACK_MIN_FOR_MIN:
        # sourcing the bound from the module under test makes the assertion hold for
        # any value of it, including 0, which is the regression it exists to catch.
        self.assertEqual(build_rules.STACK_MIN_FOR_MIN, 10)
        short = [
            m["metadata"]["name"] for m in self._emit(stack=True)
            if 0 < self._minutes(m["spec"]["for"]) < 10
        ]
        self.assertEqual(short, [], f"below the reboot floor in --stack mode: {short}")

    def test_stack_leaves_deliberately_instant_rules_instant(self):
        # The flap detectors and the cert-expiry / log-ship pairs are 0s on purpose.
        # Flooring them would turn "flapping" into "flapping continuously for ten
        # minutes", which is a different alert.
        instant = {
            m["metadata"]["name"] for m in self._emit(stack=False)
            if m["spec"]["for"] == "0s"
        }
        self.assertTrue(instant, "no instant rules left to guard the floor against")
        still_instant = {
            m["metadata"]["name"] for m in self._emit(stack=True)
            if m["spec"]["for"] == "0s"
        }
        self.assertEqual(instant, still_instant)

    def test_shipped_profile_keeps_its_own_defaults(self):
        # The floor is deployment-specific. Without --stack nothing moves, so the
        # committed manifests and the published runbook stay as authored.
        generic = {
            m["metadata"]["name"]: m["spec"]["for"] for m in self._emit(stack=False)
        }
        authored = {
            rule["name"]: build_rules.grafana_for(rule["for_min"])
            for rule in build_rules.RULES
        }
        self.assertEqual(generic, authored)
        self.assertTrue(
            any(0 < self._minutes(v) < build_rules.STACK_MIN_FOR_MIN
                for v in generic.values()),
            "no sub-floor default left, so this test no longer proves anything",
        )
