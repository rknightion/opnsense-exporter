"""Behaviour of the shipped alert rules under Grafana's evaluation model (#429).

`tools/promqlcheck` proves every expression parses. `test_manifest_contract.py`
proves every manifest field is well-formed. Neither can answer the questions an
operator actually has:

* does a two-minute blip page someone?
* if one firewall of three vanishes, does anything fire?
* if the whole scrape target disappears, does anything fire?
* if a log pipeline stalls on one box, does only that box alert?

Those are properties of Grafana's state machine — pending period, `noDataState`,
`execErrState`, MissingSeries eviction — and this file exercises them against the
REAL generated manifests through `alerts/ruleeval.py`. See that module for the
semantics and where they were verified from.

The harness is fed query RESULTS, not raw counters: it models the state machine,
not PromQL. Reimplementing `increase()` in Python would be a second, worse
Prometheus, and every interesting failure here is on the Grafana side of the query.
"""

import glob
import json
import os
import sys
import unittest
from pathlib import Path

GRAFANA_DIR = Path(__file__).resolve().parents[1]
ALERTS_DIR = GRAFANA_DIR / "alerts"
MANIFEST_DIR = ALERTS_DIR / "grafana-managed"
sys.path.insert(0, str(GRAFANA_DIR))
sys.path.insert(0, str(ALERTS_DIR))

import ruleeval  # noqa: E402
from ruleeval import (ALERTING, EVAL_ERROR, NO_DATA, NODATA, NORMAL, PENDING,  # noqa: E402
                      REASON_MISSING_SERIES)


def load_rules() -> dict:
    """title -> Rule, for every generated AlertRule manifest."""
    rules = {}
    for path in sorted(glob.glob(os.path.join(MANIFEST_DIR, "*.json"))):
        with open(path) as f:
            doc = json.load(f)
        if doc.get("kind") != "AlertRule":
            continue
        rule = ruleeval.rule_from_manifest(doc)
        rules[rule.title] = rule
    return rules


RULES = load_rules()


def steady(value, ticks: int, series="fw1") -> list:
    return [{series: value} for _ in range(ticks)]


class HarnessCoversEveryRuleTest(unittest.TestCase):
    """Before trusting any behaviour test, prove the harness can read every rule.

    An `Unsupported` raised here means a manifest shape the model has never seen —
    which is a finding, not a reason to skip the rule.
    """

    def test_every_shipped_alert_rule_is_modellable(self):
        self.assertTrue(RULES, f"no AlertRule manifests found in {MANIFEST_DIR}")
        for title, rule in RULES.items():
            with self.subTest(title=title):
                self.assertIn(rule.evaluator, ruleeval._EVALUATORS)
                self.assertGreater(rule.interval_seconds, 0)

    def test_the_rule_count_matches_the_manifests_on_disk(self):
        on_disk = 0
        for path in glob.glob(os.path.join(MANIFEST_DIR, "*.json")):
            with open(path) as f:
                on_disk += json.load(f).get("kind") == "AlertRule"
        self.assertEqual(len(RULES), on_disk)


class PendingPeriodTest(unittest.TestCase):
    """Transient vs sustained, across the poll cadences the rules actually use."""

    def test_a_blip_shorter_than_the_pending_period_never_fires(self):
        """The general property, asserted against every rule that has a pending
        period — not against one hand-picked example."""
        for title, rule in RULES.items():
            if rule.for_seconds == 0:
                continue
            ticks = max(1, rule.for_seconds // rule.interval_seconds)
            breach = _breaching_value(rule)
            with self.subTest(title=title):
                # Breach for one tick fewer than the pending period requires, then clear.
                timeline = steady(breach, ticks) + steady(_clear_value(rule), 3)
                states = ruleeval.evaluate(rule, timeline)
                self.assertNotIn(ALERTING, [s.states.get("fw1") for s in states[:ticks - 1]],
                                 f"{title} reached Alerting before its pending period elapsed")
                self.assertEqual(states[-1].states.get("fw1"), NORMAL,
                                 f"{title} did not resolve after the breach cleared")

    def test_a_sustained_breach_fires_exactly_when_the_pending_period_elapses(self):
        for title, rule in RULES.items():
            breach = _breaching_value(rule)
            ticks = rule.for_seconds // rule.interval_seconds + 3
            with self.subTest(title=title):
                states = ruleeval.evaluate(rule, steady(breach, ticks))
                first_alerting = next(
                    (s.tick for s in states if s.states.get("fw1") == ALERTING), None)
                self.assertIsNotNone(first_alerting, f"{title} never fired on a sustained breach")
                self.assertEqual(
                    first_alerting * rule.interval_seconds, rule.for_seconds,
                    f"{title} fired at {first_alerting * rule.interval_seconds}s, "
                    f"pending period is {rule.for_seconds}s")

    def test_endpoint_errors_tolerates_a_transient_burst_but_not_a_sustained_one(self):
        """The named case from #429, spelled out rather than left to the sweep."""
        rule = RULES["OPNsenseEndpointErrors"]
        clear, breach = _clear_value(rule), _breaching_value(rule)
        pending_ticks = rule.for_seconds // rule.interval_seconds

        transient = ruleeval.evaluate(
            rule, steady(clear, 3) + steady(breach, pending_ticks - 1) + steady(clear, 5))
        self.assertNotIn(ALERTING, [s.states.get("fw1") for s in transient],
                         "a burst shorter than the pending period paged someone")

        sustained = ruleeval.evaluate(rule, steady(breach, pending_ticks + 2))
        self.assertEqual(sustained[-1].states.get("fw1"), ALERTING)

    def test_an_interrupted_breach_restarts_the_pending_period(self):
        """Grafana resets on any non-breaching evaluation. A rule that fired on
        cumulative rather than consecutive breaches would page on a flapping box."""
        rule = RULES["OPNsenseEndpointErrors"]
        clear, breach = _clear_value(rule), _breaching_value(rule)
        pending_ticks = rule.for_seconds // rule.interval_seconds
        flapping = []
        for _ in range(4):
            flapping += steady(breach, pending_ticks - 1) + steady(clear, 1)
        states = ruleeval.evaluate(rule, flapping)
        self.assertNotIn(ALERTING, [s.states.get("fw1") for s in states])


class MultiInstanceTest(unittest.TestCase):
    """One firewall of several. The case a single-instance test cannot see."""

    def test_only_the_breaching_instance_fires(self):
        rule = RULES["OPNsenseLogShipCursorStalled"]
        clear, breach = _clear_value(rule), _breaching_value(rule)
        ticks = rule.for_seconds // rule.interval_seconds + 2
        timeline = [{"fw1": clear, "fw2": breach, "fw3": clear} for _ in range(ticks)]
        states = ruleeval.evaluate(rule, timeline)
        self.assertEqual(states[-1].firing(), {"fw2"},
                         "a stalled log pipeline on one box did not alert on exactly "
                         f"that box: {states[-1].states}")

    def test_one_instance_disappearing_is_MissingSeries_not_NoData(self):
        """The Grafana-only behaviour, and the reason #427 exists.

        `OPNsenseExporterDown` has `noDataState: Alerting`, which reads like "page
        when a firewall goes away". It does not: with any other firewall still
        reporting, the query still returns data, so the vanished one is a stale
        SERIES. Grafana holds its last state for two evaluation intervals and then
        RESOLVES it. Nothing pages.
        """
        rule = RULES["OPNsenseExporterDown"]
        self.assertEqual(rule.no_data_state, ALERTING,
                         "premise moved: this test explains why noDataState=Alerting "
                         "does not cover a single instance disappearing")
        timeline = ([{"fw1": 1, "fw2": 1} for _ in range(3)]
                    + [{"fw1": 1} for _ in range(5)])
        states = ruleeval.evaluate(rule, timeline)

        self.assertNotIn("", states[-1].states,
                         "one series vanishing produced a rule-level NoData state; it "
                         "is a MissingSeries, and noDataState must not apply")
        evictions = [s for s in states if s.reasons.get("fw2") == REASON_MISSING_SERIES]
        self.assertEqual(len(evictions), 1,
                         "the vanished instance was never evicted with a MissingSeries "
                         "reason, or was reported as evicted more than once")
        self.assertEqual(evictions[0].states["fw2"], NORMAL)
        self.assertNotIn("fw2", states[-1].states,
                         "an evicted instance is still being reported; Grafana removes "
                         "it from the UI once it is resolved as stale")
        self.assertNotIn(ALERTING, [s.states.get("fw2") for s in states],
                         "the vanished instance alerted; if this ever becomes true, "
                         "OPNsenseExporterInstanceMissing is redundant")

    def test_the_missing_series_holds_its_state_for_exactly_two_intervals_first(self):
        """The hold matters: it is what stops a single missed scrape resolving a
        genuine firing alert.

        TWO is written out as a literal rather than read from
        `ruleeval.MISSING_SERIES_INTERVALS`. Referring to the constant made this
        assertion self-referential — changing the constant to 3 left the test green,
        which was verified by doing exactly that. The number is Grafana's, documented
        at `alerting/best-practices/missing-data` ("marks these missing series as
        stale after two evaluation intervals"), so the test has to state it
        independently or it checks nothing.
        """
        rule = RULES["OPNsenseExporterDown"]
        firing_ticks = rule.for_seconds // rule.interval_seconds + 1
        timeline = ([{"fw1": 1, "fw2": 0} for _ in range(firing_ticks)]
                    + [{"fw1": 1} for _ in range(6)])
        states = ruleeval.evaluate(rule, timeline)

        self.assertEqual(states[firing_ticks - 1].states["fw2"], ALERTING)
        for offset in (0, 1):
            self.assertEqual(states[firing_ticks + offset].states["fw2"], ALERTING,
                             f"a firing instance was resolved {offset + 1} interval(s) "
                             "after its series vanished; Grafana holds it for two")
        eviction = next(s for s in states if s.reasons.get("fw2") == REASON_MISSING_SERIES)
        self.assertEqual(eviction.states["fw2"], NORMAL)
        self.assertEqual(eviction.tick, firing_ticks + 2,
                         "eviction did not land on the third consecutive missing "
                         "evaluation")

    def test_the_instance_missing_rule_is_what_actually_covers_the_gap(self):
        """`OPNsenseExporterInstanceMissing` sees it because its own query keeps the
        vanished instance as a series (`present_over_time ... unless`), so from
        Grafana's side there is nothing missing at all."""
        rule = RULES["OPNsenseExporterInstanceMissing"]
        breach = _breaching_value(rule)
        ticks = rule.for_seconds // rule.interval_seconds + 1
        states = ruleeval.evaluate(rule, [{"fw2": breach} for _ in range(ticks)])
        self.assertEqual(states[-1].firing(), {"fw2"})


class WholeQueryNoDataTest(unittest.TestCase):
    def test_a_totally_empty_query_settles_on_the_configured_no_data_state(self):
        for title, rule in RULES.items():
            ticks = rule.for_seconds // rule.interval_seconds + 2
            with self.subTest(title=title):
                states = ruleeval.evaluate(rule, [NO_DATA] * ticks)
                final = states[-1].states.get("")
                expected = {"Alerting": ALERTING, "NoData": NODATA,
                            "Ok": NORMAL, "KeepLast": NORMAL}[rule.no_data_state]
                self.assertEqual(final, expected,
                                 f"{title} with noDataState={rule.no_data_state} "
                                 f"settled on {final}")

    def test_no_data_honours_the_pending_period_before_paging(self):
        """A single failed scrape on a 15m rule must not page."""
        rule = RULES["OPNsenseExporterDown"]
        states = ruleeval.evaluate(rule, [NO_DATA])
        self.assertNotEqual(states[0].states.get(""), ALERTING,
                            "one empty evaluation paged immediately despite a "
                            f"{rule.for_seconds}s pending period")

    def test_exactly_the_intended_rules_page_on_a_vanished_fleet(self):
        """An inventory, so adding `noDataState: Alerting` to a rule is a decision
        someone makes rather than one that slips in."""
        paging = {t for t, r in RULES.items() if r.no_data_state == "Alerting"}
        self.assertEqual(paging, {"OPNsenseExporterDown"},
                         "the set of rules that page when the whole query returns "
                         "nothing changed; that is a paging-behaviour change")


class EvaluationErrorTest(unittest.TestCase):
    def test_an_errored_evaluation_does_not_resolve_a_firing_instance(self):
        """A datasource hiccup must not send a resolved notification for a real
        outage. Grafana holds the instance; a model that dropped it would have the
        alert flap resolved/firing every time the query timed out."""
        rule = RULES["OPNsenseEndpointErrors"]
        breach = _breaching_value(rule)
        ticks = rule.for_seconds // rule.interval_seconds + 1
        states = ruleeval.evaluate(rule, steady(breach, ticks) + [EVAL_ERROR])
        self.assertEqual(states[-2].states["fw1"], ALERTING)
        self.assertEqual(states[-1].states["fw1"], ALERTING)

    def test_every_rule_declares_error_as_its_exec_err_state(self):
        for title, rule in RULES.items():
            with self.subTest(title=title):
                self.assertEqual(rule.exec_err_state, "Error")


class ModelSelfCheckTest(unittest.TestCase):
    """The model is only useful if it can be wrong. These break it on purpose."""

    def _rule(self, **kw):
        base = dict(title="t", evaluator="gt", params=[0, 0], for_seconds=300,
                    interval_seconds=60, no_data_state="NoData", exec_err_state="Error")
        base.update(kw)
        return ruleeval.Rule(**base)

    def test_zero_pending_period_fires_on_the_first_breach(self):
        states = ruleeval.evaluate(self._rule(for_seconds=0), steady(1, 1))
        self.assertEqual(states[0].states["fw1"], ALERTING)

    def test_pending_is_reported_before_alerting(self):
        states = ruleeval.evaluate(self._rule(), steady(1, 6))
        self.assertEqual([s.states["fw1"] for s in states],
                         [PENDING, PENDING, PENDING, PENDING, PENDING, ALERTING])

    def test_a_null_value_is_not_a_breach(self):
        """`lt` rules are the trap: reading a null reduction as zero would make
        every one of them fire on a series with no value."""
        rule = self._rule(evaluator="lt", params=[1, 0], for_seconds=0)
        self.assertFalse(rule.breaches(None))
        self.assertTrue(rule.breaches(0))

    def test_an_unmodelled_evaluator_raises_rather_than_passing(self):
        with self.assertRaises(ruleeval.Unsupported):
            self._rule(evaluator="no_value").breaches(1)

    def test_an_unparseable_duration_raises(self):
        with self.assertRaises(ruleeval.Unsupported):
            ruleeval.parse_duration("forever")

    def test_durations_round_trip(self):
        self.assertEqual(ruleeval.parse_duration("0s"), 0)
        self.assertEqual(ruleeval.parse_duration("15m"), 900)
        self.assertEqual(ruleeval.parse_duration("1h30m"), 5400)


def _breaching_value(rule):
    """A value that satisfies `rule`'s condition, derived from the evaluator rather
    than hand-picked, so a rule that changes direction is still exercised."""
    p = rule.params
    candidates = {
        "gt": p[0] + 1, "gte": p[0],
        "lt": p[0] - 1, "lte": p[0],
        "within_range": (p[0] + p[1]) / 2,
        "outside_range": p[1] + 1,
    }
    value = candidates[rule.evaluator]
    assert rule.breaches(value), f"{rule.title}: {value} does not breach {rule.evaluator}{p}"
    return value


def _clear_value(rule):
    p = rule.params
    candidates = {
        "gt": p[0], "gte": p[0] - 1,
        "lt": p[0], "lte": p[0] + 1,
        "within_range": p[0] - 1,
        "outside_range": (p[0] + p[1]) / 2,
    }
    value = candidates[rule.evaluator]
    assert not rule.breaches(value), f"{rule.title}: {value} breaches {rule.evaluator}{p}"
    return value


if __name__ == "__main__":
    unittest.main()
