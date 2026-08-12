"""Can one isolated event page someone? (#594)

`test_rule_behaviour.py` models Grafana's state machine fed with query *results*, and
deliberately stops at the query boundary. That leaves one class of bug unreachable:
the interaction between an expression's **range window** and the rule's **pending
period**.

THE TRAP. A single counter increment at `T` makes `rate(m[W])` / `increase(m[W])`
positive for every evaluation in `(T, T+W]`. So a `gt 0` threshold is satisfied for a
solid `W` after one lone event. If the pending period is `<= W`, that one event is
sufficient to reach Alerting — the pending period debounces nothing, because it
expires before the window slides off. For `for` to mean "sustained" it has to
**exceed** `W`.

That is not automatically a bug: most of the rules in this shape *want* to fire on a
single occurrence ("any NAK at all is abnormal"). It is a bug only when a rule's
declared intent is "sustained" and its shape delivers "one event". #594 was exactly
that: `OPNsenseDHCP6AllocationFailures` promised, in its own runbook text, that "a
single refusal from a client that has since been served is not worth paging on", then
fired on precisely that — once an hour for months, on one HomePod asking for a prefix
delegation the box has no `pd-pools` to satisfy.

So the fix is not "make every rule insensitive". It is to force the choice to be
EXPLICIT: every windowed `gt 0` rule is classified below, and a rule claiming
`SUSTAINED` must have a pending period longer than its widest window. A new rule that
is neither classification fails the completeness test rather than silently inheriting
whichever behaviour its numbers happen to produce.
"""

import glob
import json
import os
import re
import sys
import unittest
from pathlib import Path

GRAFANA_DIR = Path(__file__).resolve().parents[1]
ALERTS_DIR = GRAFANA_DIR / "alerts"
MANIFEST_DIR = ALERTS_DIR / "grafana-managed"
sys.path.insert(0, str(GRAFANA_DIR))
sys.path.insert(0, str(ALERTS_DIR))

import ruleeval  # noqa: E402
from ruleeval import ALERTING  # noqa: E402

# Range selectors on the rate-like functions. `[$__rate_interval]` and friends are not
# used by build_rules.py; a literal duration is the only shape emitted, and an
# unparseable one must fail loudly rather than be skipped.
_WINDOWED_FN = re.compile(r"\b(?:rate|irate|increase|delta)\s*\(")
_WINDOW = re.compile(r"\[(\d+)([smhd])\]")
_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}

# Fires on a single occurrence BY DESIGN. Each entry is the rule's own reason, taken
# from its runbook `threshold` text — not a judgement made here. Adding a rule to this
# list is a statement that one event is worth alerting on; if that is not true, fix the
# rule's numbers instead.
SINGLE_EVENT_OK = {
    "OPNsenseDHCPClientNak":
        "any NAK at all is abnormal on a stable WAN",
    "OPNsenseDHCPClientScriptFailure":
        "the healthy script reasons are excluded, so any remaining one is a fault",
    "OPNsenseKernelZoneAllocationFailure":
        "scoped to zones that must never fail; one failure in those is real",
    "OPNsenseLogShipCountedLoss":
        "for_min=0 on purpose - any counted loss is worth knowing about",
    "OPNsenseLogShipResourceCapped":
        "for_min=0 on purpose - a cap being hit is a discrete fact, not a rate",
    "OPNsenseNetFlowHookDead":
        "a dead hook is a state, not a rate; one observation is the whole signal",
}

# Must NOT fire on a single occurrence: the pending period has to exceed the widest
# window. `OPNsenseEndpointErrors` is the reference shape — a deliberately SHORT inner
# window under a LONG pending period, so the condition holds only while every rolling
# window stays non-empty. #594's fix follows it.
SUSTAINED = {
    "OPNsenseDHCP6AllocationFailures":
        "#594 - one IA_PD solicit from a Thread border router is not a lease outage",
    "OPNsenseEndpointErrors":
        "a router reboot clears the 2m window before the 15m pending period (#94)",
    "OPNsenseFlowCorrelatorEvicting":
        "runbook: gt 0 sustained for 15m",
    "OPNsenseFlowLogsTruncated":
        "runbook: gt 0 sustained for 10m",
    "OPNsenseLogShipSinkErrors":
        "runbook: gt 0 sustained for 10m",
    "OPNsenseNetisrQueueDrops":
        "runbook: gt 0 (any sustained drop rate) for 10m",
    "OPNsenseNetmapRingFull":
        "#675 - two occurrences 15m apart during a traffic spike are a burst, not a full ring",
}


def _windowed_gt_zero_rules() -> dict:
    """title -> (rule, widest window in seconds), for rules a lone event can satisfy.

    Restricted to `gt 0`: that is the threshold for which "the window is non-empty" and
    "the condition is met" are the same statement. A rule thresholded above zero already
    requires more than one event and is a different question.
    """
    out = {}
    for path in sorted(glob.glob(os.path.join(MANIFEST_DIR, "*.json"))):
        with open(path) as f:
            doc = json.load(f)
        if doc.get("kind") != "AlertRule":
            continue
        expr = doc["spec"]["expressions"]["A"]["model"]["expr"]
        if not _WINDOWED_FN.search(expr):
            continue
        rule = ruleeval.rule_from_manifest(doc)
        if not (rule.evaluator == "gt" and rule.params[0] == 0):
            continue
        windows = [int(n) * _UNIT_SECONDS[u] for n, u in _WINDOW.findall(expr)]
        assert windows, (
            f"{rule.title}: uses a rate-like function but no literal range selector was "
            f"found in {expr!r}; this test cannot reason about its sensitivity")
        out[rule.title] = (rule, max(windows))
    return out


WINDOWED = _windowed_gt_zero_rules()


class ClassificationCompletenessTest(unittest.TestCase):
    """Every rule a lone event can satisfy has to declare which behaviour it wants."""

    def test_the_harness_found_windowed_rules_at_all(self):
        self.assertTrue(WINDOWED, f"no windowed gt-0 rules found in {MANIFEST_DIR}; the "
                                  "detector is broken, not the rules")

    def test_every_windowed_gt_zero_rule_is_classified(self):
        classified = set(SINGLE_EVENT_OK) | set(SUSTAINED)
        unclassified = sorted(set(WINDOWED) - classified)
        self.assertEqual(
            unclassified, [],
            "these rules can fire on one isolated event and have not said whether that "
            "is intended. Add each to SINGLE_EVENT_OK (with the reason from its runbook "
            "threshold text) or to SUSTAINED (and give it a pending period longer than "
            f"its window): {unclassified}")

    def test_no_classification_names_a_rule_that_no_longer_qualifies(self):
        """A stale entry is worse than a missing one: it reads as a considered decision
        while guarding nothing."""
        stale = sorted((set(SINGLE_EVENT_OK) | set(SUSTAINED)) - set(WINDOWED))
        self.assertEqual(
            stale, [],
            "these rules are classified here but are no longer windowed gt-0 rules. "
            f"Remove them: {stale}")

    def test_a_rule_is_not_in_both_lists(self):
        self.assertEqual(sorted(set(SINGLE_EVENT_OK) & set(SUSTAINED)), [])


class SustainedRulesTest(unittest.TestCase):
    """The invariant, stated two ways: on the shape, and on the state machine."""

    def test_the_pending_period_exceeds_the_window(self):
        """The arithmetic that makes a lone event unable to fire.

        Strictly greater, not equal: at `for == W` the pending period elapses on the
        same evaluation the window still covers the event, so it fires.
        """
        for title in sorted(SUSTAINED):
            rule, window = WINDOWED[title]
            with self.subTest(title=title):
                self.assertGreater(
                    rule.for_seconds, window,
                    f"{title} claims to need a sustained failure but its pending period "
                    f"({rule.for_seconds}s) does not exceed its {window}s window, so a "
                    "single event reaches Alerting before the window slides off")

    def test_one_isolated_event_never_reaches_alerting(self):
        """The same property through the state machine, so a future shape that satisfies
        the arithmetic differently is still covered.

        A lone increment is modelled as the query returning `1` for exactly as many
        evaluations as the window spans, then zero. For a `gt 0` rule the unit is
        immaterial — `rate` would return `1/W` and `increase` would return `1`, and both
        breach `gt 0` identically. For a rule thresholded above zero, `1` is the honest
        value: one event was counted.
        """
        for title in sorted(SUSTAINED):
            rule, window = WINDOWED[title]
            ticks = max(1, window // rule.interval_seconds)
            timeline = ([{"fw1": 1} for _ in range(ticks)]
                        + [{"fw1": 0} for _ in range(5)])
            with self.subTest(title=title):
                states = ruleeval.evaluate(rule, timeline)
                self.assertNotIn(
                    ALERTING, [s.states.get("fw1") for s in states],
                    f"{title} fired on a single isolated event: one failure kept the "
                    f"{window}s window non-empty for {ticks} evaluations, which outlasted "
                    f"its {rule.for_seconds}s pending period")

    def test_a_genuinely_sustained_failure_still_fires(self):
        """The other half. A rule that cannot fire at all is not a fix."""
        for title in sorted(SUSTAINED):
            rule, window = WINDOWED[title]
            breaching = rule.params[0] + 10
            self.assertTrue(rule.breaches(breaching))
            ticks = rule.for_seconds // rule.interval_seconds + 2
            with self.subTest(title=title):
                states = ruleeval.evaluate(rule, [{"fw1": breaching} for _ in range(ticks)])
                self.assertEqual(
                    states[-1].states.get("fw1"), ALERTING,
                    f"{title} never fires even on a sustained breach")


class DHCP6AllocationFailuresTest(unittest.TestCase):
    """The prod pattern from #594, spelled out rather than left to the sweep.

    Measured on `opnsense.rob-knight.net` on 2026-07-31: one
    `ALLOC_ENGINE_V6_ALLOC_FAIL_NO_POOLS` per hour, all 11 that day from a single DUID
    (`homepod-bedroom`), each an IA_PD-only SOLICIT answered `NoPrefixAvail` because
    both subnets carry `"pd-pools": []`. The client's IA_NA lease renewed cleanly
    throughout, so no address was ever denied.
    """

    TITLE = "OPNsenseDHCP6AllocationFailures"

    def test_the_hourly_single_client_trickle_does_not_fire(self):
        """Six hours at the measured cadence: one event, then nothing for the rest of
        the hour.

        The gaps are the whole point. Each event keeps the window non-empty for exactly
        `window` seconds and the query then returns zero, which resets the pending
        period. A rule whose pending period exceeds its window can never accumulate
        enough consecutive breaches at this cadence; the shipped rule could, because
        its window outlasted its pending period.
        """
        rule, window = WINDOWED[self.TITLE]
        per_hour = 3600 // rule.interval_seconds
        positive_ticks = max(1, window // rule.interval_seconds)
        self.assertLess(positive_ticks, per_hour,
                        "the window is an hour or wider; this model assumes the trickle "
                        "leaves the window empty between events")

        timeline = []
        for _ in range(6):
            timeline += [{"fw1": 1} for _ in range(positive_ticks)]
            timeline += [{"fw1": 0} for _ in range(per_hour - positive_ticks)]

        states = ruleeval.evaluate(rule, timeline)
        self.assertNotIn(
            ALERTING, [s.states.get("fw1") for s in states],
            "the observed prod pattern - one refused IA_PD solicit per hour from one "
            "Thread border router - still pages someone")

    def test_a_real_refusal_storm_fires(self):
        """Pool exhaustion or a genuinely missing address pool refuses every request,
        not one an hour."""
        rule, _ = WINDOWED[self.TITLE]
        storm = rule.params[0] + 60
        ticks = rule.for_seconds // rule.interval_seconds + 2
        states = ruleeval.evaluate(rule, [{"fw1": storm} for _ in range(ticks)])
        self.assertEqual(states[-1].states.get("fw1"), ALERTING)


class NetmapRingFullTest(unittest.TestCase):
    """The prod pattern from #675, and the case the sweep above structurally misses.

    `SustainedRulesTest` models ONE isolated event. That is not the only thing a
    "sustained" rule must survive: several isolated events, spaced further apart than
    the window, are still bursts, and a rule whose pending period only just exceeds its
    window can chain them into a page. The shipped rule was `rate(...[15m])` under
    `for:30m`, so TWO occurrences 15m apart held `gt 0` for the entire pending period -
    while passing `test_the_pending_period_exceeds_the_window`, because 30m > 15m.

    Measured on `opnsense.rob-knight.net` on 2026-08-12, `device=ixl0`: four increments
    of `opnsense_log_events_netmap_ring_full_events_total` at 13:50 (+8), 14:00 (+4),
    15:25 (+2) and 15:40 (+4) BST, each on a short LAN throughput burst of 100-530 Mbps.
    The datapath was healthy throughout - native netmap, `eastpect` running, the kernel's
    own lines showing the 1024-slot host ring draining immediately - and two later
    minutes at ~500 Mbps produced no occurrences at all.
    """

    TITLE = "OPNsenseNetmapRingFull"

    # Minutes past the first occurrence, from the measurement above.
    OBSERVED_OFFSETS_MIN = (0, 10, 95, 110)

    def test_the_observed_burst_cadence_does_not_fire(self):
        rule, window = WINDOWED[self.TITLE]
        positive_ticks = max(1, window // rule.interval_seconds)
        per_min = 60 // rule.interval_seconds
        self.assertLess(
            window, 10 * 60,
            "the window is 10m or wider, so the observed 10m gap no longer empties it "
            "and this model is not testing what it claims")

        timeline = []
        for start in self.OBSERVED_OFFSETS_MIN:
            at = start * per_min
            timeline += [{"fw1": 0} for _ in range(at - len(timeline))]
            timeline += [{"fw1": 1} for _ in range(positive_ticks)]
        timeline += [{"fw1": 0} for _ in range(5)]

        states = ruleeval.evaluate(rule, timeline)
        self.assertNotIn(
            ALERTING, [s.states.get("fw1") for s in states],
            "the observed prod pattern - a handful of occurrences on short traffic "
            "bursts, the nearest pair 10m apart - still pages someone")

    def test_two_occurrences_one_window_apart_do_not_chain(self):
        """The exact defect: back-to-back bursts spaced by the window itself.

        This is the worst case a burst can produce, because the second event lands on the
        evaluation the first window slides off, so the condition never goes false between
        them. It must still fall short of the pending period.
        """
        rule, window = WINDOWED[self.TITLE]
        positive_ticks = max(1, window // rule.interval_seconds)
        pending_ticks = rule.for_seconds // rule.interval_seconds
        timeline = ([{"fw1": 1} for _ in range(positive_ticks * 2)]
                    + [{"fw1": 0} for _ in range(5)])
        self.assertLess(
            positive_ticks * 2, pending_ticks,
            f"{self.TITLE}: two occurrences one window apart span {positive_ticks * 2} "
            f"evaluations, which reaches its {pending_ticks}-evaluation pending period. "
            "The window must be well under half the pending period, not merely under it")

        states = ruleeval.evaluate(rule, timeline)
        self.assertNotIn(ALERTING, [s.states.get("fw1") for s in states])

    def test_a_persistently_full_ring_still_fires(self):
        """The other half. The kernel rate-limits the log line to 2/s, so a ring that is
        genuinely full keeps every rolling window non-empty."""
        rule, _ = WINDOWED[self.TITLE]
        ticks = rule.for_seconds // rule.interval_seconds + 2
        states = ruleeval.evaluate(rule, [{"fw1": 1} for _ in range(ticks)])
        self.assertEqual(states[-1].states.get("fw1"), ALERTING)


if __name__ == "__main__":
    unittest.main()
