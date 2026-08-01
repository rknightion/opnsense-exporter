"""Guard: every hidden Prometheus presence sentinel is scoped to the selected
appliance (#414).

A sentinel drives `conditionalRendering` on a tab or a row, so it is a navigation
element, not a panel. An UNSCOPED sentinel answers "does any box in the fleet
export this metric?" while every panel behind it answers "does the SELECTED box
export it?" — so on a multi-box Prometheus a tab lights up because a different
firewall runs the plugin, and every panel inside it reads No data. That is worse
than a hidden tab: it is a navigation element that lies.

The fix is structural rather than per-call-site. `Builder.sentinel()` takes a
declared scope MODE and builds the query itself, so a new sentinel cannot be
written unscoped by accident. This test is the inventory that keeps it honest:

* `collector`     — domain metric carrying `opnsense_instance`.
* `self_labeled`  — exporter self-metric that carries `opnsense_instance` because
                    it was registered through `logship.SelfMetricsRegisterer`.
* `target_join`   — metric with NO appliance label (`go_*`, `process_*`, the
                    raw-registry `opnsense_exporter_otlp_*` family). Scoped by
                    joining to `opnsense_up` on the co-scrape identity
                    `(job, instance)`.
* `global`        — deliberately fleet-wide. Requires a `reason=` at the call site
                    AND an entry in GLOBAL_SENTINEL_ALLOWLIST below, so "I could
                    not work out the right mode" cannot masquerade as a decision.
"""

import sys
import unittest
from pathlib import Path


GRAFANA_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GRAFANA_DIR))

import build_dashboard  # noqa: E402
from builder import INSTANCE_SEL, Builder  # noqa: E402


# Sentinels that are deliberately NOT scoped to $opnsense_instance, each with the
# reason it cannot be. EMPTY BY DESIGN: `target_join` exists precisely so that a
# metric without an appliance label still gets scoped, so "the metric has no
# opnsense_instance label" is NOT a reason to land here. Adding an entry is a
# product decision about a lying navigation element — justify it in the value.
GLOBAL_SENTINEL_ALLOWLIST: dict[str, str] = {}

KNOWN_MODES = {"collector", "self_labeled", "target_join", "global"}
# The only two modes excused from carrying the matcher in their own selector:
# target_join carries it on the joined right-hand side instead, and global is an
# allowlisted deliberate exception. Anything else — including a sentinel that
# declares no mode at all — must carry it.
MATCHER_EXEMPT_MODES = {"target_join", "global"}

# A target_join sentinel must carry all three: the vector-match on the co-scrape
# identity, the many-to-one modifier, and a right-hand side that is itself scoped
# and made unique by `max by (job, instance)` (group_left() errors on duplicates).
TARGET_JOIN_FRAGMENTS = (
    "* on(job, instance) group_left()",
    f"max by (job, instance) (opnsense_up{{{INSTANCE_SEL}}})",
)


def prometheus_sentinels(builder) -> dict[str, str]:
    """Hidden Prometheus QueryVariables -> their query string, as shipped."""
    found = {}
    for variable in builder.all_variables():
        spec = variable["spec"]
        if variable["kind"] != "QueryVariable" or spec["hide"] != "hideVariable":
            continue
        query = spec["query"]
        if query["group"] != "prometheus":
            continue
        found[spec["name"]] = query["spec"]["query"]
    return found


class SentinelScopingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = build_dashboard.build_all()
        cls.sentinels = prometheus_sentinels(cls.builder)
        cls.modes = dict(getattr(cls.builder, "_sentinel_scopes", {}))

    def test_the_declared_mode_inventory_covers_every_shipped_sentinel(self):
        """Guards the guard: if the extractor above ever stops matching the shipped
        variables, every other test in this file passes vacuously."""
        self.assertTrue(self.sentinels, "no Prometheus sentinels found at all")
        self.assertEqual(
            sorted(self.sentinels),
            sorted(self.modes),
            "shipped Prometheus sentinels and declared scope modes disagree",
        )

    def test_every_prometheus_sentinel_declares_a_known_scope_mode(self):
        undeclared = sorted(n for n in self.sentinels if n not in self.modes)
        unknown = sorted(
            f"{n}={self.modes[n]!r}"
            for n in self.sentinels
            if n in self.modes and self.modes[n] not in KNOWN_MODES
        )
        self.assertEqual(
            [], undeclared,
            f"{len(undeclared)} sentinel(s) declare no scope mode: {undeclared}",
        )
        self.assertEqual([], unknown, f"sentinel(s) with an unknown scope mode: {unknown}")

    def test_sentinels_carry_the_instance_matcher_unless_exempt(self):
        unscoped = sorted(
            f"{name} -> {query}"
            for name, query in self.sentinels.items()
            if self.modes.get(name) not in MATCHER_EXEMPT_MODES
            and INSTANCE_SEL not in query
        )
        self.assertEqual(
            [], unscoped,
            f"{len(unscoped)} sentinel(s) are fleet-wide instead of scoped to "
            f"$opnsense_instance:\n  " + "\n  ".join(unscoped),
        )

    def test_target_join_sentinels_scope_through_opnsense_up(self):
        broken = []
        for name, query in self.sentinels.items():
            if self.modes.get(name) != "target_join":
                continue
            missing = [f for f in TARGET_JOIN_FRAGMENTS if f not in query]
            if missing:
                broken.append(f"{name} missing {missing} -> {query}")
        self.assertEqual(
            [], sorted(broken),
            "target_join sentinel(s) do not scope via a join to opnsense_up:\n  "
            + "\n  ".join(sorted(broken)),
        )

    def test_global_sentinels_are_individually_allowlisted(self):
        unjustified = sorted(
            name for name, mode in self.modes.items()
            if mode == "global" and name not in GLOBAL_SENTINEL_ALLOWLIST
        )
        self.assertEqual(
            [], unjustified,
            "fleet-wide sentinel(s) with no documented exception: "
            f"{unjustified} (add to GLOBAL_SENTINEL_ALLOWLIST with a reason, or "
            "pick collector/self_labeled/target_join)",
        )
        stale = sorted(n for n in GLOBAL_SENTINEL_ALLOWLIST if self.modes.get(n) != "global")
        self.assertEqual([], stale, f"stale GLOBAL_SENTINEL_ALLOWLIST entries: {stale}")


class SentinelRegistrationTest(unittest.TestCase):
    def test_a_duplicate_sentinel_name_raises_instead_of_being_dropped(self):
        """`has_netflow` was registered twice with two DIFFERENT queries (#414).
        The old silent-dedupe kept whichever module ran first, so the second
        registration was a no-op and the rows gated on it were silently gated on
        somebody else's metric."""
        builder = Builder()
        builder.sentinel("has_thing", metric="opnsense_thing_total")
        with self.assertRaises(ValueError):
            builder.sentinel("has_thing", metric="opnsense_other_total")

    def test_a_global_sentinel_must_state_a_reason(self):
        builder = Builder()
        with self.assertRaises(ValueError):
            builder.sentinel("has_thing", metric="opnsense_thing_total", scope="global")

    def test_an_unknown_scope_mode_raises(self):
        builder = Builder()
        with self.assertRaises(ValueError):
            builder.sentinel("has_thing", metric="opnsense_thing_total", scope="fleet")


if __name__ == "__main__":
    unittest.main()
