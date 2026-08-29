"""#430: generate complete per-rule runbooks.

Covers the acceptance criteria that `test_manifest_contract.py`'s per-manifest checks
don't already own:

  * exact RULES <-> runbooks.md parity (42 alert sections, no duplicate, no stale one
    left over from a renamed/removed rule) and the same for RECORDING (14),
  * every alert's `runbook_url()` anchor actually resolves against the generated
    document,
  * every rule carries all six `runbook=dict(...)` keys, non-empty,
  * every alert summary that CAN carry `opnsense_instance` does, and any exemption in
    `SUMMARY_INSTANCE_EXEMPT` carries a real reason (never a bare skip).

This suite regenerates runbooks.md into a temp path for its own assertions rather than
trusting the checked-in copy is fresh - `just grafana-check` is what enforces the
checked-in copy is not stale (same pattern as dashboard.json).
"""
import importlib.util
import re
import sys
import unittest
from pathlib import Path

GRAFANA_DIR = Path(__file__).resolve().parents[1]
ALERTS_DIR = GRAFANA_DIR / "alerts"

sys.path.insert(0, str(GRAFANA_DIR))
sys.path.insert(0, str(ALERTS_DIR))

import build_rules  # noqa: E402
import validate_manifests as vm  # noqa: E402
from uids import runbook_url  # noqa: E402

RUNBOOK_KEYS = ("measures", "threshold", "absent", "checks", "causes", "verify")

HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$", re.MULTILINE)


def _headings(markdown: str):
    """Return (level, text) for every heading line, in document order."""
    return [(len(m.group(1)), m.group(2).strip()) for m in HEADING_RE.finditer(markdown)]


class RunbookContentContractTest(unittest.TestCase):
    """Every RULES entry must carry a complete, non-empty runbook=dict(...)."""

    def test_every_rule_has_all_six_runbook_keys(self):
        for r in build_rules.RULES:
            with self.subTest(rule=r["name"]):
                self.assertIn("runbook", r, f"{r['name']} has no runbook=dict(...)")
                rb = r["runbook"]
                for key in RUNBOOK_KEYS:
                    self.assertIn(key, rb, f"{r['name']}.runbook missing {key!r}")

    def test_no_runbook_field_is_empty(self):
        for r in build_rules.RULES:
            rb = r["runbook"]
            for key in RUNBOOK_KEYS:
                value = rb[key]
                with self.subTest(rule=r["name"], key=key):
                    if isinstance(value, list):
                        self.assertTrue(value, f"{r['name']}.runbook[{key}] is empty")
                        for item in value:
                            self.assertTrue(item.strip(), f"{r['name']}.runbook[{key}] has a blank entry")
                    else:
                        self.assertTrue(value.strip(), f"{r['name']}.runbook[{key}] is empty")

    def test_a_missing_runbook_key_fails_the_gate(self):
        # Prove the gate (build_rules.require_complete_runbook, wired into
        # _runbook_section so `just rules` itself fails on this, not just a test)
        # actually fires on a broken input rather than only ever seeing the real,
        # already-complete RULES list.
        rb = dict(build_rules.RULES[0]["runbook"])
        del rb["absent"]
        with self.assertRaises(ValueError):
            build_rules.require_complete_runbook("test-rule", rb)

    def test_an_empty_checks_list_fails_the_gate(self):
        rb = dict(build_rules.RULES[0]["runbook"])
        rb["checks"] = []
        with self.assertRaises(ValueError):
            build_rules.require_complete_runbook("test-rule", rb)

    def test_a_blank_string_field_fails_the_gate(self):
        rb = dict(build_rules.RULES[0]["runbook"])
        rb["measures"] = "   "
        with self.assertRaises(ValueError):
            build_rules.require_complete_runbook("test-rule", rb)

    def test_the_real_runbook_content_passes_the_gate(self):
        for r in build_rules.RULES:
            with self.subTest(rule=r["name"]):
                build_rules.require_complete_runbook(r["name"], r["runbook"])


class RunbookDocumentParityTest(unittest.TestCase):
    """Exact-count parity between the RULES/RECORDING source and the generated doc, and
    no duplicate/stale section left behind."""

    @classmethod
    def setUpClass(cls):
        cls.markdown = build_rules.generate_runbooks_md()
        cls.headings = _headings(cls.markdown)

    def test_exact_alert_count_is_64(self):
        # Re-measured against current main (#430 audit found the tracked issue's
        # figures - 31/19 rows - stale; the epic's 2026-07-27 revalidation corrected
        # it to 42/14, confirmed again here structurally). 43 since #520 added
        # OPNsenseFlowGeoIPDatabaseStale. 50 since the kernel-telemetry wave: two
        # netisr rules (#538), one netmap ring-full (#536) and four WAN DHCP client
        # rules (#541). 53 since wave 2: two kernel-zone rules (#543) and one
        # default-route-missing (#544). 56 since wave 3: three DHCPv6 rules (#546) -
        # prefix expiring, prefix not refreshing, and kea-dhcp6 allocation failures.
        # 57 since #559 added OPNsenseCPUStreamStalled. 59 since #560 added
        # OPNsenseDHCP6AddressExpiring and OPNsenseDHCP6AddressNotRefreshing, the
        # IA_NA WAN-address-lease twin of the two #546 prefix rules. 63 since the
        # epic #593 Phase 4 alert wave (#578/#579/#581/#582): IPsec child-SA-down,
        # mbuf jumbo pool saturation, Unbound upstream lame, and OSPF LSA
        # retransmission stuck. 64 since #592 item 2 (OPNsenseFlowSourceDivergence),
        # handed to this lane by the annotation lane because the underlying metric
        # is a histogram an annotation Watch cannot carry. Back to 63 in #602:
        # OPNsenseFlowSourceDivergence was deleted, not retuned. Its threshold
        # (p90 > 1.5) sat BELOW the metric's normal operating range on every
        # interface that produces data - measured over 24h of live prod, AAISP
        # breached 100% of the time at ~40k observations/hour, so it was not a
        # small-sample artifact. The floor is set by per-packet header overhead on
        # the 2-3 packet UDP flows that are 54% of merged records by count, where
        # NetFlow counts wire bytes and Zenarmor's payload fallback does not (#604).
        # No threshold on an UNWEIGHTED per-flow ratio can express "X% of bytes went
        # uninspected" - the bytes that matter sit in a handful of large flows at
        # ~=1.0 while p90 is set by thousands of tiny ones. Byte-weighted, the two
        # sources agree (1.22-1.36). The histogram and its panel stay; only the
        # alert was wrong. 64 again since #658 added
        # OPNsenseGatewayRTTBaselineDeviation: OPNsenseGatewayHighRTT defers to the
        # operator's configured latencyhigh by design, which left every degradation
        # UNDER that ceiling unalertable - a WAN link stepped from a ~10ms baseline to
        # a sustained ~205ms at 0% loss and no rule in the set could fire on it.
        self.assertEqual(len(build_rules.RULES), 64)

    def test_exact_recording_count_is_14(self):
        self.assertEqual(len(build_rules.RECORDING), 14)

    def test_every_alert_title_has_exactly_one_h2_section(self):
        h2_titles = [text for level, text in self.headings if level == 2]
        alert_titles = [r["title"] for r in build_rules.RULES]
        for title in alert_titles:
            with self.subTest(title=title):
                self.assertEqual(
                    h2_titles.count(title), 1,
                    f"{title!r} appears {h2_titles.count(title)} times as an h2 heading "
                    "in runbooks.md, expected exactly once"
                )

    def test_no_duplicate_h2_headings(self):
        h2_titles = [text for level, text in self.headings if level == 2]
        seen = set()
        dupes = set()
        for t in h2_titles:
            if t in seen:
                dupes.add(t)
            seen.add(t)
        self.assertEqual(dupes, set(), f"duplicate h2 headings in runbooks.md: {dupes}")

    def test_no_stale_section_for_a_removed_rule(self):
        # Every h2 heading other than the fixed "Recording rules" wrapper must map
        # back to a real, current RULES title - proves the doc doesn't carry a
        # leftover section for a renamed/removed alert.
        alert_titles = {r["title"] for r in build_rules.RULES}
        h2_titles = [text for level, text in self.headings if level == 2]
        for t in h2_titles:
            if t == "Recording rules":
                continue
            with self.subTest(heading=t):
                self.assertIn(t, alert_titles, f"{t!r} is an h2 heading with no matching RULES entry")

    def test_every_recording_metric_has_exactly_one_h3_section(self):
        h3_titles = [text for level, text in self.headings if level == 3]
        for r in build_rules.RECORDING:
            with self.subTest(metric=r["metric"]):
                self.assertEqual(h3_titles.count(r["metric"]), 1)

    def test_no_stale_recording_section(self):
        recording_metrics = {r["metric"] for r in build_rules.RECORDING}
        h3_titles = [text for level, text in self.headings if level == 3]
        for t in h3_titles:
            with self.subTest(heading=t):
                self.assertIn(t, recording_metrics)


class RunbookAnchorResolutionTest(unittest.TestCase):
    """Every alert's emitted runbook_url must resolve to a real heading in the
    generated runbooks.md - checked the same structural way
    validate_manifests._runbook_anchor_resolves does, against the freshly-generated
    document rather than relying on the checked-in copy being current."""

    @classmethod
    def setUpClass(cls):
        cls.markdown = build_rules.generate_runbooks_md()
        cls.slugs = set()
        for m in re.finditer(r"^(#{1,6})\s+(.*)$", cls.markdown, re.MULTILINE):
            cls.slugs.add(vm._github_heading_slug(m.group(2).strip()))

    def test_every_alert_runbook_url_anchor_is_a_real_heading(self):
        for r in build_rules.RULES:
            url = runbook_url(r["title"])
            anchor = url.rsplit("#", 1)[1]
            with self.subTest(rule=r["name"]):
                self.assertIn(
                    anchor, self.slugs,
                    f"{r['name']}: runbook_url anchor #{anchor} has no matching heading "
                    "in the generated runbooks.md"
                )

    def test_every_alert_has_a_distinct_anchor(self):
        anchors = [runbook_url(r["title"]).rsplit("#", 1)[1] for r in build_rules.RULES]
        self.assertEqual(len(anchors), len(set(anchors)), "two alerts slug to the same anchor")

    def test_the_checked_in_runbooks_md_matches_the_generator(self):
        # `just grafana-check` / `just rules` is what enforces this isn't stale in CI;
        # this test documents the expectation and gives a clear local signal too.
        checked_in = (GRAFANA_DIR / "runbooks.md").read_text()
        self.assertEqual(
            checked_in, self.markdown,
                          "grafana/runbooks.md is stale relative to build_rules.py - run `just rules`"
        )


class SummaryInstanceIdentityTest(unittest.TestCase):
    """#430: every multi-instance alert summary must identify opnsense_instance where
    the query can carry it. SUMMARY_INSTANCE_EXEMPT is the only escape hatch, and it
    must carry a real reason, never a bare name."""

    def _label_survives(self, expr: str, label: str) -> bool:
        by_clauses = vm._agg_by_label_sets(expr)
        if not by_clauses:
            return True  # no aggregation: every base-metric label survives
        return all(label in by_labels for by_labels in by_clauses)

    def test_every_non_exempt_summary_carries_opnsense_instance(self):
        for r in build_rules.RULES:
            if r["name"] in build_rules.SUMMARY_INSTANCE_EXEMPT:
                continue
            with self.subTest(rule=r["name"]):
                self.assertIn(
                    "{{ $labels.opnsense_instance }}", r["summary"],
                    f"{r['name']}: summary does not identify opnsense_instance and is "
                    "not in SUMMARY_INSTANCE_EXEMPT"
                )

    def test_every_exemption_names_a_real_alert_and_has_a_reason(self):
        names = {r["name"] for r in build_rules.RULES}
        for name, reason in build_rules.SUMMARY_INSTANCE_EXEMPT.items():
            with self.subTest(name=name):
                self.assertIn(name, names, f"{name!r} in SUMMARY_INSTANCE_EXEMPT is not a real rule")
                self.assertTrue(reason.strip(), f"{name!r} exemption has an empty reason")

    def test_an_exempted_rules_query_genuinely_cannot_carry_the_label(self):
        # Prove the one current exemption is not a shortcut: its own query really does
        # not have opnsense_instance available (no by-clause preserving it, and the
        # metric is a bare gauge with no instance dimension at all).
        for r in build_rules.RULES:
            if r["name"] not in build_rules.SUMMARY_INSTANCE_EXEMPT:
                continue
            with self.subTest(rule=r["name"]):
                by_clauses = vm._agg_by_label_sets(r["A"])
                self.assertEqual(
                    by_clauses, [],
                    f"{r['name']} is exempt from carrying opnsense_instance in its summary, "
                    "but its query aggregates explicitly - if opnsense_instance is in a by() "
                    "clause the exemption is wrong and the summary should be fixed instead"
                )

    def test_a_summary_missing_the_instance_token_would_fail_without_an_exemption(self):
        # Prove the gate fires: take a real non-exempt rule and strip the token.
        r = next(r for r in build_rules.RULES if r["name"] not in build_rules.SUMMARY_INSTANCE_EXEMPT)
        stripped = r["summary"].replace("{{ $labels.opnsense_instance }}", "")
        self.assertNotIn("{{ $labels.opnsense_instance }}", stripped)


if __name__ == "__main__":
    unittest.main()
