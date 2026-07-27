"""Guard: the feature-sentinel documentation contract cannot drift from the live
registry (#417).

`grafana/sentinel_contract.py` generates BOTH `grafana/sentinel-contract.json` and
the marked region of `grafana/tabs/AUTHORING.md` from the same `Builder` instance
`build_dashboard.build_all()` produces. This file is the fast, no-subprocess
staleness check: it rebuilds the contract from the CURRENT registry and diffs it
against the two committed artifacts, so a sentinel added/removed/rescoped without
running `make dashboard` fails here (and, in CI, again via `make grafana-check`'s
`git diff --exit-code`).

It also re-asserts the two things #417 exists to keep true of the documentation:

* every shipped sentinel appears EXACTLY ONCE in the structured inventory
  (never zero, never duplicated);
* the #114 zero-value regression guard is visible in that inventory — exactly one
  sentinel (`has_carp_vips`) is presence-tested by VALUE, and every DHCP presence
  sentinel is presence-tested by EXISTENCE.
"""

import sys
import unittest
from pathlib import Path


GRAFANA_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GRAFANA_DIR))

import build_dashboard  # noqa: E402
import sentinel_contract  # noqa: E402
from builder import SENTINEL_SCOPES  # noqa: E402


CONTRACT_PATH = GRAFANA_DIR / "sentinel-contract.json"
AUTHORING_PATH = GRAFANA_DIR / "tabs" / "AUTHORING.md"

# The single documented exception to "presence tests series existence, not value"
# (#114 / #417). If this set ever needs a second member, the call site MUST carry
# the same kind of justification comment `tabs/carp.py` does for this one.
EXPECTED_VALUE_TESTED_SENTINELS = {"has_carp_vips"}

DHCP_PRESENCE_SENTINELS = {"has_dnsmasq", "has_kea", "has_dhcpv4_isc", "has_dhcpv6_isc"}


class SentinelContractTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = build_dashboard.build_all()
        cls.contract = sentinel_contract.build_contract(cls.builder)

    # ---- completeness -----------------------------------------------------
    def test_every_shipped_prometheus_sentinel_appears_exactly_once(self):
        shipped = sentinel_contract._extract_prometheus_sentinels(self.builder)
        documented = [e["name"] for e in self.contract["prometheus"]["sentinels"]]
        self.assertEqual(sorted(shipped), sorted(documented))
        self.assertEqual(len(documented), len(set(documented)),
                          "a sentinel is documented more than once")

    def test_every_shipped_loki_sentinel_appears_exactly_once(self):
        shipped = sentinel_contract._extract_loki_sentinels(self.builder)
        documented = [e["name"] for e in self.contract["loki"]["sentinels"]]
        self.assertEqual(sorted(shipped), sorted(documented))
        self.assertEqual(len(documented), len(set(documented)),
                          "a Loki sentinel is documented more than once")

    def test_prometheus_and_loki_sentinel_names_are_disjoint(self):
        prom_names = {e["name"] for e in self.contract["prometheus"]["sentinels"]}
        loki_names = {e["name"] for e in self.contract["loki"]["sentinels"]}
        self.assertEqual(set(), prom_names & loki_names)

    # ---- fidelity: docs must match the live registry, field by field ------
    def test_declared_scope_matches_the_live_registry(self):
        live = dict(self.builder._sentinel_scopes)
        for entry in self.contract["prometheus"]["sentinels"]:
            with self.subTest(name=entry["name"]):
                self.assertEqual(live[entry["name"]], entry["scope"])
                self.assertIn(entry["scope"], SENTINEL_SCOPES)

    def test_query_matches_the_live_registry(self):
        live = sentinel_contract._extract_prometheus_sentinels(self.builder)
        for entry in self.contract["prometheus"]["sentinels"]:
            with self.subTest(name=entry["name"]):
                self.assertEqual(live[entry["name"]], entry["query"])
        live_loki = sentinel_contract._extract_loki_sentinels(self.builder)
        for entry in self.contract["loki"]["sentinels"]:
            with self.subTest(name=entry["name"]):
                self.assertEqual(live_loki[entry["name"]], entry["query"])

    def test_by_scope_totals_match_a_direct_count(self):
        from collections import Counter
        live_counts = Counter(self.builder._sentinel_scopes.values())
        for mode in SENTINEL_SCOPES:
            with self.subTest(mode=mode):
                self.assertEqual(live_counts.get(mode, 0),
                                  self.contract["prometheus"]["by_scope"][mode])
        self.assertEqual(sum(live_counts.values()), self.contract["prometheus"]["total"])

    # ---- the #114 / #417 presence-semantics regression guard --------------
    def test_exactly_the_documented_sentinel_is_value_tested(self):
        value_tested = {
            e["name"] for e in self.contract["prometheus"]["sentinels"]
            if e["presence"] == sentinel_contract.PRESENCE_VALUE
        }
        self.assertEqual(EXPECTED_VALUE_TESTED_SENTINELS, value_tested)

    def test_every_dhcp_presence_sentinel_is_existence_tested(self):
        by_name = {e["name"]: e for e in self.contract["prometheus"]["sentinels"]}
        for name in DHCP_PRESENCE_SENTINELS:
            with self.subTest(name=name):
                self.assertEqual(sentinel_contract.PRESENCE_EXISTENCE, by_name[name]["presence"],
                                  f"{name} must gate on existence, not a lease/value threshold (#114)")

    def test_every_loki_sentinel_is_existence_tested(self):
        for e in self.contract["loki"]["sentinels"]:
            with self.subTest(name=e["name"]):
                self.assertEqual(sentinel_contract.PRESENCE_EXISTENCE, e["presence"])

    # ---- every sentinel actually gates something ---------------------------
    def test_no_sentinel_is_registered_without_gating_a_tab_or_row(self):
        dead = [e["name"] for e in
                self.contract["prometheus"]["sentinels"] + self.contract["loki"]["sentinels"]
                if not e["gates"]]
        self.assertEqual([], dead, f"sentinel(s) registered but never used as present=: {dead}")

    # ---- staleness: generated artifacts must match what ships NOW ---------
    def test_sentinel_contract_json_is_not_stale(self):
        self.assertTrue(CONTRACT_PATH.exists(),
                         f"{CONTRACT_PATH} does not exist — run `make dashboard`")
        expected = sentinel_contract.contract_json(self.contract)
        actual = CONTRACT_PATH.read_text()
        self.assertEqual(expected, actual,
                          "grafana/sentinel-contract.json is stale relative to the live "
                          "sentinel registry — run `make dashboard` and commit the result")

    def test_authoring_md_generated_section_is_not_stale(self):
        self.assertTrue(AUTHORING_PATH.exists())
        doc = AUTHORING_PATH.read_text()
        bi = doc.find(sentinel_contract.BEGIN_MARKER)
        ei = doc.find(sentinel_contract.END_MARKER)
        self.assertGreaterEqual(bi, 0, "sentinelgen begin marker missing from AUTHORING.md")
        self.assertGreaterEqual(ei, 0, "sentinelgen end marker missing from AUTHORING.md")
        current_section = doc[bi + len(sentinel_contract.BEGIN_MARKER):ei].strip()
        expected_section = sentinel_contract.render_authoring_section(self.contract).strip()
        self.assertEqual(expected_section, current_section,
                          "AUTHORING.md's generated sentinel section is stale — run "
                          "`make dashboard` and commit the result")


if __name__ == "__main__":
    unittest.main()
