"""Gate: the runtime-metric ledger and the panels agree, both ways (#591 item 4).

`up`, `go_*` and `process_*` are structurally invisible to `coverage()`. That gate
reads two generated catalogues whose row regex admits only `opnsense_`-prefixed
names, and it could not do otherwise — those documents describe what this codebase
emits, while these metrics come from the Prometheus server and the Go client library.
Widening the regex would not help; there is no row for it to match. So the gate that
reports "1020/1020 metrics referenced" has never had an opinion about the entire
runtime namespace (blind spot 1 of #591), and "we decided not to chart that" lived
only in people's heads.

`RUNTIME_METRIC_LEDGER` is the decision record, and this file is what keeps it
honest. Its PANELLED half is enforced in both directions — an unledgered runtime
metric on a panel fails, and a ledger entry claiming a panel that no longer exists
fails. Its EXCLUDED half is deliberately not enforced and the tests below say why: a
check that every excluded metric exists would have to assert against a hardcoded list
of what client_golang emits on the operator's platform and version, which is the
exact drift the ledger replaces, reintroduced one layer down.
"""
import sys
import unittest
from pathlib import Path

GRAFANA_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GRAFANA_DIR))

import build_dashboard  # noqa: E402
from builder import Builder  # noqa: E402


class RuntimeLedgerTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builders = [b for _, b in build_dashboard.build_family()]

    def test_ledger_and_panels_agree(self):
        result = build_dashboard.runtime_ledger_gaps(*self.builders)
        self.assertEqual(
            {}, result["unledgered"],
            "runtime metric(s) are queried by a panel with no PANELLED ledger entry. "
            "Add one naming the panel and the question it answers — the coverage gate "
            "cannot see these metrics at all, so the ledger is the only record that "
            f"they are charted: {sorted(result['unledgered'])}")
        self.assertEqual(
            [], result["stale"],
            "RUNTIME_METRIC_LEDGER entries are marked PANELLED but no panel queries "
            "them. The panel was removed or renamed: repoint the entry, or move it to "
            f"EXCLUDED with the reason it is no longer charted: {result['stale']}")

    def test_every_entry_carries_a_verdict_and_a_reason(self):
        """An entry without a reason is an allowlist nobody can review — the same
        contract COVERAGE_EXEMPT and the sentinel/threshold allowlists ship with."""
        for key, entry in build_dashboard.RUNTIME_METRIC_LEDGER.items():
            self.assertEqual(2, len(entry), f"{key}: expected (verdict, reason)")
            verdict, reason = entry
            self.assertIn(verdict, (build_dashboard.PANELLED, build_dashboard.EXCLUDED),
                          f"{key}: unknown verdict {verdict!r}")
            self.assertGreater(
                len(reason.strip()), 30,
                f"{key}: the reason is too short to be a decision record. Say what "
                "the metric would tell an operator and why that is or is not worth a "
                "panel — 'not useful' is not a reason.")

    def test_the_four_decisions_rob_made_are_recorded_as_panelled(self):
        """#591 item 4 is a decision, not a discovery, and these four are what was
        decided (Rob, 2026-07-31: selective coverage plus a ledger). Pinned by name so
        a later cleanup cannot quietly drop one back into EXCLUDED without a reader
        noticing that a decision was reversed."""
        ledger = build_dashboard.RUNTIME_METRIC_LEDGER
        for key in ("up", "process_open_fds", "process_max_fds",
                    "go_gc_duration_seconds*"):
            self.assertIn(key, ledger, f"{key} was decided in #591 and must stay in "
                                       "the ledger")
            self.assertEqual(build_dashboard.PANELLED, ledger[key][0],
                             f"{key} was decided PANELLED in #591; moving it to "
                             "EXCLUDED reverses an owner decision")

    def test_a_specific_name_overrides_the_family_it_sits_in(self):
        """`go_memstats_heap_inuse_bytes` is charted while the rest of
        `go_memstats_*` is not. A shortest-match lookup would hand the family's
        EXCLUDED verdict to the one member that has its own, and the gate would then
        report the Exporter Memory panel as querying an unledgered metric."""
        family = build_dashboard._ledger_entry("go_memstats_alloc_bytes")
        specific = build_dashboard._ledger_entry("go_memstats_heap_inuse_bytes")
        self.assertEqual(build_dashboard.EXCLUDED, family[0])
        self.assertEqual(build_dashboard.PANELLED, specific[0])

    def test_an_unledgered_runtime_metric_is_caught(self):
        """The gate has teeth. Without this, a scan that silently matched nothing
        would pass `test_ledger_and_panels_agree` forever."""
        b = Builder()
        b.record_expr('go_memstats_mspan_inuse_bytes{job=~"opnsense.*"}')
        result = build_dashboard.runtime_ledger_gaps(b)
        self.assertIn("go_memstats_mspan_inuse_bytes", result["unledgered"],
                      "a go_* metric with an EXCLUDED family verdict must be reported "
                      "when a panel queries it — that is the moment the decision "
                      "changed and the ledger did not")

    def test_promql_keywords_are_not_mistaken_for_runtime_metrics(self):
        """The scan governs a small closed set of namespaces rather than 'anything
        not opnsense_-prefixed', because PromQL functions, keywords and label names
        are all bare identifiers too. `up` in particular is matched EXACTLY, not as a
        prefix, or `upper` and any label value starting 'up' would be claimed."""
        b = Builder()
        b.record_expr('sort_desc(sum by (le, status) (rate(x[5m]))) > bool 0')
        self.assertEqual({}, build_dashboard.runtime_ledger_gaps(b)["unledgered"])

    def test_the_excluded_half_is_documented_as_unenforceable(self):
        """A guard on the docstring, not on behaviour. The EXCLUDED entries look like
        a checked allowlist and are not one; if that caveat is ever deleted, the next
        reader will trust them as verified coverage."""
        doc = build_dashboard.runtime_ledger_gaps.__doc__ or ""
        self.assertIn("EXCLUDED", doc)
        self.assertIn("NOT enforced", doc)


if __name__ == "__main__":
    unittest.main()
