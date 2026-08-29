"""The self-metric half of the dashboard coverage gate (#428).

Until this landed, the gate's confident "838/838 catalogue metrics referenced" was an
answer to a narrower question than anyone reading it assumed. `load_catalogue()` parsed
only docs/metrics/metrics.md, which docgen fills by walking the COLLECTOR registry — so
every metric registered outside internal/collector was invisible to it. Six were live
misses at the time of writing (both logs_debug_* counters and all four annotations_*),
and grafana/README.md claimed coverage of "every metric the exporter emits".

The tests below pin the two halves that make the stronger claim true: the self-metric
inventory really is fed into the catalogue, and a metric that reaches the inventory
without reaching a panel really does fail the build.
"""
import sys
import tempfile
import unittest
from pathlib import Path

GRAFANA_DIR = Path(__file__).resolve().parents[1]
REPO = GRAFANA_DIR.parent
sys.path.insert(0, str(GRAFANA_DIR))

import build_dashboard  # noqa: E402

SELF_METRICS_MD = REPO / "docs" / "metrics" / "self-metrics.md"


def family():
    """Every Builder in the dashboard family (#431). The gate is a union across
    them, so a check that built only the main dashboard would report every
    self-metric that moved to the health dashboard as missing."""
    return [b for _, b in build_dashboard.build_family()]


class SelfMetricCatalogueTest(unittest.TestCase):
    def test_self_metrics_reach_the_catalogue(self):
        """The generated inventory must actually be loaded, not merely exist on disk."""
        catalogue = set(build_dashboard.load_catalogue())

        # A representative metric from each family that the collector registry walk
        # cannot see. Each is registered on the self-metrics registry only.
        for metric in (
            "opnsense_exporter_logs_shipped_total",          # internal/logship
            "opnsense_exporter_logs_enrich_misses_total",    # internal/logship/enrich
            "opnsense_exporter_logs_debug_captured_total",   # internal/logship/capture
            "opnsense_exporter_annotations_written_total",   # internal/annotations
            "opnsense_exporter_otlp_exports_total",          # internal/telemetry
        ):
            self.assertIn(metric, catalogue,
                          f"{metric} is declared in source but absent from the coverage catalogue; "
                          "run `just docs` to regenerate docs/metrics/self-metrics.md")

    def test_catalogue_is_the_union_of_both_sources(self):
        """Neither source alone is the catalogue, and the overlap is deduplicated."""
        catalogue = build_dashboard.load_catalogue()
        self.assertEqual(len(catalogue), len(set(catalogue)),
                         "load_catalogue() returned duplicates; the two sources overlap on "
                         "internal/collector's meta metrics and must be unioned as a set")

        # A firewall metric reaches it only via metrics.md, a logship metric only via
        # self-metrics.md. Both present proves the union rather than a replacement.
        self.assertIn("opnsense_interfaces_received_bytes_total", catalogue)
        self.assertIn("opnsense_exporter_logs_queue_bytes", catalogue)


class SelfMetricGateFailsOnUncoveredMetricTest(unittest.TestCase):
    """#428's last acceptance criterion: prove the gate actually fails.

    A gate is only worth its runtime if it can go red. This injects a self-metric that
    exists nowhere on the dashboard and asserts coverage() names it — the same path CI
    takes, not a reimplementation of it.
    """

    def setUp(self):
        self.original = build_dashboard.SELF_METRICS_MD

    def tearDown(self):
        build_dashboard.SELF_METRICS_MD = self.original

    def _coverage_with_extra(self, extra_rows: str) -> list:
        with tempfile.TemporaryDirectory() as tmp:
            fake = Path(tmp) / "self-metrics.md"
            fake.write_text(SELF_METRICS_MD.read_text() + extra_rows)
            build_dashboard.SELF_METRICS_MD = str(fake)
            return build_dashboard.coverage(*family())

    def test_real_tree_is_fully_covered(self):
        """The control. Without this, the test below could pass on an already-red gate."""
        missing = build_dashboard.coverage(*family())
        self.assertEqual(missing, [],
                         "the coverage gate is already failing before this test injects "
                         f"anything: {missing}")

    def test_uncovered_self_metric_fails_the_gate(self):
        fake = "opnsense_exporter_totally_fictional_widgets_total"
        missing = self._coverage_with_extra(f"| {fake} | Counter | `internal/nowhere` |\n")
        self.assertIn(fake, missing,
                      "a self-metric with no panel anywhere did not fail the coverage gate; "
                      "the inventory is not reaching coverage()")

    def test_exemption_suppresses_the_failure(self):
        """The escape hatch works, so a genuinely unchartable metric is not a dead end.

        Exercised through the real COVERAGE_EXEMPT set rather than a stub, because the
        thing worth pinning is that the exemption is consulted for self-metrics too.
        """
        fake = "opnsense_exporter_totally_fictional_widgets_total"
        build_dashboard.COVERAGE_EXEMPT.add(fake)
        try:
            missing = self._coverage_with_extra(f"| {fake} | Counter | `internal/nowhere` |\n")
        finally:
            build_dashboard.COVERAGE_EXEMPT.discard(fake)
        self.assertNotIn(fake, missing,
                         "an exempted self-metric still failed the gate")


class CoverageIsUnionAcrossBuildersTest(unittest.TestCase):
    """#431 step 1: the gate spans the dashboard FAMILY, not one file.

    Scoped to a single Builder, the gate made the self-observability split
    structurally impossible — moving a panel to a second dashboard made its metric
    read as MISSING on the first, so the split could not land without weakening the
    gate or exempting every metric it moved. These tests pin the union semantics
    while there is still only one dashboard, so the behaviour is already proven when
    the second one arrives.
    """

    @staticmethod
    def _builder_charting(metric: str):
        b = build_dashboard.Builder()
        b.ts("probe", [(metric, "x")])
        return b

    def test_a_metric_charted_on_another_builder_counts_as_covered(self):
        metric = "opnsense_exporter_logs_shipped_total"
        empty = build_dashboard.Builder()
        charted = self._builder_charting(metric)

        self.assertIn(metric, build_dashboard.coverage(empty),
                      "control: an empty builder must report the metric missing, or the "
                      "test below proves nothing")
        self.assertNotIn(metric, build_dashboard.coverage(empty, charted),
                         "a metric charted on a SECOND builder still read as missing; "
                         "coverage() is not taking the union and the #431 split cannot land")

    def test_a_metric_on_no_builder_is_still_missing(self):
        """The union must not become a way to pass by supplying more builders."""
        metric = "opnsense_exporter_logs_shipped_total"
        two_empties = build_dashboard.coverage(build_dashboard.Builder(),
                                               build_dashboard.Builder())
        self.assertIn(metric, two_empties)


if __name__ == "__main__":
    unittest.main()
