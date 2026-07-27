"""Cross-surface guard for #418 and #464.

Prometheus/OTLP convention is that a monotonic sum (a Prometheus COUNTER) exports
with a `_total` suffix. The exporter's supported live backend is OTLP-fed, and
OTLP -> Prometheus canonicalization appends `_total` to every counter regardless
of what name the Go code declared it with. A Counter-typed metric declared
WITHOUT `_total` therefore produces two different names depending on backend
(direct /metrics vs the OTLP-bridged Prometheus that real deployments query),
and any dashboard panel or alert rule written against the unsuffixed name
returns no data on the supported live backend once that series exists.

This derives each metric's Prometheus export name and instrument type from the
generated catalogue (docs/metrics/metrics.md, produced by scripts/docgen from the
actual MustNewConstMetric emission — see scripts/docgen/type_resolution_test.go)
and asserts every opnsense_* metric name referenced anywhere in the generated
dashboard (grafana/dashboard.json) or the generated Grafana-managed alert/
recording rules (grafana/alerts/grafana-managed/*.json) that the catalogue types
as Counter ends in `_total`.

#418 fixed the eight firewall pf pass/block descriptors; #464 fixed the
remaining nine (ipsec phase1/phase2 byte+packet counters, vnstat bytes_total).
The guard is unconditional — there is no known-violations exemption to update
when adding a new counter; get the name right the first time.
"""
import glob
import re
import unittest
from pathlib import Path

GRAFANA_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = GRAFANA_DIR.parent
METRICS_MD = REPO_ROOT / "docs" / "metrics" / "metrics.md"
DASHBOARD_JSON = GRAFANA_DIR / "dashboard.json"
GRAFANA_MANAGED_DIR = GRAFANA_DIR / "alerts" / "grafana-managed"

CATALOGUE_ROW_RE = re.compile(r"\|\s*(opnsense_[a-z0-9_]+)\s*\|\s*(\w+)\s*\|")
METRIC_NAME_RE = re.compile(r"opnsense_[a-z0-9_]+")


def load_catalogue_types() -> dict:
    """metric name -> documented Type ("Counter"/"Gauge"/...), from the generated
    catalogue table. Mirrors build_dashboard.load_catalogue()'s row-matching regex."""
    types = {}
    with open(METRICS_MD) as f:
        for line in f:
            m = CATALOGUE_ROW_RE.match(line)
            if m:
                types[m.group(1)] = m.group(2)
    return types


def referenced_metric_names(*paths) -> set:
    names = set()
    for path in paths:
        with open(path) as f:
            names |= set(METRIC_NAME_RE.findall(f.read()))
    return names


class CounterMetricsEndInTotalTest(unittest.TestCase):
    """#418: a Counter-typed metric consumed by the generated dashboard or the
    generated Grafana-managed alert/recording rules must end in `_total`, or it
    silently returns no data against the supported OTLP-fed live backend."""

    def test_dashboard_and_managed_alerts_counters_end_in_total(self):
        catalogue = load_catalogue_types()
        self.assertTrue(catalogue, "expected a non-empty metrics catalogue")

        managed_files = sorted(glob.glob(str(GRAFANA_MANAGED_DIR / "*.json")))
        self.assertTrue(managed_files, "expected grafana-managed alert manifests")

        referenced = referenced_metric_names(DASHBOARD_JSON, *managed_files)

        violations = []
        for name in sorted(referenced):
            if catalogue.get(name) == "Counter" and not name.endswith("_total"):
                violations.append(name)

        self.assertEqual(
            [], violations,
            "Counter-typed metrics referenced in the generated dashboard/alerts "
            "must end in _total (OTLP->Prometheus canonicalization appends it "
            "regardless of the Go-declared name, so the unsuffixed name returns "
            f"no data on the supported live backend): {violations}",
        )


if __name__ == "__main__":
    unittest.main()
