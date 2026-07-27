"""#429 (manifest-contract half): validate_manifests.py checks fields Prometheus's own
syntax cannot - severity, IRM stack-routing labels, noDataState, execErrState, pending
duration, per-instance label preservation, and resolvable runbook anchors. This suite
covers both halves of that contract:

  * the checked-in grafana-managed/ manifests must pass with zero errors today, and
  * each new assertion must actually fire on a broken input - proven with a hand-built
    bad document or a mutated copy of a real one, never a test that would pass against
    any input.

Explicitly OUT of scope here (left for the timeline/MissingSeries harness, #429's other
half): promtool-style rule evaluation, synthetic time series, multi-instance No
Data/MissingSeries behaviour.
"""
import copy
import glob
import importlib.util
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

GRAFANA_DIR = Path(__file__).resolve().parents[1]
ALERTS_DIR = GRAFANA_DIR / "alerts"
REPO_ROOT = GRAFANA_DIR.parent
REAL_MANIFEST_DIR = ALERTS_DIR / "grafana-managed"

sys.path.insert(0, str(GRAFANA_DIR))
sys.path.insert(0, str(ALERTS_DIR))

import validate_manifests as vm  # noqa: E402
import build_rules  # noqa: E402
from uids import RUNBOOK_URL  # noqa: E402


def _load(name):
    with open(REAL_MANIFEST_DIR / name) as f:
        return json.load(f)


# A real, currently-passing AlertRule manifest used as the base for every
# mutation test below, so a mutation exercises the exact shape the validator
# actually meets rather than a hand-rolled shape it has never seen.
BASE_ALERT_NAME = "opnsense-carp-state-flapping.json"


def _base_alert():
    return copy.deepcopy(_load(BASE_ALERT_NAME))


class RealManifestsPassTest(unittest.TestCase):
    """The contract must hold against what is actually committed and shipped -
    a test suite that only ever exercises synthetic documents would prove
    nothing about the real tree."""

    def test_every_checked_in_manifest_is_valid(self):
        errors = vm.validate_dir(str(REAL_MANIFEST_DIR))
        self.assertEqual(errors, [], "\n".join(errors))

    def test_validate_dir_finds_the_full_committed_set(self):
        # Sanity floor so an empty/missing directory can't pass trivially.
        paths = glob.glob(str(REAL_MANIFEST_DIR / "*.json"))
        self.assertGreaterEqual(len(paths), 50)


class SeverityContractTest(unittest.TestCase):
    def test_valid_severities_pass(self):
        for severity in ("critical", "warning", "info"):
            with self.subTest(severity=severity):
                doc = _base_alert()
                doc["spec"]["labels"]["severity"] = severity
                self.assertEqual(vm.validate_document(BASE_ALERT_NAME, doc), [])

    def test_unknown_severity_is_rejected(self):
        doc = _base_alert()
        doc["spec"]["labels"]["severity"] = "urgent"  # not one of the three tiers
        errors = vm.validate_document(BASE_ALERT_NAME, doc)
        self.assertTrue(any("severity" in e and "urgent" in e for e in errors), errors)

    def test_missing_severity_is_rejected(self):
        doc = _base_alert()
        del doc["spec"]["labels"]["severity"]
        errors = vm.validate_document(BASE_ALERT_NAME, doc)
        self.assertTrue(any("severity" in e for e in errors), errors)


class ExecErrStateContractTest(unittest.TestCase):
    def test_valid_states_pass(self):
        for state in ("Alerting", "Error", "OK", "KeepLast"):
            with self.subTest(state=state):
                doc = _base_alert()
                doc["spec"]["execErrState"] = state
                self.assertEqual(vm.validate_document(BASE_ALERT_NAME, doc), [])

    def test_lowercase_typo_is_rejected(self):
        # Exactly the class of bug NODATA_STATES already guards for noDataState
        # ("Ok" not "OK") - execErrState needs the same guard.
        doc = _base_alert()
        doc["spec"]["execErrState"] = "error"
        errors = vm.validate_document(BASE_ALERT_NAME, doc)
        self.assertTrue(any("execErrState" in e for e in errors), errors)


class NoDataStateContractTest(unittest.TestCase):
    def test_invalid_value_is_rejected(self):
        doc = _base_alert()
        doc["spec"]["noDataState"] = "Ok "  # trailing space typo
        errors = vm.validate_document(BASE_ALERT_NAME, doc)
        self.assertTrue(any("noDataState" in e for e in errors), errors)


class PendingDurationContractTest(unittest.TestCase):
    def test_valid_durations_pass(self):
        for value in ("0s", "5m0s", "15m0s", "1h5m0s"):
            with self.subTest(value=value):
                doc = _base_alert()
                doc["spec"]["for"] = value
                self.assertEqual(vm.validate_document(BASE_ALERT_NAME, doc), [])

    def test_bare_unit_less_number_is_rejected(self):
        doc = _base_alert()
        doc["spec"]["for"] = "15"  # missing the trailing "m0s"/"s" unit
        errors = vm.validate_document(BASE_ALERT_NAME, doc)
        self.assertTrue(any("spec.for" in e for e in errors), errors)

    def test_negative_duration_is_rejected(self):
        doc = _base_alert()
        doc["spec"]["for"] = "-5m0s"
        errors = vm.validate_document(BASE_ALERT_NAME, doc)
        self.assertTrue(any("spec.for" in e for e in errors), errors)

    def test_non_string_is_rejected(self):
        doc = _base_alert()
        doc["spec"]["for"] = 15
        errors = vm.validate_document(BASE_ALERT_NAME, doc)
        self.assertTrue(any("spec.for" in e for e in errors), errors)


class StackRoutingLabelContractTest(unittest.TestCase):
    """build_rules.py --stack contract: domain is always "infra"; page="true" is
    added if and only if severity == "critical". Exercised both by generating
    real manifests through the builder (stack=True and stack=False) and by
    hand-mutated bad label combinations the builder itself would never emit."""

    def _emit(self, stack):
        with tempfile.TemporaryDirectory() as tmp:
            original_here = build_rules.HERE
            try:
                build_rules.HERE = tmp
                outdir, written = build_rules.emit_grafana_managed(
                    "test-prometheus", "test-opnsense-alerts", stack=stack,
            health_folder="test-opnsense-health-alerts"
                )
            finally:
                build_rules.HERE = original_here
            return [
                (os.path.basename(p), json.loads(Path(p).read_text())) for p in written
            ]

    def test_stack_false_manifests_carry_no_routing_labels(self):
        for basename, manifest in self._emit(stack=False):
            errors = vm.validate_document(basename, manifest)
            self.assertEqual(errors, [], errors)
            if manifest["kind"] == "AlertRule":
                self.assertNotIn("domain", manifest["spec"]["labels"])
                self.assertNotIn("page", manifest["spec"]["labels"])

    def test_stack_true_manifests_page_only_critical_alerts(self):
        manifests = self._emit(stack=True)
        saw_a_critical = False
        saw_a_non_critical = False
        for basename, manifest in manifests:
            errors = vm.validate_document(basename, manifest)
            self.assertEqual(errors, [], errors)
            if manifest["kind"] != "AlertRule":
                continue
            labels = manifest["spec"]["labels"]
            self.assertEqual(labels.get("domain"), "infra")
            if labels["severity"] == "critical":
                saw_a_critical = True
                self.assertEqual(labels.get("page"), "true")
            else:
                saw_a_non_critical = True
                self.assertNotIn("page", labels)
        # Both branches of the contract must actually have been exercised, or
        # the assertions above are vacuously true.
        self.assertTrue(saw_a_critical)
        self.assertTrue(saw_a_non_critical)

    def test_page_without_domain_is_rejected(self):
        doc = _base_alert()
        doc["spec"]["labels"] = {"severity": "critical", "page": "true"}  # no domain
        errors = vm.validate_document(BASE_ALERT_NAME, doc)
        self.assertTrue(any("domain" in e for e in errors), errors)

    def test_page_true_on_a_warning_is_rejected(self):
        doc = _base_alert()
        doc["spec"]["labels"] = {"severity": "warning", "domain": "infra", "page": "true"}
        errors = vm.validate_document(BASE_ALERT_NAME, doc)
        self.assertTrue(any("page" in e and "warning" in e for e in errors), errors)

    def test_page_as_boolean_true_instead_of_string_is_rejected(self):
        # JSON `true` vs the string "true" - Grafana's label value type is a
        # string, so a bare boolean is a real (and easy) mistake to make here.
        doc = _base_alert()
        doc["spec"]["labels"] = {"severity": "critical", "domain": "infra", "page": True}
        errors = vm.validate_document(BASE_ALERT_NAME, doc)
        self.assertTrue(any("page" in e for e in errors), errors)

    def test_unexpected_domain_value_is_rejected(self):
        doc = _base_alert()
        doc["spec"]["labels"] = {"severity": "warning", "domain": "network"}
        errors = vm.validate_document(BASE_ALERT_NAME, doc)
        self.assertTrue(any("domain" in e for e in errors), errors)

    def test_recording_rule_with_a_page_label_is_rejected(self):
        recording_name = "oxrec-ids-alerts-active.json"
        doc = _load(recording_name)
        doc["spec"]["labels"]["page"] = "true"
        errors = vm.validate_document(recording_name, doc)
        self.assertTrue(any("RecordingRule" in e and "page" in e for e in errors), errors)


class PerInstanceLabelPreservationContractTest(unittest.TestCase):
    """An aggregation `by (...)` clause that drops opnsense_instance merges
    independently monitored firewalls into one indistinguishable series - the
    #427/#414 class of bug. Guards both the query's own labels and any
    `{{ $labels.X }}` token in the rendered message that the query does not
    actually preserve."""

    def test_aggregation_dropping_opnsense_instance_is_rejected(self):
        doc = _base_alert()
        expr = doc["spec"]["expressions"]["A"]["model"]["expr"]
        self.assertIn("opnsense_instance", expr)
        doc["spec"]["expressions"]["A"]["model"]["expr"] = expr.replace(
            "sum by (opnsense_instance, interface, vhid)", "sum by (interface, vhid)"
        )
        errors = vm.validate_document(BASE_ALERT_NAME, doc)
        self.assertTrue(
            any("opnsense_instance" in e and "merge" in e for e in errors), errors
        )

    def test_bare_metric_with_no_aggregation_is_not_flagged(self):
        # opnsense_up carries opnsense_instance as a base-metric label with no
        # `by (...)` clause at all - nothing here is statically checkable, and
        # the absence of an aggregation must not itself be an error.
        doc = _load("opnsense-exporter-down.json")
        expr = doc["spec"]["expressions"]["A"]["model"]["expr"]
        self.assertNotRegex(expr, r"(sum|max|min|avg|count)\s+by\s*\(")
        self.assertEqual(vm.validate_document("opnsense-exporter-down.json", doc), [])

    def test_dangling_label_token_in_summary_is_rejected(self):
        doc = _base_alert()
        doc["spec"]["annotations"]["summary"] += " on {{ $labels.reason }}"
        errors = vm.validate_document(BASE_ALERT_NAME, doc)
        self.assertTrue(
            any("reason" in e and "$labels" in e for e in errors), errors
        )

    def test_dangling_label_token_in_description_is_rejected(self):
        doc = _base_alert()
        doc["spec"]["annotations"]["description"] += " ({{ $labels.reason }})"
        errors = vm.validate_document(BASE_ALERT_NAME, doc)
        self.assertTrue(
            any("reason" in e and "$labels" in e for e in errors), errors
        )

    def test_label_token_actually_preserved_by_the_by_clause_passes(self):
        doc = _base_alert()
        doc["spec"]["annotations"]["summary"] += " {{ $labels.vhid }} {{ $labels.interface }}"
        self.assertEqual(vm.validate_document(BASE_ALERT_NAME, doc), [])

    def test_recording_rule_aggregation_is_also_checked(self):
        recording_name = "oxrec-ids-alerts-active.json"
        doc = _load(recording_name)
        expr = doc["spec"]["expressions"]["A"]["model"]["expr"]
        self.assertIn("sum by (opnsense_instance)", expr)
        doc["spec"]["expressions"]["A"]["model"]["expr"] = expr.replace(
            "sum by (opnsense_instance)", "sum by (action)"
        )
        errors = vm.validate_document(recording_name, doc)
        self.assertTrue(
            any("opnsense_instance" in e and "merge" in e for e in errors), errors
        )


class RunbookAnchorContractTest(unittest.TestCase):
    """#430/#429: since per-rule anchors replaced one shared constant, every alert's
    OWN runbook_url must resolve to a real heading in grafana/runbooks.md - checked
    structurally by reading the file, never over the network. RUNBOOK_URL itself
    survives as the document-level index link (used by the dashboard's "Alert
    runbooks" DashboardLink), not as the per-alert value any more."""

    def test_the_shared_index_runbook_url_resolves(self):
        ok, why = vm._runbook_anchor_resolves(RUNBOOK_URL)
        self.assertTrue(ok, why)

    def test_every_real_manifest_has_its_own_resolving_runbook_url(self):
        for name, doc in ((n, _load(n)) for n in glob.glob("*.json", root_dir=REAL_MANIFEST_DIR)):
            if doc.get("kind") != "AlertRule":
                continue
            with self.subTest(name=name):
                url = doc["spec"]["annotations"].get("runbook_url")
                self.assertTrue(url, f"{name}: missing runbook_url")
                ok, why = vm._runbook_anchor_resolves(url)
                self.assertTrue(ok, f"{name}: {why}")

    def test_two_different_alerts_get_two_different_runbook_urls(self):
        # The old contract required every alert to carry the SAME shared constant;
        # the new one requires the opposite - each alert's anchor names ITS OWN
        # heading, so no two (real, distinct) alerts should collide.
        down = _load("opnsense-exporter-down.json")
        carp = _load(BASE_ALERT_NAME)
        self.assertNotEqual(
            down["spec"]["annotations"]["runbook_url"],
            carp["spec"]["annotations"]["runbook_url"],
        )

    def test_a_missing_runbook_url_is_rejected(self):
        doc = _base_alert()
        del doc["spec"]["annotations"]["runbook_url"]
        errors = vm.validate_document(BASE_ALERT_NAME, doc)
        self.assertTrue(any("runbook_url" in e for e in errors), errors)

    def test_a_wrong_runbook_url_is_rejected(self):
        doc = _base_alert()
        doc["spec"]["annotations"]["runbook_url"] = (
            "https://github.com/rknightion/opnsense-exporter/blob/main/README.md#alerts"
        )
        errors = vm.validate_document(BASE_ALERT_NAME, doc)
        self.assertTrue(any("runbook_url" in e for e in errors), errors)

    def test_an_anchor_that_does_not_exist_in_the_doc_is_rejected(self):
        ok, why = vm._runbook_anchor_resolves(
            "https://github.com/rknightion/opnsense-exporter/blob/main/"
            "grafana/README.md#this-heading-does-not-exist"
        )
        self.assertFalse(ok)
        self.assertIn("no heading", why)

    def test_a_nonexistent_document_is_rejected(self):
        ok, why = vm._runbook_anchor_resolves(
            "https://github.com/rknightion/opnsense-exporter/blob/main/"
            "grafana/DOES-NOT-EXIST.md#alerts"
        )
        self.assertFalse(ok)
        self.assertIn("does not exist", why)

    def test_a_url_not_shaped_like_the_repo_base_is_rejected(self):
        ok, why = vm._runbook_anchor_resolves("https://example.com/some/other/page#alerts")
        self.assertFalse(ok)
        self.assertIn("not of the form", why)

    def test_slug_matches_githubs_ampersand_behaviour(self):
        # "## Alerts & recording rules" is a real heading in grafana/README.md;
        # GitHub's own anchor for it is "alerts--recording-rules" (the removed
        # "&" leaves the doubled hyphen rather than collapsing it). Pin this so
        # a future "simplification" of the slugger does not silently start
        # resolving anchors GitHub itself would not.
        self.assertEqual(
            vm._github_heading_slug("Alerts & recording rules"),
            "alerts--recording-rules",
        )


class MissingFolderManifestContractTest(unittest.TestCase):
    def test_a_directory_with_no_folder_manifest_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            # One valid-looking alert, but no _folder.json.
            doc = _base_alert()
            with open(os.path.join(tmp, BASE_ALERT_NAME), "w") as f:
                json.dump(doc, f)
            errors = vm.validate_dir(tmp)
            self.assertTrue(any("_folder.json is missing" in e for e in errors), errors)


if __name__ == "__main__":
    unittest.main()
