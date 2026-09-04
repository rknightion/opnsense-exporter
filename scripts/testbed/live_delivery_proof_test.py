"""Focused offline checks for live_delivery_proof's secret-safe result parser."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import live_delivery_proof as proof


class TestResultParsing(unittest.TestCase):
    def test_records_keeps_structured_metadata_separate_from_labels(self):
        rows = [{"stream": {"service_name": "x"}, "values": [["1", "body", {"dst_domain": "example.com"}]]}]
        self.assertEqual(list(proof.records(rows)), [({"service_name": "x"}, "body", {"dst_domain": "example.com"})])

    def test_sensitive_key_scan_rejects_nested_secret_and_accepts_safe_document(self):
        self.assertFalse(proof.no_sensitive_keys({"entity": {"password": "not printed"}}))
        self.assertTrue(proof.no_sensitive_keys({"entity": {"description": "safe", "items": []}}))

    def test_body_scan_fails_closed_on_invalid_json_and_sensitive_keys(self):
        self.assertFalse(proof.bodies_have_no_sensitive_keys([({}, "not-json", {})]))
        self.assertFalse(proof.bodies_have_no_sensitive_keys([({}, '{"token":"not printed"}', {})]))
        self.assertFalse(proof.bodies_have_no_sensitive_keys([({}, '{"token":"not printed","token":"safe"}', {})]))
        self.assertTrue(proof.bodies_have_no_sensitive_keys([({}, '{"entity":{"description":"safe"}}', {})]))

    def test_query_diagnostic_distinguishes_label_mismatch_and_empty_window(self):
        empty = {"streams": [], "succeeded": True}
        broad_mismatch = {"streams": [{"stream": {"service_name": "x"}, "values": [["1", "body", {"opnsense_source": "configstate"}]]}], "succeeded": True}
        self.assertEqual(proof.query_diagnostic("configstate", empty, broad_mismatch), "arrived_with_unexpected_labels")
        self.assertEqual(proof.query_diagnostic("configstate", empty, empty), "instance_absent_in_explicit_window")

    def test_filterlog_uses_measurement_time(self):
        line = proof.filterlog_line("192.0.2.10", "192.0.2.20", epoch=1_786_057_200)
        self.assertTrue(line.startswith("<134>1 2026-08-06T23:00:00Z proof filterlog"))
        self.assertIn(",192.0.2.10,192.0.2.20,", line)

    def test_domain_proof_requires_expected_metadata_value_and_no_label(self):
        expected = [({"service_name": "x"}, "body", {"dst_domain": "delivery-proof.example"})]
        wrong = [({"service_name": "x"}, "body", {"dst_domain": "other.example"})]
        promoted = [({"dst_domain": "delivery-proof.example"}, "body", {"dst_domain": "delivery-proof.example"})]
        self.assertTrue(proof.has_domain_metadata(expected, "delivery-proof.example"))
        self.assertFalse(proof.has_domain_metadata(wrong, "delivery-proof.example"))
        self.assertFalse(proof.has_domain_metadata(promoted, "delivery-proof.example"))

    def test_proof_user_filter_excludes_system_and_unrelated_users(self):
        rows = {"rows": [
            {"uuid": "keep-system", "name": "deliveryproof-system", "scope": "system"},
            {"uuid": "remove", "name": "deliveryproof-123", "scope": "user"},
            {"uuid": "keep-admin", "name": "deliveryproof-admin", "scope": "user"},
            {"uuid": "remove-generated", "name": "deliveryproof0123456789abcdef", "scope": "user"},
            {"uuid": "keep-other", "name": "operator", "scope": "user"},
        ]}
        self.assertEqual(proof.proof_user_ids(rows), ["remove-generated"])

    def test_poll_error_parser_is_source_specific(self):
        metrics = ('opnsense_exporter_logs_poll_errors_total{instance="proof",source="configstate"} 2\n'
                   'opnsense_exporter_logs_poll_errors_total{instance="proof",source="configchange"} 0\n'
                   'opnsense_exporter_logs_poll_errors_total{instance="proof",source="timestamped"} 2 1786057200000\n')
        self.assertTrue(proof.poll_error_observed(metrics, "configstate"))
        self.assertFalse(proof.poll_error_observed(metrics, "configchange"))
        self.assertTrue(proof.poll_error_observed(metrics, "timestamped"))

    def test_stale_cleanup_reports_only_bounded_operation_state(self):
        class FakeAPI:
            def get(self, _path):
                return {"rows": [{"uuid": "opaque", "name": "deliveryproof0123456789abcdef", "scope": "user"}]}

            def post(self, _path, _payload=None):
                return {"result": "unexpected body text"}

        diagnostic = {}
        self.assertFalse(proof.cleanup_stale_proof_users(FakeAPI(), diagnostic))
        self.assertEqual(diagnostic["stale cleanup detail"],
                         "found:1;post:other/search-get:present,post:other/search-get:present,post:other/search-get:present")

    def test_stale_cleanup_attempts_every_matching_user(self):
        class FakeAPI:
            users = {"first": "deliveryproof0123456789abcdef", "second": "deliveryprooffedcba9876543210"}
            deleted = []

            def get(self, _path):
                return {"rows": [{"uuid": user_uuid, "name": name, "scope": "user"}
                                 for user_uuid, name in self.users.items() if user_uuid not in self.deleted]}

            def post(self, path, _payload=None):
                self.deleted.append(path.rsplit("/", 1)[-1])
                return {"result": "deleted"}

        api = FakeAPI()
        diagnostic = {}
        self.assertTrue(proof.cleanup_stale_proof_users(api, diagnostic))
        self.assertEqual(api.deleted, ["first", "second"])

    def test_user_search_falls_back_to_post(self):
        class FakeAPI:
            def get(self, _path):
                raise RuntimeError("GET unavailable")

            def post(self, _path, _payload=None):
                return {"rows": []}

        self.assertEqual(proof.search_proof_users(FakeAPI()), ([], "post-fallback"))


if __name__ == "__main__":
    unittest.main()
