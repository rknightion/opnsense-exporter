"""Focused offline checks for live_delivery_proof's secret-safe result parser."""
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import live_delivery_proof as proof


class TestResultParsing(unittest.TestCase):
    def test_records_reads_the_categorized_structured_metadata_member(self):
        # Loki's categorize-labels encoding nests each category under its own key.
        rows = [{"stream": {"service_name": "x"},
                 "values": [["1", "body", {"structuredMetadata": {"dst_domain": "example.com"}}]]}]
        self.assertEqual(list(proof.records(rows)), [({"service_name": "x"}, "body", {"dst_domain": "example.com"})])

    def test_records_yields_no_metadata_for_an_uncategorized_response(self):
        # Without the categorize-labels request header Loki merges structured
        # metadata into "stream" and drops the third element. Wave 5 read that
        # shape and reported 202 phantom promoted labels plus a domain
        # assertion that could never pass. Yielding empty metadata keeps such a
        # response failing closed rather than being read as exporter behaviour.
        rows = [{"stream": {"service_name": "x", "dst_domain": "example.com"},
                 "values": [["1", "body"]]}]
        labels, _, metadata = next(iter(proof.records(rows)))
        self.assertEqual(metadata, {})
        self.assertFalse(proof.has_domain_metadata(proof.records(rows), "example.com"))
        self.assertIn("dst_domain", labels)

    def test_loki_query_requests_categorized_labels(self):
        source = pathlib.Path(proof.__file__).read_text(encoding="utf-8")
        self.assertIn('"X-Loki-Response-Encoding-Flags": "categorize-labels"', source)

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
        broad_mismatch = {"streams": [{"stream": {"service_name": "x"},
                                       "values": [["1", "body", {"structuredMetadata": {"opnsense_source": "configstate"}}]]}], "succeeded": True}
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
        self.assertEqual(proof.poll_error_diagnostic("", "configstate"), "unavailable")

    def test_stale_cleanup_reports_only_bounded_operation_state(self):
        class FakeAPI:
            def get(self, _path):
                return {"rows": [{"uuid": "opaque", "name": "deliveryproof0123456789abcdef", "scope": "user"}]}

            def post(self, _path, _payload=None):
                return {"result": "unexpected body text"}

        diagnostic = {}
        self.assertFalse(proof.cleanup_stale_proof_users(FakeAPI(), diagnostic))
        self.assertEqual(diagnostic["stale cleanup detail"],
                         "found:1;post-path:other/search-get:present,post-path:other/search-get:present,post-path:other/search-get:present")

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
            payload = None

            def get(self, _path):
                raise RuntimeError("GET unavailable")

            def post(self, _path, payload=None):
                self.payload = payload
                return {"rows": []}

        api = FakeAPI()
        self.assertEqual(proof.search_proof_users(api), ([], "post-fallback"))
        self.assertEqual(api.payload, {})

    def test_delete_accepts_exact_deleted_result_when_search_is_unavailable(self):
        class FakeAPI:
            def get(self, _path):
                raise RuntimeError("GET unavailable")

            def post(self, path, _payload=None):
                if "/del/" in path:
                    return {"result": "deleted"}
                raise RuntimeError("POST search unavailable")

        diagnostic = []
        self.assertTrue(proof.delete_and_verify_user(FakeAPI(), "opaque", attempts=1, diagnostic=diagnostic))
        self.assertEqual(diagnostic, ["post-path:deleted/search:failed"])

    def test_delete_falls_back_to_query_parameter_and_verifies_absence(self):
        class FakeAPI:
            deleted = False

            def get(self, _path):
                raise RuntimeError("GET unavailable")

            def post(self, path, _payload=None):
                if "/del/" in path:
                    raise RuntimeError("path route unavailable")
                if path == "/api/auth/user/del?uuid=opaque":
                    self.deleted = True
                    return {"result": "deleted"}
                if path == "/api/auth/user/search":
                    rows = [] if self.deleted else [{"uuid": "opaque", "name": "deliveryproof0123456789abcdef"}]
                    return {"rows": rows}
                raise AssertionError("unexpected request")

        diagnostic = []
        self.assertTrue(proof.delete_and_verify_user(FakeAPI(), "opaque", attempts=1, diagnostic=diagnostic))
        self.assertEqual(diagnostic, ["post-query-fallback:deleted/search-post-fallback:absent"])

    def test_delete_falls_back_to_body_and_verifies_absence(self):
        class FakeAPI:
            deleted = False

            def get(self, _path):
                raise RuntimeError("GET unavailable")

            def post(self, path, payload=None):
                if "/del/" in path or "?uuid=" in path:
                    raise RuntimeError("route shape unavailable")
                if path == "/api/auth/user/del" and payload == {"uuid": "opaque"}:
                    self.deleted = True
                    return {"result": "deleted"}
                if path == "/api/auth/user/search":
                    rows = [] if self.deleted else [{"uuid": "opaque", "name": "deliveryproof0123456789abcdef"}]
                    return {"rows": rows}
                raise AssertionError("unexpected request")

        diagnostic = []
        self.assertTrue(proof.delete_and_verify_user(FakeAPI(), "opaque", attempts=1, diagnostic=diagnostic))
        self.assertEqual(diagnostic, ["post-body-fallback:deleted/search-post-fallback:absent"])


if __name__ == "__main__":
    unittest.main()
