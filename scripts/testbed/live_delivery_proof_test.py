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


if __name__ == "__main__":
    unittest.main()
