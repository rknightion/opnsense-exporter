"""Focused offline checks for live_delivery_proof's secret-safe result parser."""
import io
import pathlib
import sys
import unittest
from unittest import mock

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

    def test_exporter_poll_error_diagnostic_reads_only_the_configstate_record(self):
        rows = [
            ({"opnsense_source": "exporter"}, "log source poll error",
             {"source": "configstate", "err": "snapshot fetch failed"}),
            ({"opnsense_source": "exporter"}, "another diagnostic",
             {"source": "configstate", "err": "must not be rendered"}),
            ({"opnsense_source": "exporter"}, "log source poll error",
             {"source": "configchange", "err": "wrong source"}),
        ]
        self.assertEqual(proof.exporter_poll_error_diagnostic(rows, "configstate"), "snapshot fetch failed")
        self.assertEqual(proof.exporter_poll_error_diagnostic(rows, "routingchange"), "not_observed")

    def test_exporter_poll_error_diagnostic_redacts_credential_bearing_error(self):
        rows = [({"opnsense_source": "exporter"}, "log source poll error",
                 {"source": "configstate", "err": "request used Bearer a-secret-value"})]
        self.assertEqual(proof.exporter_poll_error_diagnostic(rows, "configstate"), "redacted")
        rows[0][2]["err"] = "request failed at https://operator@example.invalid/path"
        self.assertEqual(proof.exporter_poll_error_diagnostic(rows, "configstate"), "redacted")

    def test_proof_queries_every_source_it_generates(self):
        self.assertEqual(proof.PROOF_SOURCES,
                         ("configchange", "configstate", "exporter", "syslog", "zenarmor"))

    def test_poll_error_parser_is_source_specific(self):
        metrics = ('opnsense_exporter_logs_poll_errors_total{instance="proof",source="configstate"} 2\n'
                   'opnsense_exporter_logs_poll_errors_total{instance="proof",source="configchange"} 0\n'
                   'opnsense_exporter_logs_poll_errors_total{instance="proof",source="timestamped"} 2 1786057200000\n')
        self.assertTrue(proof.poll_error_observed(metrics, "configstate"))
        self.assertFalse(proof.poll_error_observed(metrics, "configchange"))
        self.assertTrue(proof.poll_error_observed(metrics, "timestamped"))
        self.assertEqual(proof.poll_error_diagnostic("", "configstate"), "unavailable")

    def test_dedicated_alias_discovery_pages_search_and_matches_delivery_proof(self):
        class FakeAPI:
            posts = []

            def post(self, path, payload):
                self.posts.append((path, payload))
                return {"total": 2, "rows": [
                    {"uuid": "unrelated-id", "name": "unrelated_alias"},
                    {"uuid": "alias-uuid", "name": "delivery_proof"},
                ]}

        api = FakeAPI()
        alias_uuid, alias_name = proof.resolve_delivery_proof_alias(api)
        self.assertEqual(alias_uuid, "alias-uuid")
        self.assertEqual(alias_name, "delivery_proof")
        self.assertEqual(api.posts, [
            ("/api/firewall/alias/search_item", {
                "current": 1, "rowCount": 100, "sort": {"name": "asc"},
            }),
        ])

    def test_dedicated_alias_discovery_rejects_zero_or_multiple_matches(self):
        class FakeAPI:
            def __init__(self, rows):
                self.rows = rows

            def post(self, _path, _payload):
                return {"total": len(self.rows), "rows": self.rows}

        with self.assertRaisesRegex(RuntimeError, "did not find exactly one"):
            proof.resolve_delivery_proof_alias(FakeAPI([]))
        with self.assertRaisesRegex(RuntimeError, "did not find exactly one"):
            proof.resolve_delivery_proof_alias(FakeAPI([
                {"uuid": "first", "name": "delivery-proof"},
                {"uuid": "second", "name": "delivery_proof"},
            ]))
        with self.assertRaisesRegex(RuntimeError, "did not find exactly one"):
            proof.resolve_delivery_proof_alias(FakeAPI([
                {"uuid": "unsafe", "name": "delivery.proof"},
            ]))
        with self.assertRaisesRegex(RuntimeError, "did not find exactly one"):
            proof.resolve_delivery_proof_alias(FakeAPI([
                {"uuid": "near-collision", "name": "d-e-l-i-v-e-r-y-p-r-o-o-f"},
            ]))
        self.assertEqual(
            proof.resolve_delivery_proof_alias(FakeAPI([
                {"uuid": "case-variant", "name": "Delivery_Proof"},
            ])),
            ("case-variant", "Delivery_Proof"),
        )
        self.assertEqual(
            proof.resolve_delivery_proof_alias(FakeAPI([
                {"uuid": "bounded-affixes", "name": "opnsense_delivery_proof_alias"},
            ])),
            ("bounded-affixes", "opnsense_delivery_proof_alias"),
        )

    def test_dedicated_alias_discovery_inspects_later_pages(self):
        class FakeAPI:
            posts = []

            def post(self, path, payload):
                self.posts.append((path, payload))
                if payload["current"] == 1:
                    return {"total": 101, "rows": [
                        {"uuid": "unrelated-" + str(index), "name": "unrelated_" + str(index)}
                        for index in range(100)
                    ]}
                return {"total": 101, "rows": [
                    {"uuid": "alias-uuid", "name": "delivery_proof"},
                ]}

        api = FakeAPI()
        self.assertEqual(proof.resolve_delivery_proof_alias(api), ("alias-uuid", "delivery_proof"))
        self.assertEqual(api.posts, [
            ("/api/firewall/alias/search_item", {
                "current": 1, "rowCount": 100, "sort": {"name": "asc"},
            }),
            ("/api/firewall/alias/search_item", {
                "current": 2, "rowCount": 100, "sort": {"name": "asc"},
            }),
        ])

    def test_dedicated_alias_discovery_rejects_repeated_page_and_boolean_total(self):
        rows = [
            {"uuid": "unrelated-" + str(index), "name": "unrelated_" + str(index)}
            for index in range(100)
        ]

        class RepeatingAPI:
            def post(self, _path, _payload):
                return {"total": 101, "rows": rows}

        with self.assertRaisesRegex(proof.ProofFailure, "pagination made no progress") as caught:
            proof.resolve_delivery_proof_alias(RepeatingAPI())
        self.assertEqual(caught.exception.code, "alias_search_pagination_no_progress")

        class BooleanTotalAPI:
            def post(self, _path, _payload):
                return {"total": True, "rows": []}

        with self.assertRaisesRegex(proof.ProofFailure, "complete page") as caught:
            proof.resolve_delivery_proof_alias(BooleanTotalAPI())
        self.assertEqual(caught.exception.code, "alias_search_total_invalid")

        class UnderreportedTotalAPI:
            def post(self, _path, _payload):
                return {"total": 0, "rows": [
                    {"uuid": "unexpected", "name": "unrelated_alias"},
                ]}

        with self.assertRaisesRegex(proof.ProofFailure, "complete page") as caught:
            proof.resolve_delivery_proof_alias(UnderreportedTotalAPI())
        self.assertEqual(caught.exception.code, "alias_search_total_invalid")

        class OversizedTotalAPI:
            def post(self, _path, _payload):
                return {"total": proof.ALIAS_SEARCH_MAX_ROWS + 1, "rows": []}

        with self.assertRaisesRegex(proof.ProofFailure, "complete page") as caught:
            proof.resolve_delivery_proof_alias(OversizedTotalAPI())
        self.assertEqual(caught.exception.code, "alias_search_total_invalid")

    def test_api_invalid_response_encoding_is_a_bounded_failure(self):
        api = proof.API("testbed.invalid", "key", "secret")
        invalid = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid start byte")
        with mock.patch.object(proof.urllib.request, "urlopen", side_effect=invalid):
            with self.assertRaises(proof.ProofFailure) as caught:
                api.get("/api/test")
        self.assertEqual(caught.exception.code, "testbed_api_response_not_json")

    def test_alias_description_write_and_exact_restoration_preserve_other_fields(self):
        class FakeAPI:
            calls = []

            def post(self, path, payload):
                self.calls.append((path, payload))
                return {"result": "saved"}

        api = FakeAPI()
        original = {"name": "deliveryproof", "description": "exact original", "type": "host", "content": "192.0.2.1"}
        proof.set_alias(api, "alias-uuid", proof.edited_alias(original, "temporary proof"))
        proof.set_alias(api, "alias-uuid", original)
        self.assertEqual(api.calls, [
            ("/api/firewall/alias/set_item/alias-uuid",
             {"alias": {"name": "deliveryproof", "description": "temporary proof", "type": "host", "content": "192.0.2.1"}}),
            ("/api/firewall/alias/set_item/alias-uuid", {"alias": original}),
        ])
        self.assertEqual(original["description"], "exact original")

    def test_alias_description_restoration_runs_after_later_failure(self):
        class FakeAPI:
            calls = []

            def post(self, path, payload):
                self.calls.append((path, payload))
                return {"result": "saved"}

        original = {"name": "deliveryproof", "description": "exact original", "type": "host"}
        api = FakeAPI()
        mutation = proof.AliasDescriptionMutation(api, "alias-uuid", original, "temporary proof")
        with self.assertRaisesRegex(RuntimeError, "later proof failure"):
            with mutation:
                raise RuntimeError("later proof failure")
        self.assertTrue(mutation.restored)
        self.assertEqual(api.calls[-1],
                         ("/api/firewall/alias/set_item/alias-uuid", {"alias": original}))

    def test_revision_evidence_detects_new_revision_without_rendering_ids(self):
        self.assertTrue(proof.revision_list_grew({"old"}, {"old", "new"}))
        self.assertFalse(proof.revision_list_grew({"old"}, {"old"}))

    def test_executable_proof_contains_no_auth_user_api_path_or_generated_username(self):
        source = pathlib.Path(proof.__file__).read_text(encoding="utf-8")
        self.assertNotIn("/api/auth/user/", source)
        self.assertNotIn("username", source)

    def test_pre_mutation_failure_reports_its_stage_without_exception_detail(self):
        class FailingAPI:
            def __init__(self, *_args):
                pass

            def post(self, _path, _payload):
                raise RuntimeError("https://user:credential@example.invalid/response-body")

        environment = {
            "DEVBOX_HOST": "testbed.invalid",
            "DEVBOX_API_KEY": "not-rendered",
            "DEVBOX_API_SECRET": "not-rendered",
            "GRAFANA_OTLP_USER": "not-rendered",
            "GRAFANA_LOKI_USER": "not-rendered",
            "GRAFANA_CAP_TOKEN": "not-rendered",
        }
        output = io.StringIO()
        with mock.patch.dict(proof.os.environ, environment, clear=False), \
                mock.patch.object(proof, "API", FailingAPI), \
                mock.patch("sys.stdout", output):
            self.assertEqual(proof.main(["--exporter", "not-started"]), 1)
        rendered = output.getvalue()
        self.assertIn("- proof stage: resolving_alias", rendered)
        self.assertNotIn("response-body", rendered)
        self.assertNotIn("credential@example.invalid", rendered)

    def test_alias_resolution_failure_reports_only_a_bounded_reason_code(self):
        class NoMatchAPI:
            def __init__(self, *_args):
                pass

            def post(self, _path, _payload):
                return {"total": 1, "rows": [
                    {"uuid": "unrendered-id", "name": "unrelated_alias"},
                ]}

        environment = {
            "DEVBOX_HOST": "testbed.invalid",
            "DEVBOX_API_KEY": "not-rendered",
            "DEVBOX_API_SECRET": "not-rendered",
            "GRAFANA_OTLP_USER": "not-rendered",
            "GRAFANA_LOKI_USER": "not-rendered",
            "GRAFANA_CAP_TOKEN": "not-rendered",
        }
        output = io.StringIO()
        with mock.patch.dict(proof.os.environ, environment, clear=False), \
                mock.patch.object(proof, "API", NoMatchAPI), \
                mock.patch("sys.stdout", output):
            self.assertEqual(proof.main(["--exporter", "not-started"]), 1)
        rendered = output.getvalue()
        self.assertIn("- proof failure query result: alias_search_no_approved_match", rendered)
        self.assertNotIn("unrelated_alias", rendered)
        self.assertNotIn("unrendered-id", rendered)

    def test_summary_names_only_the_validated_matched_alias(self):
        class FailingReadAPI:
            def __init__(self, *_args):
                pass

            def post(self, _path, _payload):
                return {"total": 2, "rows": [
                    {"uuid": "unrendered-id", "name": "unrelated_alias"},
                    {"uuid": "alias-id", "name": "delivery_proof"},
                ]}

            def get(self, _path):
                raise RuntimeError("do not render alias response")

        environment = {
            "DEVBOX_HOST": "testbed.invalid",
            "DEVBOX_API_KEY": "not-rendered",
            "DEVBOX_API_SECRET": "not-rendered",
            "GRAFANA_OTLP_USER": "not-rendered",
            "GRAFANA_LOKI_USER": "not-rendered",
            "GRAFANA_CAP_TOKEN": "not-rendered",
        }
        output = io.StringIO()
        with mock.patch.dict(proof.os.environ, environment, clear=False), \
                mock.patch.object(proof, "API", FailingReadAPI), \
                mock.patch("sys.stdout", output):
            self.assertEqual(proof.main(["--exporter", "not-started"]), 1)
        rendered = output.getvalue()
        self.assertIn("- proof alias: delivery_proof", rendered)
        self.assertNotIn("unrelated_alias", rendered)
        self.assertNotIn("unrendered-id", rendered)


if __name__ == "__main__":
    unittest.main()
