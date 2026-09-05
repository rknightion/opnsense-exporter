"""Focused offline checks for live_delivery_proof's secret-safe proof seams."""
import base64
import io
import json
import os
import pathlib
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import live_delivery_proof as proof


class TestLiveDeliveryProof(unittest.TestCase):
    def test_stderr_monitor_keeps_only_fixed_counts_and_hides_arbitrary_fields(self):
        secret = "arbitrary-api-key-secret"
        lines = [
            {"msg": proof.STDERR_MESSAGES["state_file_unreadable"], "path": secret, "err": secret},
            {"msg": proof.STDERR_MESSAGES["state_file_corrupt"], "path": secret},
            {"msg": proof.STDERR_MESSAGES["state_entry_corrupt"], "source": secret, "secret": secret},
            {"msg": proof.STDERR_MESSAGES["configchange_rebaseline"], "last_revision": secret},
            {"msg": proof.STDERR_MESSAGES["endpoint_terminal_rejection"], "count": 4, "err": secret},
            {"msg": proof.STDERR_MESSAGES["max_retries"], "attempts": 10, "err": secret},
            {"msg": proof.STDERR_MESSAGES["ingest_oversize"], "bytes": 99_999, "source": secret},
            {"msg": proof.STDERR_MESSAGES["source_poll_error"], "source": "configchange", "err": secret},
        ]
        stream = io.BytesIO(b"".join(json.dumps(line).encode() + b"\n" for line in lines))
        monitor = proof.StderrMonitor(stream)
        monitor.start()
        counts = monitor.finish()

        self.assertEqual(counts["stderr_state_file_unreadable_count"], 1)
        self.assertEqual(counts["stderr_state_file_corrupt_count"], 1)
        self.assertEqual(counts["stderr_state_entry_corrupt_count"], 1)
        self.assertEqual(counts["stderr_configchange_rebaseline_count"], 1)
        self.assertEqual(counts["stderr_endpoint_terminal_rejection_count"], 1)
        self.assertEqual(counts["stderr_endpoint_historical_rejection_count"], 0)
        self.assertEqual(counts["stderr_max_retries_count"], 1)
        self.assertEqual(counts["stderr_ingest_oversize_count"], 1)
        self.assertEqual(counts["stderr_configchange_poll_error_count"], 1)
        self.assertNotIn(secret, repr(counts))

    def test_stderr_monitor_classifies_known_historical_rejection_and_leaves_unknown_unknown(self):
        known = json.dumps({
            "msg": proof.STDERR_MESSAGES["endpoint_terminal_rejection"],
            "err": "greater_than_max_sample_age for historical data; bearer-secret-is-not-rendered",
        }).encode() + b"\n"
        unknown = json.dumps({
            "msg": proof.STDERR_MESSAGES["endpoint_terminal_rejection"],
            "err": "an unrecognized endpoint rejection; timestamp-cause-is-unknown",
        }).encode() + b"\n"
        monitor = proof.StderrMonitor(io.BytesIO(known + unknown))
        monitor.start()
        counts = monitor.finish()

        self.assertEqual(counts["stderr_endpoint_terminal_rejection_count"], 2)
        self.assertEqual(counts["stderr_endpoint_historical_rejection_count"], 1)
        self.assertNotIn("timestamp-cause-is-unknown", repr(counts))

    def test_stderr_monitor_discards_oversized_line_and_keeps_following_line_aligned(self):
        oversized = b"{" + b"x" * proof.STDERR_LINE_LIMIT_BYTES + b"}\n"
        valid = json.dumps({"msg": proof.STDERR_MESSAGES["state_file_corrupt"]}).encode() + b"\n"
        monitor = proof.StderrMonitor(io.BytesIO(oversized + valid))
        monitor.start()
        counts = monitor.finish()

        self.assertEqual(counts["stderr_oversized_line_count"], 1)
        self.assertEqual(counts["stderr_state_file_corrupt_count"], 1)

    def test_stderr_monitor_frames_a_real_nonblocking_pipe_and_finishes_after_writer_closes(self):
        read_fd, write_fd = os.pipe()
        read_stream = os.fdopen(read_fd, "rb")
        monitor = proof.StderrMonitor(read_stream)
        monitor.start()

        payload = (b"{" + b"x" * proof.STDERR_LINE_LIMIT_BYTES + b"}\n" +
                   json.dumps({"msg": proof.STDERR_MESSAGES["max_retries"]}).encode() + b"\n")

        def write_pipe():
            with os.fdopen(write_fd, "wb") as writer_stream:
                writer_stream.write(payload)
                writer_stream.flush()

        writer = threading.Thread(target=write_pipe, daemon=True)
        writer.start()
        writer.join(timeout=2)
        self.assertFalse(writer.is_alive(), "pipe writer blocked while stderr monitor was not consuming")
        counts = monitor.finish()

        self.assertEqual(counts["stderr_oversized_line_count"], 1)
        self.assertEqual(counts["stderr_max_retries_count"], 1)
        self.assertEqual(counts["stderr_reader_incomplete_count"], 0)

    def test_state_cursor_compare_accepts_successor_and_rejects_missing_or_corrupt_envelopes(self):
        successor = proof.RetainedRevision("config-2.xml", 2)
        path = proof.seed_revision_state(successor)
        self.addCleanup(pathlib.Path(path).unlink, missing_ok=True)
        self.assertTrue(proof.state_cursor_advanced(path, successor.id))

        with tempfile.NamedTemporaryFile() as missing:
            missing_path = missing.name
        self.assertFalse(proof.state_cursor_advanced(missing_path, successor.id))

        with tempfile.NamedTemporaryFile() as corrupt:
            corrupt.write(b'{"configchange":"not-base64"}')
            corrupt.flush()
            self.assertFalse(proof.state_cursor_advanced(corrupt.name, successor.id))

    def test_loki_query_stops_at_wall_clock_deadline(self):
        with mock.patch.object(proof.time, "monotonic", side_effect=[0, 0, 121]), \
                mock.patch.object(proof.urllib.request, "urlopen", side_effect=proof.urllib.error.URLError("offline")) as request, \
                mock.patch.object(proof.time, "sleep") as sleep:
            result = proof.loki_query("{}", "synthetic-user", "synthetic-token", 1, 2)
        self.assertEqual(request.call_count, 1)
        sleep.assert_not_called()
        self.assertFalse(result["succeeded"])

    def test_records_reads_the_categorized_structured_metadata_member(self):
        rows = [{"stream": {"service_name": "x"},
                 "values": [["1", "body", {"structuredMetadata": {"snapshot_family": "firewall"}}]]}]
        self.assertEqual(list(proof.records(rows)), [({"service_name": "x"}, "body", {"snapshot_family": "firewall"})])

    def test_loki_query_refreshes_end_per_attempt_and_returns_bounds(self):
        class FakeResponse(io.BytesIO):
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                self.close()

        requests = []
        responses = [
            FakeResponse(b'{"status":"success","data":{"result":[]}}'),
            FakeResponse(b'{"status":"success","data":{"result":[{"stream":{"source":"x"},"values":[]}]}}'),
        ]

        def fake_urlopen(request, **_kwargs):
            requests.append(request)
            return responses.pop(0)

        with mock.patch.object(proof.urllib.request, "urlopen", side_effect=fake_urlopen), \
                mock.patch.object(proof.time, "sleep"), \
                mock.patch.object(proof.time, "time_ns", side_effect=[150, 175]):
            result = proof.loki_query("{source=\"x\"}", "user", "token", 100, 120, attempts=2)

        self.assertEqual(len(requests), 2)
        self.assertEqual([proof.urllib.parse.parse_qs(proof.urllib.parse.urlsplit(request.full_url).query)
                          for request in requests], [
                              {"query": ['{source="x"}'], "limit": ["1000"], "direction": ["FORWARD"],
                               "start": ["100"], "end": ["150"]},
                              {"query": ['{source="x"}'], "limit": ["1000"], "direction": ["FORWARD"],
                               "start": ["100"], "end": ["175"]},
                          ])
        categorize_header = next((value for key, value in requests[0].header_items()
                                  if key.lower() == "x-loki-response-encoding-flags"), None)
        self.assertEqual(categorize_header, "categorize-labels")
        self.assertEqual(result["start_ns"], 100)
        self.assertEqual(result["end_ns"], 175)
        self.assertEqual(result["streams"], [{"stream": {"source": "x"}, "values": []}])

    def test_query_diagnostic_disambiguates_empty_source_query(self):
        empty = {"streams": [], "succeeded": True}
        labels_source = {"streams": [{"stream": {"opnsense_source": "configstate"}, "values": []}],
                         "succeeded": True}
        metadata_source = {"streams": [{"stream": {},
                                         "values": [["1", "body", {
                                             "structuredMetadata": {"opnsense_source": "configstate"},
                                         }]]}], "succeeded": True}
        unrelated = {"streams": [{"stream": {"opnsense_source": "exporter"}, "values": []}],
                     "succeeded": True}
        no_instance = {"streams": [], "succeeded": True}
        failed = {"streams": [], "succeeded": False}

        self.assertEqual(proof.query_diagnostic("configstate", empty, labels_source),
                         "arrived_with_unexpected_labels")
        self.assertEqual(proof.query_diagnostic("configstate", empty, metadata_source),
                         "arrived_with_unexpected_labels")
        self.assertEqual(proof.query_diagnostic("configstate", empty, unrelated),
                         "source_absent_in_instance_window")
        self.assertEqual(proof.query_diagnostic("configstate", empty, no_instance),
                         "instance_absent_in_explicit_window")
        self.assertEqual(proof.query_diagnostic("configstate", empty, failed), "query_failed")

    def test_query_start_uses_earlier_of_successor_and_process_start_windows(self):
        successor = proof.RetainedRevision("config-123.xml", 5_000)
        startup_ns = 1_000_000_000_000
        self.assertEqual(proof.query_start_ns(successor, startup_ns), startup_ns - 60_000_000_000)

    def test_configstate_family_summary_hides_unexpected_family_names(self):
        rows = [
            ({}, "body", {"snapshot_family": "firewall"}),
            ({}, "body", {"snapshot_family": "device_inventory"}),
            ({}, "body", {"snapshot_family": "private_passwords"}),
            ({}, "body", {"snapshot_family": "internal-secret-family"}),
        ]
        self.assertEqual(proof.configstate_family_summary(rows), {
            "families": "device_inventory,firewall",
            "unexpected_count": 2,
        })

    def test_redaction_assertion_requires_all_configstate_families(self):
        clean = {
            "configchange_bodies_redacted": True,
            "configstate_bodies_redacted": True,
        }
        self.assertFalse(proof.redaction_assertion_passes(
            clean, True, {"firewall", "device_inventory"}))
        self.assertFalse(proof.redaction_assertion_passes(
            clean, False, proof.REQUIRED_CONFIGSTATE_FAMILIES))
        self.assertTrue(proof.redaction_assertion_passes(
            clean, True, proof.REQUIRED_CONFIGSTATE_FAMILIES))

    def test_main_prints_each_query_bound_and_fails_partial_delivery(self):
        class FakeAPI:
            def __init__(self, *_args):
                pass

            def get(self, path):
                self.assertEqual(path, "/api/core/backup/backups/this")
                return {"items": [
                    {"id": "config-1.xml", "time": "100"},
                    {"id": "config-2.xml", "time": "101"},
                ]}

            def assertEqual(self, left, right):
                if left != right:
                    raise AssertionError((left, right))

        def query_result(streams, end):
            return {"streams": streams, "succeeded": True, "start_ns": 10, "end_ns": end}

        query_results = [
            query_result([{"stream": {}, "values": [["1", "{}"]]}], 201),
            query_result([], 202),
            query_result([{"stream": {"opnsense_source": "configstate"}, "values": []}], 203),
            query_result([], 204),
        ]
        clean = {
            "configchange_bodies": 1,
            "configchange_sensitive_elements": 0,
            "configchange_bodies_redacted": True,
            "configstate_bodies": 1,
            "configstate_sensitive_keys": 0,
            "configstate_bodies_redacted": True,
        }
        environment = {
            "DEVBOX_HOST": "testbed.invalid",
            "DEVBOX_API_KEY": "not-rendered",
            "DEVBOX_API_SECRET": "not-rendered",
            "GRAFANA_OTLP_USER": "not-rendered",
            "GRAFANA_LOKI_USER": "not-rendered",
            "GRAFANA_CAP_TOKEN": "not-rendered",
            "GITHUB_RUN_ID": "123",
        }
        process = mock.Mock(stderr=io.BytesIO((json.dumps({
            "msg": proof.STDERR_MESSAGES["source_poll_error"],
            "source": "configchange",
            "err": "arbitrary-secret-value",
        }) + "\n").encode()))
        output = io.StringIO()
        with mock.patch.dict(proof.os.environ, environment, clear=False), \
                mock.patch.object(proof, "API", FakeAPI), \
                mock.patch.object(proof.subprocess, "Popen", return_value=process) as popen, \
                mock.patch.object(proof, "stop_process_group"), \
                mock.patch.object(proof.time, "sleep"), \
                mock.patch.object(proof.time, "time_ns", side_effect=[1_000_000_000_000, 1_000_000_000_100]), \
                mock.patch.object(proof, "loki_query", side_effect=query_results), \
                mock.patch.object(proof, "verify_redaction", return_value=clean), \
                mock.patch("sys.stdout", output):
            self.assertEqual(proof.main(["--exporter", "not-started", "--redaction-verifier", "verifier"]), 1)

        popen.assert_called_once()
        self.assertEqual(popen.call_args.kwargs["stderr"], proof.subprocess.PIPE)
        self.assertIn("--log.format=json", popen.call_args.args[0])
        rendered = output.getvalue()
        self.assertIn('- query configchange: {service_name="opnsense2otel",service_instance_id="delivery-proof-123",opnsense_source="configchange"} start=10 end=201', rendered)
        self.assertIn('- query source disambiguation: {service_name="opnsense2otel",service_instance_id="delivery-proof-123"} start=10 end=203', rendered)
        self.assertIn('- query exporter diagnostic: {service_name="opnsense2otel",service_instance_id="delivery-proof-123",opnsense_source="exporter"} start=10 end=204', rendered)
        self.assertIn("- delivered bodies redacted: no", rendered)
        self.assertIn("- configstate families query result: none", rendered)
        self.assertIn("- configstate unexpected family count: 0", rendered)
        self.assertIn("- stderr configchange poll error count: 1", rendered)
        self.assertIn("- cursor advanced: no", rendered)
        self.assertNotIn("arbitrary-secret-value", rendered)

    def test_retained_revisions_match_go_timestamp_then_id_ordering(self):
        class FakeAPI:
            def get(self, path):
                self.assertEqual(path, "/api/core/backup/backups/this")
                return {"items": [
                    {"id": "config-30.3.xml", "time": "30"},
                    {"id": "config-20.2.xml", "time": "20"},
                    {"id": "config-20.1.xml", "time": "20"},
                ]}

            def assertEqual(self, left, right):
                if left != right:
                    raise AssertionError((left, right))

        revisions = proof.retained_revisions(FakeAPI())
        self.assertEqual([revision.id for revision in revisions],
                         ["config-20.1.xml", "config-20.2.xml", "config-30.3.xml"])
        self.assertEqual(revisions[-2].id, "config-20.2.xml")

    def test_retained_revisions_reject_invalid_identity_or_timestamp(self):
        class FakeAPI:
            def get(self, _path):
                return {"items": [{"id": "config-20.1.xml", "time": "NaN"}]}

        with self.assertRaisesRegex(proof.ProofFailure, "revision list") as caught:
            proof.retained_revisions(FakeAPI())
        self.assertEqual(caught.exception.code, "retained_revisions_invalid")

    def test_state_file_uses_pipeline_envelope_and_exact_inner_cursor(self):
        revision = proof.RetainedRevision("config-123.456.xml", 123.456)
        path = proof.seed_revision_state(revision)
        self.addCleanup(pathlib.Path(path).unlink, missing_ok=True)
        outer = json.loads(pathlib.Path(path).read_text(encoding="utf-8"))
        self.assertEqual(set(outer), {"configchange"})
        self.assertEqual(json.loads(base64.b64decode(outer["configchange"])),
                         {"last_revision": "config-123.456.xml"})

    def test_revision_report_only_renders_upstream_safe_filename_grammar(self):
        self.assertEqual(proof.revision_report_value(proof.RetainedRevision("config-123.456.xml", 1), 2),
                         "config-123.456.xml")
        report = proof.revision_report_value(proof.RetainedRevision("unsafe value", 1), 2)
        self.assertTrue(report.startswith("nonreportable-rank-2-sha256-"))
        self.assertNotIn("unsafe value", report)

    def test_verify_redaction_requires_the_fixed_schema(self):
        completed = mock.Mock(returncode=0, stdout=b'{"unexpected":true}')
        with mock.patch.object(proof.subprocess, "run", return_value=completed):
            self.assertIsNone(proof.verify_redaction("verifier", [], []))

    def test_exporter_poll_error_diagnostic_redacts_credential_bearing_error(self):
        rows = [({"opnsense_source": "exporter"}, "log source poll error",
                 {"source": "configstate", "err": "request used Bearer a-secret-value"})]
        self.assertEqual(proof.exporter_poll_error_diagnostic(rows, "configstate"), "redacted")

if __name__ == "__main__":
    unittest.main()
