#!/usr/bin/env python3
"""Host-independent tests for the OPN-0057 UDP harness contract."""

import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import udp_throughput as harness


def digest(value):
    return hashlib.sha256(value.encode()).hexdigest()


def observation(target_os, phase):
    role = f"udp-throughput-{target_os}-receiver"
    return {
        "phase": phase, "receiver_os": target_os, "harness": harness.harness_shape(),
        "receiver": {"role": role, "instance_identity_sha256": digest(target_os),
                     "method_identity_sha256": digest(f"method-{target_os}")},
        "binary": {"sha256": digest(f"binary-{target_os}-{phase}"),
                   "source_revision_sha256": digest(f"source-{phase}"), "version": f"test-{phase}"},
        "socket_buffer": {"state": "observed", "method": "getsockopt_so_rcvbuf",
                          "requested_bytes": 4 * 1024 * 1024,
                          "effective_bytes": 8 * 1024 * 1024 if target_os == "linux" else 4 * 1024 * 1024,
                          "linux_readback_is_doubled": target_os == "linux",
                          "evidence_sha256": digest(f"buffer-{target_os}-{phase}")},
        "isolation": {"state": "observed", "receiver_role": role,
                      "scope": "dedicated-host-and-exclusive-udp-traffic",
                      "statement": "The role had exclusive UDP traffic for the captured interval.",
                      "evidence_sha256": digest(f"isolation-{target_os}-{phase}")},
        "socket_drop": {"state": "observed", "scope": "receiver_socket" if target_os == "linux" else "system_udp",
                        "method": "fixture-counter", "start": 10, "end": 10,
                        "evidence_sha256": digest(f"socket-{target_os}-{phase}")},
        "worker_queue_drop": {"state": "observed", "metric": harness.QUEUE_DROP_METRIC,
                              "start": 20, "end": 20, "evidence_sha256": digest(f"queue-{target_os}-{phase}")},
        "receiver_accepted": {"state": "observed", "metric": harness.RECEIVER_ACCEPTED_METRIC,
                              "start": 30, "end": 300030, "evidence_sha256": digest(f"accepted-{target_os}-{phase}")},
        "sender": {"schema_version": harness.SCHEMA_VERSION, "state": "observed", "sent_packets": 300000,
                   "elapsed_seconds": 60, "packet_size_bytes": 256, "duration_seconds": 60,
                   "payload_sha256": harness.PAYLOAD_SHA256, "offered_rate_packets_per_second": 5000},
    }


class TestHarnessContract(unittest.TestCase):
    def test_payload_has_fixed_size_and_hash(self):
        self.assertEqual(len(harness.PAYLOAD), harness.PACKET_SIZE_BYTES)
        self.assertEqual(hashlib.sha256(harness.PAYLOAD).hexdigest(), harness.PAYLOAD_SHA256)

    def test_complete_four_target_comparison_is_accepted(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = write_observations(directory)
            code, result = harness.verify(paths)
        self.assertEqual(code, 0)
        self.assertEqual(result["status"], "accepted")
        self.assertEqual(result["comparison"]["linux"]["before"]["socket_drop_delta"], 0)
        self.assertEqual(result["comparison"]["freebsd"]["current"]["worker_queue_drop_delta"], 0)

    def test_missing_numeric_buffer_readback_fails_closed(self):
        sample = observation("linux", "before")
        sample["socket_buffer"]["effective_bytes"] = None
        _, errors = harness.validate_observation(sample, "linux", "before")
        self.assertIn("socket_buffer.effective_bytes must be a positive integer", errors)

    def test_unobserved_counter_is_not_zero(self):
        sample = observation("linux", "before")
        sample["worker_queue_drop"] = {"state": "unobserved"}
        _, errors = harness.validate_observation(sample, "linux", "before")
        self.assertIn("worker_queue_drop must be an observed counter, not skipped or unobserved", errors)

    def test_nonconforming_offered_load_fails_closed(self):
        sample = observation("linux", "before")
        sample["sender"]["sent_packets"] -= 1
        _, errors = harness.validate_observation(sample, "linux", "before")
        self.assertIn("sender.sent_packets does not match the fixed offered load", errors)

    def test_non_finite_elapsed_time_fails_closed(self):
        for elapsed in (float("nan"), float("inf"), float("-inf")):
            with self.subTest(elapsed=elapsed):
                sample = observation("linux", "before")
                sample["sender"]["elapsed_seconds"] = elapsed
                _, errors = harness.validate_observation(sample, "linux", "before")
                self.assertIn("sender.elapsed_seconds must be finite", errors)

    def test_sender_with_missing_packet_size_is_rejected(self):
        sample = observation("linux", "before")
        del sample["sender"]["packet_size_bytes"]
        _, errors = harness.validate_observation(sample, "linux", "before")
        self.assertIn("sender.packet_size_bytes does not match the fixed packet size", errors)

    def test_bsd_system_counter_requires_isolation_proof(self):
        sample = observation("freebsd", "before")
        sample["isolation"]["scope"] = "port-only"
        _, errors = harness.validate_observation(sample, "freebsd", "before")
        self.assertIn("a system_udp counter requires dedicated-host-and-exclusive-udp-traffic isolation", errors)

    def test_changed_method_and_same_binary_reject_pair_without_partial_result(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = write_observations(directory)
            linux_current = Path(paths["linux_current"])
            item = json.loads(linux_current.read_text())
            item["receiver"]["method_identity_sha256"] = digest("changed-method")
            linux_current.write_text(json.dumps(item))
            freebsd_current = Path(paths["freebsd_current"])
            item = json.loads(freebsd_current.read_text())
            item["binary"]["sha256"] = observation("freebsd", "before")["binary"]["sha256"]
            freebsd_current.write_text(json.dumps(item))
            code, result = harness.verify(paths)
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "rejected")
        self.assertIsNone(result["comparison"])
        self.assertTrue(any("methods differ" in x["error"] for x in result["violations"]))
        self.assertTrue(any("binary identities must differ" in x["error"] for x in result["violations"]))

    def test_changed_socket_drop_scope_rejects_pair(self):
        with tempfile.TemporaryDirectory() as directory:
            paths = write_observations(directory)
            freebsd_current = Path(paths["freebsd_current"])
            item = json.loads(freebsd_current.read_text())
            item["socket_drop"]["scope"] = "receiver_socket"
            freebsd_current.write_text(json.dumps(item))
            code, result = harness.verify(paths)
        self.assertEqual(code, 2)
        self.assertEqual(result["status"], "rejected")
        self.assertIsNone(result["comparison"])
        self.assertTrue(any("socket-drop scopes differ" in x["error"] for x in result["violations"]))

    def test_sender_failure_is_machine_readable_without_target(self):
        failing_socket = mock.MagicMock()
        failing_socket.__enter__.return_value.sendto.side_effect = OSError(55, "private target detail")
        with mock.patch.object(harness.socket, "getaddrinfo", return_value=[(2, 2, 17, "", ("192.0.2.1", 5514))]), \
             mock.patch.object(harness.socket, "socket", return_value=failing_socket):
            code, result = harness.send("receiver.internal", 5514)
        self.assertEqual(code, 2)
        self.assertEqual(result["state"], "nonconforming")
        self.assertEqual(result["sent_packets"], 0)
        self.assertEqual(result["send_error"], {"type": "OSError", "errno": 55})
        self.assertNotIn("receiver.internal", json.dumps(result))
        self.assertNotIn("private target detail", json.dumps(result))


def write_observations(directory):
    paths = {}
    for target_os in ("linux", "freebsd"):
        for phase in ("before", "current"):
            path = Path(directory) / f"{target_os}-{phase}.json"
            path.write_text(json.dumps(observation(target_os, phase)))
            paths[f"{target_os}_{phase}"] = str(path)
    return paths


if __name__ == "__main__":
    unittest.main()
