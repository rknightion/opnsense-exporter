#!/usr/bin/env python3
"""Tests for opnsense-testbed-power.sh's decision logic and guest routes (#625).

The decision tests drive the script's `--decide-only` seam, which answers a
question from its arguments alone and exits before touching Proxmox, the
network or the hold file. The route tests use temporary mock `qm` and `pct`
executables, so these run anywhere — no oli, no root, no real guest tools.

What is deliberately NOT covered: the actual start/stop calls and the readiness
gate. Those need a host and are exercised by hand at deploy time per the issue's
acceptance criteria.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent / "opnsense-testbed-power.sh"

# The prod guests on oli. If any of these is ever accepted by the allowlist,
# the script can power off Rob's home automation, the CI runners, the UniFi
# controller or a Windows server. This is the single most important assertion
# in the file.
PROD_GUESTS = ["100", "101", "103", "104", "107"]

TESTBED_GUESTS = ["102", "105", "106", "110", "111", "112"]


def decide(*args: str) -> str:
    """Run the script's decide-only seam and return its stdout, stripped."""
    result = subprocess.run(
        [str(SCRIPT), "--decide-only", *args],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise AssertionError(
            f"decide-only {args} exited {result.returncode}: {result.stderr}"
        )
    return result.stdout.strip()


def run_script(
    *args: str, env: dict[str, str] | None = None
) -> subprocess.CompletedProcess[str]:
    """Run a production command without allowing it to touch a real guest."""
    process_env = os.environ.copy()
    if env is not None:
        process_env.update(env)
    return subprocess.run(
        [str(SCRIPT), *args],
        capture_output=True,
        text=True,
        env=process_env,
        check=False,
    )


class TestAllowlist(unittest.TestCase):
    def test_testbed_guests_are_allowed(self):
        for vmid in TESTBED_GUESTS:
            self.assertEqual(decide("allowed", vmid), "yes", f"vmid {vmid}")

    def test_prod_guests_are_refused(self):
        for vmid in PROD_GUESTS:
            self.assertEqual(decide("allowed", vmid), "no", f"vmid {vmid}")

    def test_unknown_guests_are_refused(self):
        for vmid in ["0", "99", "113", "999", ""]:
            self.assertEqual(decide("allowed", vmid), "no", f"vmid {vmid!r}")

    def test_substring_ids_do_not_match(self):
        # A naive `case`/grep allowlist matches "10" inside "102" or "1020"
        # inside "102". Both would be catastrophic in opposite directions.
        for vmid in ["10", "1020", "1", "02", "11"]:
            self.assertEqual(decide("allowed", vmid), "no", f"vmid {vmid!r}")


class TestOrdering(unittest.TestCase):
    def test_up_starts_firewalls_before_everything_else(self):
        order = decide("order", "up").split()
        self.assertEqual(set(order), set(TESTBED_GUESTS))
        # Both firewalls must precede every dependent guest: the helpers DHCP,
        # route and resolve through them, so starting a client first means it
        # boots with no lease and the canary reads an empty box.
        for firewall in ("102", "106"):
            for dependent in ("105", "110", "111", "112"):
                self.assertLess(
                    order.index(firewall),
                    order.index(dependent),
                    f"{firewall} must start before {dependent}",
                )

    def test_down_is_the_exact_reverse_of_up(self):
        up = decide("order", "up").split()
        down = decide("order", "down").split()
        self.assertEqual(down, list(reversed(up)))

    def test_down_stops_dependents_before_firewalls(self):
        order = decide("order", "down").split()
        for firewall in ("102", "106"):
            for dependent in ("105", "110", "111", "112"):
                self.assertLess(
                    order.index(dependent),
                    order.index(firewall),
                    f"{dependent} must stop before {firewall}",
                )


class TestHold(unittest.TestCase):
    """A hold suppresses the scheduled shutdown so ad-hoc work is not fighting
    the timer. `hold <file> <now_epoch>` prints held|free."""

    def _write(self, content: str) -> str:
        import tempfile

        handle = tempfile.NamedTemporaryFile("w", suffix=".hold", delete=False)
        handle.write(content)
        handle.close()
        self.addCleanup(lambda: Path(handle.name).unlink(missing_ok=True))
        return handle.name

    def test_missing_file_is_free(self):
        self.assertEqual(decide("hold", "/nonexistent/hold", "1000"), "free")

    def test_future_expiry_is_held(self):
        path = self._write("2000\n")
        self.assertEqual(decide("hold", path, "1000"), "held")

    def test_past_expiry_is_free(self):
        path = self._write("500\n")
        self.assertEqual(decide("hold", path, "1000"), "free")

    def test_expiry_exactly_now_is_free(self):
        # Boundary: at the expiry instant the hold is over, not still running.
        path = self._write("1000\n")
        self.assertEqual(decide("hold", path, "1000"), "free")

    def test_malformed_hold_fails_open_to_free(self):
        # Deliberate: a stuck-on hold silently disables the whole feature,
        # which is the failure Rob would never notice. A spurious shutdown is
        # loud and recoverable with `testbed up`. So garbage means free.
        for junk in ["", "\n", "not-a-number\n", "12x34\n", "-\n"]:
            path = self._write(junk)
            self.assertEqual(decide("hold", path, "1000"), "free", repr(junk))

    def test_empty_file_is_free(self):
        path = self._write("")
        self.assertEqual(decide("hold", path, "1000"), "free")


class TestGuestRoutes(unittest.TestCase):
    @staticmethod
    def _tool(directory: Path, name: str, body: str) -> None:
        path = directory / name
        path.write_text(body)
        path.chmod(0o755)

    @staticmethod
    def _tool_env(directory: Path, **extra: str) -> dict[str, str]:
        env = {"PATH": f"{directory}{os.pathsep}{os.environ['PATH']}"}
        env.update(extra)
        return env

    def test_exec_refuses_disallowed_guest_with_allowlist_message(self):
        result = run_script("exec", "100", "--", "id")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "refusing to touch guest 100 — not in the testbed allowlist",
            result.stderr,
        )

    def test_exec_routes_ct_with_plain_output_and_guest_exit_code(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            args_file = directory / "pct.args"
            self._tool(
                directory,
                "pct",
                "#!/bin/sh\n"
                "printf '%s\\n' \"$@\" > \"$ARGS_FILE\"\n"
                "printf 'ct stdout\\n'\n"
                "printf 'ct stderr\\n' >&2\n"
                "exit 7\n",
            )
            result = run_script(
                "exec",
                "105",
                "--",
                "printf",
                "hello",
                env=self._tool_env(directory, ARGS_FILE=str(args_file)),
            )
            self.assertEqual(result.returncode, 7)
            self.assertEqual(result.stdout, "ct stdout\n")
            self.assertEqual(result.stderr, "ct stderr\n")
            self.assertEqual(
                args_file.read_text().splitlines(),
                ["exec", "105", "--", "printf", "hello"],
            )

    def test_exec_routes_vm_with_qm_timeout_and_decoded_envelope(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            args_file = directory / "qm.args"
            self._tool(
                directory,
                "qm",
                "#!/bin/sh\n"
                "printf '%s\\n' \"$@\" > \"$ARGS_FILE\"\n"
                "printf '%s' '{\"exitcode\":0,\"out-data\":\"vm stdout\",\"err-data\":\"vm stderr\"}'\n",
            )
            result = run_script(
                "exec",
                "110",
                "--",
                "uname",
                "-a",
                env=self._tool_env(
                    directory,
                    ARGS_FILE=str(args_file),
                    TMPDIR=str(directory),
                ),
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "vm stdout")
            self.assertEqual(result.stderr, "vm stderr")
            self.assertEqual(
                args_file.read_text().splitlines(),
                [
                    "guest",
                    "exec",
                    "110",
                    "--timeout",
                    "300",
                    "--",
                    "uname",
                    "-a",
                ],
            )

    def test_exec_returns_vm_guest_failure_from_envelope(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            self._tool(
                directory,
                "qm",
                "#!/bin/sh\n"
                "printf '%s' '{\"exitcode\":23,\"out-data\":\"guest out\\n\",\"err-data\":\"guest err\\n\"}'\n",
            )
            result = run_script(
                "exec",
                "102",
                "--",
                "false",
                env=self._tool_env(directory, TMPDIR=str(directory)),
            )
            self.assertEqual(result.returncode, 23)
            self.assertEqual(result.stdout, "guest out\n")
            self.assertEqual(result.stderr, "guest err\n")

    def test_exec_treats_omitted_vm_streams_as_empty(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            self._tool(
                directory,
                "qm",
                "#!/bin/sh\n"
                "printf '%s' '{\"exitcode\":0}'\n",
            )
            result = run_script(
                "exec",
                "102",
                "--",
                "true",
                env=self._tool_env(directory, TMPDIR=str(directory)),
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr, "")

    def test_exec_rejects_empty_command(self):
        result = run_script("exec", "105", "--")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exec: command is required", result.stderr)

    def test_exec_rejects_missing_separator(self):
        result = run_script("exec", "105", "id")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exec: expected '--' before command", result.stderr)

    def test_put_routes_only_ct_through_pct_push(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            args_file = directory / "pct.args"
            self._tool(
                directory,
                "pct",
                "#!/bin/sh\n"
                "printf '%s\\n' \"$@\" > \"$ARGS_FILE\"\n",
            )
            result = run_script(
                "put",
                "105",
                "/tmp/local",
                "/tmp/remote",
                env=self._tool_env(directory, ARGS_FILE=str(args_file)),
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(
                args_file.read_text().splitlines(),
                ["push", "105", "/tmp/local", "/tmp/remote"],
            )

    def test_put_refuses_vm_and_explains_fetch_checksum_route(self):
        result = run_script("put", "102", "/tmp/local", "/tmp/remote")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("qm has no guest file-write", result.stderr)
        self.assertIn("exec 102 -- fetch -o <tmp> <release-url>", result.stderr)
        self.assertIn("sha256", result.stderr)
        self.assertIn("checksums.txt", result.stderr)

    def test_exec_rejects_malformed_or_missing_vm_envelope(self):
        envelopes = [
            "{}",
            '{"exitcode":0,"out-data":null}',
            "not-json",
        ]
        for envelope in envelopes:
            with self.subTest(envelope=envelope):
                with tempfile.TemporaryDirectory() as temporary_directory:
                    directory = Path(temporary_directory)
                    self._tool(
                        directory,
                        "qm",
                        "#!/bin/sh\n"
                        "printf '%s' \"$ENVELOPE\"\n",
                    )
                    result = run_script(
                        "exec",
                        "102",
                        "--",
                        "true",
                        env=self._tool_env(
                            directory,
                            ENVELOPE=envelope,
                            TMPDIR=str(directory),
                        ),
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertEqual(result.stdout, "")
                    self.assertIn("valid JSON envelope", result.stderr)

    def test_exec_fails_closed_when_qm_times_out_without_envelope(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            directory = Path(temporary_directory)
            self._tool(
                directory,
                "qm",
                "#!/bin/sh\n"
                "printf 'timed out\\n' >&2\n"
                "exit 124\n",
            )
            result = run_script(
                "exec",
                "102",
                "--",
                "true",
                env=self._tool_env(directory, TMPDIR=str(directory)),
            )
            self.assertEqual(result.returncode, 124)
            self.assertEqual(result.stdout, "")
            self.assertIn("timed out", result.stderr)

    def test_put_refuses_disallowed_guest_with_allowlist_message(self):
        result = run_script("put", "100", "/tmp/local", "/tmp/remote")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(
            "refusing to touch guest 100 — not in the testbed allowlist",
            result.stderr,
        )


if __name__ == "__main__":
    unittest.main()
