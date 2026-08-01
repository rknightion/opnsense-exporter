#!/usr/bin/env python3
"""Tests for opnsense-testbed-power.sh's decision logic (#625).

Everything here drives the script's `--decide-only` seam, which answers a
question from its arguments alone and exits before touching Proxmox, the
network or the hold file. So these run anywhere — no oli, no root, no qm.

What is deliberately NOT covered: the actual start/stop calls and the readiness
gate. Those need a host, and mocking `qm` would test the mock. They are
exercised by hand at deploy time per the issue's acceptance criteria.
"""

import subprocess
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


if __name__ == "__main__":
    unittest.main()
