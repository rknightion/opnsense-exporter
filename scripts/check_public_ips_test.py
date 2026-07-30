#!/usr/bin/env python3
"""Unit tests for check_public_ips.py's classifier, allowlist and scan logic.

Run via `python3 scripts/check_public_ips.py --selftest` (the Makefile's
check-public-ips target runs this before the real repo scan) or directly with
`python3 -m unittest scripts.check_public_ips_test` from the repo root.
"""

import json
import tempfile
import unittest
from pathlib import Path

import check_public_ips as cpi


class TestIsGloballyRoutable(unittest.TestCase):
    def test_private_ranges_are_fine(self):
        for s in ["10.0.0.5", "172.16.0.1", "192.168.1.1", "fd12:3456::1"]:
            self.assertFalse(cpi.is_globally_routable(s), s)

    def test_loopback_link_local_multicast_are_fine(self):
        for s in ["127.0.0.1", "169.254.1.1", "239.255.255.250", "::1", "fe80::1", "ff02::fb"]:
            self.assertFalse(cpi.is_globally_routable(s), s)

    def test_cgnat_is_fine(self):
        for s in ["100.64.0.1", "100.100.100.100", "100.127.255.255"]:
            self.assertFalse(cpi.is_globally_routable(s), s)
        # just outside the /10 on both ends must NOT be treated as CGNAT
        self.assertTrue(cpi.is_globally_routable("100.63.255.255"))
        self.assertTrue(cpi.is_globally_routable("100.128.0.0"))

    def test_documentation_ranges_are_fine(self):
        for s in ["192.0.2.1", "198.51.100.6", "203.0.113.203", "2001:db8::1"]:
            self.assertFalse(cpi.is_globally_routable(s), s)

    def test_real_global_addresses_are_flagged(self):
        for s in ["1.1.1.1", "8.8.8.8", "86.31.203.106", "2606:4700::1111"]:
            self.assertTrue(cpi.is_globally_routable(s), s)

    def test_non_address_is_not_globally_routable(self):
        self.assertFalse(cpi.is_globally_routable("not.an.ip.address"))


class TestCandidateLiterals(unittest.TestCase):
    def test_finds_v4_in_json_line(self):
        line = '"src_ip": "203.0.113.9", "dst_ip": "198.51.100.4"'
        self.assertEqual(cpi.candidate_literals(line), ["203.0.113.9", "198.51.100.4"])

    def test_ignores_version_like_three_part_numbers(self):
        # A three-dot version number never matches the four-octet IPv4 pattern.
        self.assertEqual(cpi.candidate_literals("OPNsense 26.1.11 release notes"), [])

    def test_ignores_number_glued_to_a_word(self):
        # "go1.26.0" — no four-octet match, and the leading digit is glued to a
        # word character so it can't be mistaken for a bare octet run either.
        self.assertEqual(cpi.candidate_literals("built with go1.26.0 toolchain"), [])

    def test_finds_v6_with_double_colon(self):
        self.assertIn("2606:4700::1111", cpi.candidate_literals("resolver 2606:4700::1111 answered"))

    def test_mac_address_is_rejected_downstream(self):
        # candidate_literals is a deliberately permissive regex pass — a MAC address
        # (six hex octets, never "::"-compressed) is not valid IPv6 syntax, so
        # is_globally_routable (which every candidate is filtered through before
        # being reported) rejects it via a straight ipaddress parse failure.
        for lit in cpi.candidate_literals("mac 7c:10:c9:5e:84:86 seen"):
            self.assertFalse(cpi.is_globally_routable(lit), lit)


class TestAllowlistAndScan(unittest.TestCase):
    def _write(self, tmp: Path, rel: str, content: str) -> None:
        p = tmp / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content)

    def test_allowlisted_literal_with_justification_passes(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._write(root, "docs/example.md", "resolver 1.1.1.1 is well known\n")
            allowlist = {("docs/example.md", "1.1.1.1"): "Public DNS resolver used as a documented example."}
            violations, empty = cpi.scan(["docs/example.md"], allowlist, root=root)
            self.assertEqual(violations, [])
            self.assertEqual(empty, [])

    def test_allowlist_entry_with_empty_justification_still_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._write(root, "docs/example.md", "resolver 1.1.1.1 is well known\n")
            allowlist = {("docs/example.md", "1.1.1.1"): ""}
            violations, empty = cpi.scan(["docs/example.md"], allowlist, root=root)
            self.assertEqual(violations, [])
            self.assertEqual(len(empty), 1)
            self.assertIn("empty", empty[0])

    def test_allowlist_entry_with_whitespace_only_justification_still_fails(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._write(root, "docs/example.md", "resolver 1.1.1.1 is well known\n")
            allowlist = {("docs/example.md", "1.1.1.1"): "   "}
            violations, empty = cpi.scan(["docs/example.md"], allowlist, root=root)
            self.assertEqual(violations, [])
            self.assertEqual(len(empty), 1)

    def test_unallowlisted_globally_routable_literal_is_a_violation(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._write(root, "internal/collector/example_test.go", '"current_ip": "86.31.203.106",\n')
            violations, empty = cpi.scan(["internal/collector/example_test.go"], {}, root=root)
            self.assertEqual(len(violations), 1)
            self.assertEqual(violations[0].literal, "86.31.203.106")
            self.assertEqual(empty, [])

    def test_allowlist_is_scoped_to_exact_file_and_value_pair(self):
        # An allowlist entry for one file must NOT silence the same literal
        # appearing in a different file — allowlisting must never become a
        # blanket exemption for a value.
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._write(root, "docs/a.md", "see 1.1.1.1\n")
            self._write(root, "docs/b.md", "see 1.1.1.1\n")
            allowlist = {("docs/a.md", "1.1.1.1"): "Documented DNS resolver example."}
            violations, empty = cpi.scan(["docs/a.md", "docs/b.md"], allowlist, root=root)
            self.assertEqual(len(violations), 1)
            self.assertEqual(violations[0].file, "docs/b.md")

    def test_binary_file_is_skipped(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            p = root / "bin.dat"
            p.write_bytes(b"\x00\x01203.0.113.9\x00")
            violations, empty = cpi.scan(["bin.dat"], {}, root=root)
            self.assertEqual(violations, [])

    def test_doc_range_literal_never_needs_allowlisting(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            self._write(root, "docs/example.md", "example: 198.51.100.4\n")
            violations, empty = cpi.scan(["docs/example.md"], {}, root=root)
            self.assertEqual(violations, [])
            self.assertEqual(empty, [])


class TestLoadAllowlist(unittest.TestCase):
    def test_missing_file_key_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "allowlist.json"
            p.write_text(json.dumps([{"value": "1.1.1.1", "justification": "x"}]))
            entries, errors = cpi.load_allowlist(p)
            self.assertEqual(entries, {})
            self.assertEqual(len(errors), 1)

    def test_duplicate_entry_is_reported(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "allowlist.json"
            p.write_text(
                json.dumps(
                    [
                        {"file": "a", "value": "1.1.1.1", "justification": "x"},
                        {"file": "a", "value": "1.1.1.1", "justification": "y"},
                    ]
                )
            )
            entries, errors = cpi.load_allowlist(p)
            self.assertEqual(len(errors), 1)
            self.assertIn("duplicate", errors[0])

    def test_missing_allowlist_file_is_empty_not_an_error(self):
        entries, errors = cpi.load_allowlist(Path("/nonexistent/allowlist.json"))
        self.assertEqual(entries, {})
        self.assertEqual(errors, [])


if __name__ == "__main__":
    unittest.main()
