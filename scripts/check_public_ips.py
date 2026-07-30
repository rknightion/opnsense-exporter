#!/usr/bin/env python3
"""check_public_ips.py — reject globally routable IP literals in committed content.

This repository is public. A globally routable address committed in source, a test,
a fixture or a doc is durable public metadata about whoever's box produced it (#565).
Private/RFC1918, loopback, link-local, CGNAT (100.64.0.0/10), multicast and the two
documentation ranges (RFC 5737 for IPv4, RFC 3849 2001:db8::/32 for IPv6) are all
fine and are never flagged — only addresses that are actually globally routable are
a problem, because only those can identify or reach anything real.

Usage:
    python3 scripts/check_public_ips.py            # scan the repo, exit 1 on a bare
                                                     # (non-allowlisted) violation
    python3 scripts/check_public_ips.py --selftest  # run the checker's own unit
                                                     # tests (see check_public_ips_test.py)

Allowlist (scripts/public-ip-allowlist.json): a JSON array of
    {"file": "<repo-relative path>", "value": "<literal exactly as it appears>",
     "justification": "<non-empty reason this is not a real disclosure>"}
Matching is by the EXACT (file, value) pair — never a whole-file exemption — so one
legitimate literal in a file does not blind the check to a different, genuinely live
value landing in that same file later. An entry with an empty/whitespace-only
justification is treated as a bare violation, not an exemption: the point of the
allowlist is a written reason, not a bypass.
"""

from __future__ import annotations

import ipaddress
import json
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
ALLOWLIST_PATH = REPO_ROOT / "scripts" / "public-ip-allowlist.json"

# Never scanned: third-party code we don't author (vendor/), this script's own test
# fixtures (which deliberately contain both good and bad literals to prove the
# checker's behaviour, not to make a claim about real addresses), and the allowlist
# itself.
#
# The allowlist exclusion is not cosmetic: the file's whole job is to name the
# literals that are permitted, so scanning it means every entry reports itself as a
# violation, and the only way to silence that is an allowlist entry for the
# allowlist — which is unbounded. This bit once: the check passed while the file was
# still untracked and started failing the moment it was staged, because the scan
# walks `git ls-files`.
EXCLUDED_PREFIXES = ("vendor/",)
EXCLUDED_FILES = {
    "scripts/check_public_ips_test.py",
    "scripts/public-ip-allowlist.json",
}

# Documentation ranges (RFC 5737 / RFC 3849) are correct output for anonymised
# fixtures and are never a disclosure — never flagged, never need an allowlist entry.
DOC_V4_NETS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]
DOC_V6_NET = ipaddress.ip_network("2001:db8::/32")

IPV4_RE = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?![\w.])")
# A conservative IPv6 literal matcher: requires at least two colons or a "::" run,
# and at least one hex group — good enough to catch real addresses (which always
# have a "::" compression or 8 groups) while mostly staying out of MAC addresses
# (always exactly 6 groups of 2 hex digits, colon-separated, never "::") and
# timestamps/version strings, which this matches against separately below.
IPV6_RE = re.compile(
    r"(?<![\w:.])("
    r"(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,7}:"
    r"|(?:[0-9A-Fa-f]{1,4}:){1,6}:[0-9A-Fa-f]{1,4}"
    r"|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}"
    r")(?![\w:.])"
)


def is_cgnat(addr: ipaddress.IPv4Address) -> bool:
    return int(addr) >> 22 == int(ipaddress.ip_address("100.64.0.0")) >> 22


def is_documentation(addr) -> bool:
    if isinstance(addr, ipaddress.IPv4Address):
        return any(addr in net for net in DOC_V4_NETS)
    return addr in DOC_V6_NET


def is_globally_routable(literal: str) -> bool:
    """True if `literal` parses as an address that is NOT private/loopback/
    link-local/multicast/reserved/CGNAT/unspecified/documentation-range — i.e. an
    address that could identify or reach something on the real internet."""
    try:
        addr = ipaddress.ip_address(literal)
    except ValueError:
        return False
    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return False
    if addr.is_multicast or addr.is_reserved or addr.is_unspecified:
        return False
    if isinstance(addr, ipaddress.IPv4Address) and is_cgnat(addr):
        return False
    if is_documentation(addr):
        return False
    return True


def candidate_literals(line: str) -> list[str]:
    out = []
    for m in IPV4_RE.finditer(line):
        octets = m.group(1).split(".")
        if len(octets) == 4 and all(0 <= int(o) <= 255 and (o == "0" or not o.startswith("0")) for o in octets):
            out.append(m.group(1))
    for m in IPV6_RE.finditer(line):
        out.append(m.group(1))
    return out


def load_allowlist(path: Path = ALLOWLIST_PATH) -> tuple[dict[tuple[str, str], str], list[str]]:
    """Returns ({(file, value): justification}, [error strings for malformed entries])."""
    if not path.exists():
        return {}, []
    raw = json.loads(path.read_text())
    entries: dict[tuple[str, str], str] = {}
    errors: list[str] = []
    for i, item in enumerate(raw):
        try:
            f = item["file"]
            v = item["value"]
            j = item.get("justification", "")
        except (KeyError, TypeError):
            errors.append(f"allowlist entry #{i}: missing required 'file' or 'value' key")
            continue
        key = (f, v)
        if key in entries:
            errors.append(f"allowlist entry #{i}: duplicate entry for {f!r} / {v!r}")
        entries[key] = j
    return entries, errors


def tracked_files(root: Path = REPO_ROOT) -> list[str]:
    out = subprocess.run(
        ["git", "ls-files"], cwd=root, capture_output=True, text=True, check=True
    ).stdout
    files = []
    for f in out.splitlines():
        if f in EXCLUDED_FILES:
            continue
        if any(f.startswith(p) for p in EXCLUDED_PREFIXES):
            continue
        files.append(f)
    return files


class Violation:
    def __init__(self, file: str, line_no: int, literal: str, line_text: str):
        self.file = file
        self.line_no = line_no
        self.literal = literal
        self.line_text = line_text

    def __str__(self) -> str:
        return f"{self.file}:{self.line_no}: globally routable literal {self.literal!r}: {self.line_text.strip()[:160]}"


def scan(files: list[str], allowlist: dict[tuple[str, str], str], root: Path = REPO_ROOT) -> tuple[list[Violation], list[str]]:
    """Returns (bare violations, empty-justification violations-as-strings)."""
    violations: list[Violation] = []
    empty_justification: list[str] = []
    seen_per_file: dict[tuple[str, str], bool] = {}
    for rel in files:
        p = root / rel
        try:
            data = p.read_bytes()
        except OSError:
            continue
        if b"\x00" in data:
            continue  # binary file, not source/docs/fixture text
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue
        for i, line in enumerate(text.splitlines(), 1):
            for literal in candidate_literals(line):
                if not is_globally_routable(literal):
                    continue
                key = (rel, literal)
                if key in allowlist:
                    justification = allowlist[key]
                    if not justification.strip():
                        marker = (rel, literal, i)
                        if marker not in seen_per_file:
                            seen_per_file[marker] = True
                            empty_justification.append(
                                f"{rel}:{i}: literal {literal!r} is allowlisted but its justification is empty — "
                                "an allowlist entry with no reason is not an exemption"
                            )
                    continue
                violations.append(Violation(rel, i, literal, line))
    return violations, empty_justification


def main(argv: list[str]) -> int:
    if "--selftest" in argv:
        import unittest

        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        import check_public_ips_test  # noqa: PLC0415

        loader = unittest.TestLoader()
        suite = loader.loadTestsFromModule(check_public_ips_test)
        result = unittest.TextTestRunner(verbosity=2).run(suite)
        return 0 if result.wasSuccessful() else 1

    allowlist, allowlist_errors = load_allowlist()
    if allowlist_errors:
        print("check_public_ips: malformed allowlist:", file=sys.stderr)
        for e in allowlist_errors:
            print(f"  {e}", file=sys.stderr)
        return 1

    files = tracked_files()
    violations, empty_justification = scan(files, allowlist)

    if empty_justification:
        print(
            "check_public_ips: allowlist entries with an empty justification "
            "(fill in why this is not a real disclosure, or remove the entry):",
            file=sys.stderr,
        )
        for e in empty_justification:
            print(f"  {e}", file=sys.stderr)

    if violations:
        print(
            f"check_public_ips: {len(violations)} globally routable literal(s) found in "
            "committed content. Replace with an RFC 5737 (v4) / RFC 3849 (v6) documentation "
            "address, or add a justified entry to scripts/public-ip-allowlist.json:",
            file=sys.stderr,
        )
        for v in violations:
            print(f"  {v}", file=sys.stderr)

    if violations or empty_justification:
        return 1

    print(f"check_public_ips: OK ({len(files)} files scanned, {len(allowlist)} allowlist entries)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
