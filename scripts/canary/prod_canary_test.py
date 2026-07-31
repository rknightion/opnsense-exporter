"""Unit tests for camden's prod canary decision logic (#612).

The script itself needs the production firewall, an admin credential and a GitHub
token, none of which CI has. What CI *can* pin is the one piece of logic that
decides whether the run files an issue or closes it, which is exactly the piece
that was wrong: the script created and commented but never closed, and its
clean-check looked only for a warning section, so a report whose only finding was
BREAKING type drift was announced as clean.

These drive `--decide-only`, the seam that runs report_has_findings and nothing
else. It sits above every credential read and network call in the script, so
these tests touch no box and no GitHub.
"""

import os
import subprocess
import tempfile
import unittest

SCRIPT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "opnsense-prod-canary.sh")

# A clean report's real shape, trimmed from an actual apidrift run against the
# production firewall: a heading, the count sentence, and informational sections
# only. The point of pinning a real one is that ℹ️ and ⚪ sections are ALWAYS
# present on a clean prod run - prod has 56 plugin-gated absences and three
# skipped parameterized endpoints - so "clean" can never mean "no sections".
CLEAN_REPORT = """## OPNsense live-box schema canary — release 26.7.1_1

Probed **175** endpoints: 175 clean, 0 with breaking type drift, 0 with missing \
paths, 0 with unexpected top-level keys, 0 with unexpected nested keys, 56 absent \
404 (0 unexpected, 56 plugin-gated/expected), 0 probe errors, 3 skipped (no live \
parameter).

### ℹ️ Plugin-gated endpoints absent (plugin not installed — expected, not drift)

- `netbirdStatus` (`api/netbird/status/status`)

### ⚪ Skipped (parameterized, no live parameter)

- `ipsecPhase2` — covered by the e2e smoke instead

### ℹ️ Standing blind spots (required coverage the schema models as `any` — no live run can clear these)

- `hasyncVersion` `response` — backs `opnsense_hasync_remote_reachable`
"""

WARNING_SECTION = """### 🟡 Missing key paths (renamed/removed upstream, or box state)

- `ipsecSad` `rows[].allocated`
"""

BREAKING_SECTION = """### 🔴 Breaking: type mismatches

- `smartInfo` `output.endurance_used`: expected number, live box serves object
"""


def decide(body, exit_code=0):
    """Run the script's --decide-only seam over a report body."""
    with tempfile.NamedTemporaryFile("w", suffix=".md", delete=False) as fh:
        fh.write(body)
        path = fh.name
    try:
        out = subprocess.run(
            ["bash", SCRIPT, "--decide-only", path, str(exit_code)],
            capture_output=True, text=True, check=True,
        )
        return out.stdout.strip()
    finally:
        os.unlink(path)


class ProdCanaryDecisionTest(unittest.TestCase):
    def test_clean_report_is_clean(self):
        # The clean-run path, exercised against a real clean report - #612's
        # acceptance criterion. Informational sections must not read as findings.
        self.assertEqual(decide(CLEAN_REPORT), "clean")

    def test_warning_section_is_a_finding(self):
        self.assertEqual(decide(CLEAN_REPORT + WARNING_SECTION), "findings")

    def test_breaking_section_alone_is_a_finding(self):
        # THE #612 REGRESSION. apidrift exits 1 on breaking drift and the script
        # tolerates exit 1, so before the fix a 🔴-only report fell through the
        # 🟡 grep and the run announced itself clean while filing nothing. Both
        # halves are asserted: the marker on its own, and the exit code on its
        # own, because either can be true without the other.
        self.assertEqual(decide(CLEAN_REPORT + BREAKING_SECTION), "findings")

    def test_nonzero_exit_is_a_finding_even_with_no_marker(self):
        self.assertEqual(decide(CLEAN_REPORT, exit_code=1), "findings")

    def test_both_sections_is_a_finding(self):
        self.assertEqual(
            decide(CLEAN_REPORT + WARNING_SECTION + BREAKING_SECTION, exit_code=1),
            "findings",
        )

    def test_informational_markers_are_never_findings(self):
        # ℹ️ and ⚪ are informational by design. A canary that woke someone for
        # "this box has no netbird plugin" would be turned off within a week.
        for marker in ("### ℹ️ Something", "### ⚪ Something"):
            with self.subTest(marker=marker):
                self.assertEqual(decide(CLEAN_REPORT + marker + "\n"), "clean")


if __name__ == "__main__":
    unittest.main()
