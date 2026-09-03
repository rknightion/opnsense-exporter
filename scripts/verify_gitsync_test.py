"""Regression tests for the Grafana GitSync deployment verifier."""

from __future__ import annotations

import importlib.util
import pathlib
import re
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location(
    "verify_gitsync", ROOT / "scripts" / "verify-gitsync.py"
)
assert SPEC is not None and SPEC.loader is not None
VERIFY_GITSYNC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(VERIFY_GITSYNC)


class GitSyncRepositoryTest(unittest.TestCase):
    def test_canonical_url_matches_workflow_checkout(self) -> None:
        workflow = (ROOT / ".github" / "workflows" / "grafana-sync.yml").read_text(
            encoding="utf-8"
        )
        match = re.search(r"^\s+repository:\s+(\S+)\s*$", workflow, re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertEqual(
            VERIFY_GITSYNC.GITSYNC_REPO_URL,
            f"https://github.com/{match.group(1)}",
        )

    def test_find_repository_matches_canonical_url(self) -> None:
        expected = {
            "metadata": {"name": "repository-generated"},
            "spec": {"github": {"url": "https://github.com/m7kni/gc-gitsync-m7kni"}},
        }
        with mock.patch.object(
            VERIFY_GITSYNC, "gcx", return_value={"items": [expected]}
        ):
            self.assertIs(VERIFY_GITSYNC.find_repository("stacks-test"), expected)


if __name__ == "__main__":
    unittest.main()
