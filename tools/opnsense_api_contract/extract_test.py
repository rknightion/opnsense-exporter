import json
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))


def _docs_repo():
    path = os.environ.get("OPNSENSE_DOCS_REPO")
    if not path:
        raise RuntimeError("set OPNSENSE_DOCS_REPO to a checkout of github.com/opnsense/docs")
    return path


def _controller_dir(root, module):
    d = os.path.join(root, "src", "opnsense", "mvc", "app", "controllers", "OPNsense", module, "Api")
    os.makedirs(d)
    return d


def _place_valid(root):
    dest = _controller_dir(root, "Sample")
    shutil.copy(os.path.join(HERE, "testdata", "Sample", "Api", "ExampleController.php"),
                os.path.join(dest, "ExampleController.php"))


def _place_bad(root):
    dest = _controller_dir(root, "Bad")
    shutil.copy(os.path.join(HERE, "testdata", "Bad", "Api", "InstallerController.php"),
                os.path.join(dest, "InstallerController.php"))


def _run_extract(source, *extra, check=True):
    p = subprocess.run(
        [sys.executable, os.path.join(HERE, "extract.py"),
         "--docs", _docs_repo(), "--source", source, *extra],
        capture_output=True, text=True,
    )
    if check:
        assert p.returncode == 0, f"rc={p.returncode} stderr={p.stderr}"
    return p


def test_extract_emits_endpoints():
    # The upstream walker requires the controller to live under a path containing
    # 'mvc/app/controllers' and ending in '/Api'. Build that layout from the fixture.
    with tempfile.TemporaryDirectory() as tmp:
        _place_valid(tmp)
        p = _run_extract(tmp)
        endpoints = json.loads(p.stdout)
        by_path = {e["path"]: e for e in endpoints}

        assert "api/sample/example/search" in by_path, by_path
        assert "api/sample/example/status" in by_path, by_path
        # search action detects POST from isPost(); status defaults to GET.
        assert "POST" in by_path["api/sample/example/search"]["methods"]
        assert by_path["api/sample/example/status"]["methods"] == ["GET"]


def test_abstract_controller_emits_no_endpoints():
    # #146: an abstract base controller is non-routable, so extract.py must emit zero
    # entries for it, while a concrete sibling's actions are still emitted.
    with tempfile.TemporaryDirectory() as tmp:
        _place_valid(tmp)  # concrete OPNsense/Sample/Api/ExampleController.php
        absdir = _controller_dir(tmp, "Abstract")
        shutil.copy(os.path.join(HERE, "testdata", "Abstract", "Api", "BaseController.php"),
                    os.path.join(absdir, "BaseController.php"))

        p = _run_extract(tmp)
        by_path = {e["path"]: e for e in json.loads(p.stdout)}

        # Concrete sibling still emitted.
        assert "api/sample/example/search" in by_path, by_path
        # Abstract controller emits nothing.
        abstract = [path for path in by_path if path.startswith("api/abstract/")]
        assert abstract == [], f"abstract controller should emit no endpoints, got {abstract}"


def test_one_unparseable_controller_is_skipped_not_fatal():
    # #111: a valid controller alongside one the phply grammar cannot parse (PHP enum,
    # standing in for the Zenarmor construct) must exit 0, emit the valid controller's
    # endpoints, and warn naming the bad file — not crash the whole run.
    with tempfile.TemporaryDirectory() as tmp:
        _place_valid(tmp)
        _place_bad(tmp)
        p = _run_extract(tmp)
        by_path = {e["path"]: e for e in json.loads(p.stdout)}
        assert "api/sample/example/search" in by_path, by_path
        assert "InstallerController.php" in p.stderr, p.stderr
        assert "skipping unparseable" in p.stderr, p.stderr


def test_all_unparseable_below_min_exits_nonzero():
    # The --min floor still guards catastrophic breakage: only the bad controller is
    # present (0 endpoints), so --min 1 must fail even though skip-and-warn tolerated it.
    with tempfile.TemporaryDirectory() as tmp:
        _place_bad(tmp)
        p = _run_extract(tmp, "--min", "1", check=False)
        assert p.returncode != 0, p.stdout
        assert "skipping unparseable" in p.stderr, p.stderr


def test_strict_mode_fails_fast_on_unparseable():
    # --strict restores fail-fast: an unparseable controller aborts with a non-zero exit.
    with tempfile.TemporaryDirectory() as tmp:
        _place_valid(tmp)
        _place_bad(tmp)
        p = _run_extract(tmp, "--strict", check=False)
        assert p.returncode == 1, f"rc={p.returncode} stderr={p.stderr}"
        assert "failed to parse" in p.stderr, p.stderr
