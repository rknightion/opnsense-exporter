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


def test_extract_emits_endpoints():
    # The upstream walker requires the controller to live under a path containing
    # 'mvc/app/controllers' and ending in '/Api'. Build that layout from the fixture.
    with tempfile.TemporaryDirectory() as tmp:
        dest = os.path.join(tmp, "src", "opnsense", "mvc", "app", "controllers", "OPNsense", "Sample", "Api")
        os.makedirs(dest)
        shutil.copy(os.path.join(HERE, "testdata", "Sample", "Api", "ExampleController.php"),
                    os.path.join(dest, "ExampleController.php"))

        out = subprocess.check_output(
            [sys.executable, os.path.join(HERE, "extract.py"),
             "--docs", _docs_repo(), "--source", tmp],
            text=True,
        )
        endpoints = json.loads(out)
        by_path = {e["path"]: e for e in endpoints}

        assert "api/sample/example/search" in by_path, by_path
        assert "api/sample/example/status" in by_path, by_path
        # search action detects POST from isPost(); status defaults to GET.
        assert "POST" in by_path["api/sample/example/search"]["methods"]
        assert by_path["api/sample/example/status"]["methods"] == ["GET"]
