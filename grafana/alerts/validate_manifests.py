#!/usr/bin/env python3
"""
Validate the generated Grafana-managed alert/recording manifests under
grafana/alerts/grafana-managed/. Fails (exit 1) if any file is not well-formed JSON
or does not carry the expected apiVersion/kind, so a hand-edited or stale manifest
cannot ship silently. Wired into `make grafana-check` and CI (#84).

Expected shapes:
  * _folder.json          -> folder.grafana.app/v1beta1, kind Folder
  * every other *.json     -> rules.alerting.grafana.app/v0alpha1,
                              kind AlertRule or RecordingRule
"""
import glob
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST_DIR = os.path.join(HERE, "grafana-managed")

FOLDER_API = "folder.grafana.app/v1beta1"
RULE_API = "rules.alerting.grafana.app/v0alpha1"
RULE_KINDS = {"AlertRule", "RecordingRule"}

# The rules.alerting.grafana.app API rejects any other value for an AlertRule's
# noDataState (note the casing: "Ok", not "OK"). It slipped past this validator once
# and made every affected rule un-deployable via `gcx resources push`, so pin it here.
NODATA_STATES = {"NoData", "Ok", "Alerting", "KeepLast"}


def main() -> int:
    paths = sorted(glob.glob(os.path.join(MANIFEST_DIR, "*.json")))
    if not paths:
        print(f"no manifests found in {MANIFEST_DIR}", file=sys.stderr)
        return 1

    errors = []
    saw_folder = False
    for p in paths:
        name = os.path.basename(p)
        try:
            with open(p) as f:
                doc = json.load(f)
        except (OSError, json.JSONDecodeError) as e:
            errors.append(f"{name}: not well-formed JSON: {e}")
            continue

        api = doc.get("apiVersion")
        kind = doc.get("kind")
        if name == "_folder.json":
            saw_folder = True
            if api != FOLDER_API or kind != "Folder":
                errors.append(f"{name}: expected {FOLDER_API}/Folder, got {api}/{kind}")
            continue
        if api != RULE_API:
            errors.append(f"{name}: expected apiVersion {RULE_API}, got {api}")
        if kind not in RULE_KINDS:
            errors.append(f"{name}: expected kind in {sorted(RULE_KINDS)}, got {kind}")
        if not doc.get("metadata", {}).get("name"):
            errors.append(f"{name}: missing metadata.name")
        if kind == "AlertRule":
            nds = doc.get("spec", {}).get("noDataState")
            if nds not in NODATA_STATES:
                errors.append(
                    f"{name}: invalid spec.noDataState {nds!r}, "
                    f"must be one of {sorted(NODATA_STATES)}"
                )

    if not saw_folder:
        errors.append("_folder.json is missing (folder manifest must be present)")

    if errors:
        print("Grafana-managed manifest validation failed:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print(f"validated {len(paths)} grafana-managed manifests: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
