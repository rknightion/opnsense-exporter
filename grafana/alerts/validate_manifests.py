#!/usr/bin/env python3
"""
Validate the generated Grafana-managed alert/recording manifests under
grafana/alerts/grafana-managed/. Fails (exit 1) if any file is not well-formed JSON,
does not carry the expected apiVersion/kind, or violates a manifest-contract
invariant Prometheus's own syntax cannot check (severity, IRM routing labels,
noDataState, execErrState, pending duration, per-instance label preservation, or a
runbook anchor that does not actually resolve). Wired into `make grafana-check` and
CI (#84, extended #429).

Expected shapes:
  * _folder.json          -> folder.grafana.app/v1beta1, kind Folder
  * every other *.json     -> rules.alerting.grafana.app/v0alpha1,
                              kind AlertRule or RecordingRule
"""
import glob
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
MANIFEST_DIR = os.path.join(HERE, "grafana-managed")
REPO_ROOT = os.path.dirname(os.path.dirname(HERE))

# uids.py is the single registry for the runbook URL (#419/#429): import it
# rather than duplicate the literal, so the anchor this validator resolves is
# always the exact same one build_rules.py stamped onto every rule.
sys.path.insert(0, os.path.dirname(HERE))
from uids import REPO_BASE, RUNBOOK_URL  # noqa: E402

FOLDER_API = "folder.grafana.app/v1beta1"
RULE_API = "rules.alerting.grafana.app/v0alpha1"
RULE_KINDS = {"AlertRule", "RecordingRule"}

# The rules.alerting.grafana.app API rejects any other value for an AlertRule's
# noDataState (note the casing: "Ok", not "OK"). It slipped past this validator once
# and made every affected rule un-deployable via `gcx resources push`, so pin it here.
NODATA_STATES = {"NoData", "Ok", "Alerting", "KeepLast"}

# Same provenance and failure mode as NODATA_STATES: a wrong string here
# deploys fine and only misfires the day a query actually errors.
EXEC_ERR_STATES = {"Alerting", "Error", "OK", "KeepLast"}

# The only severities build_rules.py's RULES list assigns. Anything else is a
# typo, not a fourth tier - there is no routing/notification-policy contract
# for one.
SEVERITIES = {"critical", "warning", "info"}

# Grafana/Go duration string for spec.for (the alert's pending duration):
# "0s", "5m0s", "1h5m0s". Never negative, never a bare unit-less number.
FOR_DURATION_RE = re.compile(r"^(?:\d+h)?(?:\d+m)?\d+s$")

# An aggregation clause that drops opnsense_instance merges independently
# monitored firewalls into one indistinguishable alert/recording-rule series.
# This only catches the deterministic case: an explicit `by (...)` label list.
AGG_BY_RE = re.compile(r"(?:sum|max|min|avg|count)\s+by\s*\(([^)]*)\)")

# {{ $labels.foo }} tokens Grafana substitutes from the firing alert instance's
# labels. If foo was aggregated away above, this silently renders empty rather
# than erroring.
LABEL_TOKEN_RE = re.compile(r"\{\{\s*\$labels\.([a-zA-Z_][a-zA-Z0-9_]*)\s*\}\}")

_SLUG_STRIP_RE = re.compile(r"[^\w\s-]")
_SLUG_WS_RE = re.compile(r"\s")
_HEADING_RE = re.compile(r"^#{1,6}\s+(.*)$")

_anchor_cache: dict = {}


def _github_heading_slug(text: str) -> str:
    """Approximate GitHub's Markdown heading-anchor algorithm: lowercase, drop
    punctuation (keep word chars/spaces/hyphens), then turn each whitespace
    character into its own hyphen - GitHub does not collapse the doubled
    hyphen a removed '&' leaves behind, e.g. "Alerts & Recording" ->
    "alerts--recording"."""
    text = text.strip().lower()
    text = _SLUG_STRIP_RE.sub("", text)
    return _SLUG_WS_RE.sub("-", text)


def _runbook_anchor_resolves(url: str):
    """Check that a runbook_url's anchor actually exists as a heading in the
    document it names, by reading the file - never a network request."""
    if url in _anchor_cache:
        return _anchor_cache[url]

    prefix = f"{REPO_BASE}/blob/main/"
    if not url.startswith(prefix) or "#" not in url:
        result = (False, f"not of the form {prefix}<repo-relative-path>#<anchor>")
        _anchor_cache[url] = result
        return result

    rel_path, anchor = url[len(prefix):].split("#", 1)
    doc_path = os.path.join(REPO_ROOT, rel_path)
    if not os.path.isfile(doc_path):
        result = (False, f"{rel_path} does not exist in the repository")
        _anchor_cache[url] = result
        return result

    slugs = set()
    with open(doc_path) as f:
        for line in f:
            m = _HEADING_RE.match(line.rstrip())
            if m:
                slugs.add(_github_heading_slug(m.group(1)))

    if anchor not in slugs:
        result = (False, f"no heading in {rel_path} slugs to #{anchor}")
        _anchor_cache[url] = result
        return result

    return _anchor_cache.setdefault(url, (True, ""))


def _rule_expr(spec: dict) -> str:
    try:
        return spec["expressions"]["A"]["model"]["expr"]
    except (KeyError, TypeError):
        return ""


def _agg_by_label_sets(expr: str):
    return [
        {x.strip() for x in m.group(1).split(",") if x.strip()}
        for m in AGG_BY_RE.finditer(expr)
    ]


def _check_instance_preserved(name: str, expr: str, errors: list):
    for by_labels in _agg_by_label_sets(expr):
        if "opnsense_instance" not in by_labels:
            errors.append(
                f"{name}: query aggregates by ({', '.join(sorted(by_labels))}) "
                "without opnsense_instance; this would merge independently "
                "monitored firewalls into one alert/recording series"
            )


def _check_label_tokens_resolve(name: str, expr: str, summary: str, description: str, errors: list):
    label_sets = _agg_by_label_sets(expr)
    if not label_sets:
        return  # no aggregation: every base-metric label survives, nothing to check
    survivors = set().union(*label_sets)
    tokens = set(LABEL_TOKEN_RE.findall(summary)) | set(LABEL_TOKEN_RE.findall(description))
    dangling = tokens - survivors
    if dangling:
        errors.append(
            f"{name}: summary/description references {{{{ $labels.X }}}} for "
            f"{sorted(dangling)}, which the query's aggregation does not preserve "
            f"(by clause(s) keep only {sorted(survivors)}); Grafana renders a "
            "dropped label as an empty string, not an error"
        )


def validate_document(name: str, doc: dict) -> list:
    """Validate one already-parsed manifest document. Returns a list of error
    strings (empty if the document is valid). Does not know about sibling
    files - the folder-manifest-presence check lives in validate_dir."""
    errors = []
    api = doc.get("apiVersion")
    kind = doc.get("kind")

    if name == "_folder.json":
        if api != FOLDER_API or kind != "Folder":
            errors.append(f"{name}: expected {FOLDER_API}/Folder, got {api}/{kind}")
        return errors

    if api != RULE_API:
        errors.append(f"{name}: expected apiVersion {RULE_API}, got {api}")
    if kind not in RULE_KINDS:
        errors.append(f"{name}: expected kind in {sorted(RULE_KINDS)}, got {kind}")
        return errors  # nothing else below is safe to assume the shape of
    if not doc.get("metadata", {}).get("name"):
        errors.append(f"{name}: missing metadata.name")

    spec = doc.get("spec", {}) or {}
    labels = spec.get("labels", {}) or {}
    expr = _rule_expr(spec)

    if kind == "AlertRule":
        nds = spec.get("noDataState")
        if nds not in NODATA_STATES:
            errors.append(
                f"{name}: invalid spec.noDataState {nds!r}, "
                f"must be one of {sorted(NODATA_STATES)}"
            )

        ees = spec.get("execErrState")
        if ees not in EXEC_ERR_STATES:
            errors.append(
                f"{name}: invalid spec.execErrState {ees!r}, "
                f"must be one of {sorted(EXEC_ERR_STATES)}"
            )

        severity = labels.get("severity")
        if severity not in SEVERITIES:
            errors.append(
                f"{name}: invalid spec.labels.severity {severity!r}, "
                f"must be one of {sorted(SEVERITIES)}"
            )

        for_value = spec.get("for")
        if not isinstance(for_value, str) or not FOR_DURATION_RE.match(for_value):
            errors.append(
                f"{name}: invalid spec.for (pending duration) {for_value!r}, "
                "expected a Go/Grafana duration string like '0s' or '5m0s'"
            )

        # IRM routing contract (`--stack`): build_rules.py only ever emits
        # domain="infra", and only ever adds page="true" alongside a critical
        # severity. Anything else is a mis-wired notification policy waiting
        # to either page on a warning or never page a critical.
        page = labels.get("page")
        domain = labels.get("domain")
        if domain is not None and domain != "infra":
            errors.append(
                f"{name}: labels.domain={domain!r}, expected 'infra' "
                "(the only domain build_rules.py's --stack emits)"
            )
        if page is not None:
            if domain is None:
                errors.append(
                    f"{name}: labels.page is set but labels.domain is missing "
                    "(the IRM routing contract requires both together)"
                )
            if page != "true":
                errors.append(
                    f"{name}: labels.page={page!r}, the only value the IRM "
                    "contract emits is the string 'true'"
                )
            if severity != "critical":
                errors.append(
                    f"{name}: labels.page='true' on severity={severity!r}; "
                    "build_rules.py only pages critical alerts"
                )

        annotations = spec.get("annotations", {}) or {}
        runbook_url = annotations.get("runbook_url")
        if runbook_url != RUNBOOK_URL:
            errors.append(
                f"{name}: annotations.runbook_url {runbook_url!r} != the shared "
                f"registry value {RUNBOOK_URL!r} (grafana/uids.py)"
            )
        elif runbook_url:
            ok, why = _runbook_anchor_resolves(runbook_url)
            if not ok:
                errors.append(f"{name}: runbook_url {runbook_url!r} does not resolve: {why}")

        summary = annotations.get("summary", "")
        description = annotations.get("description", "")
        _check_label_tokens_resolve(name, expr, summary, description, errors)

    elif kind == "RecordingRule":
        # build_rules.py never routes a recording rule to a page, and never
        # emits a domain other than "infra".
        if labels.get("page") is not None:
            errors.append(
                f"{name}: RecordingRule carries a page label; build_rules.py "
                "never routes a recording rule to a page"
            )
        domain = labels.get("domain")
        if domain is not None and domain != "infra":
            errors.append(f"{name}: labels.domain={domain!r}, expected 'infra'")

    _check_instance_preserved(name, expr, errors)

    return errors


def validate_dir(manifest_dir: str) -> list:
    """Validate every *.json manifest in manifest_dir, including the
    directory-level folder-presence invariant. Returns a list of error
    strings (empty if everything is valid)."""
    paths = sorted(glob.glob(os.path.join(manifest_dir, "*.json")))
    if not paths:
        return [f"no manifests found in {manifest_dir}"]

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
        if name == "_folder.json":
            saw_folder = True
        errors.extend(validate_document(name, doc))

    if not saw_folder:
        errors.append("_folder.json is missing (folder manifest must be present)")

    return errors


def main() -> int:
    errors = validate_dir(MANIFEST_DIR)

    if errors:
        print("Grafana-managed manifest validation failed:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    count = len(glob.glob(os.path.join(MANIFEST_DIR, "*.json")))
    print(f"validated {count} grafana-managed manifests: OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
