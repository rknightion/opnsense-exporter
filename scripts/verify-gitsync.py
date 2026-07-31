#!/usr/bin/env python3
"""Fail the sync when Grafana did not actually accept the dashboards we pushed.

WHY THIS EXISTS (#616). `grafana-sync.yml` pushed dashboards by committing them into
the GitSync repository, and treated a successful `git push` as a successful deploy.
It is not. GitSync pulls the commit asynchronously and validates each file against the
Dashboard schema, and a file that fails validation is simply skipped — the repository
lands in `CompletedWithWarnings` and everything upstream reports success.

`dashboard-health.json` sat rejected for two days that way (its fieldConfig.overrides
serialised as a list of lists), 12 panels behind the repository, while `make dashboard`,
`make grafana-check` and CI were all green — none of them validate against the schema
Grafana enforces. Its companion dashboard, in the same commit, applied fine, so there
was not even an obvious symptom.

This closes the loop: wait for GitSync to reach the commit we pushed, then compare each
live dashboard against what we committed.

**The live comparison is the verdict, and nothing else is.** Sync warnings are collected
and printed alongside a failure because they name the offending field, but they are not
themselves a failure condition, for two reasons that both bit during this work:

  - The repository status is EPHEMERAL. A failed pull still advances lastRef, so the
    next scheduled pull sees "same commit as last time", does nothing, succeeds, and
    overwrites the status with state=success and an empty message list — reporting a
    clean sync over a resource it never wrote.
  - The job history is PERSISTENT, so a warning there may be long fixed. Failing on it
    would wedge this gate on an error that no longer applies.

Deliberately scoped to our own files. The shared GitSync repository carries other
projects' resources, and two of them warn permanently (`renovate.json` is not a
resource at all; `infrastructure/n8n-observability.json` is an unmanaged takeover
conflict). Failing on those would make this gate meaningless within a day.

Usage:
  scripts/verify-gitsync.py --ref <pushed-commit-sha> \\
      --file networking/opnsense-exporter.json=grafana/dashboard.json \\
      --file networking/opnsense-exporter-health.json=grafana/dashboard-health.json

Env: GRAFANA_STACK_ID (namespace), plus whatever `gcx` needs to authenticate.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time

GITSYNC_REPO_URL = "https://github.com/rknightion/gc-gitsync-m7kni"


def gcx(*argv: str) -> dict:
    """Run a gcx command and return the parsed JSON body.

    Three output shapes have to be handled, and getting this wrong is silent:

    1. Single-line `{"class":"hint",...}` banners precede the payload in agent mode.
       They are not the body.
    2. **A response over roughly 1 MB is SPILLED TO A TEMP FILE.** gcx then prints a
       `{"type":"gcx.spill_reference","spilled_to":"/tmp/gcx-results-*.json",...}` stub
       INSTEAD of the data. A dashboard of this size (1.4 MB) always spills, so reading
       the stub as the body yields a document with no `spec` — i.e. a perfectly healthy
       dashboard reports as "0 panels live". That is a false failure, and worse, in the
       inverse case it would be a false pass.
    3. The payload may be pretty-printed across many lines, so it cannot be parsed
       line-by-line.

    `-o json` is NOT optional. gcx only emits JSON by default when it auto-detects an
    agent (CLAUDECODE, CURSOR_AGENT and friends); on a bare CI runner it prints a HUMAN
    TABLE, which parses as nothing. Forcing it also keeps the response inline and
    sidesteps the spill in (2) entirely — the spill handling stays as a safety net.
    """
    proc = subprocess.run(["gcx", *argv, "-o", "json"], capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError(
            f"gcx {' '.join(argv)} failed ({proc.returncode}): {proc.stderr.strip()}")

    payload_lines = []
    for line in proc.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("{"):
            try:
                control = json.loads(stripped)
            except json.JSONDecodeError:
                control = None
            if isinstance(control, dict):
                if control.get("class") == "hint":
                    continue
                if control.get("type") == "gcx.spill_reference":
                    with open(control["spilled_to"], encoding="utf-8") as fh:
                        return json.load(fh)
        payload_lines.append(line)

    body = "\n".join(payload_lines).strip()
    if not body:
        raise RuntimeError(
            f"gcx {' '.join(argv)} returned no JSON body:\n{proc.stdout}")
    return json.loads(body)


def find_repository(namespace: str) -> dict:
    """Locate the GitSync repository resource by its GitHub URL, not by name.

    The name is a generated id (repository-e660907); matching on it would break the day
    the repository is recreated, and fail in a way that looks like a sync failure.
    """
    listing = gcx(
        "api",
        f"/apis/provisioning.grafana.app/v0alpha1/namespaces/{namespace}/repositories")
    for item in listing.get("items", []):
        github = (item.get("spec") or {}).get("github") or {}
        if (github.get("url") or "").rstrip("/") == GITSYNC_REPO_URL:
            return item
    raise RuntimeError(
        f"no GitSync repository in namespace {namespace} points at {GITSYNC_REPO_URL}")


def spec_fingerprint(spec: dict) -> dict:
    """The parts of a dashboard whose divergence means the deploy did not land.

    Not a full deep-equality check: Grafana normalises and defaults fields on write, so
    an exact comparison would fail constantly for reasons that are not drift. Title and
    the element set are what actually went stale in #616 (88 elements live vs 100
    committed, and a title still reading the pre-rename name).
    """
    elements = spec.get("elements") or {}
    return {
        "title": spec.get("title"),
        "elements": sorted(elements) if isinstance(elements, dict) else len(elements),
    }


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--ref", required=True,
                    help="commit SHA pushed to the GitSync repo; '' means nothing was pushed")
    ap.add_argument("--file", action="append", default=[], metavar="REPO_PATH=LOCAL_PATH",
                    help="a file we pushed, and the local artifact it came from")
    ap.add_argument("--timeout", type=int, default=600,
                    help="seconds to wait for GitSync to reach --ref (sync interval is 300s)")
    ap.add_argument("--interval", type=int, default=20)
    args = ap.parse_args()

    if not args.ref:
        print("verify-gitsync: nothing was pushed — nothing to verify")
        return 0

    namespace = f"stacks-{os.environ['GRAFANA_STACK_ID']}"
    pairs = []
    for spec in args.file:
        repo_path, _, local_path = spec.partition("=")
        pairs.append((repo_path, local_path))

    # 1. Wait for GitSync to have processed our commit.
    print(f"verify-gitsync: waiting for GitSync to reach {args.ref[:7]} "
          f"(timeout {args.timeout}s)")
    waited = 0
    repo = None
    while True:
        repo = find_repository(namespace)
        sync = (repo.get("status") or {}).get("sync") or {}
        last_ref = sync.get("lastRef") or ""
        # Either may be abbreviated, so accept a prefix match in either direction —
        # but only once lastRef is non-empty, or an empty string prefixes everything
        # and an un-synced repository would read as "already there".
        matched = bool(last_ref) and (
            last_ref.startswith(args.ref) or args.ref.startswith(last_ref))
        if matched:
            print(f"verify-gitsync: GitSync is at {last_ref[:7]} "
                  f"(state={sync.get('state')}) after {waited}s")
            break
        if waited >= args.timeout:
            print(f"::error::GitSync never reached {args.ref[:7]}; it is still at "
                  f"{last_ref[:7] or '(none)'} after {waited}s. The dashboards were "
                  f"committed but Grafana has not pulled them.")
            return 1
        time.sleep(args.interval)
        waited += args.interval

    failures = []
    our_paths = {repo_path for repo_path, _ in pairs}

    # 2. Any warning naming one of OUR files is a rejected write.
    #
    # Read the JOB history as well as the repository status, because the repository
    # status is EPHEMERAL and actively misleading. A failed pull still advances
    # lastRef, so the next scheduled pull finds "same commit as last time", does
    # nothing, succeeds — and overwrites the status with state=success and an empty
    # message list. The repository then reports a clean sync over a resource it never
    # wrote. Observed within ~10s of the failing pull, which is inside this job's own
    # polling window. The historic job keeps the real message.
    sync = (repo.get("status") or {}).get("sync") or {}
    messages = list(sync.get("message") or [])
    try:
        history = gcx(
            "api",
            f"/apis/provisioning.grafana.app/v0alpha1/namespaces/{namespace}/historicjobs")
        for job in history.get("items", []):
            status = job.get("status") or {}
            if status.get("state") not in ("warning", "error"):
                continue
            for summary in status.get("summary") or []:
                messages.extend(summary.get("warnings") or [])
                messages.extend(summary.get("errors") or [])
    except Exception as exc:  # noqa: BLE001 - never let the extra signal break the gate
        print(f"verify-gitsync: could not read job history ({exc}); "
              f"relying on repository status and the content comparison below")
    # These are DIAGNOSTICS, not the verdict. A warning may be stale — from a pull that
    # has since been fixed — and failing on the job history alone would wedge this gate
    # permanently on an error that no longer applies. The live-content comparison below
    # is the sole authority; matching warnings are printed with a failure to explain it,
    # because that message is what actually names the offending field.
    diagnostics = [m for m in messages if any(p in m for p in our_paths)]
    for message in messages:
        if message not in diagnostics:
            print(f"verify-gitsync: unrelated warning (ignored): {message[:160]}")

    # 3. The live dashboard must match what we committed.
    for repo_path, local_path in pairs:
        with open(local_path, encoding="utf-8") as fh:
            committed = json.load(fh)
        uid = committed["metadata"]["name"]
        # `gcx dashboards get` negotiates the dashboard apiVersion (these are v2);
        # a hardcoded /apis/dashboard.grafana.app/<ver>/ path returns an empty spec
        # for a v2 dashboard, which would read as "0 panels live" on a HEALTHY one.
        live = gcx("dashboards", "get", uid)
        want = spec_fingerprint(committed.get("spec") or {})
        got = spec_fingerprint(live.get("spec") or {})
        if want != got:
            want_n = len(want["elements"]) if isinstance(want["elements"], list) else want["elements"]
            got_n = len(got["elements"]) if isinstance(got["elements"], list) else got["elements"]
            detail = [f"    title  committed={want['title']!r} live={got['title']!r}",
                      f"    panels committed={want_n} live={got_n}"]
            if isinstance(want["elements"], list) and isinstance(got["elements"], list):
                missing = sorted(set(want["elements"]) - set(got["elements"]))
                extra = sorted(set(got["elements"]) - set(want["elements"]))
                if missing:
                    detail.append(f"    missing live: {', '.join(missing[:10])}")
                if extra:
                    detail.append(f"    extra live:   {', '.join(extra[:10])}")
            failures.append(
                f"live dashboard {uid} does not match {repo_path}:\n" + "\n".join(detail))
        else:
            print(f"verify-gitsync: {uid} matches ({repo_path})")

    if failures:
        for failure in failures:
            print(f"::error::{failure}")
        for diagnostic in diagnostics:
            print(f"::error::GitSync reported: {diagnostic}")
        print("::error::GitSync accepted the commit but did not apply our dashboards. "
              "A green `git push` is not a deploy — see scripts/verify-gitsync.py.")
        return 1

    print("verify-gitsync: all dashboards verified live")
    return 0


if __name__ == "__main__":
    sys.exit(main())
