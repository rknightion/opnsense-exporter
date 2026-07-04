#!/usr/bin/env python3
"""Emit OPNsense API endpoints as JSON by reusing the opnsense/docs parser.

Usage:
    extract.py --docs <opnsense/docs checkout> --source <tree to scan> [--min N] [--strict]

Output (stdout): JSON array of
    {"module", "controller", "command", "methods": [...], "path": "api/<m>/<c>/<command>"}

Fault isolation: each controller is parsed individually. A controller the vendored
phply grammar cannot parse (e.g. a third-party plugin using PHP syntax outside the
grammar's support, such as a class-constant array dereference) is skipped with a
warning to stderr naming the file, and extraction continues with the rest — so one bad
file degrades to "N of M parsed" instead of crashing the whole run and emitting no JSON.
The --min endpoint-count floor still guards against catastrophic breakage. Pass --strict
to restore fail-fast behaviour (abort on the first unparseable controller).
"""
import argparse
import contextlib
import json
import os
import sys


def _iter_controller_files(source, exclude):
    """Yield the API controller files under source, mirroring the upstream
    lib.utils.collect_api_modules walk/filters (controller.php under a
    mvc/app/controllers tree, in an .../Api dir, excluding EXCLUDE_CONTROLLERS)."""
    for root, _dirs, files in os.walk(source):
        for fname in sorted(files):
            filename = os.path.join(root, fname)
            if any(filename.endswith(x) for x in exclude):
                continue
            if (filename.lower().endswith("controller.php")
                    and filename.find("mvc/app/controllers") > -1
                    and root.endswith("Api")):
                yield filename


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--docs", required=True, help="path to an opnsense/docs checkout")
    ap.add_argument("--source", required=True, help="path to a tree containing *Controller.php")
    ap.add_argument("--min", type=int, default=0, help="fail if fewer than N endpoints are found")
    ap.add_argument("--strict", action="store_true",
                    help="abort on the first unparseable controller instead of skip-and-warn")
    args = ap.parse_args()

    sys.path.insert(0, args.docs)
    try:
        from lib import ApiParser  # noqa: E402  (path set above)
        from lib.utils import EXCLUDE_CONTROLLERS  # noqa: E402
    except Exception as exc:  # pragma: no cover - environment guard
        print(f"failed to import opnsense docs parser from {args.docs}: {exc}", file=sys.stderr)
        return 2

    controllers = []
    bad = []
    for filename in _iter_controller_files(args.source, EXCLUDE_CONTROLLERS):
        try:
            # The upstream parser prints diagnostics ("error in filename ...") to stdout
            # before raising; redirect that to stderr so our JSON output stays clean.
            with contextlib.redirect_stdout(sys.stderr):
                controller = ApiParser(filename, False).parse_api_php()
            controllers.append(controller)
        except Exception as exc:  # noqa: BLE001 - any parser failure must not abort the run
            if args.strict:
                print(f"failed to parse {filename}: {exc}", file=sys.stderr)
                return 1
            print(f"warning: skipping unparseable controller {filename}: {exc}", file=sys.stderr)
            bad.append(filename)

    if bad:
        print(f"parsed {len(controllers)} controllers, skipped {len(bad)} unparseable",
              file=sys.stderr)

    out = []
    for controller in controllers:
        # Abstract controllers (e.g. filter_base, Kea's Leases base) are non-instantiable
        # PHP base classes, never registered as routable MVC controllers — paths built
        # from them 404 live. Skip them so the manifest holds only real endpoints (#146).
        if getattr(controller, "is_abstract", False):
            continue
        for action in controller.actions:
            out.append({
                "module": controller.module,
                "controller": controller.controller,
                "command": action.command,
                "methods": list(action.methods),
                "path": f"api/{controller.module}/{controller.controller}/{action.command}",
            })

    if len(out) < args.min:
        print(f"only {len(out)} endpoints found, expected >= {args.min}; parser likely broke",
              file=sys.stderr)
        return 3

    json.dump(out, sys.stdout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
