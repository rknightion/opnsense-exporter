#!/usr/bin/env python3
"""Emit OPNsense API endpoints as JSON by reusing the opnsense/docs parser.

Usage:
    extract.py --docs <opnsense/docs checkout> --source <tree to scan> [--min N]

Output (stdout): JSON array of
    {"module", "controller", "command", "methods": [...], "path": "api/<m>/<c>/<command>"}
"""
import argparse
import json
import sys


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--docs", required=True, help="path to an opnsense/docs checkout")
    ap.add_argument("--source", required=True, help="path to a tree containing *Controller.php")
    ap.add_argument("--min", type=int, default=0, help="fail if fewer than N endpoints are found")
    args = ap.parse_args()

    sys.path.insert(0, args.docs)
    try:
        from lib.utils import collect_api_modules  # noqa: E402  (path set above)
    except Exception as exc:  # pragma: no cover - environment guard
        print(f"failed to import opnsense docs parser from {args.docs}: {exc}", file=sys.stderr)
        return 2

    modules = collect_api_modules(args.source)
    out = []
    for _module_name, controllers in modules.items():
        for controller in controllers:
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
