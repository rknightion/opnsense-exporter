#!/usr/bin/env bash
# Import the compatibility dashboard into pinned Grafana containers and read it back
# (#420). This is the acceptance test for the artifact: local JSON validity proves
# nothing about whether Grafana 11/12 will accept it — the #22 report was exactly a
# file that looked fine and 422'd on import.
#
# Used by `make compat-verify` and by .github/workflows/grafana-compat.yml. Needs
# docker. Takes the versions as arguments, defaulting to the supported pair.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DASHBOARD="$HERE/dashboard-compat.json"
VERSIONS=("${@:-}")
if [[ -z "${VERSIONS[0]:-}" ]]; then
  VERSIONS=(11.5.0 12.4.0)
fi

# Read the contract out of the artifact rather than restating it here, so the check
# cannot drift from what was generated.
EXPECTED_UID=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["uid"])' "$DASHBOARD")
EXPECTED_TITLE=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1]))["title"])' "$DASHBOARD")
EXPECTED_PANELS=$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["panels"]))' "$DASHBOARD")
EXPECTED_VARS=$(python3 -c 'import json,sys;print(len(json.load(open(sys.argv[1]))["templating"]["list"]))' "$DASHBOARD")

fail=0
for version in "${VERSIONS[@]}"; do
  name="opnsense-compat-check-$(echo "$version" | tr . -)"
  port=$(python3 -c 'import socket;s=socket.socket();s.bind(("127.0.0.1",0));print(s.getsockname()[1]);s.close()')
  echo "=== Grafana $version on port $port"
  docker rm -f "$name" >/dev/null 2>&1 || true
  docker run -d --name "$name" -p "$port:3000" \
    -e GF_AUTH_ANONYMOUS_ENABLED=false \
    -e GF_SECURITY_ADMIN_PASSWORD=admin \
    -e GF_LOG_LEVEL=error \
    "grafana/grafana:$version" >/dev/null

  # shellcheck disable=SC2064
  trap "docker rm -f $name >/dev/null 2>&1 || true" EXIT

  for _ in $(seq 1 60); do
    if curl -fsS "http://127.0.0.1:$port/api/health" >/dev/null 2>&1; then break; fi
    sleep 2
  done
  health=$(curl -fsS "http://127.0.0.1:$port/api/health")
  echo "  health: $health"

  body=$(python3 -c '
import json, sys
dash = json.load(open(sys.argv[1]))
print(json.dumps({"dashboard": dash, "overwrite": True, "folderUid": ""}))' "$DASHBOARD")

  code=$(curl -s -o /tmp/compat-import.json -w '%{http_code}' \
    -u admin:admin -H 'Content-Type: application/json' \
    -X POST "http://127.0.0.1:$port/api/dashboards/db" --data-binary "$body")
  echo "  POST /api/dashboards/db -> $code"
  if [[ "$code" != "200" ]]; then
    echo "  IMPORT FAILED:"; cat /tmp/compat-import.json; echo
    fail=1
    docker rm -f "$name" >/dev/null 2>&1 || true
    continue
  fi

  # Read back: an accepted POST is not proof the dashboard is intact. Grafana
  # migrates schemaVersion on save, and a panel it cannot understand can survive the
  # write and come back mangled.
  curl -fsS -u admin:admin \
    "http://127.0.0.1:$port/api/dashboards/uid/$EXPECTED_UID" -o /tmp/compat-readback.json
  python3 - "$EXPECTED_UID" "$EXPECTED_TITLE" "$EXPECTED_PANELS" "$EXPECTED_VARS" "$version" <<'PY'
import json, sys
uid, title, panels, variables, version = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), sys.argv[5]
got = json.load(open("/tmp/compat-readback.json"))["dashboard"]
problems = []
if got.get("uid") != uid:
    problems.append(f"uid {got.get('uid')!r} != {uid!r}")
if got.get("title") != title:
    problems.append(f"title {got.get('title')!r} != {title!r}")
if len(got.get("panels", [])) != panels:
    problems.append(f"{len(got.get('panels', []))} panels read back, expected {panels}")
if len(got.get("templating", {}).get("list", [])) != variables:
    problems.append(f"{len(got.get('templating', {}).get('list', []))} variables, expected {variables}")
unknown = sorted({p.get("type") for p in got.get("panels", [])
                  if not p.get("type") or p.get("type") == "unknown"})
if unknown:
    problems.append(f"unknown panel types after import: {unknown}")
empty = [p.get("title") for p in got.get("panels", [])
         if p.get("type") not in ("row", "text") and not p.get("targets")]
if empty:
    problems.append(f"panels that lost their targets: {empty[:5]}")
if problems:
    print(f"  READ-BACK MISMATCH on Grafana {version}:")
    for problem in problems:
        print(f"    - {problem}")
    sys.exit(1)
print(f"  read back OK on Grafana {version}: "
      f"schemaVersion {got.get('schemaVersion')}, {panels} panels, {variables} variables")
PY
  # shellcheck disable=SC2181
  if [[ $? -ne 0 ]]; then fail=1; fi
  docker rm -f "$name" >/dev/null 2>&1 || true
  trap - EXIT
done

if [[ $fail -ne 0 ]]; then
  echo "compat verification FAILED"
  exit 1
fi
echo "compat verification passed on: ${VERSIONS[*]}"
