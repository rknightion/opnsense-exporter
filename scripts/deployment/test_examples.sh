#!/usr/bin/env bash
# Validate the exact Compose example operators copy from the deployment guide.
set -euo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
compose_doc="$root/docs/deployment/docker.md"

for command in docker python3; do
  command -v "$command" >/dev/null || {
    printf 'required command not found: %s\n' "$command" >&2
    exit 2
  }
done

work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

python3 - "$compose_doc" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text()
chmod = "chmod 400 ./secrets/api-key ./secrets/api-secret"
chown = "sudo chown 65532:65532 ./secrets/api-key ./secrets/api-secret"
if source.count(chmod) != 1:
    raise SystemExit("file-secret instructions must keep credentials owner-readable only")
if source.count(chown) != 1:
    raise SystemExit("file-secret instructions must make UID 65532 the owner")
if source.index(chmod) > source.index(chown):
    raise SystemExit("file-secret instructions must set mode before ownership")
PY

python3 - "$compose_doc" "$work/compose.yaml" <<'PY'
from pathlib import Path
import sys

source = Path(sys.argv[1]).read_text()
begin = "<!-- executable:begin:compose-file-secrets -->"
end = "<!-- executable:end:compose-file-secrets -->"
if source.count(begin) != 1 or source.count(end) != 1:
    raise SystemExit("file-secret Compose example must have one executable marker pair")
region = source.split(begin, 1)[1].split(end, 1)[0].strip()
lines = region.splitlines()
if len(lines) < 3 or not lines[0].startswith("```yaml") or lines[-1] != "```":
    raise SystemExit("executable Compose region must contain exactly one YAML fence")
Path(sys.argv[2]).write_text("\n".join(lines[1:-1]) + "\n")
PY

mkdir -p "$work/secrets"
printf '%s' 'contract-api-key' >"$work/secrets/api-key"
printf '%s' 'contract-api-secret' >"$work/secrets/api-secret"
docker compose -f "$work/compose.yaml" config --quiet

printf 'deployment examples passed executable validation\n'
