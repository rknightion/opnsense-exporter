#!/usr/bin/env bash
# Bump the Go module path to a new major version.
#
# WHY THIS EXISTS. Go's semantic-import-versioning requires a module released at
# v2+ to have a module path ending /vN. release-please does NOT do this for you:
# it bumps the version in the manifest and the changelog and stops there. So a
# major release cuts a tag the module path does not match.
#
# That is not hypothetical — tailscale2otel shipped it twice (its #174 at v2.0.0
# and #244 at v3): the image, Helm chart and notices published fine, the archives,
# checksums, signatures and SBOMs did not, and re-running could not fix it because
# the TAG was what carried the wrong path. This repo ran v1-v3 on an unsuffixed
# path and landed /v4 with the opnsense2otel rename.
#
# TestModulePathMatchesReleaseVersion (./modulepath_test.go) fails as soon as the
# release-please PR bumps .release-please-manifest.json past the module's major,
# which is what routes anyone here. Run this, commit, and merge the release PR.
#
# Usage:
#   scripts/bump-module-major.sh 5      # rewrite the module path to /v5
#   scripts/bump-module-major.sh        # infer the target from the manifest
set -euo pipefail

cd "$(dirname "$0")/.."

BASE="github.com/rknightion/opnsense2otel"

current() {
  # The root module path's major, e.g. 4 for .../opnsense2otel/v4. A v0/v1 module
  # carries no suffix, so an absent match means major 1.
  local path
  path=$(awk '/^module /{print $2; exit}' go.mod)
  case "$path" in
  "$BASE"/v*) echo "${path##*/v}" ;;
  *) echo 1 ;;
  esac
}

# The manifest holds the version release-please is about to cut. On a release-please
# branch it is ALREADY the new major, which is what makes the guard test fire there.
manifest_major() {
  sed -n 's/.*": *"\([0-9]*\)\..*/\1/p' .release-please-manifest.json | head -1
}

FROM=$(current)
TO=${1:-$(manifest_major)}

if [ -z "$TO" ]; then
  echo "could not determine the target major; pass it explicitly (e.g. $0 5)" >&2
  exit 1
fi
if ! [[ $TO =~ ^[0-9]+$ ]]; then
  echo "target major must be a number, got: $TO" >&2
  exit 1
fi
if [ "$TO" = "$FROM" ]; then
  echo "module path is already at major v$FROM — nothing to do"
  exit 0
fi
if [ "$TO" -lt "$FROM" ]; then
  echo "refusing to move the module path BACKWARDS (v$FROM -> v$TO)" >&2
  exit 1
fi
if [ "$TO" -lt 2 ]; then
  echo "refusing to target v$TO: only v2+ carries a path suffix" >&2
  exit 1
fi

OLD="$BASE/v$FROM"
NEW="$BASE/v$TO"
echo "==> rewriting module path: $OLD -> $NEW"

# CHANGELOG.md is deliberately excluded: it is the historical record of past
# releases, and those releases really were published under the old path. Rewriting
# it would make the history lie about what shipped.
# Deliberately no `mapfile`/`readarray` here: macOS still ships bash 3.2, where they
# do not exist, and this has to run on a laptop as readily as in CI.
FILELIST=$(mktemp)
trap 'rm -f "$FILELIST"' EXIT
git ls-files -z |
  xargs -0 grep -l -F "$OLD" 2>/dev/null |
  grep -v '^CHANGELOG.md$' >"$FILELIST" || true

COUNT=$(wc -l <"$FILELIST" | tr -d ' ')
if [ "$COUNT" -eq 0 ]; then
  echo "no files reference $OLD" >&2
  exit 1
fi

head -5 "$FILELIST" | sed 's/^/    /'
echo "    ... $COUNT file(s) total"

while IFS= read -r f; do
  [ -n "$f" ] || continue
  # LC_ALL=C + a temp file keeps this identical on BSD (macOS) and GNU sed, whose
  # -i flags are incompatible.
  LC_ALL=C sed "s|${OLD}|${NEW}|g" "$f" >"$f.tmp"
  mv "$f.tmp" "$f"
done <"$FILELIST"

echo "==> go mod tidy (all modules)"
go mod tidy
for m in tools/*/; do
  [ -f "$m/go.mod" ] && go mod tidy -C "$m"
done

echo "==> go mod vendor (the vendor directory is committed)"
go mod vendor

echo "==> done. Verify with: go build ./... && go test ./..."
