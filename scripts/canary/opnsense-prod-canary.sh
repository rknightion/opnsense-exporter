#!/usr/bin/env bash
# Production-release-channel schema canary (#490).
#
# WHY THIS RUNS HERE AND NOT IN GITHUB ACTIONS: full canary coverage needs
# page-all on the firewall — five endpoints match no other privilege — plus
# page-system-usermanager, the CA/cert managers and the IPsec keypair pages.
# That is an admin credential, and it must not live in a public repo's secret
# store. camden already polls this box with these exact credentials, so running
# here adds no access that did not already exist and widens no tailnet ACL.
#
# The report carries endpoint names, key paths, JSON type names and HTTP
# statuses ONLY — never response values. It lands in a public issue.
set -euo pipefail

REPO_DIR=/opt/opnsense-canary/repo
ENV_FILE=/opt/opnsense-exporter/.env
TOKEN_FILE=/root/.opnsense-canary-gh-token
BOX=10.0.0.254
REPO=rknightion/opnsense-exporter
TITLE="OPNsense live-box canary drift - prod"
OUT=/var/lib/opnsense-canary/report.md

# report_has_findings decides open-vs-closed from a report file and the apidrift
# exit code. Factored out as a function ONLY so it can be tested — see
# scripts/canary/prod_canary_test.py, which drives it through the --decide-only
# seam below. Everything it needs is in its arguments, so the test never needs a
# box, credentials or a GitHub token.
#
# 🟡 marks a warning section; ℹ️ and ⚪ are informational and are not worth
# waking anyone for. Parsing the count sentence instead would break the first
# time its wording changed.
#
# 🔴 IS ALSO A FINDING, and its absence from the original check was a real hole
# (#612). apidrift exits 1 for breaking type drift and this script deliberately
# tolerates exit 1, so a report whose ONLY finding was a 🔴 fell through the 🟡
# grep and was announced as "clean" — breaking drift on prod, filing nothing.
# That is the class of miss that let #615 (smartInfo's wear fields served as
# objects, costing every per-device SMART metric) sit unreported on the one
# target that can see it. Both the section marker and the exit code are checked,
# because either can be true without the other: a warnings-only run exits 0 with
# a 🟡, and a breaking-only run exits 1 with no 🟡.
report_has_findings() {
  local report=$1 exit_code=$2
  if [ "$exit_code" -ne 0 ]; then
    return 0
  fi
  grep -q '### 🟡' "$report" || grep -q '### 🔴' "$report"
}

# Test seam, and it must come BEFORE anything that reads a credential, touches
# the network or writes to $OUT: decide from an existing report and print the
# verdict, nothing else. Production invocation passes no arguments — the systemd
# unit's ExecStart is the bare script.
if [ "${1:-}" = "--decide-only" ]; then
  if report_has_findings "$2" "${3:-0}"; then echo findings; else echo clean; fi
  exit 0
fi

mkdir -p "$(dirname "$OUT")"

# Reuse the exporter's own credentials. Read out by name rather than sourcing
# the file, so an unrelated variable in .env can never leak into this process.
KEY=$(grep -m1 '^OPNSENSE_EXPORTER_OPS_API_KEY=' "$ENV_FILE" | cut -d= -f2-)
SECRET=$(grep -m1 '^OPNSENSE_EXPORTER_OPS_API_SECRET=' "$ENV_FILE" | cut -d= -f2-)
export OPNSENSE_EXPORTER_OPS_API_KEY="$KEY" OPNSENSE_EXPORTER_OPS_API_SECRET="$SECRET"

git -C "$REPO_DIR" fetch --quiet origin main
git -C "$REPO_DIR" reset --quiet --hard origin/main

# Take the generation label off the box itself. Hardcoding it would let the
# report claim a version the box stopped running months ago — the precise
# failure this stamp exists to prevent.
VER=$(curl -sk --max-time 30 -u "$KEY:$SECRET" "https://$BOX/api/core/firmware/status" \
      | python3 -c 'import sys,json; print(json.load(sys.stdin).get("product",{}).get("product_version","unknown"))' \
      2>/dev/null || echo unknown)

cd "$REPO_DIR"
code=0
# Exit 0 = clean or warnings-only, 1 = breaking drift, anything else = probe error.
go run ./cmd/apidrift --base-url "https://$BOX" --insecure \
  --generation "release ${VER}" --profile prod --out "$OUT" >/dev/null || code=$?
if [ "$code" -ne 0 ] && [ "$code" -ne 1 ]; then
  echo "apidrift failed with code $code" >&2
  exit "$code"
fi

# A missing or empty report means the probe never ran, and it must NOT be
# reported as clean. The first hand-run of this job did exactly that: go run
# died for want of a build cache, the report was never written, and the
# find-findings grep below returned non-zero on the nonexistent file, which
# read as "no findings". A canary that cannot probe has to be loud.
if [ ! -s "$OUT" ]; then
  echo "apidrift exited ${code} but wrote no report to ${OUT} — probe did not run" >&2
  exit 3
fi

export GH_TOKEN
GH_TOKEN=$(cat "$TOKEN_FILE")

# Same label + exact-title dedupe the CI canary uses, so both generations
# collect on ONE issue and a key present on only one box shows up by contrast.
# This lookup is EXACT-TITLE and is the only thing in this script that ever
# names an issue number, so neither the close path nor the create/comment path
# below it can reach a sibling target's issue — mirroring live-canary.yml's own
# guard, whose comment says a sibling target's drift "is none of this job's
# business". Hoisted above both paths so there is exactly one such lookup.
existing=$(gh issue list --repo "$REPO" --label api-drift --state open \
  --json number,title --jq ".[] | select(.title == \"$TITLE\") | .number" | head -n1)

if ! report_has_findings "$OUT" "$code"; then
  # CLOSE-ON-CLEAN (#612). This half did not exist: the script created and
  # commented but never closed, so a prod drift that was later fixed left its
  # issue open forever. Worse, #531's triage reasoned by analogy from the CI job
  # and concluded "it closes itself on the next clean run" — wrong in both
  # halves. The CI workflow's own close step (live-canary.yml:248-266) only ever
  # touches its own matrix target's title, so the prod issue was outside the
  # reach of anything that closes.
  echo "release-channel canary clean (${VER})"
  if [ -n "$existing" ]; then
    gh issue comment "$existing" --repo "$REPO" \
      --body "Live-box canary clean on the latest prod run (release ${VER}). Closing."
    gh issue close "$existing" --repo "$REPO"
  fi
  exit 0
fi

if [ -z "$existing" ]; then
  gh issue create --repo "$REPO" --title "$TITLE" --label api-drift --body-file "$OUT"
else
  gh issue comment "$existing" --repo "$REPO" --body-file "$OUT"
fi
