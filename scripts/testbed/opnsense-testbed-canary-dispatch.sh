#!/usr/bin/env bash
# Fire live-canary.yml from `oli` once the testbed is warm, and hold the lab up
# until the run finishes.
#
# WHY THIS EXISTS. #625 put the testbed on a 06:00-08:30 UTC window sized against
# live-canary.yml's `cron: '47 6 * * *'`. GitHub does not honour that time: every
# scheduled run between 2026-08-02 and 2026-08-05 started between 08:55 and 10:26
# UTC, a 2h08-3h39 delay, so the runner dialled a box that had already been shut
# down and the canary failed four days running with `pre-flight probe failed - box
# unreachable`. GitHub documents scheduled workflows as best-effort and gives no
# upper bound on the delay, so no cron time and no window width fixes this: any
# window that reliably covers the delay is most of the day, which is the cost #625
# exists to avoid.
#
# Inverting the trigger removes the scheduler from the path entirely. oli already
# knows the exact moment the lab is ready - opnsense-testbed-power.sh up returns
# only after both firewalls serve :443 - so it is the right thing to start the run.
#
# WHY A DISPATCH AND NOT A LOCAL PROBE. camden runs the `prod` target locally
# (scripts/canary/), which needs no dispatch at all. That is deliberately NOT the
# shape here: the nightly/release-vm targets also run the end-to-end exporter smoke
# and hold the tailnet OAuth credentials in the `tailnet` GitHub environment. Moving
# that onto oli would move those credentials onto oli. Dispatching keeps the probe,
# the secrets and the report exactly where they are and changes only who says "go".
set -euo pipefail

REPO=rknightion/opnsense2otel
WORKFLOW=live-canary.yml
REF=main
TOKEN_FILE=/root/.opnsense-canary-dispatch-token
POWER=/usr/local/bin/opnsense-testbed-power.sh

# The run probes 176 endpoints on two boxes and then runs a full exporter smoke
# against each; the workflow itself is capped at timeout-minutes: 30. Waiting a
# little past that means a hung run releases the hold on its own rather than
# pinning the lab up until the 8h hold lapses.
POLL_INTERVAL=30
WAIT_TIMEOUT=2400               # 40 min
DISPATCH_APPEAR_TIMEOUT=180     # the run does not exist the instant we POST

log() { printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }

[ -r "$TOKEN_FILE" ] || die "no dispatch token at $TOKEN_FILE"
TOKEN=$(cat "$TOKEN_FILE")
[ -n "$TOKEN" ] || die "dispatch token at $TOKEN_FILE is empty"

api() {
  local method=$1 path=$2
  shift 2
  curl -sS -X "$method" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Accept: application/vnd.github+json" \
    -H "X-GitHub-Api-Version: 2022-11-28" \
    "https://api.github.com${path}" "$@"
}

# Hold the lab up for the whole run. Without this the 08:30 down timer can fire
# mid-probe and the canary reads a box that is being shut down underneath it —
# which reports as drift on whichever endpoints lost first, not as an outage.
#
# Only release a hold WE took. Rob's ad-hoc `testbed up 28800` sets an 8h hold so
# he can work on the boxes; releasing that on our way out would drop the lab from
# under him at the next 08:30, hours before he expects it.
took_hold=0
# shellcheck disable=SC2329  # invoked from the EXIT trap below
release_hold() { [ "$took_hold" = 1 ] && "$POWER" release >/dev/null 2>&1 || true; }
if "$POWER" status | grep -qi '^hold:[[:space:]]*none'; then
  "$POWER" hold 3600 >/dev/null || die "could not take a power hold"
  took_hold=1
else
  log "a hold is already live — leaving it alone"
fi
trap release_hold EXIT

# Only runs newer than this can be ours. Comparing against a timestamp taken
# BEFORE the POST is what stops us adopting the previous day's run and reporting
# its verdict as today's.
started_at=$(date -u '+%Y-%m-%dT%H:%M:%SZ')

log "dispatching $WORKFLOW on $REF"
code=$(api POST "/repos/${REPO}/actions/workflows/${WORKFLOW}/dispatches" \
  -o /tmp/canary-dispatch.out -w '%{http_code}' \
  -d "{\"ref\":\"${REF}\"}")
[ "$code" = "204" ] || die "dispatch returned HTTP $code: $(cat /tmp/canary-dispatch.out)"

# Find the run we just created. `event=workflow_dispatch` plus the timestamp
# floor is the whole identification: the dispatch API returns 204 with no body,
# so there is no run id to be had from it.
run_id=""
deadline=$(( $(date +%s) + DISPATCH_APPEAR_TIMEOUT ))
while [ -z "$run_id" ] && [ "$(date +%s)" -lt "$deadline" ]; do
  sleep 5
  run_id=$(api GET "/repos/${REPO}/actions/workflows/${WORKFLOW}/runs?event=workflow_dispatch&per_page=5" \
    | jq -r --arg since "$started_at" \
        '[.workflow_runs[] | select(.created_at >= $since)] | sort_by(.created_at) | last | .id // empty')
done
[ -n "$run_id" ] || die "dispatched run never appeared within ${DISPATCH_APPEAR_TIMEOUT}s"
log "run $run_id started: https://github.com/${REPO}/actions/runs/${run_id}"

deadline=$(( $(date +%s) + WAIT_TIMEOUT ))
while [ "$(date +%s)" -lt "$deadline" ]; do
  read -r status conclusion < <(
    api GET "/repos/${REPO}/actions/runs/${run_id}" | jq -r '"\(.status) \(.conclusion // "-")"'
  )
  if [ "$status" = "completed" ]; then
    log "run $run_id completed: $conclusion"
    # A drifting canary is a successful REPORT, so this exits non-zero only to
    # make `systemctl status` reflect the verdict. The issue machinery in the
    # workflow has already filed it either way.
    [ "$conclusion" = "success" ] || exit 1
    exit 0
  fi
  sleep "$POLL_INTERVAL"
done
die "run $run_id still $status after ${WAIT_TIMEOUT}s"
