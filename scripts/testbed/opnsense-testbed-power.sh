#!/usr/bin/env bash
# OPNsense testbed power scheduler for `oli` (#625).
#
# The six testbed guests are only needed for the daily live-canary run and
# for ad-hoc work, but they run 24/7 costing ~0.38 of a core and 24 GB of
# allocated RAM. This brings them up before the canary and takes them down
# after, so they are off ~90% of a quiet day.
#
# WHY THIS RUNS ON THE HOST AND NOT IN GITHUB ACTIONS: powering the lab from
# `live-canary.yml` would need a Proxmox API token and a `tag:ci -> oli:8006`
# ACL grant reachable from a PUBLIC repo, and a cancelled CI run would leave
# guests in an indeterminate power state. Neither is true of a host-side timer,
# and the lab gets a real warm-up instead of the ~10 minutes a CI-driven power
# cycle would give. Since the cron came off live-canary.yml the run is started BY
# this host (opnsense-testbed-canary-dispatch.sh) once `up` returns, so the warm-up
# is bounded by readiness rather than by a clock.
#
# ORDERING IS LOAD-BEARING. Every guest except the two firewalls depends on a
# firewall for DHCP, routing and DNS, so the firewalls start first and stop
# last. Start a client before its firewall and it comes up with no lease — the
# canary then reads an empty box and files it as drift.
set -euo pipefail

# ---------------------------------------------------------------------------
# Inventory. Phase 1 must be READY before phase 2 starts.
#
# THE ALLOWLIST IS A SAFETY BOUNDARY, NOT A CONVENIENCE. oli also runs 100
# (home assistant), 101 (the CI runners), 103 (unifi-os), 104 (winsrv) and 107
# (postgres). Powering any of those off is a real outage, so every qm/pct call
# below is gated on assert_allowed and the ids are hardcoded — never derived
# from `qm list` or an argument.
# ---------------------------------------------------------------------------
PHASE1_VMS=(102 106)            # firewalls: nightly, release
PHASE2_VMS=(110 111 112)        # FRR/PD peer, release client, nightly client
PHASE2_CTS=(105)                # traffgen LXC

# Readiness gate. oli reaches both boxes' webConfigurator from its 10.0.0.6 LAN
# address (the MGMT_SRC alias covers 10.0.0.0/24), verified 200 on both.
READY_URLS=(https://10.0.90.111/ https://10.0.90.119/)

HOLD_FILE=/var/lib/opnsense-testbed/hold
DEFAULT_HOLD_SECONDS=28800      # 8h — one working day, then it lapses by itself
READY_TIMEOUT=600               # 10 min; the canary dispatch waits on this unit
SHUTDOWN_TIMEOUT=180            # per guest, before falling back to a hard stop
ADDRESS_TIMEOUT=90              # per container interface, before remediating

# DHCP interfaces the traffgen container must hold before the lab counts as up.
# eth0 is its TESTLAN address (leased by VM 102, and the jump path to both
# firewalls); eth1 is VLAN 90. eth2 is CPORTAL, whose captive portal means a
# lease there is not required and not waited for.
CT_REQUIRED_IFACES=(eth0 eth1)

log() { printf '%s %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')" "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }

# ---------------------------------------------------------------------------
# Pure decision logic. Kept free of Proxmox, network and filesystem writes so
# scripts/testbed/testbed_power_test.py can drive it through --decide-only
# below without a host, root or qm.
# ---------------------------------------------------------------------------

# is_allowed exits 0 only for an EXACT id match. A substring or glob match here
# would be catastrophic in both directions: "10" must not match guest 100, and
# "1020" must not be mistaken for 102.
is_allowed() {
  local candidate=${1-} id
  for id in "${PHASE1_VMS[@]}" "${PHASE2_VMS[@]}" "${PHASE2_CTS[@]}"; do
    [ "$candidate" = "$id" ] && return 0
  done
  return 1
}

# guest_order prints the ids for a direction, in the order they must be acted
# on. down is the exact reverse of up.
guest_order() {
  local direction=$1 up=("${PHASE1_VMS[@]}" "${PHASE2_CTS[@]}" "${PHASE2_VMS[@]}")
  case "$direction" in
    up) printf '%s\n' "${up[@]}" ;;
    down)
      local i
      for ((i = ${#up[@]} - 1; i >= 0; i--)); do printf '%s\n' "${up[$i]}"; done
      ;;
    *) die "guest_order: unknown direction '$direction'" ;;
  esac
}

# hold_is_live decides whether a scheduled shutdown must be skipped.
#
# A malformed or empty hold file FAILS OPEN to "free" on purpose. The two
# failure modes are not symmetric: a stuck-on hold silently disables the whole
# feature and nobody notices for months, whereas a shutdown during ad-hoc work
# is immediately obvious and `testbed up` undoes it in ~3 minutes. So garbage
# means proceed, loudly.
hold_is_live() {
  local file=$1 now=$2 expiry
  case "$now" in '' | *[!0-9]*) die "hold_is_live: '$now' is not an epoch" ;; esac
  [ -f "$file" ] || return 1
  expiry=$(head -n1 "$file" 2>/dev/null | tr -d '[:space:]')
  case "$expiry" in
    '' | *[!0-9]*)
      log "WARNING: hold file '$file' is malformed ('$expiry'); ignoring it" >&2
      return 1
      ;;
  esac
  # Expiry exactly now counts as over, not still running.
  [ "$now" -lt "$expiry" ]
}

# --- Test seam. MUST stay above anything that reads state or touches a guest.
# Production invocations never pass --decide-only.
if [ "${1-}" = "--decide-only" ]; then
  case "${2-}" in
    allowed) if is_allowed "${3-}"; then echo yes; else echo no; fi ;;
    order)   guest_order "${3-}" | tr '\n' ' ' | sed 's/ $//' && echo ;;
    hold)    if hold_is_live "${3-}" "${4-}"; then echo held; else echo free; fi ;;
    *)       die "--decide-only: unknown question '${2-}'" ;;
  esac
  exit 0
fi

# ---------------------------------------------------------------------------
# Proxmox interaction
# ---------------------------------------------------------------------------

assert_allowed() {
  is_allowed "$1" || die "refusing to touch guest $1 — not in the testbed allowlist"
}

# guest_kind resolves vm-vs-container from the hardcoded lists, NOT by probing
# Proxmox, so a typo can never make the script guess at a prod guest.
guest_kind() {
  local id=$1 ct
  for ct in "${PHASE2_CTS[@]}"; do
    [ "$id" = "$ct" ] && { echo ct; return; }
  done
  echo vm
}

guest_state() {
  local id=$1
  if [ "$(guest_kind "$id")" = ct ]; then
    pct status "$id" 2>/dev/null | awk '{print $2}'
  else
    qm status "$id" 2>/dev/null | awk '{print $2}'
  fi
}

start_guest() {
  local id=$1 kind
  assert_allowed "$id"
  kind=$(guest_kind "$id")
  if [ "$(guest_state "$id")" = running ]; then
    log "guest $id already running — nothing to do"
    return 0
  fi
  log "starting $kind $id"
  if [ "$kind" = ct ]; then pct start "$id"; else qm start "$id"; fi
}

# stop_guest shuts down gracefully and only escalates on timeout. OPNsense
# needs a clean shutdown — a hard stop risks the config filesystem, and these
# boxes carry hand-built state that is tedious to rebuild.
stop_guest() {
  local id=$1 kind
  assert_allowed "$id"
  kind=$(guest_kind "$id")
  if [ "$(guest_state "$id")" != running ]; then
    log "guest $id already stopped — nothing to do"
    return 0
  fi
  log "shutting down $kind $id (timeout ${SHUTDOWN_TIMEOUT}s)"
  if [ "$kind" = ct ]; then
    pct shutdown "$id" --timeout "$SHUTDOWN_TIMEOUT" || true
  else
    qm shutdown "$id" --timeout "$SHUTDOWN_TIMEOUT" || true
  fi
  if [ "$(guest_state "$id")" = running ]; then
    log "WARNING: $kind $id ignored ACPI shutdown; forcing stop"
    if [ "$kind" = ct ]; then pct stop "$id"; else qm stop "$id"; fi
  fi
}

# wait_ready blocks until both firewalls serve their webConfigurator. This is
# the gate that matters: a canary that probes a half-booted box files bogus
# drift, which is worse than a late start.
wait_ready() {
  local started=$SECONDS deadline=$((SECONDS + READY_TIMEOUT)) url pending
  log "waiting for firewalls to serve :443 (timeout ${READY_TIMEOUT}s)"
  while [ "$SECONDS" -lt "$deadline" ]; do
    pending=0
    for url in "${READY_URLS[@]}"; do
      curl -sk -o /dev/null -m 6 "$url" || pending=1
    done
    if [ "$pending" -eq 0 ]; then
      log "both firewalls ready after $((SECONDS - started))s"
      return 0
    fi
    sleep 10
  done
  die "firewalls did not serve :443 within ${READY_TIMEOUT}s — the canary will probe a cold box"
}

# ct_iface_address prints a container interface's IPv4 address, empty if none.
ct_iface_address() {
  pct exec "$1" -- ip -4 -br addr show "$2" 2>/dev/null | awk '{print $3}'
}

# settle_containers makes sure the traffgen LXC actually holds its leases.
#
# WHY THIS EXISTS (found by the #625 acceptance test, not theorised): the
# firewalls serve :443 about 31s into boot, but Kea binds UDP/67 later. The VM
# guests ride systemd-networkd/netplan, which retries DHCP indefinitely and
# self-heals. The container rides ifupdown, whose dhclient gives up
# PERMANENTLY after its boot-time attempt — so 105 came up with no address on
# any NIC and no routes, silently. Every collector fed by the traffgen (ARP,
# NDP, states, netflow, unbound, leases) would then read empty and the canary
# would file it as drift.
#
# Waiting longer before starting phase 2 does not fix this, because the race is
# against a signal we cannot observe remotely. Asserting the outcome does.
settle_containers() {
  local id iface addr waited
  for id in "${PHASE2_CTS[@]}"; do
    assert_allowed "$id"
    for iface in "${CT_REQUIRED_IFACES[@]}"; do
      waited=0
      while [ "$waited" -lt "$ADDRESS_TIMEOUT" ]; do
        addr=$(ct_iface_address "$id" "$iface")
        [ -n "$addr" ] && break
        sleep 10
        waited=$((waited + 10))
      done
      if [ -n "$addr" ]; then
        log "ct $id $iface holds $addr"
        continue
      fi
      # dhclient has already given up; a plain retry of the same lease request
      # is what recovers it.
      log "WARNING: ct $id $iface has no address after ${waited}s — re-running dhclient"
      pct exec "$id" -- dhclient -1 "$iface" >/dev/null 2>&1 || true
      addr=$(ct_iface_address "$id" "$iface")
      if [ -n "$addr" ]; then
        log "ct $id $iface recovered with $addr"
      else
        log "ERROR: ct $id $iface still has no address — the traffgen is not feeding the box" >&2
      fi
    done
    restart_address_dependent_services "$id"
  done
}

# restart_address_dependent_services re-starts the container units that need an
# address at START time, now that settle_containers has guaranteed one.
#
# WHY: shaper-keepalive@ holds a dummynet flow open so trafficShaperStatistics
# items[].flows[] is populated when the canary polls — without it those paths
# read unverified, because dnctl only reports LIVE flows. It starts at boot,
# long before DHCP completes, and was observed crash-looping TWENTY times on
# "Network is unreachable" before the address arrived. systemd's Restart= does
# converge it, so this is not repairing a broken unit — it is removing the race,
# so the flow is established when `up` returns rather than up to a restart
# window later. That margin was ample either way back when the canary ran on a
# 47-minute lead behind a GitHub cron; since #654 there is no lead at all — the
# dispatch fires the moment `up` returns — so "established when `up` returns" is
# now load-bearing rather than a nicety. Making it deterministic also means a
# genuinely broken keepalive shows up here as a failure instead of hiding behind
# a lucky retry.
restart_address_dependent_services() {
  local id=$1 unit
  assert_allowed "$id"
  while read -r unit; do
    [ -n "$unit" ] || continue
    log "restarting $unit on ct $id"
    pct exec "$id" -- systemctl restart "$unit" >/dev/null 2>&1 \
      || log "WARNING: could not restart $unit on ct $id"
  done < <(pct exec "$id" -- systemctl list-units 'shaper-keepalive@*' \
             --state=loaded --no-legend --plain 2>/dev/null | awk '{print $1}')
}

# warm_firmware_check makes each firewall store an update check.
#
# WHY (found by the #625 acceptance test): OPNsense's firmware check result does
# not survive a reboot. A box that has not checked since boot serves the bare
# three-key envelope, so `firmware` `product.product_check.upgrade_needs_reboot`
# reads as unverified — and that path is REQUIRED coverage, because it is the
# fallback arm of firmwareStatusResponse.upgradeNeedsReboot(). On a box that
# omits the top-level pointer the metric is computed entirely from it.
#
# Under the old always-on regime the box had checked at some point and the path
# was covered. Without this step the daily power cycle would file a canary
# warning issue EVERY morning — turning a clean signal into permanent noise,
# which is exactly how a canary stops being read.
warm_firmware_check() {
  local id
  for id in "${PHASE1_VMS[@]}"; do
    assert_allowed "$id"
    log "running firmware check on vm $id (restores product_check coverage)"
    # Fire-and-tolerate: this is warm-up, not a gate. It runs `pkg update`, so
    # it needs working DNS and WAN — both boxes are acceptDNS=0 precisely
    # because MagicDNS breaks pkg and hangs firmware/info forever.
    if ! qm guest exec "$id" --timeout 240 -- \
        /usr/local/sbin/configctl firmware check >/dev/null 2>&1; then
      log "WARNING: firmware check on vm $id did not complete — expect a product_check coverage warning"
    fi
  done
}

# ---------------------------------------------------------------------------
# Subcommands
# ---------------------------------------------------------------------------

cmd_up() {
  local hold_seconds=${1-}
  log "bringing the testbed up"
  for id in "${PHASE1_VMS[@]}"; do start_guest "$id"; done
  wait_ready
  # Phase 2 only after the firewalls serve, so every dependent guest finds a
  # DHCP server and a default route on its first attempt.
  for id in "${PHASE2_CTS[@]}" "${PHASE2_VMS[@]}"; do start_guest "$id"; done
  settle_containers
  warm_firmware_check
  if [ -n "$hold_seconds" ]; then
    cmd_hold "$hold_seconds"
  fi
  log "testbed up"
}

cmd_down() {
  local now expiry
  now=$(date +%s)
  if hold_is_live "$HOLD_FILE" "$now"; then
    expiry=$(head -n1 "$HOLD_FILE")
    log "hold active until $(date -u -d "@$expiry" '+%Y-%m-%dT%H:%M:%SZ') — skipping shutdown"
    return 0
  fi
  log "taking the testbed down"
  # Reverse order: dependents first, firewalls last, so nothing loses its
  # gateway mid-shutdown and hangs.
  while read -r id; do stop_guest "$id"; done < <(guest_order down)
  log "testbed down"
}

cmd_hold() {
  local seconds=${1:-$DEFAULT_HOLD_SECONDS} expiry
  case "$seconds" in ''|*[!0-9]*) die "hold: '$seconds' is not a number of seconds" ;; esac
  expiry=$(( $(date +%s) + seconds ))
  mkdir -p "$(dirname "$HOLD_FILE")"
  echo "$expiry" > "$HOLD_FILE"
  log "hold set until $(date -u -d "@$expiry" '+%Y-%m-%dT%H:%M:%SZ')"
}

cmd_release() {
  rm -f "$HOLD_FILE"
  log "hold released — the next scheduled down will run"
}

cmd_status() {
  local now id state
  now=$(date +%s)
  if hold_is_live "$HOLD_FILE" "$now"; then
    printf 'hold:   active until %s\n' \
      "$(date -u -d "@$(head -n1 "$HOLD_FILE")" '+%Y-%m-%dT%H:%M:%SZ')"
  else
    printf 'hold:   none\n'
  fi
  while read -r id; do
    state=$(guest_state "$id")
    printf 'guest %s (%s): %s\n' "$id" "$(guest_kind "$id")" "${state:-unknown}"
  done < <(guest_order up)
}

usage() {
  cat <<'EOF'
Usage: opnsense-testbed-power.sh <command>

  up [seconds]   Start the testbed in dependency order and block until both
                 firewalls serve :443. With [seconds], also set a hold.
  down           Gracefully stop the testbed, unless a hold is active.
  hold [seconds] Suppress the scheduled shutdown (default 8h). Auto-expires.
  release        Clear an active hold.
  status         Show hold state and every guest's power state.
EOF
}

case "${1-}" in
  up)      shift; cmd_up "${1-}" ;;
  down)    cmd_down ;;
  hold)    shift; cmd_hold "${1-}" ;;
  release) cmd_release ;;
  status)  cmd_status ;;
  -h|--help|help) usage ;;
  *)       usage >&2; exit 2 ;;
esac
