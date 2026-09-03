---
id: OPN-0031
title: Gateway/routing change events (snapshot diff mode)
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 09:09'
updated_date: '2026-09-03 19:36'
labels: []
milestone: m-1
dependencies:
  - OPN-0028
priority: low
type: feature
ordinal: 204
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Diff successive `routingTable`/`gatewaysStatus` snapshots to emit default-route-move and flap-detail events. Built as the C2 snapshot framework's diff mode (OPN-0028), not standalone — dpinger syslog already covers alarms; this adds the routing-table delta itself.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Default-route change produces one event with before/after; no event storm during flapping (rate-bounded)
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Add a default-off stateful routingchange source over the existing routingTable and gatewaysStatus endpoints.
2. Baseline without emission, emit one redacted before/after record for effective default-route movement, ignore dpinger-only status changes, and coalesce flapping behind a one-minute bound.
3. Register the closed log source in documentation and dashboard coverage, regenerate artifacts, and verify focused plus full gates.
4. Finalize atomically, commit only OPN-0031 paths, and push main.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 2 did not start this dependent because OPN-0028 could not land through the required CodeRabbit gate. Resume only after applying `codex/wip-wave2-coderabbit-blocked.patch`, obtaining a completed review, landing OPN-0028, and confirming its frozen configstate record and flag contract.

Unblocked 2026-09-02: OPN-0028 landed on main in `a482f637`, so its state and cursor contract is now available. This task was parked only on that dependency.

Wave 3 implementation complete. The default-off routingchange source establishes a no-emission baseline, compares effective default routes and gateway state, ignores dpinger-only status changes, and emits one redacted before/after record after a one-minute cooldown with intermediate flaps coalesced into bounded suppression detail. Stateful cursor data round-trips. Focused race/options and Config/source-coverage tests passed; just gen registered 10/10 log sources with 1050/1050 metric coverage; full just check passed with 427 Grafana tests. CodeRabbit phase1-logship-options and phase1-grafana slices completed with no unresolved critical/major findings.

Wave 4 OPN-0060 live-proof disposition: NOT PROVEN. The testbed became ready, but its API credentials were unavailable to the mandated local process and exist only in the protected CI environment; CI was forbidden as a substitute. No exporter delivery run, Loki query, or on-wire result occurred for this source. Resume through OPN-0060 after an authorised local testbed credential launcher exists.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added a default-off, stateful routing-change log source with no-emission baseline, one-minute coalescing, before/after records, Config dashboard coverage, and closed source registration. Verified by focused race tests, just gen, and full just check. The exact task commit SHA is recorded in the wave report.
<!-- SECTION:FINAL_SUMMARY:END -->
