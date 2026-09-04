---
id: OPN-0066
title: Persist device-inventory seen identities across restart
status: Done
assignee:
  - '@codex'
created_date: '2026-09-04 05:38'
updated_date: '2026-09-04 07:26'
labels:
  - needs-triage
dependencies: []
modified_files:
  - internal/logship/configsnapshot/device_inventory.go
  - internal/logship/configsnapshot/source.go
  - internal/logship/configsnapshot/source_test.go
priority: medium
type: bug
ordinal: 20000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Device inventory derives its new_device event from an in-memory seen set, while the source state file persists only family hash and last-emitted time. After restart the restored hash can suppress the first unchanged poll, but the next heartbeat or unrelated inventory change emits every pre-existing device as newly observed. The shipped dashboard then raises false new-device events after ordinary exporter restarts.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A failing regression saves state after observing devices, restores it into a fresh source, then forces a heartbeat or one-device change and shows that old identities are currently marked new
- [x] #2 Persisted state restores committed device identities atomically with the family state and does not persist an uncommitted failed poll
- [x] #3 After restart only genuinely unseen identities have new_device=true; existing hash-dedupe and heartbeat behavior remains intact
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Extend the config-snapshot provider/source state seam so the device provider can save and restore committed seen identities, begin with a restart regression, preserve the current commit-after-whole-poll rule, and keep malformed or old state safe by treating missing provider state as a fresh baseline without corrupting family state.
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Fixed by d3f47f4b. Configsnapshot state now persists committed device identity keys alongside the family cursor, excludes pending failed-poll observations, tolerates legacy family-only state and isolates malformed provider state. The restart regression failed before the fix and passed after it; integrated just check passed. CodeRabbit completed one pass with zero findings.
<!-- SECTION:FINAL_SUMMARY:END -->
