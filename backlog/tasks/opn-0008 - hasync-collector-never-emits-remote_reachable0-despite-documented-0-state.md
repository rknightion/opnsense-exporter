---
id: OPN-0008
title: hasync collector never emits remote_reachable=0 despite documented 0 state
status: Parked
assignee:
  - '@codex'
created_date: '2026-08-30 08:30'
updated_date: '2026-09-01 23:42'
labels: []
milestone: m-0
dependencies: []
priority: medium
type: bug
ordinal: 107
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The metric help at `internal/collector/hasync.go:45-46` documents "1 = reachable, 0 = unreachable/unconfigured", but `Update()` (`hasync.go:78-82`) returns without emitting when `!data.Reachable`, so the series is only ever written with value 1 (`hasync.go:89-90`). The collector is opt-in (`--exporter.enable-hasync`), so anyone enabling it has an HA peer and wants the 0: as shipped, "peer went unreachable" and "collector produced nothing" are indistinguishable, forcing staleness-based alerting for the one fault the collector exists to catch. Minimum fix: correct the help text. Better: emit 0 when a peer is configured but unreachable, stay silent only when unconfigured — if `FetchHasyncStatus` cannot distinguish those two, that distinction is the real work. The silence is a deliberate D6 decision for single-node boxes; the fix must not reintroduce noise on unconfigured nodes.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Confirmed whether FetchHasyncStatus can distinguish unconfigured from unreachable
- [ ] #2 remote_reachable emits 0 when a peer is configured but unreachable, and emits nothing on unconfigured single-node boxes
- [ ] #3 Help text matches actual emission behaviour
- [ ] #4 Test covers the configured-but-unreachable case
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 1 plan: inspect FetchHasyncStatus and upstream payload branches to distinguish unconfigured from unreachable; add a failing configured-unreachable test; emit zero only for configured peers, keep single-node silence, and run focused hasync tests.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 1 staged WIP fixes configured-but-unreachable HA peers while keeping unconfigured single-node installations silent; focused tests and the integrated just check passed. Post-correction L14 found no remaining issue. Not landed: the required CodeRabbit review produced no complete event in two attempts because its service WebSocket closed before analysis. Resume: restore CodeRabbit, review the staged diff, fix every critical/major finding, commit this task with explicit pathspecs, integrate current origin/main without rebasing, rerun just check, push, and verify exact-SHA CI.
<!-- SECTION:NOTES:END -->
