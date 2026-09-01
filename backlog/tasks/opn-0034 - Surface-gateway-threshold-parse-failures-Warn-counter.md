---
id: OPN-0034
title: Surface gateway threshold parse failures (Warn + counter)
status: Parked
assignee:
  - '@codex'
created_date: '2026-08-30 09:09'
updated_date: '2026-09-01 23:42'
labels: []
milestone: m-4
dependencies: []
priority: medium
type: enhancement
ordinal: 501
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`internal/collector/gateways.go:180-197` drops an unparseable RTT/loss threshold with a Debug-only log — invisible at default Info level; the threshold series silently vanishes. Mirror the smart.go #615 pattern: Warn log + a `gateway_threshold_parse_errors_total` counter.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Unparseable threshold produces a Warn and increments a parse-errors counter; series absence is explained
- [ ] #2 Test covers a malformed threshold payload
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 1 L9 plan: read the receiver/pipeline acceptance contract, write the required focused regression first where applicable, implement only the task-owned files, return root-owned wiring precisely, and stop before OPN-0036.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 1 staged WIP surfaces gateway threshold parse failures through warnings and a counter, with tests and dashboard coverage; integrated just check passed and L14 found no remaining issue. Not landed because CodeRabbit produced no complete event. Resume: obtain a complete review, triage findings, commit explicitly, integrate current origin/main, rerun just check, push, verify exact-SHA CI, then confirm the counter with a malformed live/test payload if runtime proof is required.
<!-- SECTION:NOTES:END -->
