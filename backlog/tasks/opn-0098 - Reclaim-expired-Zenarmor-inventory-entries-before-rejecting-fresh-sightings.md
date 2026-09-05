---
id: OPN-0098
title: Reclaim expired Zenarmor inventory entries before rejecting fresh sightings
status: Done
assignee:
  - '@codex'
created_date: '2026-09-05 21:28'
updated_date: '2026-09-05 21:57'
labels:
  - needs-triage
dependencies: []
priority: medium
type: bug
ordinal: 52000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Wave 8 fresh retained-state audit: boundedInventory.seen in internal/collector/boundedinventory.go checks key and byte capacity before TTL pruning, which runs only from live during snapshot construction. At capacity, an expired inventory can reject a new one-time device observation and count a false capacity refusal until the next snapshot. The lost observation cannot be recovered by subsequent pruning. This is the same stale-capacity class as the DNS cache repair, on a distinct state store not covered by the Wave 6/7 audit tables.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 An observation at capacity reclaims expired entries before rejecting the new sighting, without requiring a prior snapshot
- [x] #2 Genuinely full live inventories still count refusals and refresh existing entries; byte accounting remains correct
- [x] #3 A focused regression fails before and passes after the repair
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Add a deterministic expiry-before-admission regression, observe failure, reclaim expired entries only when admission is otherwise capacity-blocked, then run focused race tests and integrate under root CodeRabbit and just check.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Failing-before: TestBoundedInventory_AdmissionReclaimsExpiredEntries failed with live = [current], want [current visitor]. After capacity-triggered expiry reclamation: go test -race ./internal/collector -run ^TestBoundedInventory -count=1 returned ok in 1.455s. The earliest-expiry bound avoids a full scan on every rejected sighting while every held entry is live. Integration gate and source review still pending.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Expired capacity is reclaimed before admission, with conservative next-expiry indexing and correct byte accounting. Deterministic failing-before regression: live = [current], want [current visitor]. Focused race tests passed in 1.455s. CodeRabbit two-file source slice complete/review_completed, zero findings, one completed pass. Integrated just check passed exit 0 in isolated exact-source worktree; just gen completed with no inventory-generated changes. Commit follows in the same root integration batch.
<!-- SECTION:FINAL_SUMMARY:END -->
