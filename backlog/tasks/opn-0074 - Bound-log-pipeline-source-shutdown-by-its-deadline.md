---
id: OPN-0074
title: Bound log pipeline source shutdown by its deadline
status: Done
assignee:
  - '@codex'
created_date: '2026-09-04 12:43'
updated_date: '2026-09-04 18:22'
labels: []
dependencies: []
modified_files:
  - internal/logship/pipeline.go
  - internal/logship/push_test.go
priority: high
type: bug
ordinal: 28000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
pipeline.stop waits on pollerWG without consulting its shutdown context. A push or poll source that ignores cancellation can therefore hang SIGTERM indefinitely even though the stop contract promises a bounded timeout error; the current regression uses a fake that returns on cancellation and never tests the stated failure mode.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A source that ignores cancellation cannot keep pipeline stop blocked past its context deadline
- [x] #2 Timeout returns and logs an attributable source-shutdown error without closing delivery resources still owned by a live producer
- [x] #3 A regression deliberately holds a source past cancellation and releases it for test cleanup
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Replace the unconditional poller wait with a context-aware completion channel. On deadline return an attributable source-shutdown error and leave shared delivery resources open while ownership is unresolved; add a cancellation-ignoring fake source regression that is released for cleanup.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented at 2389ac3b. A cancellation-ignoring source regression failed before the fix and passes after it; final just check passed.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Fixed at 2389ac3b. Source shutdown now respects its context deadline, returns and logs an attributable error, and leaves delivery resources owned by a live producer open for a later safe stop. Focused race tests and final just check passed.
<!-- SECTION:FINAL_SUMMARY:END -->
