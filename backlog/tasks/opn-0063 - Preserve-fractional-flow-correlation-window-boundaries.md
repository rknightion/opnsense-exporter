---
id: OPN-0063
title: Preserve fractional flow-correlation window boundaries
status: Done
assignee:
  - '@codex'
created_date: '2026-09-04 05:38'
updated_date: '2026-09-04 07:26'
labels:
  - needs-triage
dependencies: []
modified_files:
  - internal/flow/correlate.go
  - internal/flow/correlate_test.go
priority: medium
type: bug
ordinal: 17000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The flow correlator accepts any positive duration, but its key calculation truncates the configured window to whole seconds. A sub-second window maps every record for a Community ID into one bucket, and a non-integral duration uses different boundaries for grouping and expiry. Distinct connection windows can therefore merge and produce wrong bytes, fragment counts, pairing and partial-window status.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A regression with a sub-second window proves records for the same Community ID in distinct configured windows do not merge
- [x] #2 A regression with a non-integral-second window proves grouping and expiry use the same exact duration boundary
- [x] #3 Existing whole-second and whole-minute correlation behavior remains unchanged
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Write failing sub-second and non-integral-duration correlator tests, then compute the bucket from the full duration without a whole-second truncation and run the focused flow suite.
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Fixed by 2a8e9c98. Correlation buckets now divide Unix nanoseconds by the exact configured duration, preserving sub-second and non-integral-second boundaries. Both regressions failed before the fix and passed after it; the integrated race suite and just check passed. Reviewed in the combined flow slice, whose final pass completed with zero findings.
<!-- SECTION:FINAL_SUMMARY:END -->
