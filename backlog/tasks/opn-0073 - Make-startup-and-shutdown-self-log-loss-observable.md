---
id: OPN-0073
title: Make startup and shutdown self-log loss observable
status: Done
assignee:
  - '@codex'
created_date: '2026-09-04 12:43'
updated_date: '2026-09-04 18:22'
labels: []
dependencies: []
modified_files:
  - internal/logship/selflog.go
  - internal/logship/selflog_test.go
priority: medium
type: bug
ordinal: 27000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The exporter self-log handler silently overwrites the oldest of its 256 pre-bind records, and submit can snapshot the live enqueue callback immediately before Unbind then push after the pipeline queue closes. Both paths lose an OTLP copy while the wrapped stderr record remains, with no bounded loss reason.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Startup-buffer overflow produces a bounded direct diagnostic identifying the self-log overflow
- [x] #2 Unbind waits for submissions that acquired the enqueue callback before the pipeline closes its queue
- [x] #3 Barrier-controlled regressions cover the 257th pre-bind record and the submit/Unbind/queue-close interleaving
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Add failing overflow and interleaving regressions; emit a bounded direct diagnostic when the pre-bind ring evicts; track in-flight submit callbacks so Unbind waits for callbacks that already acquired enqueue before returning.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented at 2389ac3b. Both the 257th-record overflow and submit/Unbind interleaving regressions failed before the fix and pass after it; final just check passed.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Fixed at 2389ac3b. Startup self-log overflow emits one direct bounded diagnostic, and Unbind waits for callbacks admitted before shutdown. Barrier-controlled regressions and final just check passed.
<!-- SECTION:FINAL_SUMMARY:END -->
