---
id: OPN-0073
title: Make startup and shutdown self-log loss observable
status: In Progress
assignee:
  - '@codex'
created_date: '2026-09-04 12:43'
updated_date: '2026-09-04 12:43'
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
- [ ] #1 Startup-buffer overflow produces a bounded direct diagnostic identifying the self-log overflow
- [ ] #2 Unbind waits for submissions that acquired the enqueue callback before the pipeline closes its queue
- [ ] #3 Barrier-controlled regressions cover the 257th pre-bind record and the submit/Unbind/queue-close interleaving
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Add failing overflow and interleaving regressions; emit a bounded direct diagnostic when the pre-bind ring evicts; track in-flight submit callbacks so Unbind waits for callbacks that already acquired enqueue before returning.
<!-- SECTION:PLAN:END -->
