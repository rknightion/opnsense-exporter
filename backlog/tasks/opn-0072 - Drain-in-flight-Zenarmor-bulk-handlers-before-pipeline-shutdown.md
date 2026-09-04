---
id: OPN-0072
title: Drain in-flight Zenarmor bulk handlers before pipeline shutdown
status: In Progress
assignee:
  - '@codex'
created_date: '2026-09-04 12:43'
updated_date: '2026-09-04 12:43'
labels: []
dependencies: []
modified_files:
  - internal/logship/zenarmor/source.go
  - internal/logship/zenarmor/source_test.go
priority: high
type: bug
ordinal: 26000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Zenarmor Run returns after a fixed five-second graceful-shutdown timeout even though a bulk handler may still be running under the receiver 120-second request window. The pipeline then closes its queue; a late handler emit is accepted by the source wrapper, advances last_received and is silently discarded by the closed queue.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Source Run does not return while an admitted bulk handler can still emit into the pipeline queue
- [ ] #2 A shutdown-grace expiry explicitly terminates and joins active handlers before shared delivery resources close
- [ ] #3 Shutdown timeout or abandoned input is surfaced without falsely advancing receive freshness
- [ ] #4 A barrier-controlled regression exercises a bulk request held past graceful shutdown
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Add a barrier-controlled handler regression, make graceful shutdown failure explicitly close active connections and wait for handlers to exit before Source.Run returns, and propagate an attributable shutdown error so the pipeline cannot report successful admission after queue closure.
<!-- SECTION:PLAN:END -->
