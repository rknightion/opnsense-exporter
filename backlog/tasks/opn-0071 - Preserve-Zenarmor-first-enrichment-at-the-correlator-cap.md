---
id: OPN-0071
title: Preserve Zenarmor-first enrichment at the correlator cap
status: In Progress
assignee:
  - '@codex'
created_date: '2026-09-04 12:42'
labels: []
dependencies: []
modified_files:
  - internal/flow/correlate.go
  - internal/flow/correlate_test.go
priority: high
type: bug
ordinal: 25000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
At max entries, a novel Zenarmor-first connection is silently refused while a later NetFlow record is admitted without its L7, verdict and enrichment. The public max-entries contract says cap pressure force-emits the oldest entry and is counted, but this path neither evicts nor increments CorrelatorStats.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 At capacity, a novel Zenarmor-first key causes the oldest eligible entry to be force-emitted and counted before the new enrichment holder is admitted
- [ ] #2 A subsequent NetFlow record for that key emits a merged record retaining the Zenarmor contribution
- [ ] #3 The cap remains hard and Zenarmor-only entries still never emit on expiry or flush
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Write a cap=1 regression for NetFlow A, Zenarmor B, NetFlow B; reuse the existing oldest-entry force-emit path for Zenarmor-first admission; run focused correlator tests and the repository gate.
<!-- SECTION:PLAN:END -->
