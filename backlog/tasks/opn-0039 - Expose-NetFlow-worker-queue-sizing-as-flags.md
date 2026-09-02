---
id: OPN-0039
title: Expose NetFlow worker/queue sizing as flags
status: Parked
assignee: []
created_date: '2026-08-30 09:09'
updated_date: '2026-09-02 07:01'
labels: []
milestone: m-4
dependencies: []
priority: low
type: enhancement
ordinal: 506
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`internal/flow/netflow/listener.go:20-23` hardcodes 4 workers / 1024 queue; drops are counted but not tunable. Add two flags with the current values as defaults.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Worker count and queue depth configurable; defaults unchanged; just docs regenerated
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 2 implementation is complete: validated worker/queue flags feed the bounded NetFlow listener, with negative-value rejection and concurrency/queue tests. Focused tests, full indexed `just check`, and L13 review passed. Landing is blocked solely by two CodeRabbit connection failures with no complete event. Preserved in `codex/wip-wave2-coderabbit-blocked.patch`; resume by applying it, rerunning the gate, and obtaining a completed CodeRabbit review.
<!-- SECTION:NOTES:END -->
