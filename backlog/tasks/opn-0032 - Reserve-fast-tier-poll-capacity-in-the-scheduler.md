---
id: OPN-0032
title: Reserve fast-tier poll capacity in the scheduler
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 09:09'
updated_date: '2026-09-02 05:16'
labels:
  - first-wave
milestone: m-0
dependencies: []
priority: high
type: enhancement
ordinal: 104
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`maxPollConcurrency = 8` (`internal/collector/scheduler.go:19`) is shared by ~65 collectors with a 50s default poll timeout; a 15s fast-tier CARP/gateways poll can queue behind eight wedged slow/cold polls, and the deterministic name-hash startup jitter (`scheduler.go:420-439`) makes the collision recur at the same offset every cycle. Reserve slot(s) for the fast tier and/or give fast-tier polls a shorter timeout so failover detection latency holds exactly when the firewall is degraded (`interval_tiers.go:190` states the 15s rationale).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Fast-tier polls cannot be starved by slow/cold polls occupying all semaphore slots (test proves it under a wedged-endpoint simulation)
- [x] #2 Behaviour documented; scheduler self-metrics expose fast-tier wait if a new metric is warranted
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 1 plan: add a deterministic wedged-slow-poll regression test using the existing scheduler harness; implement reserved fast-tier capacity without changing unrelated poll semantics; document the behaviour and run focused scheduler tests.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 1 staged WIP reserves fast-tier scheduler capacity and adds wedged-slow-poll regression coverage; focused tests and integrated just check passed. Post-correction L14 found no remaining issue. Not landed because CodeRabbit produced no complete event. Resume: obtain a complete review, fix critical/major findings, commit this task explicitly, integrate current origin/main, rerun just check, push, and verify exact-SHA CI.

Integrated commit 5a241bb73917a874cb4771ecab1a9a3c3b9dfa84 reserves one of eight poll slots for fast-tier work while preserving the global cap. The deterministic wedged-general regression admits seven general polls and proves a fast gateway poll still runs. No new self-metric was warranted because the change prevents the starvation state.

Decision, Rob 2026-09-02: no tier-specific admission/wait metric. The reservation prevents the starvation state rather than introducing a new one, so there is no wait condition for an operator to observe. Revisit only if a real scheduler stall is reported that this telemetry would have caught.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Reserved fast-tier scheduler capacity with deterministic race-tested coverage. just check and a zero-finding CodeRabbit review passed; exact-head CI run 33582936222 succeeded at 5a241bb73917a874cb4771ecab1a9a3c3b9dfa84.
<!-- SECTION:FINAL_SUMMARY:END -->
