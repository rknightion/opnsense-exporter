---
id: OPN-0032
title: Reserve fast-tier poll capacity in the scheduler
status: To Do
assignee: []
created_date: '2026-08-30 09:09'
updated_date: '2026-08-30 09:35'
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
- [ ] #1 Fast-tier polls cannot be starved by slow/cold polls occupying all semaphore slots (test proves it under a wedged-endpoint simulation)
- [ ] #2 Behaviour documented; scheduler self-metrics expose fast-tier wait if a new metric is warranted
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
