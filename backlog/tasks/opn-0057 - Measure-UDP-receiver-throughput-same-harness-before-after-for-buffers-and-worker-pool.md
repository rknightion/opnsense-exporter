---
id: OPN-0057
title: >-
  Measure UDP receiver throughput: same-harness before/after for buffers and
  worker pool
status: To Do
assignee: []
created_date: '2026-09-02 05:20'
labels:
  - needs-triage
milestone: m-4
dependencies:
  - OPN-0035
priority: low
type: task
ordinal: 11000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OPN-0036 landed a configurable 4 MiB SO_RCVBUF default plus a clamp warning that names net.core.rmem_max, and OPN-0035 will land a bounded queue and worker pool for the syslog UDP read loop. Neither change carries a throughput measurement: OPN-0036's report explicitly makes no performance claim, and the effective buffer size has never been read back on a deployed Linux or BSD target. Establish what the two changes actually bought, so the next receiver change has a baseline to move.

Deferred deliberately at wave 1 closeout (decision by Rob 2026-09-02): the clamp warning is the operationally useful half and it shipped; the number is worth having but is not worth blocking a receiver fix on.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Before and after come from the SAME harness at the SAME offered load and packet size - a better number produced by a changed measurement method is a false pass, not a result
- [ ] #2 Effective SO_RCVBUF is read back on a deployed Linux target (accounting for the kernel doubling the requested value) and on a BSD target, and both are reported as numbers
- [ ] #3 Drop counts at the socket and at the worker queue are reported alongside throughput, so a throughput gain that is really a drop is visible
- [ ] #4 The measured numbers are recorded on this task; no throughput claim is made anywhere in docs or release notes that this task has not measured
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
