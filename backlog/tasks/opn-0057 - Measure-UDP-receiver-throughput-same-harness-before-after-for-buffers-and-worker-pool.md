---
id: OPN-0057
title: >-
  Measure UDP receiver throughput: same-harness before/after for buffers and
  worker pool
status: Parked
assignee:
  - '@codex'
created_date: '2026-09-02 05:20'
updated_date: '2026-09-03 19:34'
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

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 4: in the same testbed hold but only after live-delivery traffic stops, run one controlled identical-load harness for before and after, read effective Linux and BSD receive buffers, and record throughput plus socket and worker-queue drops as measured numbers or park at the exact missing observation.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 3 park: resume with one controlled harness that applies identical offered UDP load and packet size before and after the buffer/worker-pool changes. Read back numeric effective SO_RCVBUF on deployed Linux and BSD, accounting for Linux doubling, and capture both socket drops and bounded worker-queue drops alongside throughput. Do not make a throughput claim until all four measurements are recorded here.

Wave 4 feasibility result: no throughput trial ran. The testbed hold was released before L2 traffic because the repository has no committed identical-load sender harness, receiver deployment topology, or fixed payload/rate/duration contract. Current code exposes queue_full loss but not a successful numeric effective SO_RCVBUF read-back; the BSD candidate socket-drop counter is system-wide unless receiver isolation is proved. A comparison without those facts would fail acceptance criteria 1 through 3 and any number would be manufactured. PARKED RESUME BOUNDARY: define one committed same-payload/rate/duration harness runnable against immutable pre-feature and current binaries, name the deployed Linux and BSD receiver targets, expose or trace numeric getsockopt SO_RCVBUF on both, and prove attributable socket-drop deltas before running the comparison.
<!-- SECTION:NOTES:END -->
