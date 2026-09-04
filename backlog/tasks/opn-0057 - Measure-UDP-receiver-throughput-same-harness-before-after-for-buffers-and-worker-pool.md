---
id: OPN-0057
title: >-
  Measure UDP receiver throughput: same-harness before/after for buffers and
  worker pool
status: Parked
assignee:
  - '@codex'
created_date: '2026-09-02 05:20'
updated_date: '2026-09-04 18:22'
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

Wave 5: first commit a deterministic UDP throughput contract naming the sender command, fixed payload, packet size, offered rate, duration, immutable before/current binaries, isolated Linux and BSD receiver targets, successful numeric SO_RCVBUF read-back, and attributable socket plus worker-queue drop counters. Only after that contract lands may the root take the shared testbed hold and measure; otherwise re-park with the exact missing observation.

Wave 6: expose opnsense_exporter_syslog_udp_accepted_total immediately after successful UDP queue admission and a positive opnsense_exporter_syslog_udp_receive_buffer_bytes gauge from the actual getsockopt read-back. Preserve Linux doubled and FreeBSD undoubled semantics without equality assertions. Regenerate owned docs/dashboard after source integration, but do not run the throughput harness; re-park on the two missing isolated host roles.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 3 park: resume with one controlled harness that applies identical offered UDP load and packet size before and after the buffer/worker-pool changes. Read back numeric effective SO_RCVBUF on deployed Linux and BSD, accounting for Linux doubling, and capture both socket drops and bounded worker-queue drops alongside throughput. Do not make a throughput claim until all four measurements are recorded here.

Wave 4 feasibility result: no throughput trial ran. The testbed hold was released before L2 traffic because the repository has no committed identical-load sender harness, receiver deployment topology, or fixed payload/rate/duration contract. Current code exposes queue_full loss but not a successful numeric effective SO_RCVBUF read-back; the BSD candidate socket-drop counter is system-wide unless receiver isolation is proved. A comparison without those facts would fail acceptance criteria 1 through 3 and any number would be manufactured. PARKED RESUME BOUNDARY: define one committed same-payload/rate/duration harness runnable against immutable pre-feature and current binaries, name the deployed Linux and BSD receiver targets, expose or trace numeric getsockopt SO_RCVBUF on both, and prove attributable socket-drop deltas before running the comparison.

Wave 5 contract landed in 8c4d92ce. The fixed 256-byte, 5,000 packets/s, 60-second sender and fail-closed four-observation verifier passed 11 focused tests and the full just check gate. CodeRabbit completed three source-only passes: pass 1 found a major before/current socket-drop-scope gap plus a major non-JSON socket-failure path and a minor formatting issue; pass 2 found non-finite elapsed values could pass validation; pass 3 completed with zero findings after all were fixed. No traffic ran and no throughput number was observed. PARKED RESUME BOUNDARY: expose an ingress-accepted counter immediately after successful syslog UDP queue admission and a successful numeric getsockopt SO_RCVBUF read-back on each deployed receiver; provide immutable before/current deployments on the named isolated Linux and FreeBSD roles with the same instance and counter-capture method; then run the committed four-observation contract under one testbed hold and record buffer, accepted rate, socket drops, and queue drops. A CI-only API credential does not provide the missing FreeBSD binary deployment or receiver-local counters.

Wave 6 implementation: added opnsense_exporter_syslog_udp_accepted_total at successful non-empty, allowlisted bounded-queue admission and opnsense_exporter_syslog_udp_receive_buffer_bytes from the positive getsockopt(SO_RCVBUF) read-back. The read-back is surfaced unchanged: Linux commonly reports roughly double the request while FreeBSD does not, and no equality assertion was added. Generated self-metric documentation and two dashboard panels; just gen and the complete just check gate passed. CodeRabbit source review completed for the syslog slice in one pass with zero findings; the dashboard-only pass raised one major slice-context false positive because the listener source that registers the gauge was excluded, and the combined four-file pass completed with zero findings. No traffic ran and no throughput, drop or buffer number was observed; acceptance criteria 1 through 4 remain unproven. PARKED RESUME BOUNDARY: provide the two isolated receiver host roles required by the committed contract, one Linux and one FreeBSD, then run that contract.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Committed the deterministic OPN-0057 measurement contract at 8c4d92ce; numeric measurement remains unproven and is parked at the exact missing receiver observations.

Wave 6 supersession: observability shipped at b10ffbb5. opnsense_exporter_syslog_udp_accepted_total counts successful bounded-queue admission and opnsense_exporter_syslog_udp_receive_buffer_bytes exposes the positive getsockopt SO_RCVBUF read-back. Linux commonly reports roughly double the request while FreeBSD does not; no equality assertion was added. No traffic ran and no throughput, drop or buffer number was observed. PARKED RESUME BOUNDARY: provide the two isolated receiver host roles required by the committed contract, one Linux and one FreeBSD, then run it.
<!-- SECTION:FINAL_SUMMARY:END -->
