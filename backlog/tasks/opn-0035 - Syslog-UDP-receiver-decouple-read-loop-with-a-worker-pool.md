---
id: OPN-0035
title: 'Syslog UDP receiver: decouple read loop with a worker pool'
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 09:09'
updated_date: '2026-09-02 15:53'
labels:
  - first-wave
milestone: m-0
dependencies: []
priority: high
type: enhancement
ordinal: 105
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`internal/logship/syslog/listener.go:373-393` runs parse/dispatch/enrichment/emit synchronously before the next `ReadFromUDPAddrPort`; a slow enrichment miss stalls the socket and kernel-level overflow is invisible. NetFlow already has the right pattern — worker pool + counted `QueueDropped` (`internal/flow/netflow/listener.go:142-188`). Apply the same to syslog, the highest-volume receiver: bounded queue, counted drops, workers.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Datagram read decoupled from processing via bounded queue + workers; queue drops counted in a metric
- [x] #2 Throughput/overload behaviour covered by a test; no reordering guarantees silently broken (document if ordering changes)
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 1 plan: benchmark the current UDP listener with the existing harness, add a failing overload test, introduce a bounded datagram queue and workers with counted drops, document ordering semantics, and report before/after from the same harness.

Wave 2 L4: apply the preserved per-lane patch, review queue, worker, shutdown, ordering and drop-accounting semantics against current main, then rerun focused concurrency tests.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 1 staged WIP decouples syslog UDP reads through a bounded worker queue with counted drops and shutdown coverage; targeted concurrency tests and integrated just check passed. Post-correction L14 found no remaining issue. Not landed because CodeRabbit failed before analysis twice. Resume: obtain a complete review, fix critical/major findings, commit explicitly, integrate current origin/main, rerun just check, push, verify exact-SHA CI, then run sustained live UDP overload if operational throughput proof is required.

Wave 2 applied the preserved worker-pool patch cleanly and passed focused race tests plus the full indexed `just check`; L13 found no lifecycle or shutdown defect. Landing is blocked solely by two CodeRabbit connection failures with no complete event. Both `codex/wip-opn-0035-syslog-worker-pool.patch` and `codex/wip-wave2-coderabbit-blocked.patch` are retained. Resume by applying the combined patch, rerunning the gate, and obtaining a completed CodeRabbit review.

Landed on main in `a482f637`. Bounded queue plus worker pool decouples the datagram read from processing; queue drops are counted; race, queue, drop and shutdown tests pass under `-race`. Loss of ordering guarantees is documented. No sustained live throughput claim is made here: OPN-0057 owns the same-harness before/after measurement.
<!-- SECTION:NOTES:END -->
