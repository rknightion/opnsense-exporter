---
id: OPN-0035
title: 'Syslog UDP receiver: decouple read loop with a worker pool'
status: To Do
assignee: []
created_date: '2026-08-30 09:09'
labels:
  - first-wave
dependencies: []
priority: high
type: enhancement
ordinal: 35000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`internal/logship/syslog/listener.go:373-393` runs parse/dispatch/enrichment/emit synchronously before the next `ReadFromUDPAddrPort`; a slow enrichment miss stalls the socket and kernel-level overflow is invisible. NetFlow already has the right pattern — worker pool + counted `QueueDropped` (`internal/flow/netflow/listener.go:142-188`). Apply the same to syslog, the highest-volume receiver: bounded queue, counted drops, workers.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Datagram read decoupled from processing via bounded queue + workers; queue drops counted in a metric
- [ ] #2 Throughput/overload behaviour covered by a test; no reordering guarantees silently broken (document if ordering changes)
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
