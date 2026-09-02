---
id: OPN-0031
title: Gateway/routing change events (snapshot diff mode)
status: Parked
assignee: []
created_date: '2026-08-30 09:09'
updated_date: '2026-09-02 07:02'
labels: []
milestone: m-1
dependencies:
  - OPN-0028
priority: low
type: feature
ordinal: 204
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Diff successive `routingTable`/`gatewaysStatus` snapshots to emit default-route-move and flap-detail events. Built as the C2 snapshot framework's diff mode (OPN-0028), not standalone — dpinger syslog already covers alarms; this adds the routing-table delta itself.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Default-route change produces one event with before/after; no event storm during flapping (rate-bounded)
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 2 did not start this dependent because OPN-0028 could not land through the required CodeRabbit gate. Resume only after applying `codex/wip-wave2-coderabbit-blocked.patch`, obtaining a completed review, landing OPN-0028, and confirming its frozen configstate record and flag contract.
<!-- SECTION:NOTES:END -->
