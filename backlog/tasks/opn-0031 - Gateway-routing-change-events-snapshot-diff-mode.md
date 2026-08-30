---
id: OPN-0031
title: Gateway/routing change events (snapshot diff mode)
status: To Do
assignee: []
created_date: '2026-08-30 09:09'
updated_date: '2026-08-30 09:35'
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
