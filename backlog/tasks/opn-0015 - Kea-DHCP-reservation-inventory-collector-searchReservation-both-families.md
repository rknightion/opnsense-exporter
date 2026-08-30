---
id: OPN-0015
title: 'Kea DHCP reservation inventory collector (searchReservation, both families)'
status: To Do
assignee: []
created_date: '2026-08-30 09:08'
labels: []
dependencies:
  - OPN-0007
priority: high
type: feature
ordinal: 15000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Add `api/kea/dhcpv4/searchReservation` + `api/kea/dhcpv6/searchReservation` as first-class endpoints: reservation counts per subnet and reservation inventory. This is also the fix vehicle for OPN-0007 (26.7 removed `is_reserved` from lease search), hence the dependency — the endpoint registration should land once, shared. Follow AGENTS.md new-collector steps end to end.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Reservation count metrics exported per address family (and per subnet where payload allows)
- [ ] #2 Endpoints registered per AGENTS.md (endpoints map, schema registry, contract manifest, docs, dashboard panels)
- [ ] #3 just check, just docs, just grafana-check clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
