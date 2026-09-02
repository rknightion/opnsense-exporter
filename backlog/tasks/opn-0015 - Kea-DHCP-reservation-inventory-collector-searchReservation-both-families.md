---
id: OPN-0015
title: 'Kea DHCP reservation inventory collector (searchReservation, both families)'
status: To Do
assignee: []
created_date: '2026-08-30 09:08'
updated_date: '2026-09-02 05:20'
labels: []
milestone: m-2
dependencies:
  - OPN-0007
priority: high
type: feature
ordinal: 301
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
BLOCKED ON A RE-DERIVATION, 2026-09-02. This task was filed on the same premise as OPN-0007 - that OPNsense 26.7 removed is_reserved from the lease rows and reservations therefore had to come from searchReservation. Wave 1 disproved that against released 26.7/26.7.3 source: get_kea_leases.py still emits is_reserved on every row and the exporter already decodes it. OPN-0007 is closed as disproved.

So the ORIGINAL justification for this collector is gone. Do not start it as written. Re-derive the case first: a reservation inventory collector may still be worth having on its own merits (reservations that have never been claimed are invisible in lease data, and hostname/description live only on the reservation), but that is a different argument for a different metric set, and the acceptance criteria below were written for the repair, not for the inventory. Either rewrite them from the inventory case or close this task.
<!-- SECTION:NOTES:END -->
