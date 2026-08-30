---
id: OPN-0007
title: >-
  Kea reserved/dynamic lease split silently wrong on OPNsense 26.7 (upstream
  removed is_reserved)
status: To Do
assignee: []
created_date: '2026-08-30 08:30'
labels: []
dependencies: []
priority: high
type: bug
ordinal: 7000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OPNsense 26.7.0 removed the `is_reserved` enrichment from `api/kea/leases4/search` and `api/kea/leases6/search` rows (upstream `src/opnsense/mvc/app/controllers/OPNsense/Kea/Api/LeasesController.php`: present at tag 26.1, gone at 26.7/26.7.3/master, replaced by a `stats{active,inactive,total}` aggregate and a new `delLeaseAction`). Our `opnsense/kea.go:54` decodes `is_reserved` and `kea.go:197` feeds `opnsense_kea_dhcp4/6_leases_reserved_total` / `dynamic_total`, so on a 26.7 box reserved reads 0 and dynamic == total, silently. Verdict shape per the canary triage taxonomy: chase. Replacement source: `api/kea/dhcpv4/searchReservation` + `api/kea/dhcpv6/searchReservation`, matched client-side (hw_address/duid), tolerant across the 26.1+26.7 support window. Found by upstream API-surface research 2026-08-30; not yet proven against a live 26.7 box.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Bug proven or disproven against a 26.7 leases4/leases6 payload (live box or upstream-derived fixture)
- [ ] #2 Reserved/dynamic lease metrics are correct on both 26.1-shape (is_reserved present) and 26.7-shape (reservation search) payloads, resolved by payload shape, not version sniffing
- [ ] #3 New reservation endpoints registered per AGENTS.md steps (endpoints map, schema registry, contract manifest, canary exemptions as needed)
- [ ] #4 Tests cover both generations; just schemas and just docs clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
