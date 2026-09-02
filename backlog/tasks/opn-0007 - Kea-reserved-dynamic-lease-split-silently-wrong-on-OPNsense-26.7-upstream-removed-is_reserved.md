---
id: OPN-0007
title: >-
  Kea reserved/dynamic lease split silently wrong on OPNsense 26.7 (upstream
  removed is_reserved)
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 08:30'
updated_date: '2026-09-02 05:19'
labels:
  - bug
  - first-wave
milestone: m-0
dependencies: []
priority: high
type: bug
ordinal: 101
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OPNsense 26.7.0 removed the `is_reserved` enrichment from `api/kea/leases4/search` and `api/kea/leases6/search` rows (upstream `src/opnsense/mvc/app/controllers/OPNsense/Kea/Api/LeasesController.php`: present at tag 26.1, gone at 26.7/26.7.3/master, replaced by a `stats{active,inactive,total}` aggregate and a new `delLeaseAction`). Our `opnsense/kea.go:54` decodes `is_reserved` and `kea.go:197` feeds `opnsense_kea_dhcp4/6_leases_reserved_total` / `dynamic_total`, so on a 26.7 box reserved reads 0 and dynamic == total, silently. Verdict shape per the canary triage taxonomy: chase. Replacement source: `api/kea/dhcpv4/searchReservation` + `api/kea/dhcpv6/searchReservation`, matched client-side (hw_address/duid), tolerant across the 26.1+26.7 support window. Found by upstream API-surface research 2026-08-30; not yet proven against a live 26.7 box.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Bug proven or disproven against a 26.7 leases4/leases6 payload (live box or upstream-derived fixture)
- [x] #2 Reserved/dynamic lease metrics are correct on both 26.1-shape (is_reserved present) and 26.7-shape (reservation search) payloads, resolved by payload shape, not version sniffing
- [ ] #3 New reservation endpoints registered per AGENTS.md steps (endpoints map, schema registry, contract manifest, canary exemptions as needed)
- [x] #4 Tests cover both generations; just schemas and just docs clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 1 plan: prove the 26.7 chase from upstream-produced shapes with a failing regression test; implement shape-based reservation matching while preserving the 26.1 is_reserved path; return exact root-owned endpoint/schema/contract wiring; run focused Kea tests and identify required generated artifacts.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 1 investigation disproved the task premise against released upstream source. OPNsense core tags 26.7 and 26.7.3 move reservation enrichment into src/opnsense/scripts/kea/get_kea_leases.py, but the script still emits is_reserved on every record: [] for dynamic leases and a non-empty identity array for reserved leases, matched within subnet-id. The exporter already accepts the array form via flexBool and existing v4/v6 tests pass. No synthetic missing-is_reserved fixture or reservation endpoint was added because inspected supported source cannot produce that shape. Live-box payload remains unobserved; source-derived proof is the accepted AC1 route.

Wave 1 result: released OPNsense 26.7 and 26.7.3 source disproved the task premise; get_kea_leases.py still emits is_reserved for every row, and the exporter already accepts the emitted array shape. Existing v4/v6 tests and the integrated just check passed. A local tracker-only commit records this, but it is not on origin/main because the remote advanced during the run. Resume: reconcile the local tracker commit onto current origin/main, land it as documentation-only, verify CI at that exact SHA, and then finalize the disproven task; use a live 26.7 payload only if source-derived proof is no longer accepted.

Closeout reconciliation: source-finding commit 4916dd73e8d195f244a45986275fcc3aa41ba420 is on main. The task remains Parked only because a live 26.7 lease payload was not observed. Resume: decide whether the released 26.7/26.7.3 payload-producing source is sufficient to close the disproved premise; if live proof is required, capture a 26.7 lease response and compare is_reserved rows before changing code. Do not add a synthetic missing-is_reserved fixture or reservation endpoint without a source- or live-produced shape.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Closed as DISPROVED on released-source evidence, decision by Rob 2026-09-02. OPNsense 26.7 and 26.7.3 still emit is_reserved on every lease row from src/opnsense/scripts/kea/get_kea_leases.py ([] for dynamic, a non-empty identity array for reserved), and the exporter's existing flexBool already accepts that array form. The premise in the description - that 26.7 removed the field - was wrong, so the reserved/dynamic split was never broken. AC1 is disproved from the payload-producing source, which is the standard AGENTS.md sets; AC2 and AC4 are satisfied by the existing v4/v6 tests covering both generations. AC3 is VOID: no reservation endpoint is needed, and adding searchReservation would have modelled a shape upstream does not produce, which is recurring defect class 1. Source finding recorded in 4916dd73. No live 26.7 capture was taken and none is required. IMPORTANT for OPN-0015: it was filed on this same disproved premise, so its scope must be re-derived from source before it starts.
<!-- SECTION:FINAL_SUMMARY:END -->
