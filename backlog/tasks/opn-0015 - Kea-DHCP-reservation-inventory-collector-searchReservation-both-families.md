---
id: OPN-0015
title: >-
  Kea DHCP reservation inventory counts for unclaimed reservations (both
  families)
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 09:08'
updated_date: '2026-09-03 06:37'
labels: []
milestone: m-2
dependencies: []
priority: high
type: feature
ordinal: 301
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Add standalone, low-cardinality inventory metrics for configured Kea DHCP reservations in both address families. This is not a repair for reserved/dynamic lease metrics: those continue to use the lease-row `is_reserved` enrichment, which released 26.7/26.7.3 still emit.

The independent operator value is configuration visibility. `api/kea/leases4/search` and `api/kea/leases6/search` describe issued leases; released 26.7.3 `get_kea_leases.py` only consults reservations when matching an existing lease identity. A configured reservation that has never been claimed therefore has no lease-row representation. `api/kea/dhcpv4/searchReservation` and `api/kea/dhcpv6/searchReservation` expose the configured inventory.

Export aggregate reservation counts by address family and configured subnet only. Do not add a per-reservation info metric or labels from hostname, description, address, hardware address, DUID, client ID, or UUID in this task. The reservation model has configured hostname and description fields, but lease rows also have a client-reported hostname; this task makes no claim that hostname is lease-invisible.

Support the current and previous stable OPNsense generations by payload shape, not version detection. Before modelling the response, derive every consumed field from the payload-producing OPNsense controller/model/grid source and pin it with a source-derived fixture or a redacted live capture. Do not add `searchReservation` to repair the disproved OPN-0007 premise.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Source-derived fixtures or redacted live captures prove the empty and populated `searchReservation` response shapes for DHCPv4 and DHCPv6 on the supported generations, including the subnet relation used by this collector; no field is modelled from a guessed payload shape.
- [x] #2 The existing Kea collector exports complete configured-reservation counts for DHCPv4 and DHCPv6, with a resolved configured-subnet dimension. Counts include reservations with no current lease and are not derived from lease rows, `is_reserved`, or a paginated subset.
- [x] #3 The two endpoints are integrated under the repository contract: endpoint map, client tests, ACL classification, schema registry/goldens, generated API contract, docs, and dashboard coverage are updated. No per-reservation info metric is added.
- [x] #4 Focused reservation/collector tests cover empty inventories, unclaimed reservations, both families, and subnet resolution; `just check`, `just docs`, and `just grafana-check` pass.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Integrate the source-derived DHCPv4 and DHCPv6 searchReservation readers into the existing Kea collector and endpoint/schema contracts.
2. Export only configured-reservation gauges aggregated by resolved subnet, with no reservation identity labels.
3. Add the Kea reservation inventory dashboard panel, regenerate repository artifacts, and verify focused tests plus just gen and just check.
4. Finalize the tracker atomically, commit only OPN-0015 paths, and push main.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
BLOCKED ON A RE-DERIVATION, 2026-09-02. This task was filed on the same premise as OPN-0007 - that OPNsense 26.7 removed is_reserved from the lease rows and reservations therefore had to come from searchReservation. Wave 1 disproved that against released 26.7/26.7.3 source: get_kea_leases.py still emits is_reserved on every row and the exporter already decodes it. OPN-0007 is closed as disproved.

So the ORIGINAL justification for this collector is gone. Do not start it as written. Re-derive the case first: a reservation inventory collector may still be worth having on its own merits (reservations that have never been claimed are invisible in lease data, and hostname/description live only on the reservation), but that is a different argument for a different metric set, and the acceptance criteria below were written for the repair, not for the inventory. Either rewrite them from the inventory case or close this task.

Re-derived 2026-09-02 after OPN-0007 was closed as disproved. This task is retained only as standalone configuration inventory: released OPNsense 26.1 and 26.7.3 controllers expose both searchReservation routes, and UIModelGrid returns all configuration rows when no rowCount is supplied. Released 26.7.3 lease code starts from issued leases and consults reservations only to mark matching lease identities, so never-claimed reservations are invisible to the existing lease metrics. Scope is deliberately aggregate-only (family + configured subnet): no hostname/description/address/identity labels and no per-reservation info metric. No live searchReservation payload has been captured; implementation must first use source-derived fixtures or redacted live payloads for both families. OPN-0007 is not a dependency and must not be reopened through this work.

Wave 3 implementation complete. Released OPNsense 26.1 and 26.7 source-derived fixtures cover empty and populated DHCPv4/DHCPv6 searchReservation shapes and subnet relations. The existing Kea collector now emits only aggregate configured-reservation gauges by resolved subnet; endpoint, ACL, schema, generated documentation, and dashboard contracts are integrated. Focused Go tests passed, just gen completed with 1050/1050 dashboard metric coverage and 179 schema goldens, and just check passed including the race suite, fuzz smoke, Grafana 425-test suite, generator freshness, PromQL validation, and vulnerability scan. CodeRabbit source slices phase1-opnsense-collector and phase1-grafana completed; all critical/major findings were resolved.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added source-derived Kea DHCPv4/DHCPv6 configured-reservation inventory metrics aggregated only by resolved subnet, including never-claimed reservations, with endpoint/ACL/schema/docs/dashboard integration. Verified by focused API and collector tests, just gen, and full just check. This task is landed by the commit containing this final summary; the exact SHA is recorded in the wave report.
<!-- SECTION:FINAL_SUMMARY:END -->
