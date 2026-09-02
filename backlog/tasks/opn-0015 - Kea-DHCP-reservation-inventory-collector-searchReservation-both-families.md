---
id: OPN-0015
title: >-
  Kea DHCP reservation inventory counts for unclaimed reservations (both
  families)
status: To Do
assignee: []
created_date: '2026-08-30 09:08'
updated_date: '2026-09-02 06:16'
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
- [ ] #1 Source-derived fixtures or redacted live captures prove the empty and populated `searchReservation` response shapes for DHCPv4 and DHCPv6 on the supported generations, including the subnet relation used by this collector; no field is modelled from a guessed payload shape.
- [ ] #2 The existing Kea collector exports complete configured-reservation counts for DHCPv4 and DHCPv6, with a resolved configured-subnet dimension. Counts include reservations with no current lease and are not derived from lease rows, `is_reserved`, or a paginated subset.
- [ ] #3 The two endpoints are integrated under the repository contract: endpoint map, client tests, ACL classification, schema registry/goldens, generated API contract, docs, and dashboard coverage are updated. No per-reservation info metric is added.
- [ ] #4 Focused reservation/collector tests cover empty inventories, unclaimed reservations, both families, and subnet resolution; `just check`, `just docs`, and `just grafana-check` pass.
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

Re-derived 2026-09-02 after OPN-0007 was closed as disproved. This task is retained only as standalone configuration inventory: released OPNsense 26.1 and 26.7.3 controllers expose both searchReservation routes, and UIModelGrid returns all configuration rows when no rowCount is supplied. Released 26.7.3 lease code starts from issued leases and consults reservations only to mark matching lease identities, so never-claimed reservations are invisible to the existing lease metrics. Scope is deliberately aggregate-only (family + configured subnet): no hostname/description/address/identity labels and no per-reservation info metric. No live searchReservation payload has been captured; implementation must first use source-derived fixtures or redacted live payloads for both families. OPN-0007 is not a dependency and must not be reopened through this work.
<!-- SECTION:NOTES:END -->
