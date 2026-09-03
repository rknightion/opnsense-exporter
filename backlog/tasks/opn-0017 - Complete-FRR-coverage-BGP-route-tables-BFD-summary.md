---
id: OPN-0017
title: 'Complete FRR coverage: BGP route tables + BFD summary'
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 09:08'
updated_date: '2026-09-03 08:52'
labels: []
milestone: m-3
dependencies: []
priority: medium
type: feature
ordinal: 401
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Add `api/quagga/diagnostics/searchBgproute4`, `searchBgproute6` and `bfdsummary` to the existing quagga collector family (we already cover BGP neighbors/summary, OSPF, BFD counters/neighbors). Route-table size/prefix counts need cardinality care — export aggregates, not per-prefix series.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 BGP route-table aggregate metrics (v4+v6) and BFD summary exported
- [x] #2 No per-prefix label cardinality
- [x] #3 AGENTS.md new-collector steps complete; gates clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Add source-derived GET fetchers for FRR BGP IPv4/IPv6 route tables and BFD summary, reducing route rows to aggregate counts and bounded BFD status/identity metrics without prefix labels. 2. Wire the three endpoints into the client, plugin 404 cache, ACL evidence, schema registry, and schema goldens while preserving concurrent lanes. 3. Add focused client and collector tests, FRR dashboard panels, regenerate docs/dashboard artifacts as required, and run targeted checks plus just check. 4. Finalize the task only after objective acceptance evidence and a reviewed exact diff.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Root integration registered the three source-derived GET routes, plugin-absence cache and ACL semantics, structure-only schemas, aggregate-only BGP route metrics, bounded BFD summary status labels, opt-in route polling, and independently gated Grafana panels. Focused client and collector tests passed. just gen produced 67 collectors, 1,059/1,059 dashboard coverage and 185 schemas. CodeRabbit completed a ten-file source slice with one valid minor dashboard-sentinel finding; the fix was covered by a second one-file review_completed slice with zero findings. just check passed, including the full race suite, 427 Grafana tests, 1,216 Prometheus targets, 80 manifests and no called vulnerabilities.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Completed FRR BGP route-table aggregate and BFD summary coverage without per-prefix labels. Verified against upstream controller and FRR source, focused tests, two completed source-only CodeRabbit slices, just gen and the full just check gate.
<!-- SECTION:FINAL_SUMMARY:END -->
