---
id: OPN-0017
title: 'Complete FRR coverage: BGP route tables + BFD summary'
status: To Do
assignee: []
created_date: '2026-08-30 09:08'
updated_date: '2026-08-30 09:35'
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
- [ ] #1 BGP route-table aggregate metrics (v4+v6) and BFD summary exported
- [ ] #2 No per-prefix label cardinality
- [ ] #3 AGENTS.md new-collector steps complete; gates clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
