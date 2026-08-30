---
id: OPN-0020
title: IPsec per-lease collector (api/ipsec/leases/search)
status: To Do
assignee: []
created_date: '2026-08-30 09:08'
labels: []
dependencies: []
priority: low
type: feature
ordinal: 20000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
We fetch IPsec lease pools only; `api/ipsec/leases/search` adds per-lease mobile-client visibility (who holds which address from which pool). Aggregate counts as metrics; keep per-client identity out of labels (bounded cardinality — count by pool, not by client).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Lease counts per pool exported; no unbounded per-client labels
- [ ] #2 AGENTS.md new-collector steps complete; gates clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
