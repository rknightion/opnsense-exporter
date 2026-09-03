---
id: OPN-0020
title: IPsec per-lease collector (api/ipsec/leases/search)
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 09:08'
updated_date: '2026-09-03 09:17'
labels: []
milestone: m-3
dependencies: []
priority: low
type: feature
ordinal: 404
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
We fetch IPsec lease pools only; `api/ipsec/leases/search` adds per-lease mobile-client visibility (who holds which address from which pool). Aggregate counts as metrics; keep per-client identity out of labels (bounded cardinality — count by pool, not by client).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Lease counts per pool exported; no unbounded per-client labels
- [x] #2 AGENTS.md new-collector steps complete; gates clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Verify the current IPsec pool collector against this task acceptance contract; confirm it exports online/offline lease counts only by bounded pool dimensions from the existing list_leases.py-backed response; avoid adding the redundant leases/search call or duplicate metric family; run focused IPsec pool tests, just gen and just check; record the supersession and finalize as a tracker-only task.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Reconciled the task against current main before adding code. The existing IPsec collector already exports online and offline lease counts per pool as opnsense_ipsec_pool_leases_online and opnsense_ipsec_pool_leases_offline with only bounded pool and net labels. FetchIPsecPools consumes the leases/pools response produced by the same list_leases.py backend as leases/search, and the existing optional per-user metric is separately default-off. Adding the preserved ipsec_leases collector would duplicate the accepted signal and add a redundant firewall API call, so no source change was made. Verification: just test IPsecCollector_Update_Pools and just test FetchIPsecPools passed; just gen was clean; just check passed including 427 Grafana tests, 1,220 Prometheus targets, 80 manifests and no called vulnerabilities. CodeRabbit was skipped because this is tracker-only reconciliation with no source diff.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Closed as already satisfied by the existing IPsec pool metrics: online/offline lease counts are exported per bounded pool and network labels from the shared list_leases.py payload, with per-user identity excluded from the always-on series. Avoided a duplicate collector and extra API call. Focused pool/client tests, just gen and the full just check gate passed; no code review was required for the tracker-only change.
<!-- SECTION:FINAL_SUMMARY:END -->
