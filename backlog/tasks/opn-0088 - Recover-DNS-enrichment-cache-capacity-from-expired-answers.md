---
id: OPN-0088
title: Recover DNS enrichment cache capacity from expired answers
status: Done
assignee:
  - '@codex'
created_date: '2026-09-05 18:55'
updated_date: '2026-09-05 19:10'
labels:
  - needs-triage
dependencies: []
priority: high
type: bug
ordinal: 42000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
DNSCache Put rejects a new key at capacity before removing expired unrelated entries. Expiry currently occurs only when Lookup visits that exact key. A cache filled by one-off answers can therefore reject every fresh answer indefinitely after all entries expire, losing domain enrichment without recovering capacity.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A new answer can occupy capacity held by expired entries even when those keys were never looked up
- [x] #2 Unexpired entries retain stop-insert protection and rejection counters count only actual refused insertions
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Add a deterministic failing-before expired-full-cache Put regression; reclaim expired entries only at new-key capacity pressure using the existing caller clock and TTL boundary, without LRU eviction or a full scan on every ordinary Put; retain existing unexpired-cap tests and run focused race checks.

Integration refinement: avoid scanning a full, entirely live cache on every rejected new answer. Track a conservative earliest expiry and scan only when caller time passes it; recompute that bound during reclamation. Updates may leave an early stale bound (one harmless scan), but must never leave a late bound that hides expired capacity. Preserve the existing strict age > ttl boundary.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Expired-capacity regression failed before with Entries:2 and Rejected:1. Focused DNS race tests passed after the repair and root earliest-expiry refinement. No throughput or performance measurement claimed.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Landed in d2549a5dd314f40bdfaf6ad56f056dcde4821e0a. Targeted evidence recorded above; full just check passed (exit 0), terminal: Your code is affected by 0 vulnerabilities. No generated artifacts changed, so just gen not applicable. Source-only CodeRabbit completed review_completed across 13 files, findings=1; one pass. The sole minor finding concerned the intentionally reversed backup test-server branch and was retained with the regression rationale recorded on OPN-0086. No critical or major findings.
<!-- SECTION:FINAL_SUMMARY:END -->
