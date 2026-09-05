---
id: OPN-0089
title: Count tolerated ZeroTier per-network 404 fetch failures
status: Done
assignee:
  - '@codex'
created_date: '2026-09-05 18:55'
updated_date: '2026-09-05 19:10'
labels:
  - needs-triage
dependencies: []
priority: medium
type: bug
ordinal: 43000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
ZeroTier per-network info tolerates a stale UUID 404 and returns a successful collector poll. Its observer collapses the dynamic route to a static plugin-gated path, so pollRequestObserver misclassifies the resource failure as plugin absence and leaves partial_fetch_failures_total unchanged despite missing runtime metrics.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A successful ZeroTier search followed by a tolerated per-network info 404 leaves the poll successful but increments its partial-fetch failure count
- [x] #2 A genuine static plugin-absent 404 remains excluded and metric endpoint labels remain bounded
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Add a failing-before scheduler regression using the real ZeroTier client path. Require the original APICallError endpoint to match the observed static endpoint before excluding a plugin 404; preserve static endpoint attribution and existing plugin-absence behavior. Run targeted scheduler tests and the final integrated gate.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Real ZeroTier tolerated dynamic info 404 regression failed before: partial_fetch_failures_total{collector=zerotier} = 0, want 1. Focused race tests passed after: ok github.com/rknightion/opnsense2otel/v4/internal/collector 1.385s. Static and cached plugin absence remain excluded; request labels remain bounded.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Landed in d2549a5dd314f40bdfaf6ad56f056dcde4821e0a. Targeted evidence recorded above; full just check passed (exit 0), terminal: Your code is affected by 0 vulnerabilities. No generated artifacts changed, so just gen not applicable. Source-only CodeRabbit completed review_completed across 13 files, findings=1; one pass. The sole minor finding concerned the intentionally reversed backup test-server branch and was retained with the regression rationale recorded on OPN-0086. No critical or major findings.
<!-- SECTION:FINAL_SUMMARY:END -->
