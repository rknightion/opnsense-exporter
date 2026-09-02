---
id: OPN-0040
title: 'Operator console: receivers/flow visibility tab'
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 09:10'
updated_date: '2026-09-02 03:39'
labels: []
milestone: m-4
dependencies: []
priority: medium
type: enhancement
ordinal: 507
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The console's entire push-pipeline view is `LogThroughput() (shipped, dropped)` plus the ifindex map (`internal/webui/server.go:80-86`), while the pipeline exports per-reason rejects, parse stages, correlator occupancy, rollup capping. Add a Logs/Flow tab fed from the passive metricsnap capture the Cardinality tab already reads — never Gather() on the live registry (webui invariant).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Console tab shows per-reason rejects, parse stages, correlator occupancy from metricsnap only
- [x] #2 No live-registry Gather introduced (existing invariant test still holds)
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 1 L10 plan: implement and test only the first console task in its owned web UI files, preserve passive snapshot-only handlers, return root wiring if any, and stop before OPN-0048.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 1 staged WIP adds passive receiver/flow pipeline visibility to the operator console without gathering the live registry; focused web UI tests and integrated just check passed. Post-correction L14 found no remaining issue. Not landed because CodeRabbit produced no complete event. Resume: obtain a complete review, commit explicitly, integrate current origin/main, rerun just check, push, verify exact-SHA CI, then exercise the console route in a deployed browser session for person-visible proof.

Landed passive metricsnap-based Logs and Flow views at the existing console routes in 9ff61e58fd88a4d52c6f145de7ed6a687d3e5c4b. CodeRabbit returned zero findings.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added passive receiver and flow pipeline visibility without introducing a live-registry gather. Focused web UI tests and just check passed; exact-head CI run 33584279038 succeeded at 9ff61e58fd88a4d52c6f145de7ed6a687d3e5c4b.
<!-- SECTION:FINAL_SUMMARY:END -->
