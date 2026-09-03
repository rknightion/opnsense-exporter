---
id: OPN-0022
title: 'pfTop / top-talkers diagnostics collector, capped top-N'
status: Parked
assignee:
  - '@codex'
created_date: '2026-08-30 09:08'
updated_date: '2026-09-03 09:37'
labels: []
milestone: m-3
dependencies: []
priority: medium
type: feature
ordinal: 403
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
DECIDED 2026-08-30: build, opt-in, capped top-N (Rob). `api/diagnostics/firewall/queryPfTop` + `api/diagnostics/traffic/top`: top-N states/talkers for boxes WITHOUT the NetFlow receiver (flow logs already cover the rest). Use the existing boundedinventory/cappedcounter pattern for cardinality; `exporter.enable-*` (default-off) flag family per AGENTS.md step 4 since this has extra per-scrape cost and cardinality.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Opt-in collector exports capped top-N talkers/states with a documented, bounded cardinality ceiling
- [ ] #2 Docs state the NetFlow-receiver overlap and when to prefer which
- [ ] #3 AGENTS.md new-collector steps complete; gates clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 3 park: the current task does not freeze the exact top-N ranking key, tie-breaking, state/talker merge behavior, or overflow aggregation semantics. Resume by recording those bounded-cardinality semantics on this task first; then implement the default-off pfTop diagnostics collector and document its overlap with the NetFlow receiver. Existing internal/flow/toptalkers.go is not the requested API collector.
<!-- SECTION:NOTES:END -->
