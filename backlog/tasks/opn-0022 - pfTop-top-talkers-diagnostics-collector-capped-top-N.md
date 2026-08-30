---
id: OPN-0022
title: 'pfTop / top-talkers diagnostics collector, capped top-N'
status: To Do
assignee: []
created_date: '2026-08-30 09:08'
labels: []
dependencies: []
priority: medium
type: feature
ordinal: 22000
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
