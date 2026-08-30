---
id: OPN-0040
title: 'Operator console: receivers/flow visibility tab'
status: To Do
assignee: []
created_date: '2026-08-30 09:10'
updated_date: '2026-08-30 09:35'
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
- [ ] #1 Console tab shows per-reason rejects, parse stages, correlator occupancy from metricsnap only
- [ ] #2 No live-registry Gather introduced (existing invariant test still holds)
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
