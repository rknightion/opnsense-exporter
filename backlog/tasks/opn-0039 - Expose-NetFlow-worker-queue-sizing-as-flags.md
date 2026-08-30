---
id: OPN-0039
title: Expose NetFlow worker/queue sizing as flags
status: To Do
assignee: []
created_date: '2026-08-30 09:09'
updated_date: '2026-08-30 09:35'
labels: []
milestone: m-4
dependencies: []
priority: low
type: enhancement
ordinal: 506
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`internal/flow/netflow/listener.go:20-23` hardcodes 4 workers / 1024 queue; drops are counted but not tunable. Add two flags with the current values as defaults.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Worker count and queue depth configurable; defaults unchanged; just docs regenerated
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
