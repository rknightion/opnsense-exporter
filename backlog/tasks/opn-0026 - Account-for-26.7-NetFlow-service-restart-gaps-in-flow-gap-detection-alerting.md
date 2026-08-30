---
id: OPN-0026
title: Account for 26.7 NetFlow-service restart gaps in flow gap-detection/alerting
status: To Do
assignee: []
created_date: '2026-08-30 09:09'
updated_date: '2026-08-30 09:35'
labels: []
milestone: m-2
dependencies: []
priority: low
type: task
ordinal: 307
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
26.7 stops the NetFlow service before config reloads, so brief flow-export gaps are now expected behaviour on config changes. Review internal/flow gap handling and any Grafana alert thresholds keyed on flow arrival so a config reload does not page; document the expectation in docs/flow.md.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Config-reload-length flow gaps do not fire alerts; behaviour documented
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
