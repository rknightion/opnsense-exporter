---
id: OPN-0042
title: Gateway threshold-vs-actual dashboard panel
status: To Do
assignee: []
created_date: '2026-08-30 09:10'
labels: []
dependencies: []
priority: medium
type: enhancement
ordinal: 42000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
No panel shows gateway loss/RTT against the alert's own thresholds (`grafana/alerts/build_rules.py:561`); operators do the comparison by hand. Add threshold overlay(s) to the gateway tab. If OPN-0034 lands threshold metrics as series, use those; otherwise pin the alert constants.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Gateway panel overlays loss/RTT thresholds; just grafana-check clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
