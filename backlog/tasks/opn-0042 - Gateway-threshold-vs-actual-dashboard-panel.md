---
id: OPN-0042
title: Gateway threshold-vs-actual dashboard panel
status: Parked
assignee: []
created_date: '2026-08-30 09:10'
updated_date: '2026-09-02 07:02'
labels: []
milestone: m-4
dependencies:
  - OPN-0034
priority: medium
type: enhancement
ordinal: 502
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 2 did not start dashboard-module work because OPN-0056 could not land through the required CodeRabbit gate. Resume after applying the preserved patch, obtaining a completed review, and landing OPN-0056 first; edit `grafana/tabs/` modules and regenerate JSON through `just dashboard`.
<!-- SECTION:NOTES:END -->
