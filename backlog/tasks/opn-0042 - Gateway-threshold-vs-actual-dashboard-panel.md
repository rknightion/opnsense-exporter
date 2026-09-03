---
id: OPN-0042
title: Gateway threshold-vs-actual dashboard panel
status: Done
assignee: []
created_date: '2026-08-30 09:10'
updated_date: '2026-09-03 07:09'
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
- [x] #1 Gateway panel overlays loss/RTT thresholds; just grafana-check clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Overlay each gateway's configured high RTT and packet-loss threshold series on the existing actual-value panels, retain the existing threshold tables and alert-boundary caveat, regenerate dashboard artifacts, validate the authored blob against the completed Grafana review, run the full gate, and land as one task commit.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 2 did not start dashboard-module work because OPN-0056 could not land through the required CodeRabbit gate. Resume after applying the preserved patch, obtaining a completed review, and landing OPN-0056 first; edit `grafana/tabs/` modules and regenerate JSON through `just dashboard`.

Unblocked 2026-09-02: OPN-0056 landed on main in `a482f637`. Edit `grafana/tabs/` modules only and regenerate JSON through `just dashboard`; never hand-edit `dashboard.json`.

Overlaid each gateway's configured high RTT and high packet-loss threshold series on the existing actual-value timeseries. The packet-loss description explicitly distinguishes the configured diagnostic threshold from the alert's fixed 20% boundary. The authored module exactly matches the completed phase1-grafana CodeRabbit slice (review_completed, zero findings after fixes). No new unit test was added because this is declarative dashboard configuration; generation, PromQL validation, and the full repository gate are the proportionate checks. just gen completed with 1,052/1,052 dashboard coverage and 179 schemas; just check passed, including 427 Grafana tests and 1,208 Prometheus target validations.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added configured high-threshold overlays to gateway RTT and packet-loss panels, with the alert-boundary caveat preserved. Generated dashboard artifacts and the full just check gate passed.
<!-- SECTION:FINAL_SUMMARY:END -->
