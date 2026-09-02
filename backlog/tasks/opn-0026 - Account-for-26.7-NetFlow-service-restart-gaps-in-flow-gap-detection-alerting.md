---
id: OPN-0026
title: Account for 26.7 NetFlow-service restart gaps in flow gap-detection/alerting
status: Done
assignee: []
created_date: '2026-08-30 09:09'
updated_date: '2026-09-02 06:49'
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
- [x] #1 Config-reload-length flow gaps do not fire alerts; behaviour documented
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 2 L11: inspect current NetFlow gap metrics and alert thresholds, establish whether a configuration-reload-length restart can page, document the expected 26.7 restart gap, and change no runtime or alert logic unless the existing threshold is demonstrably unsafe. Documentation-only lane.
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Documented the expected OPNsense 26.7 NetFlow restart gap and proved from the existing rule contract that OPNsenseNetFlowHookDead requires 45 minutes of silence plus traffic evidence and a 5-minute hold, so a reload-length gap cannot page. Landed in commit e0309efc. Verified with `just docs-check </dev/null`: doclint passed and all generated docs were current. CodeRabbit was deliberately skipped because this was documentation-only.
<!-- SECTION:FINAL_SUMMARY:END -->
