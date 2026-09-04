---
id: OPN-0075
title: Correct false manual flow and Zenarmor runtime contracts
status: Done
assignee:
  - '@codex'
created_date: '2026-09-04 12:43'
updated_date: '2026-09-04 18:22'
labels: []
dependencies: []
modified_files:
  - docs/zenarmor-receiver.md
  - docs/flow.md
  - docs/log-shipping.md
priority: medium
type: docs
ordinal: 29000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
A contract audit found four manual-guide claims that disagree with runtime: Zenarmor family aliases that the parser rejects, an unlimited flow-log default that is actually 10000 per minute, a flow-log gate omitting exporter.disable-flow, and derived-counter scope overstated as every Zenarmor document.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Zenarmor family selection documents only the accepted wire tokens unless runtime normalization is intentionally added
- [x] #2 The flow guide reports the actual 10000-per-minute default
- [x] #3 Flow-log enablement names exporter.disable-flow as a required gate
- [x] #4 Derived-counter scope matches family filtering, self-traffic filtering, parse-failure and exclusion order
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Correct only the four manual documentation claims, run doc lint or the repository gate, and skip code tests because runtime behavior is unchanged.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Documentation-only contract repair committed at 2389ac3b. just docs-check and final just check passed; CodeRabbit was skipped for this docs-only lane.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Corrected at 2389ac3b. The manuals now name only accepted Zenarmor wire tokens, the real 10000-per-minute flow-log default, the exporter.disable-flow gate, and the actual derived-counter admission order. Generated-doc and full repository gates passed.
<!-- SECTION:FINAL_SUMMARY:END -->
