---
id: OPN-0034
title: Surface gateway threshold parse failures (Warn + counter)
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 09:09'
updated_date: '2026-09-02 03:40'
labels: []
milestone: m-4
dependencies: []
priority: medium
type: enhancement
ordinal: 501
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`internal/collector/gateways.go:180-197` drops an unparseable RTT/loss threshold with a Debug-only log — invisible at default Info level; the threshold series silently vanishes. Mirror the smart.go #615 pattern: Warn log + a `gateway_threshold_parse_errors_total` counter.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Unparseable threshold produces a Warn and increments a parse-errors counter; series absence is explained
- [x] #2 Test covers a malformed threshold payload
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 1 L9 plan: read the receiver/pipeline acceptance contract, write the required focused regression first where applicable, implement only the task-owned files, return root-owned wiring precisely, and stop before OPN-0036.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 1 staged WIP surfaces gateway threshold parse failures through warnings and a counter, with tests and dashboard coverage; integrated just check passed and L14 found no remaining issue. Not landed because CodeRabbit produced no complete event. Resume: obtain a complete review, triage findings, commit explicitly, integrate current origin/main, rerun just check, push, verify exact-SHA CI, then confirm the counter with a malformed live/test payload if runtime proof is required.

Landed threshold parse warnings, a persistent monotonic parse-error counter, malformed-payload regression coverage, and a dashboard panel in 36bd99a7b4c0b2eb1b760ca9262664bfcf9c988e. CodeRabbit identified counter reset on registration; the implementation and regression were corrected before commit.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Malformed gateway thresholds now emit a warning and increment gateway_threshold_parse_errors_total while explaining the absent threshold series. Focused tests and just check passed; exact-head CI run 33587198497 succeeded at 36bd99a7b4c0b2eb1b760ca9262664bfcf9c988e.
<!-- SECTION:FINAL_SUMMARY:END -->
