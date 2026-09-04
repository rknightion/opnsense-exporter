---
id: OPN-0064
title: Account for Zenarmor connections rejected at the cap
status: Done
assignee:
  - '@codex'
created_date: '2026-09-04 05:38'
updated_date: '2026-09-04 07:26'
labels:
  - needs-triage
dependencies: []
modified_files:
  - internal/logship/zenarmor/source.go
  - internal/logship/zenarmor/source_test.go
priority: medium
type: bug
ordinal: 18000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
When the configured Zenarmor connection cap is full, the limited listener accepts each additional TCP connection and closes it immediately, then continues without a rejection counter or bounded diagnostic. A slow-connection flood can make sender writes fail or retry while every receiver metric remains healthy, hiding that the configured cap is the cause.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A listener-level regression holds the configured connection slots, attempts one more connection and observes explicit cap-rejection accounting
- [x] #2 The rejection signal is bounded and identifies the connection-cap reason without adding an unbounded label
- [x] #3 Normal accepted-connection slot release and shutdown behavior remain unchanged
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Add a failing limited-listener regression for an over-cap connection, then expose a bounded rejection counter through the existing Zenarmor receiver stats and add a rate-limited diagnostic only if the counter is insufficient for the operator path.
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Fixed by a4e0e20a. Zenarmor socket-cap refusals now increment the existing bounded rejected-record counter with reason conn_limit, with no peer label. The listener-level regression failed before the fix and passed after it, including slot reuse and shutdown. Integrated just check passed. CodeRabbit completed one pass with zero findings.
<!-- SECTION:FINAL_SUMMARY:END -->
