---
id: OPN-0048
title: Troubleshooting docs for the push receivers (syslog/Zenarmor/NetFlow)
status: Parked
assignee:
  - '@codex'
created_date: '2026-08-30 09:10'
updated_date: '2026-09-01 23:42'
labels: []
milestone: m-4
dependencies: []
priority: high
type: docs
ordinal: 508
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`docs/troubleshooting.md` covers only the polling collectors; an operator whose receiver gets nothing has no entry point. Add a push-receiver section pointing at `logs_rejected_total{reason}` / `logs_shipped_total` and the per-stage parse metrics, cross-linked from the three receiver pages. Also add "nothing arrives" headings to `zenarmor-receiver.md` and `flow.md` matching `syslog-receiver.md`'s pattern (the OPNsense-side Reporting-NetFlow step is the classic misconfiguration).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 troubleshooting.md has a receiver section keyed on the real reject/ship metrics
- [ ] #2 zenarmor-receiver.md and flow.md each have a nothing-arrives heading; cross-links in place
- [ ] #3 just docs-check clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Add receiver-first troubleshooting keyed to the actual shipped/rejected/parse metrics, add nothing-arrives sections and reciprocal links across the three receiver pages, then validate docs generation without changing generated regions by hand.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 1 staged WIP adds receiver-first troubleshooting using the shipped/rejected/parse/drop metrics, nothing-arrives sections, and reciprocal receiver-page links. docs-check and integrated just check passed; post-correction L14 verified the metrics and links. Not landed because the shared code-bearing batch lacks a complete CodeRabbit review. Resume: obtain the review, commit this documentation task explicitly, integrate current origin/main, rerun just check, push, and verify exact-SHA CI.
<!-- SECTION:NOTES:END -->
