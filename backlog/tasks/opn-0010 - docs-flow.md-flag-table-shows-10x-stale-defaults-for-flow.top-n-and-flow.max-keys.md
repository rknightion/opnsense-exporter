---
id: OPN-0010
title: >-
  docs/flow.md flag table shows 10x-stale defaults for --flow.top-n and
  --flow.max-keys
status: Parked
assignee:
  - '@codex'
created_date: '2026-08-30 08:30'
updated_date: '2026-09-01 23:42'
labels: []
milestone: m-0
dependencies: []
priority: low
type: bug
ordinal: 109
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`docs/flow.md:35-36` shows `--flow.top-n`/`--flow.max-keys` defaults as 1000/2500; code defaults are 10000/100000 (`internal/options/flow.go:81,93`). `docs/configuration.md` (docgen-owned) agrees with code, so only the hand-written flow.md table drifted. Operators reading flow.md underestimate default cardinality/memory by 10x. Consider making that table docgen-owned so it cannot drift again.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 flow.md defaults match code
- [ ] #2 Either the table is docgen-owned or a doc-lint check pins these values
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Verify the live flow defaults, make the hand-written table non-drifting with the narrowest existing documentation mechanism, and validate the documentation gate.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 1 staged WIP corrects the flow defaults to 10000 and 100000 and adds a documentation drift guard. docs-check and the integrated just check passed; post-correction L14 verified the values and guard. Not landed because the shared code-bearing batch lacks a complete CodeRabbit review. Resume: after CodeRabbit clears the staged batch, commit this documentation task with explicit pathspecs, integrate current origin/main, rerun the gate, push, and verify exact-SHA CI.
<!-- SECTION:NOTES:END -->
