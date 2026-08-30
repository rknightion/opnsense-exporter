---
id: OPN-0010
title: >-
  docs/flow.md flag table shows 10x-stale defaults for --flow.top-n and
  --flow.max-keys
status: To Do
assignee: []
created_date: '2026-08-30 08:30'
updated_date: '2026-08-30 09:35'
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
