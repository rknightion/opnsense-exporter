---
id: OPN-0056
title: Correct `just gen` dependency order for new catalogue metrics
status: To Do
assignee: []
created_date: '2026-09-02 03:37'
labels:
  - needs-triage
dependencies: []
type: bug
ordinal: 10000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The aggregate generator currently runs dashboard generation before documentation/catalogue regeneration. When a change adds a metric, the dashboard coverage gate reads the stale catalogue and `just gen` fails even though the dashboard module already references the new metric. The observed recovery was to run `just docs` before `just gen`; the aggregate recipe should encode that dependency order itself.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 `just gen` regenerates the metric catalogue before any dashboard coverage validation that consumes it
- [ ] #2 A clean tree containing a newly added catalogue metric and matching dashboard panel completes `just gen` without requiring a preparatory command
- [ ] #3 `just --dump --dump-format json` and `just --fmt --check` both exit zero
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
