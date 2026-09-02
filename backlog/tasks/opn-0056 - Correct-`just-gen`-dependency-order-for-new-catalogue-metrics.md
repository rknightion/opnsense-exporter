---
id: OPN-0056
title: Correct `just gen` dependency order for new catalogue metrics
status: Done
assignee:
  - '@codex'
created_date: '2026-09-02 03:37'
updated_date: '2026-09-02 15:53'
labels:
  - needs-triage
dependencies: []
priority: medium
type: bug
ordinal: 10000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The aggregate generator currently runs dashboard generation before documentation/catalogue regeneration. When a change adds a metric, the dashboard coverage gate reads the stale catalogue and `just gen` fails even though the dashboard module already references the new metric. The observed recovery was to run `just docs` before `just gen`; the aggregate recipe should encode that dependency order itself.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 `just gen` regenerates the metric catalogue before any dashboard coverage validation that consumes it
- [x] #2 A clean tree containing a newly added catalogue metric and matching dashboard panel completes `just gen` without requiring a preparatory command
- [x] #3 `just --dump --dump-format json` and `just --fmt --check` both exit zero
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 2 L1: inspect the aggregate generator dependency graph, add regression coverage for a fresh catalogue metric plus dashboard panel, correct the dependency order, and run focused justfile validation.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Decision, Rob 2026-09-02: fix this BEFORE the next metric-bearing task. It already cost wave 1 a detour on OPN-0034, and every collector in the M3/M4 train adds catalogue metrics, so the train would hit it repeatedly.

Wave 2 implementation and regression are complete and `just gen` plus the full indexed `just check` passed. Landing is blocked solely by the hard CodeRabbit gate: both permitted reviews failed during connection with `WebSocket closed` and emitted no complete event. Preserved in `codex/wip-wave2-coderabbit-blocked.patch`. Resume by applying that patch on current main, rerunning `just check`, obtaining one completed CodeRabbit review, then commit OPN-0056 first.

Landed on main in `a482f637`. `gen` now runs docs -> dashboard -> rules -> docs -> schemas: the first docs pass refreshes the metric catalogue before dashboard coverage reads it, the second refreshes dashboard and rule statistics after those generators have produced their artifacts. `GeneratorOrderTest` in `grafana/tests/test_build_dashboard.py` pins the order against `just --dry-run gen` and skips only when just is absent from PATH, which cannot happen in CI because the gate is reached through just itself. `just check` green at the landed tree.
<!-- SECTION:NOTES:END -->
