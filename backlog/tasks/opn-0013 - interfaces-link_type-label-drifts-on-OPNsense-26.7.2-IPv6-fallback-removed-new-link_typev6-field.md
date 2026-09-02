---
id: OPN-0013
title: >-
  interfaces link_type label drifts on OPNsense 26.7.2: IPv6 fallback removed,
  new link_typev6 field
status: In Progress
assignee:
  - '@codex'
created_date: '2026-08-30 08:30'
updated_date: '2026-09-02 01:38'
labels: []
milestone: m-0
dependencies: []
priority: low
type: bug
ordinal: 111
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OPNsense 26.7.2 changed `api/interfaces/overview/interfaces_info` (upstream `Interfaces/Api/OverviewController.php`): `link_type` no longer falls back to the IPv6 configuration and a new sibling `link_typev6` was added. On v6-only interfaces our `link_type` label (decoded at `opnsense/interfaces.go:360`, emitted at `internal/collector/interfaces.go:177`) flips to `none` on 26.7.2+ where it previously reported the v6 link type. Verdict shape: chase — tolerant read of `link_typev6` alongside the legacy field, resolved by payload shape across the 26.1+26.7 window. Found by upstream API-surface research 2026-08-30; not yet proven against a live 26.7.2 box.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Behaviour proven against a 26.7.2-shape payload (fixture derived from upstream source branches or live capture)
- [ ] #2 v6-only interfaces keep a meaningful link_type label on both payload generations, without version sniffing
- [ ] #3 Schema registry/exemptions updated as needed; just schemas clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 1 execution: derive the 26.7.2 response branch from upstream source already cited by the task; write a failing tolerant-reader regression for v6-only old and new payload shapes; add link_typev6 alongside the legacy field and resolve a stable effective label without version sniffing; request any root-owned schema/exemption updates exactly; run focused interfaces tests.
<!-- SECTION:PLAN:END -->
