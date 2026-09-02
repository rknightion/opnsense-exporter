---
id: OPN-0013
title: >-
  interfaces link_type label drifts on OPNsense 26.7.2: IPv6 fallback removed,
  new link_typev6 field
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 08:30'
updated_date: '2026-09-02 02:00'
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
- [x] #1 Behaviour proven against a 26.7.2-shape payload (fixture derived from upstream source branches or live capture)
- [x] #2 v6-only interfaces keep a meaningful link_type label on both payload generations, without version sniffing
- [x] #3 Schema registry/exemptions updated as needed; just schemas clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 1 execution: derive the 26.7.2 response branch from upstream source already cited by the task; write a failing tolerant-reader regression for v6-only old and new payload shapes; add link_typev6 alongside the legacy field and resolve a stable effective label without version sniffing; request any root-owned schema/exemption updates exactly; run focused interfaces tests.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Landed as 8c6ea64ca026ea6a6f166c206cf31a25b4e7bc4f. Upstream stable/26.1 source proves the legacy IPv6 fallback and tag 26.7.2 source proves separate link_type/link_typev6 output. The fail-first regression reproduced link_type=none for the new v6-only shape; the tolerant reader now preserves IPv4 precedence and uses a non-none link_typev6 without version sniffing. just schemas added only rows[].link_typev6:string, focused tests and just check passed, and CodeRabbit completed with zero findings. Exact-head CI run 33581026630 completed successfully and ci-success passed. Live 26.7.2 capture was unavailable; the fixture is source-derived.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added source-derived tolerant reading for the OPNsense 26.7.2 link_typev6 field while preserving the historical IPv4-first label contract, plus old/new-shape regression coverage and the regenerated structure schema. Verified focused tests, just schemas, just check, zero-finding CodeRabbit review, and exact-head CI run 33581026630. Commit: 8c6ea64ca026ea6a6f166c206cf31a25b4e7bc4f.
<!-- SECTION:FINAL_SUMMARY:END -->
