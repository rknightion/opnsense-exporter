---
id: OPN-0061
title: Fix Grafana GitSync verifier after repository ownership move
status: In Progress
assignee:
  - '@codex'
created_date: '2026-09-03 20:51'
updated_date: '2026-09-03 20:59'
labels: []
dependencies: []
priority: high
type: bug
ordinal: 15000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The dashboard sync has failed since the GitSync hub moved from the user account to the m7kni organisation. The workflow checks out and pushes m7kni/gc-gitsync-m7kni, but scripts/verify-gitsync.py still searches Grafana provisioning resources for the old repository URL, so verification aborts before checking the live dashboards. This is a local verifier defect, not a shared-workflow release issue.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The verifier locates the same GitSync repository URL that the workflow checks out and pushes
- [x] #2 A focused regression test fails for the stale owner URL and passes for the corrected canonical URL
- [ ] #3 The Grafana sync workflow completes and verifies both live dashboards after the fix is pushed
- [x] #4 just check and a completed CodeRabbit review pass
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Add a focused unit test around repository selection, centralize or correct the canonical GitSync URL without changing deployment authority, run targeted and full gates, review, push, and verify the new workflow run.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 4 lane-zero diagnosis: run 33804484167 failed because find_repository searched for the old rknightion URL while the same workflow checked out and pushed the m7kni repository. gh release list confirms v1.18.1 is still the latest shared-workflow release, but grafana-sync is a local workflow and this failure is unrelated to a reusable pin.

Test-first evidence: before correcting the URL, both focused tests failed against the stale rknightion owner. After correction, python3 -m unittest scripts/verify_gitsync_test.py -q passed 2/2. Two source-only CodeRabbit passes completed with zero findings across justfile, scripts/verify-gitsync.py, and scripts/verify_gitsync_test.py. just gen completed with no generated drift; full just check passed, including 427 Grafana tests and no called vulnerabilities. Live workflow verification remains pending the pushed commit.
<!-- SECTION:NOTES:END -->
