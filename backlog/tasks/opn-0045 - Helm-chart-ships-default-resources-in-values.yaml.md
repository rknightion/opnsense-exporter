---
id: OPN-0045
title: Helm chart ships default resources in values.yaml
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 09:10'
updated_date: '2026-09-02 03:39'
labels: []
milestone: m-5
dependencies: []
priority: medium
type: chore
ordinal: 601
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`charts/opnsense2otel/values.yaml:33` ships `resources: {}` while the raw manifest ships 64Mi/100m-128Mi/500m (`deploy/k8s/deployment.yaml:100-106`). Give the chart the same defaults (still overridable).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Chart default resources match the raw manifest; helm-validate clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 1 L11 plan: align the declarative deployment resource defaults with the task contract, validate rendered chart/manifests without a test-first ceremony, and stop before dependency-gated OPN-0046.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 1 staged WIP adds the chart resource defaults and keeps rendered deployment contracts valid. Helm/deployment validation and integrated just check passed; L14 found no remaining issue. Not landed because the shared code-bearing batch lacks a complete CodeRabbit review. Resume: obtain the review, commit this declarative task explicitly, integrate current origin/main, rerun just check, push, and verify exact-SHA CI.

Integrated commit a19057783e28d8fcada4cbb2188b30f6db5a82f9 gives the chart the raw-manifest resource defaults. CodeRabbit was skipped because the change is declarative YAML. Its exact-head CI attempt 33583303283 was cancelled by the next main push; descendant exact-head run 33583442198 at 3090b8cffabe39f2241fffd6340dc773277b8632 succeeded with the commit included.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Aligned Helm resource defaults with the raw manifest and validated the rendered chart. just check passed; descendant exact-head CI 33583442198 succeeded with commit a19057783e28d8fcada4cbb2188b30f6db5a82f9 included.
<!-- SECTION:FINAL_SUMMARY:END -->
