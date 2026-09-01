---
id: OPN-0045
title: Helm chart ships default resources in values.yaml
status: Parked
assignee:
  - '@codex'
created_date: '2026-08-30 09:10'
updated_date: '2026-09-01 23:42'
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
- [ ] #1 Chart default resources match the raw manifest; helm-validate clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 1 L11 plan: align the declarative deployment resource defaults with the task contract, validate rendered chart/manifests without a test-first ceremony, and stop before dependency-gated OPN-0046.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 1 staged WIP adds the chart resource defaults and keeps rendered deployment contracts valid. Helm/deployment validation and integrated just check passed; L14 found no remaining issue. Not landed because the shared code-bearing batch lacks a complete CodeRabbit review. Resume: obtain the review, commit this declarative task explicitly, integrate current origin/main, rerun just check, push, and verify exact-SHA CI.
<!-- SECTION:NOTES:END -->
