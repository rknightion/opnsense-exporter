---
id: OPN-0045
title: Helm chart ships default resources in values.yaml
status: To Do
assignee: []
created_date: '2026-08-30 09:10'
labels: []
dependencies: []
priority: medium
type: chore
ordinal: 45000
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
