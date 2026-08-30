---
id: OPN-0047
title: Raw k8s manifest gets the config-check initContainer the chart already has
status: To Do
assignee: []
created_date: '2026-08-30 09:10'
labels: []
dependencies: []
priority: low
type: chore
ordinal: 47000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The chart runs a `--config.check` initContainer (`charts/opnsense2otel/templates/_helpers.tpl:34-45`); the raw manifest (`deploy/k8s/deployment.yaml`) does not. Add parity so bad config fails fast on both paths.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Raw manifest runs config-check before the main container; manifests stay valid
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
