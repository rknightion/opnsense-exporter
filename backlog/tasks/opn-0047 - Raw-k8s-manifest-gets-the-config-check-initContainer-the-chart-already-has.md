---
id: OPN-0047
title: Raw k8s manifest gets the config-check initContainer the chart already has
status: Done
assignee: []
created_date: '2026-08-30 09:10'
updated_date: '2026-09-02 03:39'
labels: []
milestone: m-5
dependencies: []
priority: low
type: chore
ordinal: 603
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The chart runs a `--config.check` initContainer (`charts/opnsense2otel/templates/_helpers.tpl:34-45`); the raw manifest (`deploy/k8s/deployment.yaml`) does not. Add parity so bad config fails fast on both paths.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Raw manifest runs config-check before the main container; manifests stay valid
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Landed raw-manifest config validation parity and regenerated Kubernetes documentation in 513dc385073848b9392ca25b9718ad9f46c49399. CodeRabbit was skipped because the change is declarative YAML plus generated docs.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added the config-check initContainer to the raw Kubernetes manifest and validated deployment contracts. just check passed; exact-head CI run 33586045688 succeeded at 513dc385073848b9392ca25b9718ad9f46c49399.
<!-- SECTION:FINAL_SUMMARY:END -->
