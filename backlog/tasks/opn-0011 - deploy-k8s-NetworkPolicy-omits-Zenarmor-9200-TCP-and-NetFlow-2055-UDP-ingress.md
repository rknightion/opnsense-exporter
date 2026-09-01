---
id: OPN-0011
title: >-
  deploy/k8s NetworkPolicy omits Zenarmor (9200/TCP) and NetFlow (2055/UDP)
  ingress
status: Parked
assignee:
  - '@codex'
created_date: '2026-08-30 08:30'
updated_date: '2026-09-01 23:42'
labels: []
milestone: m-0
dependencies: []
priority: medium
type: bug
ordinal: 108
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`deploy/k8s/networkpolicy.yaml:42` opens ingress for the syslog receiver only. Zenarmor (9200/TCP) and NetFlow (2055/UDP) are exposed by the Deployment and documented, but under the shipped policy enabling either receiver has its traffic silently dropped by the CNI — the exact failure mode the file's own comment warns about for syslog. Fix the raw manifest; the related enhancement (an opt-in NetworkPolicy template in the Helm chart) is tracked separately in candidates, not here.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 NetworkPolicy admits all three receiver ports, each commented with its receiver and disable guidance
- [ ] #2 Ports match the Deployment/container ports (no hand-transcription drift)
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Align the raw NetworkPolicy receiver ingress with the existing Deployment ports, keep receiver-specific disable guidance beside each rule, and validate the executable deployment contracts without widening into the separate Helm policy enhancement.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 1 staged WIP aligns the raw container ports, Service ports, NetworkPolicy ingress, and generated Kubernetes guide for Zenarmor TCP/9200 and NetFlow UDP/2055. deployment-test, docs-check, integrated just check, and post-correction L14 passed. Not landed because the integrated code batch has no complete CodeRabbit review. Resume: obtain the review, commit the task explicitly, integrate current origin/main, rerun just check, push, verify exact-SHA CI, then apply to a disposable cluster if live NetworkPolicy enforcement proof is desired.
<!-- SECTION:NOTES:END -->
