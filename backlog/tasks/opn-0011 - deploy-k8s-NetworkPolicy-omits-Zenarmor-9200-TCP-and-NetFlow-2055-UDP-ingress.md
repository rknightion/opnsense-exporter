---
id: OPN-0011
title: >-
  deploy/k8s NetworkPolicy omits Zenarmor (9200/TCP) and NetFlow (2055/UDP)
  ingress
status: To Do
assignee: []
created_date: '2026-08-30 08:30'
updated_date: '2026-08-30 09:35'
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
