---
id: OPN-0046
title: Opt-in NetworkPolicy template in the Helm chart (all three receiver ports)
status: To Do
assignee: []
created_date: '2026-08-30 09:10'
labels: []
dependencies:
  - OPN-0011
priority: medium
type: enhancement
ordinal: 46000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Chart companion to OPN-0011 (which fixes the raw manifest): an opt-in NetworkPolicy template covering scrape ingress plus syslog, Zenarmor (9200/TCP) and NetFlow (2055/UDP), each toggled with its receiver's enablement so an enabled receiver is never silently CNI-dropped.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Template gated by a values toggle; receiver ports open iff the matching receiver is enabled in values
- [ ] #2 helm-validate/kubeconform clean with real schemas
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
