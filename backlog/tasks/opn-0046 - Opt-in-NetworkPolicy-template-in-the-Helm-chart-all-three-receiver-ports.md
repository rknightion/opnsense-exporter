---
id: OPN-0046
title: Opt-in NetworkPolicy template in the Helm chart (all three receiver ports)
status: Done
assignee: []
created_date: '2026-08-30 09:10'
updated_date: '2026-09-02 03:39'
labels: []
milestone: m-5
dependencies:
  - OPN-0011
priority: medium
type: enhancement
ordinal: 602
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Chart companion to OPN-0011 (which fixes the raw manifest): an opt-in NetworkPolicy template covering scrape ingress plus syslog, Zenarmor (9200/TCP) and NetFlow (2055/UDP), each toggled with its receiver's enablement so an enabled receiver is never silently CNI-dropped.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Template gated by a values toggle; receiver ports open iff the matching receiver is enabled in values
- [x] #2 helm-validate/kubeconform clean with real schemas
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Landed the opt-in Helm NetworkPolicy and chart contract coverage in 1c3b37123c682b0037c7173e6fcf82060a66b772. CodeRabbit completed with zero findings.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added an opt-in Helm NetworkPolicy whose receiver ports follow the matching enablement values. Helm validation, kubeconform, and just check passed; exact-head CI run 33586622286 succeeded at 1c3b37123c682b0037c7173e6fcf82060a66b772.
<!-- SECTION:FINAL_SUMMARY:END -->
