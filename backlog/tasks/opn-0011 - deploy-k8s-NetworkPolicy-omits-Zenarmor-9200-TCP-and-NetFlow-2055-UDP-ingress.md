---
id: OPN-0011
title: >-
  deploy/k8s NetworkPolicy omits Zenarmor (9200/TCP) and NetFlow (2055/UDP)
  ingress
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 08:30'
updated_date: '2026-09-02 01:28'
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
- [x] #1 NetworkPolicy admits all three receiver ports, each commented with its receiver and disable guidance
- [x] #2 Ports match the Deployment/container ports (no hand-transcription drift)
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Align the raw NetworkPolicy receiver ingress with the existing Deployment ports, keep receiver-specific disable guidance beside each rule, and validate the executable deployment contracts without widening into the separate Helm policy enhancement.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 1 staged WIP aligns the raw container ports, Service ports, NetworkPolicy ingress, and generated Kubernetes guide for Zenarmor TCP/9200 and NetFlow UDP/2055. deployment-test, docs-check, integrated just check, and post-correction L14 passed. Not landed because the integrated code batch has no complete CodeRabbit review. Resume: obtain the review, commit the task explicitly, integrate current origin/main, rerun just check, push, verify exact-SHA CI, then apply to a disposable cluster if live NetworkPolicy enforcement proof is desired.

Landed as 4e5bbbb75b6fb8cf230464f547bf22790e056efc. just docs regenerated the embedded Kubernetes guide; just deployment-test, just docs-check, just check-public-ips, and integrated just check passed. CodeRabbit was skipped because the change is declarative YAML plus generated documentation. Exact-head CI run 33578549881 completed successfully and ci-success passed.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added the Zenarmor 9200/TCP and NetFlow 2055/UDP container, Service, and NetworkPolicy ports with receiver-specific disable and exposure guidance; regenerated the embedded Kubernetes deployment guide. Verified deployment contracts, generated docs, the public-IP gate, just check, and exact-head CI run 33578549881. Commit: 4e5bbbb75b6fb8cf230464f547bf22790e056efc.
<!-- SECTION:FINAL_SUMMARY:END -->
