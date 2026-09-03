---
id: OPN-0016
title: 'Gateway groups collector (api/routing/groupsettings, new in 26.7)'
status: Done
assignee: []
created_date: '2026-08-30 09:08'
updated_date: '2026-09-03 08:12'
labels: []
milestone: m-2
dependencies: []
priority: medium
type: feature
ordinal: 302
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
New 26.7 core surface (`Routing/Api/GroupSettingsController.php`): gateway failover-group topology — which gateways sit in which group/tier. Pairs with existing gateway status metrics to answer "is this failover group degraded". Plugin/version-gated behaviour: on pre-26.7 boxes the endpoint 404s — treat as feature-absent per the plugin-gated pattern.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Group membership/tier exported as metrics joinable with existing gateway status series
- [x] #2 404 on pre-26.7 handled as feature-absent (negative-cacheable), collector silent
- [x] #3 AGENTS.md new-collector steps complete; gates clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Reconstruct the source-derived gateway-group collector, wire its 26.7 feature-absence contract through the root-owned endpoint/schema/cache/collector registries, add dashboard coverage, regenerate artifacts, run targeted and full gates, complete sliced CodeRabbit review, then finalize and land one green commit.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Root integration added the 26.7 gatewayGroups GET route, semantic and negative-cacheable 404 handling, schema/ACL registration, cold polling, default-on disable switch, main wiring, generated docs/schema, and dashboard coverage. CodeRabbit pass 1 found a major join defect: group address was configured gateway while gateways_status address was monitor address and disabled gateways emitted no status. Failing active/disabled join tests reproduced both defects; the fix exposes monitor address as the join label, retains gateway_address separately, and emits disabled status with the upstream ~ sentinel. CodeRabbit pass 2 completed with zero findings. just gen reported 66 collectors, 1,053/1,053 dashboard coverage, and 180 schemas. just check passed: 427 Grafana tests, 1,210 Prometheus targets, 80 manifests, and govulncheck found no called vulnerabilities.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added joinable gateway failover-group membership metrics with pre-26.7 silent feature absence. Verified targeted race tests, source-derived upstream behavior, two completed CodeRabbit passes with the sole major fixed, just gen, and the full just check gate.
<!-- SECTION:FINAL_SUMMARY:END -->
