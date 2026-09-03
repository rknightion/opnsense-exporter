---
id: OPN-0019
title: 'Firewall legacy-rule migration debt gauge (api/firewall/migration, 26.7)'
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 09:08'
updated_date: '2026-09-03 08:27'
labels: []
milestone: m-2
dependencies: []
priority: medium
type: feature
ordinal: 303
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`api/firewall/migration/countRules|countOutbound` (new in 26.7) reports how many legacy firewall/outbound-NAT rules remain unmigrated to MVC. Time-limited relevance (the 26.7 upgrade cycle) but exactly when users need it. Feature-absent on pre-26.7.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Unmigrated rule-count gauges exported; absent endpoint handled silently
- [x] #2 AGENTS.md new-collector steps complete; gates clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Reconstruct the source-derived firewall migration debt collector; correct both 26.7 controller action paths; wire endpoint, semantic/negative-cacheable 404, schema, ACL-unknown evidence, cold polling, default-on option, dashboard and generated artifacts; then run focused tests, sliced source review, just gen and just check before finalizing one green commit.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Root integration corrected the controller paths to countRules/countOutbound from OPNsense stable/26.7 source, wired both version-gated GETs through schema, ACL evidence, negative-cache semantics, cold polling, default-on collector controls, dashboard coverage and generated docs. Focused race tests passed. just gen produced 67 collectors, 1,055/1,055 dashboard coverage and 182 schemas. CodeRabbit completed its source slice with one inapplicable major: schema_registry.go stores response types, not paths, and the suggested snake-case URLs contradict both upstream action routing and cmd/apicontract normalization. just check passed, including 427 Grafana tests, 1,212 Prometheus targets, 80 manifests and no called vulnerabilities.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added firewall and outbound-NAT legacy migration debt gauges with silent pre-26.7 absence. Verified against upstream stable/26.7 source, focused race tests, a completed source-only CodeRabbit review with its sole false finding disproved, just gen and the full just check gate.
<!-- SECTION:FINAL_SUMMARY:END -->
