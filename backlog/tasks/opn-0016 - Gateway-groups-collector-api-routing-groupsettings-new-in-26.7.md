---
id: OPN-0016
title: 'Gateway groups collector (api/routing/groupsettings, new in 26.7)'
status: To Do
assignee: []
created_date: '2026-08-30 09:08'
labels: []
dependencies: []
priority: medium
type: feature
ordinal: 16000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
New 26.7 core surface (`Routing/Api/GroupSettingsController.php`): gateway failover-group topology — which gateways sit in which group/tier. Pairs with existing gateway status metrics to answer "is this failover group degraded". Plugin/version-gated behaviour: on pre-26.7 boxes the endpoint 404s — treat as feature-absent per the plugin-gated pattern.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Group membership/tier exported as metrics joinable with existing gateway status series
- [ ] #2 404 on pre-26.7 handled as feature-absent (negative-cacheable), collector silent
- [ ] #3 AGENTS.md new-collector steps complete; gates clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
