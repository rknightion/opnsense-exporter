---
id: OPN-0019
title: 'Firewall legacy-rule migration debt gauge (api/firewall/migration, 26.7)'
status: To Do
assignee: []
created_date: '2026-08-30 09:08'
updated_date: '2026-08-30 09:35'
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
- [ ] #1 Unmigrated rule-count gauges exported; absent endpoint handled silently
- [ ] #2 AGENTS.md new-collector steps complete; gates clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
