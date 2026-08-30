---
id: OPN-0021
title: HAProxy maintenance-state visibility (api/haproxy/maintenance/searchServer)
status: To Do
assignee: []
created_date: '2026-08-30 09:08'
updated_date: '2026-08-30 09:35'
labels: []
milestone: m-3
dependencies: []
priority: low
type: feature
ordinal: 405
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Servers in maintenance vs actually down are indistinguishable today. `api/haproxy/maintenance/searchServer` distinguishes planned from unplanned — export a maintenance-state series alongside the existing haproxy collector. Plugin-gated.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Maintenance state exported per backend server, joinable with existing haproxy series
- [ ] #2 AGENTS.md new-collector steps complete; gates clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
