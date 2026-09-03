---
id: OPN-0021
title: HAProxy maintenance-state visibility (api/haproxy/maintenance/searchServer)
status: Parked
assignee:
  - '@codex'
created_date: '2026-08-30 09:08'
updated_date: '2026-09-03 09:37'
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

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 3 park: do not implement from the current route name alone. Resume by auditing the current HAProxy plugin controller and proving that api/haproxy/maintenance/searchServer is a safe, read-only scrape surface; the existing maintenance endpoints include action paths that can reload templates. Once the safe endpoint and response shape are evidenced, implement the plugin-gated collector and complete the nine-step collector checklist.
<!-- SECTION:NOTES:END -->
