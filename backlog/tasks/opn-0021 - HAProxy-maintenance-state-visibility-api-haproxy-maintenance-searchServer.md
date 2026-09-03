---
id: OPN-0021
title: HAProxy maintenance-state visibility (api/haproxy/maintenance/searchServer)
status: Parked
assignee:
  - '@codex'
created_date: '2026-08-30 09:08'
updated_date: '2026-09-03 19:14'
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

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 4: audit the current HAProxy plugin controller first and prove searchServer is read-only; only then freeze the response contract and implement the plugin-gated collector.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 3 park: do not implement from the current route name alone. Resume by auditing the current HAProxy plugin controller and proving that api/haproxy/maintenance/searchServer is a safe, read-only scrape surface; the existing maintenance endpoints include action paths that can reload templates. Once the safe endpoint and response shape are evidenced, implement the plugin-gated collector and complete the nine-step collector checklist.

Wave 4 upstream-source audit, released OPNsense 26.7.3: MaintenanceController::searchServerAction calls  before reading . The core template generator opens configured targets for writing, including HAProxy staging and service configuration files. Therefore POST api/haproxy/maintenance/searchServer is mutating and is not a safe scheduled scrape surface. No live firewall call was needed for that verdict; exact response values remain unobserved. PARKED RESUME BOUNDARY: obtain or upstream a separate read-only HAProxy socket-status endpoint that omits the template reload, then audit its entire call chain and response shape before implementing a collector.

CORRECTION to the preceding Wave 4 note: the omitted command names are template reload OPNsense/HAProxy and server_status_list. The shell consumed Markdown backticks while writing that note; no evidence or task meaning changed.
<!-- SECTION:NOTES:END -->
