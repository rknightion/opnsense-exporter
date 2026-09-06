---
id: OPN-0021
title: HAProxy maintenance-state visibility (api/haproxy/maintenance/searchServer)
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 09:08'
updated_date: '2026-09-06 11:08'
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
- [x] #1 Maintenance state exported per backend server, joinable with existing haproxy series
- [x] #2 AGENTS.md new-collector steps complete; gates clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 4: audit the current HAProxy plugin controller first and prove searchServer is read-only; only then freeze the response contract and implement the plugin-gated collector.

Wave 9 D4 unpark: audit released 26.7.x HAProxy countersAction and every configd/script call for purity and upstream status vocabulary. Pure permits server_maintenance from the already-decoded status with existing server_status labels, dashboard panel and state annotation; impure re-parks and files the already-scraped endpoint finding. No new endpoint, schema or flag. Root integrates after rename Grafana lane and earlier phases.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 3 park: do not implement from the current route name alone. Resume by auditing the current HAProxy plugin controller and proving that api/haproxy/maintenance/searchServer is a safe, read-only scrape surface; the existing maintenance endpoints include action paths that can reload templates. Once the safe endpoint and response shape are evidenced, implement the plugin-gated collector and complete the nine-step collector checklist.

Wave 4 upstream-source audit, released OPNsense 26.7.3: MaintenanceController::searchServerAction calls  before reading . The core template generator opens configured targets for writing, including HAProxy staging and service configuration files. Therefore POST api/haproxy/maintenance/searchServer is mutating and is not a safe scheduled scrape surface. No live firewall call was needed for that verdict; exact response values remain unobserved. PARKED RESUME BOUNDARY: obtain or upstream a separate read-only HAProxy socket-status endpoint that omits the template reload, then audit its entire call chain and response shape before implementing a collector.

CORRECTION to the preceding Wave 4 note: the omitted command names are template reload OPNsense/HAProxy and server_status_list. The shell consumed Markdown backticks while writing that note; no evidence or task meaning changed.

Wave 9 counters audit verdict PURE: released plugins 26.7.3 StatisticsController countersAction -> actions_haproxy.conf statistics -> queryStats.php showStat/socketCmd; core Backend configdRun/configdStream only transports the read-only command. HAProxy 3.2 show stat emits MAINT, inherited/resolution MAINT forms and existing UP/DOWN/DRAIN/NOLB/no-check vocabulary. Implementation uses MAINT prefix on the existing decoded row, identical server_status labels, no new endpoint, JSON schema or flag. AGENTS steps 1-5 do not apply to this existing collector; generated docs/dashboard satisfy steps 8-9. Source-only CodeRabbit completed six files, zero findings.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Wave 9 completed at d55d99707867ef6dd749678c14d2760d78b11d56: server_maintenance is 1 for MAINT-prefixed counters rows and 0 otherwise, with the exact server_status labels. Released upstream audit is PURE; no new endpoint, schema or flag. Test-first failure: expected 5 server_maintenance series, got 0. Final HAProxy race subset passed; just gen and just check passed including 427 Grafana tests; source-only CodeRabbit six files completed with zero findings. Added maintenance timeline and explicit no-annotation state-gauge reason. AGENTS new-collector steps 1-5 are inapplicable to this existing collector; regenerated docs/dashboard cover steps 8-9. Completing this final milestone task closes m-3.
<!-- SECTION:FINAL_SUMMARY:END -->
