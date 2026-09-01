---
id: OPN-0009
title: >-
  Secondary-fetch failures invisible: scrape_collector_success stays 1 and
  endpoint_errors_total never increments
status: Parked
assignee:
  - '@codex'
created_date: '2026-08-30 08:30'
updated_date: '2026-09-01 23:42'
labels:
  - bug
  - first-wave
milestone: m-0
dependencies: []
priority: high
type: bug
ordinal: 102
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`opnsense_exporter_endpoint_errors_total` is incremented only at `internal/collector/scheduler.go:280` (panic) and `:291` (top-level Update error), while ~24 collector files (39 sites: `grep -n "c.log.Warn(\"failed to fetch" internal/collector/*.go | grep -v _test`) log-and-continue on secondary fetch failures — e.g. `ipsec.go:473,488,531,678,695`, `unbound_dns.go:543,819,836,888,951`, `haproxy.go:273,375`, `firewall.go:373,391,411`, `interfaces.go:403,517`. A collector can lose most of its data every cycle while `scrape_collector_success` reads 1 and endpoint_errors_total reads 0; the help text at `collector.go:1366` claims broader coverage than reality. The only trail is `api_requests_total{endpoint,code}`, which requires knowing every endpoint name. Fix options: increment endpointErrors from these sites, or add `opnsense_exporter_partial_fetch_failures_total{collector}` and narrow the help text — the latter preserves tolerated-404 (plugin absent) semantics without over-alerting. Tolerated plugin-absent 404s must NOT count as failures.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Partial fetch failures are observable via a per-collector metric an operator can alert on without enumerating endpoint names
- [ ] #2 Plugin-absent (negative-cached 404) fetches do not count as failures
- [ ] #3 endpoint_errors_total help text matches its actual increment sites
- [ ] #4 Dashboard/alerts updated if a new metric is introduced (just grafana-check clean)
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 1 plan: inventory every secondary-fetch error path and establish failing tests for partial failure visibility and tolerated plugin-absence; specify the narrow metric/accounting and help-text change for the root-owned collector.go; update owned tests and return exact dashboard/registry edits; run focused collector tests.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 1 staged WIP accounts secondary-fetch failures through a per-poll observer, preserves tolerated plugin absence, and adds partial-fetch regression coverage; focused collector/client tests and the integrated just check passed. Post-correction L14 found no remaining issue. Not landed: CodeRabbit failed twice before analysis and emitted no complete event. Resume: obtain a complete CodeRabbit finding set, fix critical/major findings, commit this task with explicit pathspecs, integrate current origin/main without rebasing, rerun just check, push, and verify exact-SHA CI.
<!-- SECTION:NOTES:END -->
