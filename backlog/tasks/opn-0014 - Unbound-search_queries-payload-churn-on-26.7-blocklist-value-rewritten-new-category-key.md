---
id: OPN-0014
title: >-
  Unbound search_queries payload churn on 26.7: blocklist value rewritten, new
  category key
status: Parked
assignee:
  - '@codex'
created_date: '2026-08-30 08:30'
updated_date: '2026-09-02 02:15'
labels: []
milestone: m-0
dependencies: []
priority: low
type: bug
ordinal: 112
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Upstream `Unbound/Api/OverviewController.php` (26.7 series) now always overwrites the `blocklist` value in `api/unbound/overview/search_queries` rows with the display description, and adds a new `category` key. We model `policy`/`status` (the `get_policies` shape change is already handled in `opnsense/unbound_dns.go`), but anything keying on raw `blocklist` values changes silently, and `category` will surface as canary drift — pre-classify it as an opportunity key (`knownExtraTopKeys`) rather than letting the daily canary file it as unexplained. Found by upstream API-surface research 2026-08-30.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Confirmed whether any shipped label/attribute carries the raw blocklist value; if so it stays stable across generations
- [x] #2 category pre-classified in canary exemptions so the daily canary stays quiet
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 1 execution: trace the unbound search_queries response through decoding and metric emission to determine whether raw blocklist is shipped; verify the 26.7 upstream category addition; add the narrow root-owned canary opportunity exemption only if it matches the response schema; run focused canary/schema checks and the integrated gate. Declarative ledger changes are validated rather than tested unless existing regression coverage has a clear extension point.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Source inspection proves no Prometheus label carries blocklist, but the Unbound log source ships the API row blocklist value in its JSON body and Loki structured metadata. OPNsense 26.7 rewrites that value to the configured display value, so AC1 is not satisfied by the current pass-through contract. Added the narrow rows[].category knownExtraPaths opportunity exemption and validated both known-extra-path tests, just schemas, and just check. CodeRabbit was skipped because the landed repository change is a declarative JSON compatibility ledger plus tracker records. Follow-up OPN-0055 owns the stable identity contract.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Parked with AC2 complete: rows[].category is classified as a nested opportunity path and the schema/canary checks plus just check pass. AC1 remains open because the shipped blocklist attribute changes meaning across response generations; resume via OPN-0055 by defining a recoverable stable identity or explicitly omitting the unstable value, with old/new-shape regression coverage.
<!-- SECTION:FINAL_SUMMARY:END -->
