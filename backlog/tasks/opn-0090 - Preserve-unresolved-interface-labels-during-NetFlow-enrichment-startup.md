---
id: OPN-0090
title: Preserve unresolved interface labels during NetFlow enrichment startup
status: Done
assignee:
  - '@codex'
created_date: '2026-09-05 18:55'
updated_date: '2026-09-05 19:10'
labels:
  - needs-triage
dependencies: []
priority: medium
type: bug
ordinal: 44000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The refresher publishes interface order before metadata. BuildIfMap can therefore publish a device-only mapping with Unresolved false, and Processor enrichment neither sets nor clears that flag. NetFlow during ordinary startup emits a raw device label before later switching to the resolved name, contrary to the documented all-flow-lanes unresolved sentinel.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A NetFlow interface with a device but unavailable metadata uses the unresolved metric label while retaining its device metadata
- [x] #2 A populated table that lacks a device preserves the honest raw-device fallback and an explicit interface name remains authoritative
- [x] #3 Arrival of a resolved name clears Unresolved before metric rollup
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Add failing-before regressions at BuildIfMap and Processor enrichment seams for cold metadata and later resolution. Use existing IfaceNames/Ifaces availability and Unresolved semantics; preserve explicit overrides and local-origin names, without holding records or changing the ifIndex contract. Run focused flow checks.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Both cold-label and cold-to-resolved regressions failed before repair. Focused flow race tests passed after: ok github.com/rknightion/opnsense2otel/v4/internal/flow 1.409s. Both ends handled; explicit names retained, populated missing-device fallback preserved.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Landed in d2549a5dd314f40bdfaf6ad56f056dcde4821e0a. Targeted evidence recorded above; full just check passed (exit 0), terminal: Your code is affected by 0 vulnerabilities. No generated artifacts changed, so just gen not applicable. Source-only CodeRabbit completed review_completed across 13 files, findings=1; one pass. The sole minor finding concerned the intentionally reversed backup test-server branch and was retained with the regression rationale recorded on OPN-0086. No critical or major findings.
<!-- SECTION:FINAL_SUMMARY:END -->
