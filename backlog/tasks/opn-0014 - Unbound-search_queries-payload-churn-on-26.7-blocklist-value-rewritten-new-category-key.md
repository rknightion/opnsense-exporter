---
id: OPN-0014
title: >-
  Unbound search_queries payload churn on 26.7: blocklist value rewritten, new
  category key
status: To Do
assignee: []
created_date: '2026-08-30 08:30'
labels: []
dependencies: []
priority: low
type: bug
ordinal: 14000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Upstream `Unbound/Api/OverviewController.php` (26.7 series) now always overwrites the `blocklist` value in `api/unbound/overview/search_queries` rows with the display description, and adds a new `category` key. We model `policy`/`status` (the `get_policies` shape change is already handled in `opnsense/unbound_dns.go`), but anything keying on raw `blocklist` values changes silently, and `category` will surface as canary drift — pre-classify it as an opportunity key (`knownExtraTopKeys`) rather than letting the daily canary file it as unexplained. Found by upstream API-surface research 2026-08-30.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Confirmed whether any shipped label/attribute carries the raw blocklist value; if so it stays stable across generations
- [ ] #2 category pre-classified in canary exemptions so the daily canary stays quiet
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
