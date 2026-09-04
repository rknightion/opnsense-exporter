---
id: OPN-0068
title: State pfTop retained-cardinality and address-label costs accurately
status: Done
assignee:
  - '@codex'
created_date: '2026-09-04 05:39'
updated_date: '2026-09-04 07:26'
labels:
  - needs-triage
dependencies: []
modified_files:
  - docs/flow.md
  - grafana/tabs/firewall.py
priority: medium
type: docs
ordinal: 22000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The pfTop documentation and dashboard describe a 611-series hard ceiling, but the bounded inventories cap only one current scrape. After the five-minute expiry, a disjoint top set can replace every address and port label, so retained Prometheus storage can accumulate many more distinct series and endpoint-identifying values. The opt-in feature remains bounded in process, but the published capacity and privacy contract is incomplete.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Documentation and dashboard wording distinguish the simultaneous active-series ceiling from historical distinct-series churn over a retention window
- [x] #2 The opt-in warning names source, destination, gateway and port labels as endpoint-identifying telemetry and gives operators a concrete retention/cardinality planning caution
- [x] #3 No claim is made about a live deployment or retention volume that was not measured
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Correct the hand-written pfTop capacity/privacy prose and the dashboard panel text without changing the bounded-inventory behavior, regenerate dashboard artifacts once, and validate the source plus generated forms.
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Fixed by afda1a4c, with the regenerated dashboard line landing in b360e86b. The docs and dashboard now distinguish simultaneous active series from retained identity churn and name the endpoint-identifying labels and retention implications without claiming a measured live volume. just dashboard reported coverage 1087/1087 and log streams 10/10; just docs-check and integrated just check passed. Tests and CodeRabbit were intentionally skipped for prose/declarative dashboard wording.
<!-- SECTION:FINAL_SUMMARY:END -->
