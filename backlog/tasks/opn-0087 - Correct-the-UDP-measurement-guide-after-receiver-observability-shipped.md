---
id: OPN-0087
title: Correct the UDP measurement guide after receiver observability shipped
status: In Progress
assignee:
  - '@codex'
created_date: '2026-09-05 18:36'
labels:
  - needs-triage
dependencies: []
priority: low
type: docs
ordinal: 41000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
docs/udp-throughput-harness.md still says ingress-accepted and numeric SO_RCVBUF observations are not exposed and measurement is blocked until implementation. Both metrics shipped in Wave 6, so this published prerequisite is false and can send the next measurement session back into completed implementation work.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The guide names the shipped ingress and numeric buffer observations without inventing a throughput result or relaxing the committed measurement method
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Replace only the obsolete observability-blocker paragraph with the implemented metrics and their observation requirement; preserve the fixed method and verifier contract. Validate as documentation with the integrated gate; no new tests or CodeRabbit review for this paragraph.
<!-- SECTION:PLAN:END -->
