---
id: OPN-0052
title: >-
  Metric naming lint: reject non-monotonic _total gauges and unsuffixed
  timestamp metrics
status: Parked
assignee:
  - '@codex'
created_date: '2026-08-30 09:35'
updated_date: '2026-09-01 23:42'
labels: []
milestone: m-0
dependencies: []
priority: medium
type: chore
ordinal: 106
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Split out of OPN-0033 so the guard lands before the M3/M4 collector wave. Add a lint/test that rejects (a) new non-monotonic gauges named `_total` and (b) new Unix-timestamp metrics missing the `_timestamp_seconds` suffix, with an explicit allowlist naming the existing violations (`crowdsec.go`, `dhcpv4.go`, `smart.go`, `hasync.go`, `carp.go`, `wireguard.go` peer_last_handshake_seconds) so they keep building until OPN-0033 renames them at the next major.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Lint/test fails on a new violating metric and passes on the allowlisted existing ones
- [ ] #2 Allowlist entries reference OPN-0033 as the removal trigger
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 1 plan: inventory existing descriptor construction and exact legacy violations; add a deterministic lint tool with an OPN-0033-scoped allowlist, negative tests for new _total gauges and unsuffixed Unix timestamps, and a documented just recipe wired into just check; verify the CI workflow invokes just check and run the focused tool tests plus just formatting validation.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 1 staged WIP adds deterministic metric naming lint, negative tests, an OPN-0033-scoped legacy allowlist, and just check wiring. Focused tests and integrated just check passed, including metric naming lint: OK; post-correction L14 found no remaining issue. Not landed because CodeRabbit failed twice before analysis. Resume: obtain a complete review, fix critical/major findings, commit explicitly, integrate current origin/main, rerun just check, push, and verify exact-SHA CI.
<!-- SECTION:NOTES:END -->
