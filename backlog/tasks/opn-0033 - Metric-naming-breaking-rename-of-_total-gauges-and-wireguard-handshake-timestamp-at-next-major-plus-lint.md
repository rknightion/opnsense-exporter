---
id: OPN-0033
title: >-
  Metric naming: breaking rename of _total gauges and wireguard handshake
  timestamp at next major, plus lint
status: To Do
assignee: []
created_date: '2026-08-30 09:09'
labels: []
dependencies: []
priority: medium
type: enhancement
ordinal: 33000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
DECIDED 2026-08-30 (Rob): take the breaking rename at the next major release, with dashboard/alert migration in the same release. Non-monotonic current-count gauges carrying `_total`: `crowdsec.go:77-88`, `dhcpv4.go:40-55`, `smart.go:58-61`, `hasync.go:52-53`, `carp.go:53-56`. Also `wireguard.go:68-71` `peer_last_handshake_seconds` is a Unix timestamp missing the project `_timestamp_seconds` suffix. Add the naming lint/test now so no new violations land before the major; stage the renames + generated docs/dashboard/alert updates + an upgrading.md migration table behind the major release.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Lint/test rejects new non-monotonic gauges named _total and unsuffixed timestamp metrics
- [ ] #2 Rename change staged for the next major: metrics, dashboards, alerts, docs, upgrading.md migration table all in one release
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
