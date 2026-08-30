---
id: OPN-0033
title: >-
  Metric naming: breaking rename of _total gauges and wireguard handshake
  timestamp at next major
status: To Do
assignee: []
created_date: '2026-08-30 09:09'
updated_date: '2026-08-30 09:36'
labels: []
milestone: m-6
dependencies:
  - OPN-0052
priority: medium
type: enhancement
ordinal: 701
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
DECIDED 2026-08-30 (Rob): take the breaking rename at the next major release, with dashboard/alert migration in the same release. The guarding lint landed separately as OPN-0052 (dependency) — this task is the rename itself. Non-monotonic current-count gauges carrying `_total`: `crowdsec.go:77-88`, `dhcpv4.go:40-55`, `smart.go:58-61`, `hasync.go:52-53`, `carp.go:53-56`. Also `wireguard.go:68-71` `peer_last_handshake_seconds` is a Unix timestamp missing the project `_timestamp_seconds` suffix. Rename metrics + regenerate docs/dashboards/alerts + upgrading.md migration table, all in the same major release; remove the OPN-0052 allowlist entries as each rename lands.
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
