---
id: OPN-0034
title: Surface gateway threshold parse failures (Warn + counter)
status: To Do
assignee: []
created_date: '2026-08-30 09:09'
updated_date: '2026-08-30 09:35'
labels: []
milestone: m-4
dependencies: []
priority: medium
type: enhancement
ordinal: 501
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`internal/collector/gateways.go:180-197` drops an unparseable RTT/loss threshold with a Debug-only log — invisible at default Info level; the threshold series silently vanishes. Mirror the smart.go #615 pattern: Warn log + a `gateway_threshold_parse_errors_total` counter.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Unparseable threshold produces a Warn and increments a parse-errors counter; series absence is explained
- [ ] #2 Test covers a malformed threshold payload
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
