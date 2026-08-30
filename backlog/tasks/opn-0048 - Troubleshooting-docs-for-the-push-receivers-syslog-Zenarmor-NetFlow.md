---
id: OPN-0048
title: Troubleshooting docs for the push receivers (syslog/Zenarmor/NetFlow)
status: To Do
assignee: []
created_date: '2026-08-30 09:10'
labels: []
dependencies: []
priority: high
type: docs
ordinal: 48000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`docs/troubleshooting.md` covers only the polling collectors; an operator whose receiver gets nothing has no entry point. Add a push-receiver section pointing at `logs_rejected_total{reason}` / `logs_shipped_total` and the per-stage parse metrics, cross-linked from the three receiver pages. Also add "nothing arrives" headings to `zenarmor-receiver.md` and `flow.md` matching `syslog-receiver.md`'s pattern (the OPNsense-side Reporting-NetFlow step is the classic misconfiguration).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 troubleshooting.md has a receiver section keyed on the real reject/ship metrics
- [ ] #2 zenarmor-receiver.md and flow.md each have a nothing-arrives heading; cross-links in place
- [ ] #3 just docs-check clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
