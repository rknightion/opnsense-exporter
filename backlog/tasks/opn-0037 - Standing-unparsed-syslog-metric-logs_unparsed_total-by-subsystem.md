---
id: OPN-0037
title: Standing unparsed-syslog metric (logs_unparsed_total by subsystem)
status: To Do
assignee: []
created_date: '2026-08-30 09:09'
updated_date: '2026-08-30 09:35'
labels: []
milestone: m-4
dependencies: []
priority: medium
type: enhancement
ordinal: 504
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The `parsed` flag (`internal/logship/syslog/generic.go:35-52`) feeds only the opt-in debug capture (`syslog/source.go:272-295`); `logs_parse_errors_total{stage="envelope"}` covers envelope failures only. Parser-coverage erosion is therefore invisible in steady state. Add `logs_unparsed_total{subsystem}` keyed by the code-defined `subsystemFor` vocabulary (bounded cardinality).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Unparsed messages counted per subsystem with bounded label vocabulary
- [ ] #2 Dashboard panel/alert candidate added; gates clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
