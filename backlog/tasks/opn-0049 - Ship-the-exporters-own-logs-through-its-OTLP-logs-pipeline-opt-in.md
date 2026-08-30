---
id: OPN-0049
title: Ship the exporter's own logs through its OTLP logs pipeline (opt-in)
status: To Do
assignee: []
created_date: '2026-08-30 09:10'
labels: []
dependencies: []
priority: medium
type: enhancement
ordinal: 49000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Own slog output goes only to stderr; the transport, resource attributes and delivery accounting already exist (`internal/telemetry/`, `internal/logship/sink_otlp.go`). Opt-in flag routes the exporter's own log records into the same OTLP sink so the 03:00 error line lands in Loki next to the firewall logs. Guard against feedback loops (sink errors logging into the sink).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Opt-in flag ships own logs via OTLP with correct resource attributes; default off
- [ ] #2 Sink-failure log lines cannot recurse into the sink (bounded, tested)
- [ ] #3 Documented; gates clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
