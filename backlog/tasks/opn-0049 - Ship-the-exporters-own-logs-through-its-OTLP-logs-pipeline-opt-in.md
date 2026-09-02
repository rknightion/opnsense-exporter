---
id: OPN-0049
title: Ship the exporter's own logs through its OTLP logs pipeline (opt-in)
status: Parked
assignee:
  - '@codex'
created_date: '2026-08-30 09:10'
updated_date: '2026-09-02 07:01'
labels: []
milestone: m-1
dependencies: []
priority: medium
type: enhancement
ordinal: 205
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

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 2 L6: add an opt-in exporter self-log path through the existing OTLP sink with bounded recursion protection, tests, documentation, and an exact root wiring request.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 2 implementation is complete: default-off self-log forwarding preserves stderr, uses the bounded OTLP pipeline, fixes resource identity, and breaks sink-diagnostic recursion. Focused tests, full indexed `just check`, and L13 review passed. Landing is blocked solely by two CodeRabbit connection failures with no complete event. Preserved in `codex/wip-wave2-coderabbit-blocked.patch`; resume by applying it, rerunning the gate, and obtaining a completed CodeRabbit review.
<!-- SECTION:NOTES:END -->
