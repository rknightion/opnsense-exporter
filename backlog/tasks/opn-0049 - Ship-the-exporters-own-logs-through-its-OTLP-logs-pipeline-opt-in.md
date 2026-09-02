---
id: OPN-0049
title: Ship the exporter's own logs through its OTLP logs pipeline (opt-in)
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 09:10'
updated_date: '2026-09-02 15:53'
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
- [x] #1 Opt-in flag ships own logs via OTLP with correct resource attributes; default off
- [x] #2 Sink-failure log lines cannot recurse into the sink (bounded, tested)
- [x] #3 Documented; gates clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 2 L6: add an opt-in exporter self-log path through the existing OTLP sink with bounded recursion protection, tests, documentation, and an exact root wiring request.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 2 implementation is complete: default-off self-log forwarding preserves stderr, uses the bounded OTLP pipeline, fixes resource identity, and breaks sink-diagnostic recursion. Focused tests, full indexed `just check`, and L13 review passed. Landing is blocked solely by two CodeRabbit connection failures with no complete event. Preserved in `codex/wip-wave2-coderabbit-blocked.patch`; resume by applying it, rerunning the gate, and obtaining a completed CodeRabbit review.

Landed on main in `a482f637`. Opt-in, default off, correct resource attributes, documented.

CHANGED AT LANDING, and it changes how AC2 is satisfied: the wave 2 implementation bounded sink-failure recursion with a `forwarding` boolean on the shared handler state. That flag is process-wide, so it cannot distinguish re-entry from concurrency. `TestSelfLogHandlerDeliversConcurrentRecords` was written against the old code and delivered 1 of 8 records: with 65 collector pollers and the push receivers all logging, self-log records were being dropped silently and without any drop accounting.

The flag is removed. Recursion is prevented structurally instead, which it already was: `pipeline.go:109` constructs the pipeline with `DiagnosticLogger`, a one-way path that bypasses this handler entirely, and `TestSelfLogDiagnosticLoggerCannotReenterSink` pins that. The remaining requirement is a contract, documented at `Bind`: the enqueue callback must not log through this handler. `TestSelfLogHandlerSinkFailureRecursionIsBounded` was removed because it asserted the behaviour of a callback that deliberately violates that contract; it is replaced by the concurrency test, which was verified to fail 1-of-8 against the old guard.

Found by CodeRabbit at severity major. Live OTLP delivery was not exercised.
<!-- SECTION:NOTES:END -->
