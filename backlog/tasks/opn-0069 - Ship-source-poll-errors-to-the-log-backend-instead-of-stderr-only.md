---
id: OPN-0069
title: Ship source poll errors to the log backend instead of stderr only
status: Done
assignee: []
created_date: '2026-09-04 08:32'
updated_date: '2026-09-04 08:37'
labels:
  - bug
dependencies: []
ordinal: 23000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
logship.Start routes EVERY pipeline diagnostic to SelfLogHandler.DiagnosticLogger(), the non-forwarding handler. The recursion guard that motivates this is real but covers sink, retry and shutdown diagnostics: those describe the delivery path, so shipping one manufactures another record per failed attempt while the endpoint is down. DiagnosticLogger's own docstring says exactly that ("sink, retry and shutdown diagnostics").

A source poll error is not one of those three. It describes the firewall/API side, it is the only place the reason behind a logs_poll_errors_total increment exists, and shipping it cannot make it recur. Routing it to stderr leaves an operator watching a counter move with the cause reachable only from the container console.

Observed in the Wave 5 OPN-0060 proof run: configstate's poll-error counter was positive and no reason reached the backend, which is why that assertion could not be diagnosed.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A source poll error emitted while self-log shipping is on reaches the OTLP sink with its source and err attributes intact
- [x] #2 Sink, retry, ingest-cap and shutdown diagnostics still never re-enter the queue
- [x] #3 The test scaffolding resolves both logger roles through the same helper Start uses, so the mirror cannot drift
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed by splitDiagnosticLoggers in internal/logship/pipeline.go. Start now resolves two roles: sourceLog keeps the forwarding handler and carries pollOnce's poll-error warning; pipelineLog is the non-forwarding handler and still carries sink, retry, ingest-cap and shutdown diagnostics. Sources themselves still receive pipelineLog via deps.Logger - deliberately unchanged, since widening that is a separate blast radius and was not the observed failure.

Regression TestPipeline_SourcePollErrorReachesTheLogBackend fails on the old routing with 'condition not met before deadline' (the warning never reaches the sink) and passes after, asserting the shipped record carries source=configstate and the underlying error text. TestPipeline_SinkDiagnosticsStayOffTheWire pins the other half at zero forwarded records.

startWithSink now resolves both roles through the same helper Start uses, so the test mirror cannot drift from production wiring.

just check passed. CodeRabbit: 1 pass, complete, zero findings.
<!-- SECTION:NOTES:END -->
