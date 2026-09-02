---
id: OPN-0012
title: AGENTS.md mislabels internal/options/otlp.go as OTLP-tracing config
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 08:30'
updated_date: '2026-09-02 01:38'
labels: []
milestone: m-0
dependencies: []
priority: low
type: bug
ordinal: 110
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`AGENTS.md:87` (architecture section, internal/options bullet) says `otlp.go` configures the "OTLP-tracing" telemetry family. It configures OTLP metrics push (`internal/options/otlp.go:307-311`); no TracerProvider/sdktrace exists anywhere outside vendor. The binary ships OTLP metrics and logs plus Pyroscope profiles — no traces. Fix the wording (and any other doc echoing it) so agents stop planning against a tracing family that does not exist.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 AGENTS.md and any echoing docs describe otlp.go as OTLP metrics push
- [x] #2 No remaining doc claims the exporter emits its own traces
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 1 execution: correct the sole false tracing claim in the repository architecture guide to OTLP metrics push; verify no documentation claims the exporter emits traces; run generated-doc validation and the integrated gate. This is documentation-only, so validate rather than add a test and skip CodeRabbit.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Landed as 66192f54a39d765eec356ec97ee05045d85a3624. The sole false trace-emission claim was corrected to OTLP metrics push; targeted telemetry-language search found no remaining documentation claim. just docs-check and integrated just check passed. CodeRabbit was skipped because this is documentation-only. Exact-head CI run 33579700413 completed successfully and ci-success passed.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Corrected the architecture guide to describe internal/options/otlp.go as OTLP metrics push rather than tracing and confirmed no documentation claims the exporter emits OpenTelemetry traces. Verified just docs-check, just check, and exact-head CI run 33579700413. Commit: 66192f54a39d765eec356ec97ee05045d85a3624.
<!-- SECTION:FINAL_SUMMARY:END -->
