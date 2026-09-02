---
id: OPN-0012
title: AGENTS.md mislabels internal/options/otlp.go as OTLP-tracing config
status: In Progress
assignee:
  - '@codex'
created_date: '2026-08-30 08:30'
updated_date: '2026-09-02 01:29'
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
- [ ] #1 AGENTS.md and any echoing docs describe otlp.go as OTLP metrics push
- [ ] #2 No remaining doc claims the exporter emits its own traces
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 1 execution: correct the sole false tracing claim in the repository architecture guide to OTLP metrics push; verify no documentation claims the exporter emits traces; run generated-doc validation and the integrated gate. This is documentation-only, so validate rather than add a test and skip CodeRabbit.
<!-- SECTION:PLAN:END -->
