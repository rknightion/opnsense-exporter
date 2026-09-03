---
id: OPN-0037
title: Standing unparsed-syslog metric (logs_unparsed_total by subsystem)
status: Done
assignee: []
created_date: '2026-08-30 09:09'
updated_date: '2026-09-03 06:59'
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
- [x] #1 Unparsed messages counted per subsystem with bounded label vocabulary
- [x] #2 Dashboard panel/alert candidate added; gates clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Implement a shared logs_unparsed_total counter with source and bounded subsystem labels; count only registered-parser shape misses, document and dashboard the signal, regenerate artifacts, run the targeted race tests and full pre-commit gate, then finalize and land as one task commit.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 2 did not start this metric-bearing lane because OPN-0056 could not land through the required CodeRabbit gate. Resume after applying `codex/wip-wave2-coderabbit-blocked.patch`, obtaining a completed review, and landing OPN-0056 first.

Unblocked 2026-09-02: OPN-0056 landed on main in `a482f637`, so a new catalogue metric and its dashboard panel now build together in one `just gen`. Add the metric and its dashboard coverage in the same change.

Implemented shared opnsense_exporter_logs_unparsed_total{source,subsystem} registration and zero-initialisation from the closed syslog subsystem vocabulary. The source increments only when a registered parser declines a body; unknown programs continue as ordinary generic traffic. Added focused regression tests, operator documentation, dashboard coverage, and generated artifacts. Verification: targeted internal/logship race tests passed; just gen completed with 1051/1051 metric coverage and 179 schemas; just check passed, including 427 Grafana tests, fuzz legs, generated-file checks, manifest validation, PromQL validation, public-IP scan, and govulncheck. CodeRabbit source coverage was completed in phase1-logship-options (one false-positive major about intentionally excluded docs/dashboard, disproved by the integrated tree and green gates) and phase1-grafana (review_completed, zero findings after fixes).
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added a standing bounded-cardinality parser-coverage metric and Log Shipping dashboard panel. Registered-parser shape misses are counted per source/subsystem without counting unknown generic programs, while records continue to ship. Targeted race tests, just gen, and the full just check gate passed.
<!-- SECTION:FINAL_SUMMARY:END -->
