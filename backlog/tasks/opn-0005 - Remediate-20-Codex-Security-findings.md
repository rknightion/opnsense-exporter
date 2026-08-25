---
id: OPN-0005
title: Remediate 20 Codex Security findings
status: Done
assignee:
  - '@codex'
created_date: '2026-08-25 09:46'
updated_date: '2026-08-25 10:52'
labels:
  - security
dependencies: []
priority: high
type: bug
ordinal: 5000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Close every validated finding from the repository-wide Codex Security scan of revision df3b51fe58b8c540e7d18b38b3319ae08f41ef5c while preserving legitimate chart, receiver, exporter, console, capture, and telemetry behavior.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 All 20 validated scan findings are either fixed with regression coverage or proven already safe from current repository evidence.
- [x] #2 Resource-amplification paths enforce defensible byte, count, concurrency, and time budgets before expensive work or retention.
- [x] #3 Authentication, admission, transport, redirect, file-permission, and chart-serialization boundaries are enforced consistently across all affected entry points.
- [x] #4 Original malicious triggers no longer reproduce and legitimate controls continue to work.
- [x] #5 Relevant focused tests, repository gates, CodeRabbit review, and the required independent security review pass.
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 make lint
- [x] #2 make test
- [x] #3 make check-public-ips
- [x] #4 make docs-check
- [x] #5 make grafana-check
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Harden Helm argv serialization and API capture body/file boundaries.
2. Bound NetFlow decode/template/correlator/log amplification.
3. Bound capture, metric-label, response-cache, and GeoIP retained work.
4. Enforce Zenarmor/syslog transport, connection, and write admission.
5. Bound console/auth/device-fetch work and make the sensitive console opt-in.
6. Reject OTLP redirects and regenerate affected documentation.
7. Run CodeRabbit, independent bypass review, repository gates, write the scan fix report, finalize, commit, and push.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented all 20 scan remediations across chart serialization, protocol/resource budgets, admission controls, secure capture I/O, cache bounds, OTLP redirect/TLS handling, and private-by-default console configuration. Added focused regressions for malicious triggers and legitimate controls. Fresh boundary and bypass reviews completed; all blocking observations and actionable lower-severity gaps were fixed. The optional short-TTL console cache suggestion was not needed because the opt-in route now has hard concurrency, response-size, and write-time bounds. CodeRabbit completed under the repository organisation plan and all findings were fixed. Verification passed: make lint (0 issues), make test, make check-public-ips (21 self-tests; 1312 files), make docs-check, make grafana-check (1046/1046 metrics; 80 manifests), plus explicit vendored exporter-toolkit web tests.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Fixed and regression-tested all 20 validated Codex Security findings. Wrote the canonical scan fix report to the scan artifact directory, passed all repository and review gates, and preserved documented compatibility overrides and ordinary valid traffic.
<!-- SECTION:FINAL_SUMMARY:END -->
