---
id: OPN-0065
title: Redact credential-bearing URLs from exporter self-logs
status: Done
assignee:
  - '@codex'
created_date: '2026-09-04 05:38'
updated_date: '2026-09-04 07:26'
labels:
  - needs-triage
dependencies: []
modified_files:
  - internal/logship/selflog.go
  - internal/logship/selflog_test.go
priority: high
type: bug
ordinal: 19000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The exporter self-log handler flattens arbitrary structured attributes unchanged and buffers startup records until the OTLP log pipeline binds. Explicit endpoint values are logged before that bind and URL userinfo or sensitive query parameters survive endpoint parsing. An operator-supplied credential or bearer token in an endpoint can therefore be forwarded to the remote log backend as structured metadata.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A failing regression covers startup self-log buffering with URL userinfo and sensitive query parameters and proves the pre-fix value is present
- [x] #2 Self-log records redact credential-bearing URL components before they enter the pending queue or live pipeline
- [x] #3 Ordinary endpoint host, path and non-sensitive diagnostic attributes remain useful after redaction
- [x] #4 No credential fixture value appears in test output or generated artifacts
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Add a production-sequence regression that buffers an endpoint-bearing startup record, then centralize self-log attribute sanitization at record construction so both pending and live submissions cross the same boundary. Review URL userinfo and sensitive query keys without treating all non-URL diagnostics as secrets.
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Fixed by 1fd32f4d. Exporter self-log URL attributes now redact userinfo and sensitive query values before either startup buffering or live export while retaining scheme, host, path and safe query context. The regression failed before the fix and passed after it; no fixture credential appeared in output or generated artifacts. Integrated just check passed. CodeRabbit completed one pass with zero findings.
<!-- SECTION:FINAL_SUMMARY:END -->
