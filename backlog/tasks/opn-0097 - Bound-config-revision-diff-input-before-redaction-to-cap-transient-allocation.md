---
id: OPN-0097
title: Bound config revision diff input before redaction to cap transient allocation
status: Done
assignee:
  - '@claude'
created_date: '2026-09-05 19:54'
updated_date: '2026-09-06 13:00'
labels:
  - enhancement
  - security
dependencies: []
priority: low
ordinal: 51000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Independent redaction review 2026-09-05 (codex/findings-2026-09-05-redaction-review.md, F5, informational). configChangeRecord in internal/logship/configchange.go unescapes and redacts the FULL diff returned by FetchConfigBackupDiff before truncating to configChangeMaxBodyBytes (192 KiB, configchange.go:26). Upstream bounds a diff at roughly 64 MiB, so a pathological revision pair costs about three times that in transient allocation inside a process that runs on the firewall or beside it. The redact-then-truncate order is correct and deliberately pinned by a test (truncating first could split a credential across the cut); this task is only about bounding the input, for example capping the fetched diff at the client with a marker before unescape, and never about reordering. Low priority: no live occurrence, no measured pressure. Do not start it ahead of a shipped-behaviour defect.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A diff larger than a documented input bound is cut at the client before redaction with a visible truncation marker, and the redact-before-truncate order test still passes
- [x] #2 A regression proves a credential straddling the input cut cannot ship in clear
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Attended 2026-09-06: implement the 4 MiB client-side input bound with visible marker in FetchConfigBackupDiff; failing-before straddling-credential regression first; redact-before-truncate order test untouched.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Landed a274e928. boundConfigBackupDiffLines cuts at a line boundary within a 4 MiB budget that reserves the marker, so the returned diff never exceeds ConfigBackupDiffMaxInputBytes; FetchConfigBackupDiff also lowers the request-scoped response cap to 16 MiB so an oversized JSON body is refused before decoding (CodeRabbit major finding, fixed). Tests: TestBoundConfigBackupDiffLines_CutAtLineBoundaryWithMarker, TestBoundConfigBackupDiffLines_UnderBoundUnchanged, TestFetchConfigBackupDiff_RefusesOversizedResponseBeforeDecoding, TestFetchConfigBackupDiff_ClientBoundIsLineSafeAgainstCredentialStraddle (credential line straddling the cut never ships in clear, failing-before by absent symbol), TestConfigChangeRecord_RedactsBeforeTruncation unchanged and green. go test ./opnsense/ ./internal/logship/ ok; just check exit 0; CodeRabbit two passes, final pass one minor (marker overshoot) fixed.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Wave 9 Phase 6 not started: higher-priority OPN-0099 remains Parked at the delivered flushed-instance redaction assertion, so the frozen only-if-nothing-above-is-open entry condition is not satisfied. No diff-bound source, test or documentation change was made; no acceptance criterion is claimed. PARKED RESUME BOUNDARY: close the higher-priority live-proof gap (and any OPN-0057 observation park), then implement the frozen 4 MiB client-side line-safe bound and visible marker with a failing-before straddling-credential regression, preserving redact-before-output-truncate order. D7 remains a batched planner-default question.

Bounded the fetched config diff at the client (4 MiB line-safe budget with a visible marker, 16 MiB raw-body cap before decoding) ahead of unescape and redaction, preserving the redact-before-truncate order. Verified by four unit tests including a straddling-credential regression, just check green, CodeRabbit clean after fixes. Commit a274e928.
<!-- SECTION:FINAL_SUMMARY:END -->
