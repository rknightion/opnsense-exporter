---
id: OPN-0097
title: Bound config revision diff input before redaction to cap transient allocation
status: Parked
assignee: []
created_date: '2026-09-05 19:54'
updated_date: '2026-09-06 11:07'
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
- [ ] #1 A diff larger than a documented input bound is cut at the client before redaction with a visible truncation marker, and the redact-before-truncate order test still passes
- [ ] #2 A regression proves a credential straddling the input cut cannot ship in clear
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Wave 9 Phase 6 not started: higher-priority OPN-0099 remains Parked at the delivered flushed-instance redaction assertion, so the frozen only-if-nothing-above-is-open entry condition is not satisfied. No diff-bound source, test or documentation change was made; no acceptance criterion is claimed. PARKED RESUME BOUNDARY: close the higher-priority live-proof gap (and any OPN-0057 observation park), then implement the frozen 4 MiB client-side line-safe bound and visible marker with a failing-before straddling-credential regression, preserving redact-before-output-truncate order. D7 remains a batched planner-default question.
<!-- SECTION:FINAL_SUMMARY:END -->
