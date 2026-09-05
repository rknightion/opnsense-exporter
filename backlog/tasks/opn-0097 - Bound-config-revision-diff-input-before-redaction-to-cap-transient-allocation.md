---
id: OPN-0097
title: Bound config revision diff input before redaction to cap transient allocation
status: To Do
assignee: []
created_date: '2026-09-05 19:54'
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
