---
id: OPN-0080
title: Resynchronise credential URL scanning after redacted overlaps
status: In Progress
assignee:
  - '@codex'
created_date: '2026-09-04 20:05'
updated_date: '2026-09-04 20:21'
labels:
  - needs-triage
dependencies: []
priority: high
type: bug
ordinal: 34000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The Wave 6 pre-close confidentiality review found that malformed API response formatting resumes after a rewritten quoted URL candidate. If that candidate closing quote is also the next credential URL opener, the second value is skipped and can reach APICallError and shipped poll diagnostics.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 JSON-like URL scanning reconsiders overlapping quote positions even after replacing an earlier candidate
- [ ] #2 Two overlapping credential URL candidates are both redacted from malformed APICallError output
- [ ] #3 Focused redaction tests and the repository gate pass
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Add the independent reviewer overlapping-URL reproducer and observe the second credential survive.
2. Resynchronise over shared quote boundaries after replacement without copying replaced bytes twice.
3. Run focused race tests, CodeRabbit review, the repository gate, then commit and push.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Observed the overlapping-URL regression fail before the fix. Complete rewritten JSON-string tokens now leave the source closing quote available as a possible overlapping opener; the focused race-enabled truncation suite passes.
<!-- SECTION:NOTES:END -->
