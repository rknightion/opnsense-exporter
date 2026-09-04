---
id: OPN-0080
title: Resynchronise credential URL scanning after redacted overlaps
status: Done
assignee:
  - '@codex'
created_date: '2026-09-04 20:05'
updated_date: '2026-09-04 22:03'
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
- [x] #1 JSON-like URL scanning reconsiders overlapping quote positions even after replacing an earlier candidate
- [x] #2 Two overlapping credential URL candidates are both redacted from malformed APICallError output
- [x] #3 Focused redaction tests and the repository gate pass
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
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

Validation at implementation commit 3bb2bdd9: the focused race-enabled redaction suites and final just check passed; the final CodeRabbit two-file source slice completed with findings=0. The independent reviewer found the last overlapping-quote bypass, its object/array/comma reproducers failed before the fix and passed after it; the requested final independent retry was platform-blocked and is not counted as a clean pass.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Closed the malformed API-response credential-redaction bypass described by this task in implementation commit 3bb2bdd9. Focused race tests, the repository gate, and a completed zero-finding CodeRabbit source review passed.
<!-- SECTION:FINAL_SUMMARY:END -->
