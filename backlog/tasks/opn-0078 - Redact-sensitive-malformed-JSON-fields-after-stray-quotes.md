---
id: OPN-0078
title: Redact sensitive malformed-JSON fields after stray quotes
status: Done
assignee:
  - '@codex'
created_date: '2026-09-04 19:23'
updated_date: '2026-09-04 22:03'
labels:
  - needs-triage
dependencies: []
priority: high
type: bug
ordinal: 32000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The Wave 6 pre-close security review found that malformed API response formatting skips an entire quoted candidate when it is not followed by a colon. A stray leading quote can overlap a real sensitive field opener, prevent that field from being classified, and expose its value through APICallError and shipped poll diagnostics.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Malformed-body scanning reconsiders overlapping quote positions after a quoted candidate is not a key
- [x] #2 A stray quote before a sensitive JSON-like field cannot expose that field value in APICallError output
- [x] #3 Focused redaction tests and the repository gate pass
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Add the independent reviewer reproducer and observe the sensitive value survive.
2. Advance one byte after non-key quoted candidates so overlapping key openers are reconsidered.
3. Run focused race tests, CodeRabbit review, the full repository gate, then commit and push.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
The exact stray-quote reproducer failed before the fix and passed after non-key quoted candidates began advancing one byte so overlapping quote openers are reconsidered. The focused race-enabled truncation suite passes.

Validation at implementation commit 3bb2bdd9: the focused race-enabled redaction suites and final just check passed; the final CodeRabbit two-file source slice completed with findings=0. The independent reviewer found the last overlapping-quote bypass, its object/array/comma reproducers failed before the fix and passed after it; the requested final independent retry was platform-blocked and is not counted as a clean pass.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Closed the malformed API-response credential-redaction bypass described by this task in implementation commit 3bb2bdd9. Focused race tests, the repository gate, and a completed zero-finding CodeRabbit source review passed.
<!-- SECTION:FINAL_SUMMARY:END -->
