---
id: OPN-0079
title: Redact credential URLs in malformed JSON after stray quotes
status: Done
assignee:
  - '@codex'
created_date: '2026-09-04 19:41'
updated_date: '2026-09-04 22:03'
labels:
  - needs-triage
dependencies: []
priority: high
type: bug
ordinal: 33000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The Wave 6 pre-close security review found that malformed API response formatting skips to the end of every complete quoted candidate while searching JSON strings for credential-bearing URLs. A stray leading quote can overlap the real URL value opener, prevent that value from being inspected, and expose URL credentials through APICallError and shipped poll diagnostics.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Malformed JSON-string scanning reconsiders overlapping quote positions when a candidate contains no redaction
- [x] #2 A stray quote before a credential-bearing URL value cannot expose URL userinfo in APICallError output
- [x] #3 Focused redaction tests and the repository gate pass
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Add the independent reviewer reproducer and observe both URL credential components survive.
2. Resynchronise the JSON-string scanner over overlapping quoted candidates when it emits no replacement.
3. Run focused race tests, CodeRabbit review, the full repository gate, then commit and push.

4. HTML-normalize decoded JSON-string values before URL classification so JSON-escaped ampersands cannot defer a supported HTML reference past the redaction pass.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
The exact malformed-prefix URL reproducer failed before the fix with both credential components present. After JSON-string candidates resynchronise one byte at a time until a replacement is emitted, the full race-enabled truncation suite passes.

Independent review found JSON-escaped ampersands could expose a credential suffix or conceal an HTML-encoded question mark or key character. All three regressions failed before the fix and pass after HTML normalization is composed after JSON decoding but only rewritten when a credential is actually redacted.

Validation at implementation commit 3bb2bdd9: the focused race-enabled redaction suites and final just check passed; the final CodeRabbit two-file source slice completed with findings=0. The independent reviewer found the last overlapping-quote bypass, its object/array/comma reproducers failed before the fix and passed after it; the requested final independent retry was platform-blocked and is not counted as a clean pass.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Closed the malformed API-response credential-redaction bypass described by this task in implementation commit 3bb2bdd9. Focused race tests, the repository gate, and a completed zero-finding CodeRabbit source review passed.
<!-- SECTION:FINAL_SUMMARY:END -->
