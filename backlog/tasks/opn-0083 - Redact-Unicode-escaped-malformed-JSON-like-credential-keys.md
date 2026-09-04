---
id: OPN-0083
title: Redact Unicode-escaped malformed JSON-like credential keys
status: Done
assignee:
  - '@codex'
created_date: '2026-09-04 20:35'
updated_date: '2026-09-04 22:03'
labels:
  - needs-triage
dependencies: []
priority: high
type: bug
ordinal: 37000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The Wave 6 CodeRabbit review found that the tolerant malformed-body key scanner treats backslash-u sequences as literal key text. An unquoted or otherwise non-strict JSON-like credential key can therefore encode a sensitive character, evade SensitiveConfigKey classification, and expose its value through APICallError and shipped poll diagnostics.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Unicode escapes in malformed JSON-like key candidates are decoded before shared sensitive-key classification
- [x] #2 Malformed escape-bearing key candidates fail closed rather than exposing an associated value
- [x] #3 Focused redaction tests, independent confidentiality review and the repository gate pass
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Add valid and malformed escaped-key reproducers and observe credential leakage. 2. Decode valid Unicode escapes in bounded JSON-like key candidates and classify malformed escape-bearing candidates fail closed. 3. Run the focused race suite, independent review, CodeRabbit and the repository gate.

4. Recognize a Unicode-escaped colon as a malformed field delimiter outside quoted strings.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Both an unquoted Unicode-escaped password key and an invalid escape-bearing key leaked in the failing-before regression. The bounded JSON-like key decoder now resolves valid Unicode escapes and treats malformed escapes as sensitive ambiguity; the focused race suite passes.

Independent review found that a Unicode-escaped colon after a sensitive key bypassed discovery even though key escapes were decoded. The regression failed before the fix and now passes with encoded-colon recognition outside quoted strings.

Validation at implementation commit 3bb2bdd9: the focused race-enabled redaction suites and final just check passed; the final CodeRabbit two-file source slice completed with findings=0. The independent reviewer found the last overlapping-quote bypass, its object/array/comma reproducers failed before the fix and passed after it; the requested final independent retry was platform-blocked and is not counted as a clean pass.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Closed the malformed API-response credential-redaction bypass described by this task in implementation commit 3bb2bdd9. Focused race tests, the repository gate, and a completed zero-finding CodeRabbit source review passed.
<!-- SECTION:FINAL_SUMMARY:END -->
