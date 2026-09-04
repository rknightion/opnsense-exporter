---
id: OPN-0083
title: Redact Unicode-escaped malformed JSON-like credential keys
status: In Progress
assignee:
  - '@codex'
created_date: '2026-09-04 20:35'
updated_date: '2026-09-04 20:53'
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
- [ ] #1 Unicode escapes in malformed JSON-like key candidates are decoded before shared sensitive-key classification
- [ ] #2 Malformed escape-bearing key candidates fail closed rather than exposing an associated value
- [ ] #3 Focused redaction tests, independent confidentiality review and the repository gate pass
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
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
<!-- SECTION:NOTES:END -->
