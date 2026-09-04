---
id: OPN-0082
title: Redact sensitive fields in malformed JSON-like syntax
status: In Progress
assignee:
  - '@codex'
created_date: '2026-09-04 20:05'
updated_date: '2026-09-04 21:48'
labels:
  - needs-triage
dependencies: []
priority: high
type: bug
ordinal: 36000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The Wave 6 pre-close confidentiality review found that malformed API response formatting recognises sensitive field names only when they use strict double-quoted JSON syntax. Single-quoted, unquoted, and split-quote JSON-like keys can therefore expose credential values through APICallError and shipped poll diagnostics.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Malformed-body sensitive-field classification covers single-quoted and unquoted keys through the shared SensitiveConfigKey vocabulary
- [ ] #2 Split-quote sensitive key fragments cannot expose their associated value in APICallError output
- [ ] #3 Focused redaction tests and the repository gate pass without over-redacting benign JSON-like fields
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Add the three observed malformed-key reproducers and observe each value survive.
2. Add a bounded JSON-like key scanner that delegates classification to SensitiveConfigKey and fails closed on split sensitive names.
3. Run focused race tests, CodeRabbit review, the repository gate, then commit and push.

4. Treat single-quoted strings as opaque inside composite sensitive values, consume malformed scalar suffixes fail closed, and skip JSON-like colon candidates inside genuine quoted strings.

5. Validate apparent quoted-token boundaries before skipping them, and make malformed-suffix scanning quote-aware so delimiters inside a suffix fragment cannot terminate redaction early.

6. Only skip a quoted token when its opener and trailing boundary form a structurally valid key or value position; a top-level string followed by a delimiter is malformed and must be rescanned.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Observed single-quoted, unquoted and split-quote key regressions fail before the fix. A bounded object-key pass strips quote artifacts, delegates to SensitiveConfigKey and preserves explicit benign JSON-like controls; the focused race-enabled truncation suite passes.

Independent review additionally reproduced a composite delimiter leak, a malformed suffix after a quoted sensitive scalar, and benign prose over-redaction. All failed before the fix and pass after single-quote-aware composite scanning, malformed-suffix consumption and opener-aware string skipping.

Independent review found that a stray opening quote could hide a later unquoted password field and that a comma inside a quoted malformed suffix leaked the tail. Both regressions failed before the fix and now pass under the focused race suite.

Independent review found a credential beginning with a comma, brace or bracket could make a stray leading quote look complete and hide an unquoted password field. The comma regression failed before the fix and passes after token skipping became context-aware.

Final independent-review reproducer: an apparently valid outer object, array, or comma-delimited string could end at password: while its closing quote simultaneously opened the malformed credential value. All three cases failed before the fix and pass after structurally skippable quoted tokens began yielding when they end at a shared sensitive-field delimiter.
<!-- SECTION:NOTES:END -->
