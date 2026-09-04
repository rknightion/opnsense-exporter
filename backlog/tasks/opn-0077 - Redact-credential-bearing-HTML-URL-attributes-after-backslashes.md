---
id: OPN-0077
title: Redact credential-bearing HTML URL attributes after backslashes
status: Done
assignee:
  - '@codex'
created_date: '2026-09-04 18:39'
updated_date: '2026-09-04 22:03'
labels:
  - needs-triage
dependencies: []
priority: high
type: bug
ordinal: 31000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The independent Wave 6 pre-close security review found that malformed API response formatting applies JSON backslash quote rules while scanning HTML attributes. A benign attribute containing a backslash before its closing quote can therefore desynchronise attribute boundaries and hide a later credential-bearing URL from redaction before the response is shipped as a poll error.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 HTML attribute scanning treats backslash as ordinary attribute data and still inspects each later approved URL attribute independently
- [x] #2 A malformed body containing a benign backslash-bearing attribute followed by a credential-bearing URL is redacted before it reaches APICallError output
- [x] #3 Focused redaction tests and the repository gate pass
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Add the independent reviewer reproducer and observe it fail for credential leakage.
2. Separate HTML quote-end scanning from the existing JSON escape-aware helper.
3. Run focused race tests, CodeRabbit source review, the full repository gate, then commit and push.

Security review exposed that the generic truncated-token fallback also scans JSON; keep escape-aware quote matching there and apply HTML quote semantics only at attribute-aware boundaries.

The attribute-aware scanner must run the full shared URL-value redactor and re-escape the decoded safe URL so query credentials are removed without discarding benign diagnostic host data.

Apply the same full URL-value classification to incomplete quoted HTML attributes before the existing fail-closed replacement, covering query credentials cut at the diagnostic boundary.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Regression evidence: the complete HTML reproducer failed before the first fix, and the truncated JSON reproducer failed after the overly broad first fix. Both focused race-enabled truncation suites now pass.

Third security reproducer failed before its fix: a leading text quote plus a quoted HTML query left the whitespace-delimited credential suffix. The focused race-enabled truncation suite passes after applying the shared URL-value redactor inside the isolated attribute.

Fourth security reproducer failed before its fix: a truncated quoted HTML query left the whitespace-delimited credential suffix. The focused race-enabled truncation suite passes after incomplete attributes use the shared URL classifier.

Validation at implementation commit 3bb2bdd9: the focused race-enabled redaction suites and final just check passed; the final CodeRabbit two-file source slice completed with findings=0. The independent reviewer found the last overlapping-quote bypass, its object/array/comma reproducers failed before the fix and passed after it; the requested final independent retry was platform-blocked and is not counted as a clean pass.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Closed the malformed API-response credential-redaction bypass described by this task in implementation commit 3bb2bdd9. Focused race tests, the repository gate, and a completed zero-finding CodeRabbit source review passed.
<!-- SECTION:FINAL_SUMMARY:END -->
