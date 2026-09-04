---
id: OPN-0081
title: Redact credential URLs after malformed single-quoted HTML
status: In Progress
assignee:
  - '@codex'
created_date: '2026-09-04 20:05'
updated_date: '2026-09-04 20:53'
labels:
  - needs-triage
dependencies: []
priority: high
type: bug
ordinal: 35000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The Wave 6 pre-close confidentiality review found that a malformed single-quoted HTML attribute can consume the opener of a later URL attribute. The attribute scanner then skips the later value, JSON scanning cannot recover single-quoted HTML, and whitespace-bearing URL credentials can reach APICallError and shipped poll diagnostics.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Quoted HTML URL scanning reconsiders overlapping attribute boundaries after a non-sensitive candidate
- [ ] #2 Credential userinfo and query values remain redacted after malformed single-quoted HTML and in standalone single-quoted diagnostic URLs
- [ ] #3 Focused redaction tests and the repository gate pass
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Add the reviewer malformed-attribute and standalone single-quoted URL reproducers and observe leakage.
2. Resynchronise the HTML attribute scanner and cover standalone quoted diagnostic tokens without weakening JSON escape handling.
3. Run focused race tests, CodeRabbit review, the repository gate, then commit and push.

4. Inspect incomplete standalone single-quoted URL tokens before returning, and use escape-aware generic quote boundaries so an escaped apostrophe cannot split credential userinfo.

5. Treat an incomplete standalone single-quoted authority prefix as possible userinfo even when the whole body is below the truncation limit.

6. After a quoted URL rewrite, skip internal quote candidates but reconsider its closing quote as the only possible overlap boundary; apply the same rule to nested HTML attributes.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Observed all three single-quote regressions fail before the fix. HTML attribute scanning now reconsiders nested equals boundaries, and a post-normalization single-quoted URL pass protects standalone diagnostic tokens; the focused race-enabled truncation suite passes.

Independent review additionally reproduced incomplete and backslash-escaped standalone single-quoted credential URLs. Both failed before the fix and pass after the generic pass began inspecting incomplete tokens and using escape-aware quote termination.

CodeRabbit pass 2 found that an incomplete short single-quoted userinfo prefix still leaked because EOF classification was tied to body truncation. The focused regression failed before the fix; incomplete single-quoted tokens now apply the fail-closed quoted-userinfo suffix classifier regardless of body length.

Independent review found two panic paths from rescanning quotes inside already rewritten URL spans. Both panic reproducers now pass: a rewrite jumps to its closing quote rather than an escaped internal apostrophe, while a rewritten outer HTML attribute does not re-enter a nested attribute whose credentials were already scrubbed by the shared value redactor.
<!-- SECTION:NOTES:END -->
