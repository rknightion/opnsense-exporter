---
id: OPN-0055
title: >-
  Preserve stable Unbound blocklist identity across search-query response
  generations
status: Parked
assignee:
  - '@codex'
created_date: '2026-09-02 02:13'
updated_date: '2026-09-02 07:01'
labels:
  - needs-triage
dependencies: []
priority: low
type: bug
ordinal: 9000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The Unbound search-query log source ships the API row blocklist value as a JSON attribute and Loki structured metadata. OPNsense 26.7 rewrites that value from the backend short code to the configured display value, so downstream identity changes silently across supported response generations. Define a stable, shape-tolerant identity contract without inventing data absent from the 26.7 response.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Search-query records expose a stable blocklist identity across the legacy short-code response and the 26.7 display-value response, or explicitly omit the unstable identity when it cannot be recovered
- [ ] #2 Regression coverage pins both supported response generations and the chosen log-record attribute contract
- [ ] #3 Documentation names any compatibility limitation that downstream Loki consumers must account for
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 2 L10: implement the frozen omit-when-unrecoverable blocklist identity contract across legacy and 26.7 shapes, with regression coverage and compatibility documentation.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Decision, Rob 2026-09-02: take AC1's second branch - explicitly OMIT the blocklist identity when the legacy short code cannot be recovered, and document the limitation. Do not introduce a new display-valued attribute: inventing a stable-looking identity the 26.7 response does not guarantee is recurring defect class 1 (modelling a payload shape upstream cannot produce), and downstream would consume it as though it were stable.

Wave 2 implemented frozen D6: legacy short-code identity is retained, while 26.7 rows proven by `category` presence omit unrecoverable blocklist identity from body and metadata. Focused tests, full indexed `just check`, and L13 review passed. Landing is blocked solely by two CodeRabbit connection failures with no complete event. Preserved in `codex/wip-wave2-coderabbit-blocked.patch`; resume by applying it, rerunning the gate, and obtaining a completed CodeRabbit review.
<!-- SECTION:NOTES:END -->
