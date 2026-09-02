---
id: OPN-0055
title: >-
  Preserve stable Unbound blocklist identity across search-query response
  generations
status: To Do
assignee: []
created_date: '2026-09-02 02:13'
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
