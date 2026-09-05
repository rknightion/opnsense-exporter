---
id: OPN-0091
title: >-
  Present console API counters as lifetime history rather than current auth
  health
status: In Progress
assignee:
  - '@codex'
created_date: '2026-09-05 18:58'
updated_date: '2026-09-05 19:07'
labels:
  - needs-triage
dependencies: []
priority: medium
type: bug
ordinal: 45000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The console derives AuthOK from cumulative API 401/403 counters. Once any endpoint has failed, the Auth badge says failing for the rest of the process even after access recovers; before any requests it says ok. The request total is also labelled last scrape although the value is cumulative. The source has no current-auth observation to support either live verdict.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Initial render and polling updates describe observed lifetime auth-error history without claiming current auth success or failure
- [ ] #2 API request count and duration labels state their process-lifetime scope and the underlying counters are preserved
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Add a failing rendered-output regression for no recorded errors and historical errors; change the card labels and both server/client badge text to historical wording, preserving the JSON fields and counts. Document AuthOK as compatibility history semantics. Verify rendered HTML and integrated tests; no new live-health inference.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Both rendered history cases failed before wording repair and passed afterward. Server and polling update use none recorded/errors recorded; counters and AuthOK JSON compatibility preserved. Rendered HTML verified; no browser layout exercise or live-auth claim.
<!-- SECTION:NOTES:END -->
