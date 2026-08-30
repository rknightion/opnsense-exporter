---
id: OPN-0051
title: >-
  Comment the deliberate is_enabled (not isBlockListEnabled) choice in the
  unbound client
status: To Do
assignee: []
created_date: '2026-08-30 09:28'
labels: []
dependencies: []
priority: low
type: chore
ordinal: 51000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Upstream comment-deprecated `isBlockListEnabled` in favour of `is_enabled` on the unbound overview API; we already use `is_enabled` (`unboundQueryStatsEnabled` → `api/unbound/overview/is_enabled`). Add a short code comment at the endpoint/consumer recording that this is deliberate and the deprecated sibling must not be "restored", so future drift work does not fix it backwards.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Comment in place naming the deprecated upstream sibling; no behaviour change
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
