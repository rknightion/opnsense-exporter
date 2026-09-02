---
id: OPN-0051
title: >-
  Comment the deliberate is_enabled (not isBlockListEnabled) choice in the
  unbound client
status: Done
assignee: []
created_date: '2026-08-30 09:28'
updated_date: '2026-09-02 04:08'
labels: []
milestone: m-2
dependencies: []
priority: low
type: chore
ordinal: 308
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Upstream comment-deprecated `isBlockListEnabled` in favour of `is_enabled` on the unbound overview API; we already use `is_enabled` (`unboundQueryStatsEnabled` → `api/unbound/overview/is_enabled`). Add a short code comment at the endpoint/consumer recording that this is deliberate and the deprecated sibling must not be "restored", so future drift work does not fix it backwards.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Comment in place naming the deprecated upstream sibling; no behaviour change
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Landed a comment at the endpoint map naming upstream isBlockListEnabled as deprecated and preserving the current is_enabled route in 70aa2bccf6f88798b5edf93aa4c2288c4e89a5c9. CodeRabbit was skipped because the change is comment-only.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Documented the deliberate current Unbound endpoint choice without changing behavior. The endpoint-count test and just check passed; exact-head CI run 33589098221 succeeded at 70aa2bccf6f88798b5edf93aa4c2288c4e89a5c9.
<!-- SECTION:FINAL_SUMMARY:END -->
