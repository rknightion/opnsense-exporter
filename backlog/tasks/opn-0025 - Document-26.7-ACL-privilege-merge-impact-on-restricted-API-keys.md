---
id: OPN-0025
title: Document 26.7 ACL privilege merge impact on restricted API keys
status: Done
assignee: []
created_date: '2026-08-30 09:09'
updated_date: '2026-09-02 06:49'
labels: []
milestone: m-2
dependencies: []
priority: low
type: docs
ordinal: 306
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OPNsense 26.7 consolidated user-management privileges; restricted API keys may need re-granting for `auth/*` search endpoints (`authUsers`, `authGroups`, `authAPIKeys`). Add a docs/compatibility.md note and check whether the recommended-permissions guidance in docs/security or getting-started needs updating.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 compatibility docs describe the 26.7 ACL change and the re-grant needed for auth endpoints
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 2 L11: verify the released 26.7 ACL privilege consolidation against repository guidance, document only the operator-visible re-grant requirement, and validate generated-document consistency. Documentation-only lane; no runtime changes.
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Documented the OPNsense 26.7 user-management ACL consolidation, the restricted-user re-grant procedure, and the affected auth endpoint family in commit e0309efc. Verified with `just docs-check </dev/null`: doclint passed and all generated docs were current. CodeRabbit was deliberately skipped because this was documentation-only.
<!-- SECTION:FINAL_SUMMARY:END -->
