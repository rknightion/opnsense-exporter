---
id: OPN-0025
title: Document 26.7 ACL privilege merge impact on restricted API keys
status: To Do
assignee: []
created_date: '2026-08-30 09:09'
labels: []
dependencies: []
priority: low
type: docs
ordinal: 25000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OPNsense 26.7 consolidated user-management privileges; restricted API keys may need re-granting for `auth/*` search endpoints (`authUsers`, `authGroups`, `authAPIKeys`). Add a docs/compatibility.md note and check whether the recommended-permissions guidance in docs/security or getting-started needs updating.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 compatibility docs describe the 26.7 ACL change and the re-grant needed for auth endpoints
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
