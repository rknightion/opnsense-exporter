---
id: OPN-0024
title: Verify monit status-XML parser against monit 6.0.0 (ships in OPNsense 26.7.3)
status: To Do
assignee: []
created_date: '2026-08-30 09:08'
updated_date: '2026-08-30 09:35'
labels: []
milestone: m-2
dependencies: []
priority: medium
type: spike
ordinal: 304
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OPNsense 26.7.3 bumps monit to 6.0.0. We parse `api/monit/status/get/xml` (`opnsense/monit*.go`). Verify the XML shape against monit 6 output (upstream monit source or a live 26.7.3 box); fix tolerantly if drifted, close with a note if compatible.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 monit 6.0.0 XML shape verified against parser; drift fixed tolerantly or compatibility recorded
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
