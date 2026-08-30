---
id: OPN-0036
title: Set SO_RCVBUF on syslog and NetFlow UDP sockets
status: To Do
assignee: []
created_date: '2026-08-30 09:09'
updated_date: '2026-08-30 09:35'
labels: []
milestone: m-4
dependencies: []
priority: medium
type: enhancement
ordinal: 503
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
No `SetReadBuffer` call exists anywhere; OS-default UDP buffers (~208KB) are the classic source of invisible kernel-level drops that the pipeline's otherwise-exhaustive loss accounting cannot see. Set a sane default with a flag override on both receivers, and Warn when the OS clamps the requested size (Linux caps at net.core.rmem_max).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Both UDP sockets request a configurable receive buffer; clamped requests produce a Warn naming the sysctl
- [ ] #2 Flags documented via just docs
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
