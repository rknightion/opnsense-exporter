---
id: OPN-0030
title: Security posture snapshot to Loki
status: To Do
assignee: []
created_date: '2026-08-30 09:09'
updated_date: '2026-09-02 15:54'
labels: []
milestone: m-1
dependencies:
  - OPN-0028
priority: medium
type: feature
ordinal: 203
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Snapshot family via the C2 framework (OPN-0028): firmware status/pending updates, package versions, listening sockets, cert-expiry roll-up, API keys with owners. Ship on change + weekly heartbeat (posture moves slower than config — deviating from the 6h default deliberately). Ship OPNsense's own update-available verdict; NO CVE matching (no advisory feed).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Posture family ships on change + weekly heartbeat behind its own default-off flag
- [ ] #2 Dashboard posture panel renders the snapshot
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 2 did not start this dependent because OPN-0028 could not land through the required CodeRabbit gate. Resume only after applying `codex/wip-wave2-coderabbit-blocked.patch`, obtaining a completed review, landing OPN-0028, and confirming its frozen configstate record and flag contract.

Unblocked 2026-09-02: OPN-0028 landed on main in `a482f637`. This task was parked only on that dependency. Retain the deliberate 7-day posture heartbeat override rather than the framework 6h default.
<!-- SECTION:NOTES:END -->
