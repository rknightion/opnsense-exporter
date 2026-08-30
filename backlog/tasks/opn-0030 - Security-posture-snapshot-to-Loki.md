---
id: OPN-0030
title: Security posture snapshot to Loki
status: To Do
assignee: []
created_date: '2026-08-30 09:09'
labels: []
dependencies:
  - OPN-0028
priority: medium
type: feature
ordinal: 30000
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
