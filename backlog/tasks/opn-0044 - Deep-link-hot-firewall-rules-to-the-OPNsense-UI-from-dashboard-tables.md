---
id: OPN-0044
title: Deep-link hot firewall rules to the OPNsense UI from dashboard tables
status: Parked
assignee: []
created_date: '2026-08-30 09:10'
updated_date: '2026-09-02 07:02'
labels: []
milestone: m-4
dependencies: []
priority: low
type: enhancement
ordinal: 510
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
From the top-20 firewall rule tables (`grafana/tabs/firewall.py:310-379`), link each rule to its OPNsense UI page if a stable URL exists. 26.7.3's persistent pf `rlabel` may be the stable join key between rule stats and rule definitions — investigate that first; if no stable URL exists, close with a note.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Rule rows deep-link to the firewall UI, or the task records why no stable link is possible
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 2 did not start this lower-priority dashboard polish because OPN-0056 could not land through the required CodeRabbit gate. Resume after OPN-0056 lands; author only in `grafana/tabs/` and regenerate the dashboard artifacts.
<!-- SECTION:NOTES:END -->
