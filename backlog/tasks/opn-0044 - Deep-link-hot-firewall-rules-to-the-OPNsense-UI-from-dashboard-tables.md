---
id: OPN-0044
title: Deep-link hot firewall rules to the OPNsense UI from dashboard tables
status: To Do
assignee: []
created_date: '2026-08-30 09:10'
labels: []
dependencies: []
priority: low
type: enhancement
ordinal: 44000
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
