---
id: OPN-0044
title: Deep-link hot firewall rules to the OPNsense UI from dashboard tables
status: Done
assignee: []
created_date: '2026-08-30 09:10'
updated_date: '2026-09-03 07:13'
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
- [x] #1 Rule rows deep-link to the firewall UI, or the task records why no stable link is possible
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Record the already-completed stable/26.7 source investigation: persistent UUID/rlabel supports metric-to-rule identity, but available UUID routes lead only to diagnostics state/log views and no stable rule editor URL. Make no dashboard change, regenerate to prove no drift, run the full gate, then close with the precise evidence.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 2 did not start this lower-priority dashboard polish because OPN-0056 could not land through the required CodeRabbit gate. Resume after OPN-0056 lands; author only in `grafana/tabs/` and regenerate the dashboard artifacts.

Unblocked 2026-09-02: OPN-0056 landed on main in `a482f637`. First prove whether a persistent `rlabel` yields a stable OPNsense UI URL; if no stable link exists, close the task with that evidence rather than shipping a fragile deep link.

Investigated upstream stable/26.7 at bf16bfcdaf436a29d12ea0345292d1f09f5ea062. Rule statistics can join to persistent rule UUID/rlabel, but the available UUID-bearing UI targets are diagnostics state/log views, not a stable firewall rule editor route. A guessed editor URL would be fragile, so grafana/tabs/firewall.py is deliberately unchanged. just gen produced no source/generated diff; just check passed with 427 Grafana tests and 1,209 Prometheus target validations. CodeRabbit was skipped because this is a tracker-only no-change disposition with no code or authored dashboard diff.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Closed with no dashboard change: persistent UUID/rlabel supports rule identity, but upstream exposes no stable rule-editor deep link. Generation and the full repository gate passed unchanged.
<!-- SECTION:FINAL_SUMMARY:END -->
