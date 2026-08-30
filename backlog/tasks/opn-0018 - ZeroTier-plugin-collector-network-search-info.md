---
id: OPN-0018
title: ZeroTier plugin collector (network search/info)
status: To Do
assignee: []
created_date: '2026-08-30 09:08'
labels: []
dependencies: []
priority: medium
type: feature
ordinal: 18000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Cover `api/zerotier/network/search|info` — the best-value uncovered plugin per the 2026-08-30 upstream sweep. Joins the mesh-VPN family alongside tailscale/netbird/wireguard: network membership, status, assigned addresses. Plugin-gated: 404 = plugin absent.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 ZeroTier network status/membership metrics exported; plugin-absent 404 silent and negative-cached
- [ ] #2 AGENTS.md new-collector steps complete; gates clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
