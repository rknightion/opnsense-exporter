---
id: OPN-0029
title: 'Device inventory fusion: one record per device to Loki'
status: Parked
assignee: []
created_date: '2026-08-30 09:09'
updated_date: '2026-09-02 07:02'
labels: []
milestone: m-1
dependencies:
  - OPN-0028
priority: medium
type: feature
ordinal: 202
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Fuse ARP + NDP + DHCP leases + hostdiscovery + lldpd (all already fetched; `internal/logship/enrich` does partial identity fusion today) into one record per device: MAC, IPs, hostname, interface, first/last seen, OUI vendor. Ship-on-change + heartbeat via the C2 snapshot framework (dependency). Devices table panel; "new device on network" annotation; joins with flow/firewall logs by IP in Explore.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 One deduped record per device with the fused identity fields
- [ ] #2 New-device annotation layer works
- [ ] #3 Opt-in flag, default off; gates clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 2 did not start this dependent because OPN-0028 could not land through the required CodeRabbit gate. Resume only after applying `codex/wip-wave2-coderabbit-blocked.patch`, obtaining a completed review, landing OPN-0028, and confirming its frozen configstate record and flag contract.
<!-- SECTION:NOTES:END -->
