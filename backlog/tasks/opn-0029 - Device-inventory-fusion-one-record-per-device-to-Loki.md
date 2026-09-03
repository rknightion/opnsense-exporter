---
id: OPN-0029
title: 'Device inventory fusion: one record per device to Loki'
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 09:09'
updated_date: '2026-09-03 19:36'
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
- [x] #1 One deduped record per device with the fused identity fields
- [x] #2 New-device annotation layer works
- [x] #3 Opt-in flag, default off; gates clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Fuse ARP, NDP, DHCP, host-discovery, and LLDP observations into stable device identities with bounded canonical output and shared sensitive-key redaction.
2. Integrate the default-off device provider into the existing configstate source, preserving new-device markers transactionally across failed polls.
3. Add the Config device table and nested new-device annotation, regenerate all artifacts, and verify focused tests plus just gen and just check.
4. Finalize atomically, commit only OPN-0029 paths, and push main.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 2 did not start this dependent because OPN-0028 could not land through the required CodeRabbit gate. Resume only after applying `codex/wip-wave2-coderabbit-blocked.patch`, obtaining a completed review, landing OPN-0028, and confirming its frozen configstate record and flag contract.

Unblocked 2026-09-02: the OPN-0028 configstate framework and its frozen record/flag contract landed on main in `a482f637`. This task was parked only on that dependency.

Wave 3 implementation complete. The device-inventory provider fuses ARP, NDP, DHCP, host-discovery, and LLDP observations into stable MAC-first identities with bounded unambiguous IP fallback, sorted fields, first/last-seen and OUI vendor data, and shared SensitiveConfigKey redaction. Snapshot cursor changes are committed only after every provider succeeds, so a failed later provider cannot consume the one-time new_device marker. The default-off flag is OPN2OTEL_LOGS_CONFIG_SNAPSHOT_DEVICES_ENABLED. Focused race/API/options and 29 Grafana annotation/config tests passed; just gen completed with 1050/1050 dashboard metric coverage and just check passed with 427 Grafana tests. CodeRabbit slices phase1-opnsense-collector, phase1-logship-options, and phase1-grafana completed; all actionable major findings were resolved.

Wave 4 OPN-0060 live-proof disposition: NOT PROVEN. The testbed became ready, but its API credentials were unavailable to the mandated local process and exist only in the protected CI environment; CI was forbidden as a substitute. No exporter delivery run, Loki query, or on-wire result occurred for this source. Resume through OPN-0060 after an authorised local testbed credential launcher exists.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added default-off, redacted device-inventory fusion to configstate with one deduplicated record per device, transactional new-device markers, a Config table, and a nested-entity annotation. Verified by focused race tests, just gen, and full just check. This task is landed by the commit containing this summary; the exact SHA is recorded in the wave report.
<!-- SECTION:FINAL_SUMMARY:END -->
