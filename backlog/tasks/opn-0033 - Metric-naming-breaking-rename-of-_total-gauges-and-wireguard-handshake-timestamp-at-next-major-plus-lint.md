---
id: OPN-0033
title: >-
  Metric naming: breaking rename of _total gauges and wireguard handshake
  timestamp at next major
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 09:09'
updated_date: '2026-09-06 10:54'
labels: []
milestone: m-6
dependencies:
  - OPN-0052
priority: medium
type: enhancement
ordinal: 701
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
DECIDED 2026-08-30 (Rob): take the breaking rename at the next major release, with dashboard/alert migration in the same release. The guarding lint landed separately as OPN-0052 (dependency) — this task is the rename itself. Non-monotonic current-count gauges carrying `_total`: `crowdsec.go:77-88`, `dhcpv4.go:40-55`, `smart.go:58-61`, `hasync.go:52-53`, `carp.go:53-56`. Also `wireguard.go:68-71` `peer_last_handshake_seconds` is a Unix timestamp missing the project `_timestamp_seconds` suffix. Rename metrics + regenerate docs/dashboards/alerts + upgrading.md migration table, all in the same major release; remove the OPN-0052 allowlist entries as each rename lands.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Lint/test rejects new non-monotonic gauges named _total and unsuffixed timestamp metrics
- [x] #2 Rename change staged for the next major: metrics, dashboards, alerts, docs, upgrading.md migration table all in one release
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 9: extract all 66 rename rows and references; root freezes RenamedMetrics and proves unrenamed descriptors fail lint; parallel owned collector, Grafana and docgen lanes; regenerate, stage generated outputs, just check, source-only CodeRabbit slices and independent REVIEW; land one breaking 5.0 commit and leave the release PR unmerged.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 9 seam freeze: actual LegacyAllowlist has 65 entries across 35 files (57 count gauges, 8 timestamps), not the goal estimate of 66/58. Verified exact set equality before replacing it with RenamedMetrics. Preserved existing detail metrics by resolving aggregate collisions to opnsense_arp_table_table_entries, opnsense_ndp_table_entries and opnsense_openvpn_current_sessions. just metric-lint exited 1 with exactly 65 retired_metric_name violations covering every ledger row before collector changes. The moved-file/counter regression failed before implementation as expected.

Wave 9 integration correction: resolving full metric names exposed three existing gauges whose local name is total, so the old local-only suffix check never saw their emitted _total suffix: certificate_total, mbuf_total and snapshots_total. The ledger was re-frozen at 68 rows (60 count gauges, 8 timestamps) across 36 files, retaining all 65 original entries and adding certificate_certificates, mbuf_mbufs and snapshots_boot_environments under the opnsense namespace. Each extra failed retired_metric_name before its rename. Source, tests and Grafana references migrate together; no lint exception was added.

Wave 9 review: source-only CodeRabbit completed collectors (66 files, 28 findings) and integration (41 files, 7 findings). Companion-file findings were verified against the full renamed tree; stale HA-sync description, DHCPv6 comment and DynDNS absence comment were corrected. Pre-existing assertion-strengthening suggestions were read and left under the frozen no-test-growth contract. Independent REVIEW checked the 68-row ledger, collisions and migration table; its WireGuard Unix-timestamp help and local-name prose corrections are incorporated. First just check found seven newly recognizable timestamps without annotation disposition; explicit no-annotation reasons now preserve existing behavior. A subsequent gate intersected the guest-route failing-before regression and is not recorded as a pass.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Wave 9 completed at dbfbbe57c0695101610e6fb82a32822c0dd9475a: atomic 5.0 metric migration of 68 rows (60 current-count gauges and 8 timestamps); the actual old allowlist had 65 rows and full-name resolution exposed three additional gauges. just gen and just check passed, metric naming lint: OK, retired-name reference sweep 0 outside ledger/negative tests/history/migration table, rendered table 68 rows. Source-only CodeRabbit completed both slices (66 and 41 files); independent REVIEW corrections incorporated. Release-please PR 735 is chore(main): release 5.0.0 and remains open/unmerged for Rob. Alert changes: certificate expiry warning/critical and HA-sync unreachable; recording rules required no metric-reference change.
<!-- SECTION:FINAL_SUMMARY:END -->
