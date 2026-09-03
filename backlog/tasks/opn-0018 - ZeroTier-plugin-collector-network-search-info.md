---
id: OPN-0018
title: ZeroTier plugin collector (network search/info)
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 09:08'
updated_date: '2026-09-03 09:13'
labels: []
milestone: m-3
dependencies: []
priority: medium
type: feature
ordinal: 402
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Cover `api/zerotier/network/search|info` — the best-value uncovered plugin per the 2026-08-30 upstream sweep. Joins the mesh-VPN family alongside tailscale/netbird/wireguard: network membership, status, assigned addresses. Plugin-gated: 404 = plugin absent.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 ZeroTier network status/membership metrics exported; plugin-absent 404 silent and negative-cached
- [x] #2 AGENTS.md new-collector steps complete; gates clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Reconstruct the source-derived ZeroTier API client and collector for network search/info; parse membership/status/assigned-address data with bounded status labels and plugin-absent 404 handling; wire endpoint defaults, cache/ACL/schema/canary contracts, collector option and main registration, dashboard and generated docs; run focused tests plus generation and just check, then finalize with exact evidence.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented the source-derived ZeroTier search/info join with bounded status labels, explicit runtime-field presence, plugin-absent search handling, static observer labels for UUID routes, live-canary UUID path resolution, default-on collector wiring, generated docs/schemas, and VPN dashboard coverage. Validation: focused ZeroTier and contract tests passed; just gen produced 68 collectors, 1,063/1,063 dashboard coverage and 187 schema goldens; just check passed including race tests, fuzz smoke, 427 Grafana tests, 1,220 Prometheus targets, 80 manifests, public-data scan and govulncheck. CodeRabbit source slice completed review_completed with zero findings across all 17 changed source files.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added the ZeroTier plugin collector for configured network count, enable state, bounded runtime status and assigned-address count. Search 404s stay silent and negative-cached; the parameterized info route is plugin-gated without an ineffective base-path TTL, and the live canary resolves a real network UUID before probing. Generated documentation, schemas and dashboard artifacts are current; focused tests, just gen, just check and a completed zero-finding CodeRabbit source review prove the task.
<!-- SECTION:FINAL_SUMMARY:END -->
