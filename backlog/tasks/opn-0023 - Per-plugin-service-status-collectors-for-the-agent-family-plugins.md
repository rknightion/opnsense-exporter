---
id: OPN-0023
title: Per-plugin service-status collectors for the agent-family plugins
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 09:08'
updated_date: '2026-09-03 09:36'
labels: []
milestone: m-3
dependencies: []
priority: low
type: feature
ordinal: 406
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
DECIDED 2026-08-30: per-plugin collectors, not one umbrella (Rob). Cover the agent-family plugins whose only observable surface is the base-class `*/service/status` (collectd, telegraf, netdata, nrpe, zabbix-agent, wazuh-agent, and peers found in the plugins repo sweep): one small collector each, service-up metric, plugin-absent 404 negative-cached, individual disable flags. Enumerate the exact plugin list from opnsense/plugins at implementation time rather than trusting this description.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Each covered plugin has its own collector + disable flag; absent plugins stay silent
- [x] #2 Plugin list enumerated from upstream at build time and recorded in the task notes
- [x] #3 AGENTS.md new-collector steps complete per plugin; gates clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Reconstruct the 13 source-enumerated agent-family plugin service collectors and shared implementation; wire the root-owned endpoint, cache, ACL, schema, subsystem, availability, option and main registries; add dashboard coverage; reconcile the historical api-landmines won’t-build note; run focused tests, generation, source-only CodeRabbit slices and just check; finalize and land as one task commit.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Enumerated the stable opnsense/plugins agent and monitoring service-status family at commit 335042e9801015b609fac5f24b4ccf372a520626: beats, collectd, munin-node, net-snmp, netdata, node_exporter, nrpe, puppet-agent, qemu-guest-agent, telegraf, wazuh-agent, zabbix-agent and zabbix-proxy. ntopng and cloudflared remain outside the decided family scope. Implemented one collector and disable flag per plugin with silent plugin-absent handling and negative-cached 404s; wired endpoint, schema, ACL, availability, options, main, docs and dashboard coverage. just gen produced 81 collectors, 1,035 metrics, 200 schema goldens and 1,076/1,076 dashboard catalogue coverage. Focused plugin-service tests and just check passed. CodeRabbit source review completed with zero findings over the full task source set. A post-lint 14-file wrapper/test slice also completed; its three major endpoint-registration findings were verified as slice-context false positives because opnsense/client.go in the real tree already registers all 13 routes.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added 13 independent agent-family plugin service-status collectors with per-plugin disable controls, silent missing-plugin behavior, negative 404 caching, generated schemas/docs and complete dashboard coverage. Verified with focused tests, just gen, two completed source-only CodeRabbit slices, and the full just check gate.
<!-- SECTION:FINAL_SUMMARY:END -->
