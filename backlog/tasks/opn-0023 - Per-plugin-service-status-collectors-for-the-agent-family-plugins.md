---
id: OPN-0023
title: Per-plugin service-status collectors for the agent-family plugins
status: To Do
assignee: []
created_date: '2026-08-30 09:08'
labels: []
dependencies: []
priority: low
type: feature
ordinal: 23000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
DECIDED 2026-08-30: per-plugin collectors, not one umbrella (Rob). Cover the agent-family plugins whose only observable surface is the base-class `*/service/status` (collectd, telegraf, netdata, nrpe, zabbix-agent, wazuh-agent, and peers found in the plugins repo sweep): one small collector each, service-up metric, plugin-absent 404 negative-cached, individual disable flags. Enumerate the exact plugin list from opnsense/plugins at implementation time rather than trusting this description.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Each covered plugin has its own collector + disable flag; absent plugins stay silent
- [ ] #2 Plugin list enumerated from upstream at build time and recorded in the task notes
- [ ] #3 AGENTS.md new-collector steps complete per plugin; gates clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
