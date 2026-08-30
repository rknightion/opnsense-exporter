---
id: OPN-0028
title: >-
  Config-state snapshots to Loki: per-entity JSON, opt-in per family, 6h
  heartbeat
status: To Do
assignee: []
created_date: '2026-08-30 09:09'
labels: []
dependencies: []
priority: high
type: feature
ordinal: 28000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
DECIDED 2026-08-30 (Rob): every family opt-in via its own flag, default off; ship-on-change (content hash) plus a full heartbeat re-snapshot every 6h. Mechanism per the research verdict: plain JSON, one log record per entity (NOT base64, NOT one giant line — Loki max_line_size 256KB default), `snapshot.id` + `seq` as structured-metadata attributes, rendered via LogQL `| json` / Extract-fields table panels under a new Config dashboard tab. Families: firewall rules + all four NAT rule sets (already fetched), aliases WITH resolved contents (new endpoints — today we fetch table sizes only), users/groups/API keys, certificates with CN/SAN detail, DHCP reservations, VPN instance configs, interface assignments. Reuse `internal/logship.Source`; keep `opnsense.source`/`opnsense.subsystem` as the only stream labels. Likely worth splitting into per-family subtasks at planning time.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Snapshot framework: hash-dedupe + 6h heartbeat, per-entity records with snapshot.id/seq attributes
- [ ] #2 Each family behind its own default-off flag; identity-bearing families documented as such
- [ ] #3 Config dashboard tab renders at least the firewall-rules family as an ordered table
- [ ] #4 Loki line-size cap respected by construction; gates clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
