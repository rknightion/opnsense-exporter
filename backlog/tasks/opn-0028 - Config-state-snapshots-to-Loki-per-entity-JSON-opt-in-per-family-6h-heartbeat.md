---
id: OPN-0028
title: >-
  Config-state snapshots to Loki: per-entity JSON, opt-in per family, 6h
  heartbeat
status: Parked
assignee:
  - '@codex'
created_date: '2026-08-30 09:09'
updated_date: '2026-09-02 05:17'
labels: []
milestone: m-1
dependencies: []
priority: high
type: feature
ordinal: 201
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

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 1 frozen seam (L0, 2026-09-01; dependents must not reopen):

Package/entry point: implement the reusable framework in internal/logship/configsnapshot; Source.Name() is configstate, every record sets opnsense.subsystem=config, and the root wires the package into main with a blank import. Reuse logship.Source/StatefulSource; do not create a parallel sink or poll loop.

Flag names, all bool/default false and requiring --logs.enabled:
- --logs.config-snapshot.firewall.enabled (one logical family containing entity kinds filter_rule, source_nat, d_nat, one_to_one, npt)
- --logs.config-snapshot.aliases.enabled
- --logs.config-snapshot.identities.enabled (users, groups, API keys)
- --logs.config-snapshot.certificates.enabled
- --logs.config-snapshot.dhcp-reservations.enabled
- --logs.config-snapshot.vpn.enabled
- --logs.config-snapshot.interfaces.enabled
Reserved for dependent tasks on the same seam: --logs.config-snapshot.devices.enabled (OPN-0029), --logs.config-snapshot.security-posture.enabled (OPN-0030), --logs.config-snapshot.routing-changes.enabled (OPN-0031). No umbrella flag is added in this wave.

Record body schema v1 (compact JSON):
{"schema":"opnsense.config.snapshot.v1","family":"<closed family name>","entity_id":"<stable family-defined id>","entity":{...family payload...},"truncated":false}
The body is one entity and must remain valid JSON. Record structured-metadata attributes are snapshot.id (opaque batch id shared by the family batch), snapshot.seq (1-based decimal in stable entity-id order), snapshot.total, snapshot.family, snapshot.reason (change|heartbeat), and snapshot.entity_id. These remain structured metadata; the only stream-label candidates stay opnsense.source=configstate and opnsense.subsystem=config.

Dedupe/heartbeat contract: canonicalise each family as the stable entity-id-ordered v1 bodies, SHA-256 that canonical byte stream, and persist per-family {hash,last_emitted_at} through StatefulSource. A changed hash emits a full family snapshot. An unchanged family emits nothing until 6h since last_emitted_at, then emits a full heartbeat snapshot. The security-posture dependent deliberately overrides its family heartbeat to 7d. Snapshot ids are opaque and unique per emitted batch; consumers may correlate on them but must not parse them.

Line bound: encoded Body must be <=196608 bytes. If a family entity would exceed that bound, emit one valid v1 envelope for that entity with entity=null, truncated=true, original_bytes and content_sha256 fields, plus snapshot.truncated=true metadata. Never byte-slice JSON and never create a second stream label. Family implementations should split naturally repeated data into stable entities before this fallback.

Reachability: the Config dashboard queries {opnsense_source="configstate",opnsense_subsystem="config"} | json and orders the firewall table by snapshot.seq. Framework tests must prove changed/unchanged/6h heartbeat behavior, persistence round-trip, stable ordering, shared snapshot id, 1..N sequence, valid bounded JSON and the oversize fallback.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 1 staged WIP implements the frozen configstate snapshot framework, options, firewall family, persistence/dedupe/heartbeat/bounds, and Config dashboard reachability. Focused tests, Grafana coverage, and integrated just check passed; L14 found no remaining issue. The dashboard table deliberately shows distinct in-range batch/entity rows because current opaque batch IDs and labels cannot select only the dynamically latest batch in LogQL. Not landed because CodeRabbit failed twice before analysis. Resume: obtain a complete review, commit explicitly, integrate current origin/main, rerun gates, push, verify exact-SHA CI, then decide whether latest-batch-only selection warrants a backend or label-contract change.

Decision, Rob 2026-09-02: keep the reversible in-range batch/entity table. Do NOT reshape the backend record or the label contract to make latest-complete-batch selection expressible in dashboard-only LogQL - that is a display concern buying a permanent data-contract cost, and the current table is truthful about what it shows. Revisit only if an operator hits the ambiguity in practice.
<!-- SECTION:NOTES:END -->
