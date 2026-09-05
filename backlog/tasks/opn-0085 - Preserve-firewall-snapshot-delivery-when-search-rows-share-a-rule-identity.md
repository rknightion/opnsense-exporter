---
id: OPN-0085
title: Preserve firewall snapshot delivery when search rows share a rule identity
status: In Progress
assignee:
  - '@codex'
created_date: '2026-09-05 18:04'
updated_date: '2026-09-05 18:20'
labels:
  - needs-triage
dependencies: []
priority: high
type: bug
ordinal: 39000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Live proof run 33982574173 at 809ba1b9 reached m7kni and shipped a configstate poll error from canonicalEntities: the firewall snapshot contained a duplicate filter_rule entity identity. No configuration snapshot family arrived because the source discards its batch on this error. The API snapshot projection currently assumes every search row UUID is unique. Inspect the upstream search-rule producer before deciding whether rows are duplicates or distinct expansions; preserve every meaningful row without weakening the canonical uniqueness invariant.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 The upstream producer branch allowing repeated rule identities is documented and fixtures represent only shapes it can produce
- [ ] #2 Valid repeated-identity search rows produce a deterministic complete firewall snapshot without suppressing other families
- [ ] #3 A regression fails before the repair and passes afterward, including order stability and no silent loss of distinct rows
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Upstream stable/26.7 and stable/26.1 non-MVC rule enumeration maps repeated PF labels into uuid while assigning distinct sort_order. Preserve unique UUID identities; discriminate repeated filter_rule UUIDs by producer sort_order, require that discriminator, preserve complete redacted rows, and retain canonical duplicate rejection. Add a failing-before regression with valid generated-rule shapes and reversed row order; run targeted tests, source-only review and just check.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Upstream source basis: opnsense/core stable/26.7 at 6fc5e865f1859f209a84016e610615aa176efbea and stable/26.1 at 8cc69b21e0f4c2622fc8a62df2a15ba7cb1e731f. src/opnsense/mvc/app/controllers/OPNsense/Firewall/Api/FilterController.php searchRuleAction merges non-MVC rows. src/opnsense/scripts/filter/list_non_mvc_rules.php:51-74 maps PF label into uuid and emits every enabled row; :115-122 assigns distinct sort_order from priority and incrementing sequence. Firewall/Plugin.php registerFilterRule uses calcRuleHash for unlabeled rules; iterateFilterRules does not deduplicate. Firewall/Util.php:409-422 excludes descr, updated and created from the hash. Distinct upstream rows can therefore share a uuid; keeping only one would lose configuration. The specific dynamic registration pair on the live box was not inspected.

Frozen implementation retains unique raw UUIDs and uses uuid plus producer sort_order only for repeated filter rules. Focused regression observed the duplicate-ID/missing-discriminator failures before repair; afterward: ok github.com/rknightion/opnsense2otel/v4/opnsense 0.367s. Response fixture uses upstream description (derived from descr), legacy, is_automatic, enabled and distinct sort_order. Reversed response order retains ID-to-row mapping and every NAT row. No canonical invariant changes.
<!-- SECTION:NOTES:END -->
