---
id: OPN-0059
title: Prune pre-25.1 healthCheck legacy fields and their canary exemptions
status: To Do
assignee: []
created_date: '2026-09-03 13:06'
labels: []
dependencies: []
priority: low
ordinal: 13000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The `healthCheck` tolerant readers and their `opnsense/testdata/schemas/exemptions.json` entries carry OPNsense generations older than 25.1. Those prune triggers have now fired: the generations sit outside the stated support window of current plus previous stable OPNsense.

Wave 3 deliberately did not act on this. Deleting them narrows the compatibility promise, which is a support-contract change rather than a canary tidy-up, so it needs to be a reviewable commit of its own rather than a side effect of an unrelated wave.

Two things move together and the second is the reason this is worth doing at all: the legacy readers widen what the exporter accepts, and the matching exemptions blind the daily canary to those fields. An exemption on a consumed field is the failure mode the triage rules in AGENTS.md call out by name, so leaving them costs real canary coverage, not just tidiness.

Scope is the pre-25.1 `healthCheck` generation only. Do not prune an entry whose trigger names a box state rather than a release, and do not touch any exemption whose prune trigger has not fired.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Every pruned field is named, with the release that last emitted it and evidence that release is outside the current-plus-previous support window
- [ ] #2 docs/compatibility.md records the narrowed support promise and what an operator on an older box loses
- [ ] #3 Exemptions whose prune trigger has NOT fired are left in place, and the task states which were kept and why
- [ ] #4 just check passes and the daily canary is green on the next scheduled run, or its findings are triaged under the five-verdict taxonomy
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
