---
id: OPN-0059
title: Prune pre-25.1 healthCheck legacy fields and their canary exemptions
status: Done
assignee:
  - '@codex'
created_date: '2026-09-03 13:06'
updated_date: '2026-09-03 20:49'
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
- [x] #1 Every pruned field is named, with the release that last emitted it and evidence that release is outside the current-plus-previous support window
- [x] #2 docs/compatibility.md records the narrowed support promise and what an operator on an older box loses
- [x] #3 Exemptions whose prune trigger has NOT fired are left in place, and the task states which were kept and why
- [x] #4 just check passes and the daily canary is green on the next scheduled run, or its findings are triaged under the five-verdict taxonomy
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 4: identify only pre-25.1 healthCheck fields and release-triggered exemptions from upstream history; remove those readers and exemptions, document the narrowed support contract, and preserve every box-state or unexpired exemption.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 4 source audit proved OPNsense 24.7.12 was the last release to emit the pre-25.1 healthCheck top-level System.status, CrashReporter message/status/statusCode, and Firewall message/status/statusCode fields. Upstream refactor 1fc5a6335 landed before 25.1; 24.7.12 is outside the current-plus-previous support window. Those readers, their two fixtures, four field-audit exemptions, and the three matching schema missingOK paths were pruned. Kept metadata.CrashReporter.*, metadata.Firewall.*, metadata.System.status, and top-level subsystems missingOK entries because their triggers are supported-shape or box-state conditions; all knownExtraPaths remain because their opportunity/presentation triggers have not fired. docs/compatibility.md states that older boxes retain reachability reporting but lose health-status interpretation. Focused tests, two completed zero-finding CodeRabbit passes, just gen, and the integrated just check passed. AC4 remains open pending the post-push live canary.

Post-push live-canary run 33804225885 completed success at exact head 9e1a7ba6191af48a6f12b92720115a027a463f12. Both nightly and release-vm jobs passed Schema canary and End-to-end exporter smoke. The report contained no healthCheck finding, so the pruned supported schema was accepted on both live targets; unrelated standing warnings remained outside this task.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Pruned the pre-25.1 healthCheck readers, fixtures, field-audit exemptions, and release-triggered schema exemptions while preserving supported-shape and box-state entries. Documented the narrowed support contract and verified with focused tests, two completed zero-finding CodeRabbit passes, exact-candidate just gen and just check, plus successful two-target live-canary run 33804225885 at the landed SHA.
<!-- SECTION:FINAL_SUMMARY:END -->
