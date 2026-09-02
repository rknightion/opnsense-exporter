---
id: OPN-0050
title: >-
  Pre-classify expected canary drift from 26.7 daemon bumps (Kea 3.0.4, Unbound
  1.26, Suricata 8.0.6, dpinger 3.6)
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 09:28'
updated_date: '2026-09-02 03:39'
labels: []
milestone: m-2
dependencies: []
priority: low
type: chore
ordinal: 305
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OPNsense 26.7 bumps Kea to 3.0.4, Unbound to 1.26, Suricata to 8.0.6 and dpinger to 3.6 — classic sources of new stats counters and flex-type payload changes. Rather than triaging the daily live-box canary (`cmd/apidrift`) finding-by-finding as they arrive, sweep the affected endpoints against the new daemon versions and pre-classify: new keys as `knownExtraTopKeys` opportunities, representation changes as absorb (flex types), per the canary triage taxonomy in AGENTS.md. Verify against upstream source before assigning any verdict.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Kea/Unbound/Suricata/dpinger-backed endpoints checked against the 26.7 daemon versions; expected drift pre-classified in exemptions.json with prune triggers
- [x] #2 just schemas clean; canary quiet on the pre-classified keys
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Inspect the 26.7-backed upstream sources for Kea, Unbound, Suricata and dpinger payload-shape changes, classify only source-proven drift under the repository taxonomy, and return any shared exemption edits to root for atomic application.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 1 source audit found no Kea, Unbound, dpinger, or production-path Suricata drift that warrants an exemptions.json entry; adding speculative exemptions would weaken the canary. just schemas/integrated just check passed, and live canary run 33571438780 succeeded for both release and nightly profiles at exact SHA d91cfb1b. The tracker result is not landed because origin/main advanced while the integrated staged batch remained under review. Resume: land this tracker-only no-change classification on current origin/main, verify exact-SHA CI, and finalize; re-open only for a source-proven or live-canary finding.

The source audit found no Kea, Unbound, dpinger, or production-path Suricata payload drift warranting an exemptions entry; adding speculative exemptions would weaken the canary.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Audited the 26.7-backed daemon payload sources at d91cfb1bdc148af9273982749145011647a4b5a2 and found no source-proven drift to pre-classify. just schemas and just check passed; live canary run 33571438780 succeeded for both profiles at that exact SHA.
<!-- SECTION:FINAL_SUMMARY:END -->
