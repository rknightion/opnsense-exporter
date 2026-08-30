---
id: OPN-0050
title: >-
  Pre-classify expected canary drift from 26.7 daemon bumps (Kea 3.0.4, Unbound
  1.26, Suricata 8.0.6, dpinger 3.6)
status: To Do
assignee: []
created_date: '2026-08-30 09:28'
labels: []
dependencies: []
priority: low
type: chore
ordinal: 50000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OPNsense 26.7 bumps Kea to 3.0.4, Unbound to 1.26, Suricata to 8.0.6 and dpinger to 3.6 — classic sources of new stats counters and flex-type payload changes. Rather than triaging the daily live-box canary (`cmd/apidrift`) finding-by-finding as they arrive, sweep the affected endpoints against the new daemon versions and pre-classify: new keys as `knownExtraTopKeys` opportunities, representation changes as absorb (flex types), per the canary triage taxonomy in AGENTS.md. Verify against upstream source before assigning any verdict.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Kea/Unbound/Suricata/dpinger-backed endpoints checked against the 26.7 daemon versions; expected drift pre-classified in exemptions.json with prune triggers
- [ ] #2 just schemas clean; canary quiet on the pre-classified keys
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
