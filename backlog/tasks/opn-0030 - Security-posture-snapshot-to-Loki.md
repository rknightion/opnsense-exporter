---
id: OPN-0030
title: Security posture snapshot to Loki
status: Parked
assignee:
  - '@codex'
created_date: '2026-08-30 09:09'
updated_date: '2026-09-03 06:50'
labels: []
milestone: m-1
dependencies:
  - OPN-0028
priority: medium
type: feature
ordinal: 203
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Snapshot family via the C2 framework (OPN-0028): firmware status/pending updates, package versions, listening sockets, cert-expiry roll-up, API keys with owners. Ship on change + weekly heartbeat (posture moves slower than config — deviating from the 6h default deliberately). Ship OPNsense's own update-available verdict; NO CVE matching (no advisory feed).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Posture family ships on change + weekly heartbeat behind its own default-off flag
- [x] #2 Dashboard posture panel renders the snapshot
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Build a default-off security_posture configstate provider from existing firmware, certificate, and API-key endpoints, with recursive sensitive-key redaction and a seven-day heartbeat.
2. Aggregate OPNsense update verdict/pending packages, certificate expiry, and API-key owners; omit listening sockets until released source or a real capture proves listener semantics.
3. Wire the provider into the shared factory and Config dashboard, regenerate artifacts, and run focused plus full gates.
4. Land the proven partial implementation and park the remaining listening-socket subfeature at its exact evidence boundary.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 2 did not start this dependent because OPN-0028 could not land through the required CodeRabbit gate. Resume only after applying `codex/wip-wave2-coderabbit-blocked.patch`, obtaining a completed review, landing OPN-0028, and confirming its frozen configstate record and flag contract.

Unblocked 2026-09-02: OPN-0028 landed on main in `a482f637`. This task was parked only on that dependency. Retain the deliberate 7-day posture heartbeat override rather than the framework 6h default.

Wave 3 landed the source-proven portion: a default-off security_posture configstate family with exact seven-day heartbeat, change dedupe, OPNsense update verdict and pending package versions, certificate expiry roll-up, API-key owner aggregation, and recursive SensitiveConfigKey redaction. The Config dashboard renders the stream. Focused race tests passed across opnsense, options, and configsnapshot; just gen completed with 1050/1050 metric coverage; full just check passed with 427 Grafana tests. CodeRabbit slices phase1-opnsense-collector, phase1-logship-options, and phase1-grafana completed with no unresolved actionable critical/major findings.

PARKED RESUME BOUNDARY: obtain released upstream controller/source or a redacted real capture that proves which response field represents listening sockets and its listener-state semantics. Then add only that bounded listening-socket aggregate to SecurityPosture and its provider tests; do not infer listeners from the existing active-socket counts.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Partial implementation landed: weekly, default-off security posture snapshots now cover firmware/package state, certificate expiry, and API-key owners with redaction and a dashboard view. Listening-socket posture remains unproven and is the sole parked remainder. Resume from released source or a redacted capture proving listener fields and semantics; exact commit SHA is recorded in the wave report.
<!-- SECTION:FINAL_SUMMARY:END -->
