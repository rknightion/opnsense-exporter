---
id: OPN-0030
title: Security posture snapshot to Loki
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 09:09'
updated_date: '2026-09-03 20:41'
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
- [x] #1 Posture family ships on change + weekly heartbeat behind its own default-off flag
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

Wave 4: derive the listening-socket response field and semantics from released upstream source first; if proved, add only the bounded listening-socket aggregate and focused provider tests.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 2 did not start this dependent because OPN-0028 could not land through the required CodeRabbit gate. Resume only after applying `codex/wip-wave2-coderabbit-blocked.patch`, obtaining a completed review, landing OPN-0028, and confirming its frozen configstate record and flag contract.

Unblocked 2026-09-02: OPN-0028 landed on main in `a482f637`. This task was parked only on that dependency. Retain the deliberate 7-day posture heartbeat override rather than the framework 6h default.

Wave 3 landed the source-proven portion: a default-off security_posture configstate family with exact seven-day heartbeat, change dedupe, OPNsense update verdict and pending package versions, certificate expiry roll-up, API-key owner aggregation, and recursive SensitiveConfigKey redaction. The Config dashboard renders the stream. Focused race tests passed across opnsense, options, and configsnapshot; just gen completed with 1050/1050 metric coverage; full just check passed with 427 Grafana tests. CodeRabbit slices phase1-opnsense-collector, phase1-logship-options, and phase1-grafana completed with no unresolved actionable critical/major findings.

PARKED RESUME BOUNDARY: obtain released upstream controller/source or a redacted real capture that proves which response field represents listening sockets and its listener-state semantics. Then add only that bounded listening-socket aggregate to SecurityPosture and its provider tests; do not infer listeners from the existing active-socket counts.

Wave 4 OPN-0060 live-proof disposition: NOT PROVEN. The testbed became ready, but its API credentials were unavailable to the mandated local process and exist only in the protected CI environment; CI was forbidden as a substitute. No exporter delivery run, Loki query, or on-wire result occurred for this source. Resume through OPN-0060 after an authorised local testbed credential launcher exists.

Wave 4 completed the parked listening-socket remainder from released upstream source: the socket-statistics response carries listen-queue-sizes only for accept-queue listeners, with Internet listeners restricted to wildcard-remotes and UNIX-domain listeners counted by section. The provider now emits the bounded aggregate. Focused race tests passed, the integrated just gen reported 82 collectors and 1,046 metrics, and the full just check passed including 427 Grafana tests. Two source-only CodeRabbit passes completed with zero findings. Live Loki delivery remains explicitly unproven under OPN-0060 because no authorised local testbed API credential source existed.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Partial implementation landed: weekly, default-off security posture snapshots now cover firmware/package state, certificate expiry, and API-key owners with redaction and a dashboard view. Listening-socket posture remains unproven and is the sole parked remainder. Resume from released source or a redacted capture proving listener fields and semantics; exact commit SHA is recorded in the wave report.

Wave 4 completed the weekly default-off security-posture snapshot by adding the released-source-derived listening-socket aggregate. Verified with focused race tests, two completed zero-finding CodeRabbit passes, just gen, and the full just check; live backend delivery remains tracked separately by OPN-0060.
<!-- SECTION:FINAL_SUMMARY:END -->
