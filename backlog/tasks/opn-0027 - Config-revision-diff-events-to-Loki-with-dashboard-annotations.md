---
id: OPN-0027
title: Config revision diff events to Loki with dashboard annotations
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 09:09'
updated_date: '2026-09-02 15:53'
labels:
  - first-wave
milestone: m-0
dependencies: []
priority: high
type: feature
ordinal: 103
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Top-ranked candidate of the 2026-08-30 research (all three lanes). Trigger off the already-polled `backupHistory` (`api/core/backup/backups/this`); on a new revision fetch `api/core/backup/diff/{host}/{old}/{new}` — upstream computes the unified diff (verified: `BackupController.php:109`, output is HTML-escaped, unescape before shipping). Ship one OTLP log event per revision via a new `internal/logship.Source` (`source="configchange"`): diff as body, user/uri/revision as attributes, StatefulSource cursor, ~192KB cap with truncation marker. Wire into the existing `grafana/annotations.py` Loki-driven annotation contract ("config changed here" on every graph) plus a config-change log panel. Works with the syslog receiver disabled; complements (does not replace) the audit syslog parser.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Each new config revision produces exactly one event with who/when/revision attributes and the unified diff body (unescaped, capped with truncation marker)
- [x] #2 Dashboard annotation layer + config-change log panel wired via the generated annotation contract
- [x] #3 Restart does not re-ship old revisions (cursor persistence semantics documented)
- [x] #4 just check, just docs, just grafana-check clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 1 plan: map the existing backup-history and OTLP source seams; write failing tests for exactly-once revision emission, unescaping, truncation and cursor restart semantics; implement the config-change source within the lane-owned files; return exact root wiring/dashboard edits and run focused tests.

Wave 2 L2: apply the preserved per-lane patch, review it against current acceptance criteria and moved main, rerun focused tests, then return root-owned wiring needed for integration.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 1 staged WIP implements config revision diff events with persisted cursor semantics, bounded/unescaped bodies, dashboard annotations, and context-cancellable fetches; focused tests and integrated just check passed. Post-correction L14 rechecked cancellation and found no remaining issue. Not landed because CodeRabbit failed twice before analysis. Resume: obtain a complete CodeRabbit review, fix critical/major findings, commit this task explicitly, integrate current origin/main, rerun just check, push, verify exact-SHA CI, then prove Loki delivery against a deployed instance.

Wave 2 applied the preserved patch cleanly, fixed endpoint-label cardinality, re-derived current endpoint/schema/ACL/canary/dashboard/docs wiring, and passed focused tests plus the full indexed `just check`. Landing is blocked solely by two CodeRabbit connection failures with no complete event. Both `codex/wip-opn-0027-config-revision-events.patch` and the reviewed combined `codex/wip-wave2-coderabbit-blocked.patch` are retained. Resume by applying the combined patch, rerunning the gate, and obtaining a completed CodeRabbit review.

Landed on main in `a482f637`.

SECURITY FIX APPLIED AT LANDING, not present in the wave 2 preserved patch: the shipped diff body had no redaction whatsoever, while the sibling OPN-0028 snapshot path did. An OPNsense config.xml diff carries user password hashes, API keys and secrets, WireGuard and IPsec private keys, RADIUS shared secrets and certificate private halves whenever those sections change, so every one of them left the firewall in a log record body. `redactConfigChangeDiff` in `internal/logship/configchange.go` now strips credential values before truncation, keeping the element name so an operator still sees WHAT changed. The vocabulary is shared with the snapshot path through the exported `opnsense.SensitiveConfigKey` rather than duplicated: the two had already drifted once into a camelCase bypass. The scanner carries an unterminated element across lines because base64 key material wraps, and drops that state at a hunk header so over-redaction cannot run away.

Found by CodeRabbit at severity major. Regression coverage: `TestRedactConfigChangeDiff_RemovesCredentials` (password, camelCase apiKey, kebab pre-shared-key, snake_case radius_secret, short `prv` and `privkey` elements), `_RedactsWrappedValues`, `_KeepsNonSensitiveContent`, `_HunkHeaderBoundsOverRedaction`, and `TestConfigChangeRecord_RedactsBeforeTruncation` which was verified to fail with the credential present when the redaction call is removed.

Live Loki delivery was not exercised.
<!-- SECTION:NOTES:END -->
