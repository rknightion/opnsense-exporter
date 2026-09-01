---
id: OPN-0027
title: Config revision diff events to Loki with dashboard annotations
status: Parked
assignee:
  - '@codex'
created_date: '2026-08-30 09:09'
updated_date: '2026-09-01 23:42'
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
- [ ] #1 Each new config revision produces exactly one event with who/when/revision attributes and the unified diff body (unescaped, capped with truncation marker)
- [ ] #2 Dashboard annotation layer + config-change log panel wired via the generated annotation contract
- [ ] #3 Restart does not re-ship old revisions (cursor persistence semantics documented)
- [ ] #4 just check, just docs, just grafana-check clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 1 plan: map the existing backup-history and OTLP source seams; write failing tests for exactly-once revision emission, unescaping, truncation and cursor restart semantics; implement the config-change source within the lane-owned files; return exact root wiring/dashboard edits and run focused tests.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 1 staged WIP implements config revision diff events with persisted cursor semantics, bounded/unescaped bodies, dashboard annotations, and context-cancellable fetches; focused tests and integrated just check passed. Post-correction L14 rechecked cancellation and found no remaining issue. Not landed because CodeRabbit failed twice before analysis. Resume: obtain a complete CodeRabbit review, fix critical/major findings, commit this task explicitly, integrate current origin/main, rerun just check, push, verify exact-SHA CI, then prove Loki delivery against a deployed instance.
<!-- SECTION:NOTES:END -->
