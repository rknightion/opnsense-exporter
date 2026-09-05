---
id: OPN-0086
title: Emit configuration revision diffs in old-to-new order
status: Done
assignee:
  - '@codex'
created_date: '2026-09-05 18:35'
updated_date: '2026-09-05 19:10'
labels:
  - needs-triage
dependencies: []
priority: high
type: bug
ordinal: 40000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
FetchConfigBackupDiff names its arguments oldRevision and newRevision but puts them into the upstream route in that order. BackupController diffAction on both supported stable branches executes diff with backup2 first and backup1 second. Consequently the configchange event for a new revision reverses additions and deletions. Existing test response is hard-coded independently of requested operands and masks the error. This is separate from the unresolved live configchange absence.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Configchange fetches the upstream diff with the old revision as diff input and the new revision as diff output on both supported source contracts
- [x] #2 A source-derived regression fails for the reversed orientation before repair and passes afterward while static observer endpoint attribution is preserved
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Verify stable/26.7 and stable/26.1 BackupController operand order; make the existing diff test emulate that producer order and observe failure; swap only route argument order in FetchConfigBackupDiff, document upstream convention, run targeted test and integrated review/gate.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 7 targeted regression failed before with reversed diff headers and deletion; after route operand correction: ok github.com/rknightion/opnsense2otel/v4/opnsense 0.313s. Both supported BackupController sources execute diff(backup2, backup1). This does not prove or explain live configchange absence.

CodeRabbit source review raised a minor request to exercise or remove the reverse-route fixture branch. Retained deliberately: this branch models the actual upstream response to the pre-fix request and made the regression fail for reversed diff semantics rather than an artificial route rejection. A second test of the test server adds no production contract coverage. Awaiting terminal review event and full gate.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Landed in d2549a5dd314f40bdfaf6ad56f056dcde4821e0a. Targeted evidence recorded above; full just check passed (exit 0), terminal: Your code is affected by 0 vulnerabilities. No generated artifacts changed, so just gen not applicable. Source-only CodeRabbit completed review_completed across 13 files, findings=1; one pass. The sole minor finding concerned the intentionally reversed backup test-server branch and was retained with the regression rationale recorded on OPN-0086. No critical or major findings.
<!-- SECTION:FINAL_SUMMARY:END -->
