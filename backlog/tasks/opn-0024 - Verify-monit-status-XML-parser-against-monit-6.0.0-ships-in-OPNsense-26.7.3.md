---
id: OPN-0024
title: Verify monit status-XML parser against monit 6.0.0 (ships in OPNsense 26.7.3)
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 09:08'
updated_date: '2026-09-02 03:39'
labels: []
milestone: m-2
dependencies: []
priority: medium
type: spike
ordinal: 304
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OPNsense 26.7.3 bumps monit to 6.0.0. We parse `api/monit/status/get/xml` (`opnsense/monit*.go`). Verify the XML shape against monit 6 output (upstream monit source or a live 26.7.3 box); fix tolerantly if drifted, close with a note if compatible.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 monit 6.0.0 XML shape verified against parser; drift fixed tolerantly or compatibility recorded
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 1 L12 plan: verify the released upstream payload-producing source, write a focused regression for the Monit 26.7 behavior, implement only task-owned files, return root registry edits, and stop before OPN-0050.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 1 staged WIP verifies the Monit 6.0.0 XML shape from released payload-producing source and adds focused parser coverage; the integrated just check passed. Not landed because the shared code-bearing batch lacks a complete CodeRabbit review. Resume: obtain the CodeRabbit complete event, triage findings, commit this task with explicit pathspecs, integrate current origin/main, rerun just check, push, and verify exact-SHA CI.

Landed as 12f6097adf9ff0dac1fb99652b831ab28b95d371. The release-6.0.0 source-derived fixture proves the parser accepts the paging node without exporting it. CodeRabbit paging-assertion feedback was fixed before commit.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Verified Monit 6.0.0 status compatibility with a source-derived regression fixture; no parser change was required. just check and CodeRabbit passed; exact-head CI run 33583896929 succeeded at 12f6097adf9ff0dac1fb99652b831ab28b95d371.
<!-- SECTION:FINAL_SUMMARY:END -->
