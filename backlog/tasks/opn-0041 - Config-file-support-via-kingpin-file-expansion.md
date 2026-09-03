---
id: OPN-0041
title: Config-file support via kingpin @file expansion
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 09:10'
updated_date: '2026-09-03 09:49'
labels: []
milestone: m-5
dependencies: []
priority: low
type: enhancement
ordinal: 604
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
~150 flags are CLI/env-only. kingpin supports `@file` argument expansion — document and wire it as the supported config-file mechanism for systemd/bare-metal deployments (one flag per line). Cheap first step before any YAML config debate.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 @file expansion works and is documented with a systemd unit example
- [x] #2 --config.check validates an @file invocation
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Enable Kingpin file expansion immediately before production parsing; add subprocess coverage that forces expansion off, proves Init re-enables it, parses the required @file flags one argument per line with comments and blanks, and keeps --config.check as an outside argument; document equals-form systemd args-file reuse by ExecStartPre and ExecStart; run focused options and real-exporter config-check validation, then root generation, review and full gate.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Enabled Kingpin @file expansion immediately at the production parse boundary. Added subprocess coverage that forces the dependency switch off first, parses required flags from a comments-and-blanks arguments file, keeps --config.check outside that file, and runs the real exporter to observe config check OK. Documented one --flag=value argument per line and a systemd drop-in that shares the file without changing the canonical unit fence; credentials remain in environment or secret files. just test AtFile passed. CodeRabbit reviewed internal/options/init.go and internal/options/at_file_test.go with terminal review_completed and zero findings. In an isolated worktree, just gen changed no generated artifact and just check passed: 0 lint issues, all Go/race and fuzz tests, 427 Grafana tests, 1,233 Prometheus targets, 80 manifests and no called vulnerabilities.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Enabled and documented Kingpin @file configuration for bare-metal/systemd deployments, with the config-check flag deliberately outside the shared arguments file. Subprocess tests exercise both production parsing and the real exporter; generation, completed source review and the full repository gate passed.
<!-- SECTION:FINAL_SUMMARY:END -->
