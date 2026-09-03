---
id: OPN-0058
title: Narrow auto-rc so only shipped-code commits cut a release candidate
status: Done
assignee:
  - '@codex'
created_date: '2026-09-02 16:05'
updated_date: '2026-09-03 09:44'
labels:
  - wave3
dependencies: []
priority: low
ordinal: 12000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The `auto-rc` workflow cuts a prerelease on every movement of `main`. Wave 2 produced six release candidates (v4.2.0-rc.49 through rc.54) for tracker, documentation and dependency-pin commits, and each one published binaries, images, chart, notices, signatures, attestations and SBOMs for a change that alters no shipped artifact.

Narrow the trigger so a release candidate is cut only when a commit touches code that ends up in a shipped artifact. Paths that should NOT trigger one: `backlog/`, `docs/`, `codex/`, `README.md`, `CHANGELOG.md`, and repository-meta files. Paths that should: Go sources, `go.mod`/`go.sum`/`vendor/`, `grafana/`, `charts/`, `deploy/`, the `justfile` and the workflows that build the artifacts.

The reusable lives in `rknightion/.github`, so establish first whether the narrowing belongs in the caller or the reusable. A change to the reusable is a fleet change affecting every consumer, not a change to this repository.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 auto-rc does not cut a release candidate for a commit touching only backlog/, docs/, codex/, README.md or CHANGELOG.md
- [x] #2 auto-rc still cuts one for any commit touching Go sources, vendor/, grafana/, charts/, deploy/ or the justfile
- [x] #3 Decision recorded on whether the change belongs in the caller or in the rknightion/.github reusable, with the blast radius of the chosen option stated
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Keep narrowing in this repository's caller because shipped-input policy is repository-specific; a shared reusable change would affect every consumer and is outside this wave's authority. Add a successful-CI shipped-change job that checks out github.event.workflow_run.head_sha, diffs the exact commit NUL-safely against its first parent with rename splitting, emits a positive shipped-artifact decision, and gates the existing reusable RC call while preserving downstream non-empty-tag gates. Validate YAML and representative positive, negative, mixed and rename path cases; root runs generation and the full gate.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Decision: keep the shipped-artifact classification in this repository's caller. The policy is repository-specific; moving it into rknightion/.github would alter every consumer and is outside this wave's write authority. The new shipped-change job runs only after successful CI, checks out github.event.workflow_run.head_sha, compares that exact commit with its first parent using NUL-delimited no-rename paths, and gates the shared RC call on a positive allowlist. Representative classifier cases passed for release-neutral paths (backlog, docs, codex, README, CHANGELOG and Renovate metadata), every required shipped category, mixed commits, and removal-side renames. actionlint and git diff --check passed. In an isolated worktree, just gen changed no generated artifact and just check passed: 0 lint issues, all Go/race and fuzz tests, 427 Grafana tests, 1,233 Prometheus targets, 80 manifests and no called vulnerabilities. CodeRabbit was intentionally skipped because this is declarative CI YAML. Live positive and negative workflow behavior remains a separate post-push observation, not local proof.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Narrowed auto-rc in the repository caller so only exact successful-CI commits touching a positive set of shipped-artifact inputs reach the shared RC workflow. Release-neutral tracker/docs/meta commits now stop after classification; exact head_sha handling and downstream publication gates are preserved. Validated with actionlint, representative path cases, just gen and the full just check gate.
<!-- SECTION:FINAL_SUMMARY:END -->
