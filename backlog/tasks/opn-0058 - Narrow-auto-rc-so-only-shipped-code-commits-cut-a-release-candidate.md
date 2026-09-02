---
id: OPN-0058
title: Narrow auto-rc so only shipped-code commits cut a release candidate
status: To Do
assignee: []
created_date: '2026-09-02 16:05'
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
- [ ] #1 auto-rc does not cut a release candidate for a commit touching only backlog/, docs/, codex/, README.md or CHANGELOG.md
- [ ] #2 auto-rc still cuts one for any commit touching Go sources, vendor/, grafana/, charts/, deploy/ or the justfile
- [ ] #3 Decision recorded on whether the change belongs in the caller or in the rknightion/.github reusable, with the blast radius of the chosen option stated
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
