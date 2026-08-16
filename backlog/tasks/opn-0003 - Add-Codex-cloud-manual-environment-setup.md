---
id: OPN-0003
title: Add Codex cloud manual environment setup
status: Done
assignee:
  - Codex
created_date: '2026-08-16 10:27'
updated_date: '2026-08-16 11:34'
labels: []
dependencies: []
references:
  - 'https://learn.chatgpt.com/docs/environments/cloud-environment#manual-setup'
  - 'https://code.claude.com/docs/en/cloud-environments#setup-scripts'
modified_files:
  - scripts/cloud-environment-setup.sh
  - backlog/tasks/opn-0003 - Add-Codex-cloud-manual-environment-setup.md
ordinal: 3000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Provide a repository-owned setup script for Codex cloud tasks so agents receive the pinned project runtimes, validation tools, and Backlog.md CLI instead of relying on automatic environment setup.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The script installs Backlog.md at the repository-compatible pinned version and makes the backlog command available during the agent phase
- [x] #2 The script provisions the Go, Python, Helm, and lint tooling required by the repository's documented local and CI validation commands
- [x] #3 The script is safe to rerun in a cached Codex cloud environment and validates that required tools are available
- [x] #4 The setup entry point is `scripts/cloud-environment-setup.sh` and begins with a warning telling non-cloud agents not to execute it
- [x] #5 The script is usable as a Bash setup script in both Codex cloud and Claude Code cloud environments
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 make lint
- [x] #2 make test
- [x] #3 make check-public-ips
- [x] #4 make docs-check
- [x] #5 make grafana-check
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
1. Derive exact tool versions and validation needs from go.mod, Makefile, and CI workflows.

2. Add an idempotent Codex cloud setup script that persists PATH changes and installs Backlog.md plus project validation tools.

3. Exercise the setup script, run repository checks, record results, and commit the implementation.

4. Move the entry point to the requested scripts path, add the local-agent warning, and align persistence and runtime behavior with both vendors' cloud setup semantics.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Added .codex/setup.sh with pinned Go 1.26.4, golangci-lint 2.12.2, Helm 3.19.0, Backlog.md 1.50.1, the pinned Python validation dependencies, bootstrap OS tooling, checksum verification, persistent shell configuration, and cache-safe idempotent checks.

Validation passed for setup execution and rerun, shell syntax, make lint, make test, make check-public-ips, make docs-check, and make grafana-check. The optional deployment contract could not run in this agent container because no Docker command/daemon was preinstalled; the setup script now includes docker.io among conditional bootstrap packages for Codex cloud.

Follow-up review: moved the setup entry point to scripts/cloud-environment-setup.sh, added the required local-agent do-not-run warning at the start, and documented compatibility with both Codex cloud's separate-shell setup model and Claude Code cloud's cached setup-script model.

Follow-up validation passed: bash -n scripts/cloud-environment-setup.sh, make test, make docs-check, and make check-public-ips. Per the new header, the setup script itself was not executed by this non-cloud agent.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added and exercised an idempotent Codex cloud manual setup script that persists a pinned Go toolchain, golangci-lint, Helm, Python validation dependencies, Docker/bootstrap utilities, and Backlog.md for future agent shells. Verified the script twice plus the repository lint, test, public-IP, generated-doc, and Grafana gates.

Follow-up review moved the executable to scripts/cloud-environment-setup.sh and added an explicit opening warning that non-cloud agents must not run it. The Bash setup remains compatible with Codex cloud and Claude Code cloud environment setup fields, with durable filesystem installs and shell-path persistence.
<!-- SECTION:FINAL_SUMMARY:END -->
