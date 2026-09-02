---
id: OPN-0054
title: CodeQL initialization fails with repository Contents API 404
status: Done
assignee: []
created_date: '2026-09-02 00:26'
updated_date: '2026-09-02 05:50'
labels:
  - needs-triage
dependencies: []
priority: high
type: bug
ordinal: 8000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
CodeQL cannot begin analysis on main because Initialize CodeQL fails with a GitHub repository Contents API Not Found error. The failure affects the Go, Python, and Actions matrices; autobuild and analysis are skipped. It repeated on run 33572390041 attempts 1 and 2 and run 33574848860, so this is not established as a source regression in the Wave 1 implementation.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Identify why CodeQL initialization cannot read repository content
- [x] #2 Restore successful initialization and analysis for Go, Python, and Actions
- [x] #3 Verify a terminal CodeQL run at the exact repaired SHA
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Evidence: runs 33572390041 (attempts 1 and 2) and 33574848860 all failed during Initialize CodeQL with: Not Found - https://docs.github.com/rest/repos/contents#get-repository-content. Autobuild and analysis did not run. Resume by inspecting workflow permissions and CodeQL action inputs at those run attempts, then make the narrowest workflow repair and prove it on the exact pushed SHA.

ROOT CAUSE FOUND 2026-09-02, and it is not in this repository. rknightion/.github commit 240da9e3 (2026-09-01 22:27 UTC, released as v1.18.0 at 22:30) moved the shared CodeQL reusable to an inline config: block and DELETED codeql/codeql-config.yml. This repo's caller is pinned at v1.17.1 (79a72d21), and that pinned reusable passes 'config-file: rknightion/.github/codeql/codeql-config.yml@main'. A SHA pin on a reusable does NOT pin what that reusable itself fetches from @main, so the deletion reached every pinned caller instantly. That is the Contents API 404 inside the 'Load language configuration' group.

Timeline proves it: CodeQL was success at d91cfb1b 22:15, and has failed on every run from 2a2eb12b 23:45 onward. The wave-1 report correlated the break with 2a2eb12b, but that commit changed backlog markdown only - the correlation is coincidental and the cause predates it by 78 minutes.

BLAST RADIUS: 16 rknightion repositories pin the same v1.17.1 SHA and have all been failing CodeQL since 22:27 - autopi-ha, bumblebee-catalog, bumblebee-intune, fleet-management-operator, genai-otel-bridge, grafana-cloud-org-insights, graph2otel, grotTrack, meraki-dashboard-ha, openbao-plugin-secrets-github, opnsense2otel, polylens2otel, rfc6035-2otel, sagemcom-f3896-py, synthkit, transceiver-exporter.

FIX: restore codeql/codeql-config.yml on rknightion/.github main. One commit, unbreaks all 16 at once, and does not revert the inline-config design because HEAD no longer reads the file. Bumping this caller to v1.18.1 is the follow-up Renovate will raise anyway, but it fixes one repo at a time and leaves the trap live for anything still pinned old. The restored file should carry a header comment saying why it must not be deleted again.

This task's AC2/AC3 cannot be satisfied by any change in this repository.

The other 15 affected repositories are fixed by the same commit and need no per-repo action: autopi-ha, bumblebee-catalog, bumblebee-intune, fleet-management-operator, genai-otel-bridge, grafana-cloud-org-insights, graph2otel, grotTrack, meraki-dashboard-ha, openbao-plugin-secrets-github, polylens2otel, rfc6035-2otel, sagemcom-f3896-py, synthkit, transceiver-exporter. Their next CodeQL run initializes normally; no re-run is required unless a green result is wanted at a specific older SHA.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
FIXED 2026-09-02 in another repository. rknightion/.github commit 09c52f4a restored codeql/codeql-config.yml, which 240da9e3 had deleted on 2026-09-01 22:27. This repo's caller is pinned at v1.17.1 and that pinned reusable passes 'config-file: rknightion/.github/codeql/codeql-config.yml@main' - a SHA pin on a reusable does not pin what the reusable itself resolves at run time, so one deletion broke 16 pinned repositories at once.

Proof: re-ran the failing CodeQL run 33590596566 at the unchanged SHA d780775115b35f854a2bdaec03e59ff70f3fe7cb after the restore. All three matrices concluded success - Analyze (go), Analyze (python), Analyze (actions). Same SHA, same workflow, same caller pin; only the file in the other repository changed, which isolates the cause exactly.

No change was made in this repository and none is needed. The restored file carries a header comment explaining why it must not be deleted again. Bumping this caller to v1.18.1, which inlines the config, is a separate Renovate follow-up and not a prerequisite.
<!-- SECTION:FINAL_SUMMARY:END -->
