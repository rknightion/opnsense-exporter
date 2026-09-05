---
id: OPN-0084
title: 'Serialize Release Please: no concurrency group on a workflow that publishes'
status: Done
assignee: []
created_date: '2026-09-05 17:03'
updated_date: '2026-09-05 17:03'
labels:
  - bug
dependencies: []
ordinal: 38000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
release-please.yml has no concurrency block. It derives the next version from git tags plus commits and reconciles a single release PR, so two runs in flight reach the same answer and then fight over it.

Observed on 2026-09-05 during a burst of Renovate merges: three Release Please runs overlapped (835fdd51 at 10:25:05, e467076e at 10:26:57, 20eaf345 at 10:27:17) and all three release-please jobs ran to completion against the same release PR.

Fix is one shared repo-wide group with cancel-in-progress false, so runs queue instead of racing and nothing is ever cancelled mid-publish.

Deliberately NOT the same group as the container-publish reusable this workflow calls: a parent holding a group while its child waits on that same group deadlocks. The reusable keeps its own group.

Not a defect and left alone: container-publish cancels superseded EDGE builds only, via cancel-in-progress set to inputs.release-tag == ''. That is why cancelled Release Please runs show the cancel landing on 'edge / image / merge + sign + sbom' after both arch builds succeeded. A stale :main manifest is corrected by the next push and a release publish is never cancelled there.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 release-please.yml carries one repo-wide concurrency group with cancel-in-progress false
- [x] #2 The group differs from the called reusable's, with the deadlock reason recorded in the file
- [x] #3 actionlint passes
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fixed in .github/workflows/release-please.yml. actionlint passes; golangci-lint 0 issues. Tests skipped deliberately: this is declarative CI YAML with no branching, validated by actionlint rather than a manufactured unit test. CodeRabbit skipped per the CI-YAML-tweak carve-out.
<!-- SECTION:NOTES:END -->
