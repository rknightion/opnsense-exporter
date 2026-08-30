---
id: OPN-0041
title: Config-file support via kingpin @file expansion
status: To Do
assignee: []
created_date: '2026-08-30 09:10'
updated_date: '2026-08-30 09:35'
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
- [ ] #1 @file expansion works and is documented with a systemd unit example
- [ ] #2 --config.check validates an @file invocation
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
