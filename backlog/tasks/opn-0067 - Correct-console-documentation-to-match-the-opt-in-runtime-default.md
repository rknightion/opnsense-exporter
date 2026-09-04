---
id: OPN-0067
title: Correct console documentation to match the opt-in runtime default
status: Done
assignee:
  - '@codex'
created_date: '2026-09-04 05:39'
updated_date: '2026-09-04 07:26'
labels:
  - needs-triage
dependencies: []
modified_files:
  - README.md
  - docs/deployment.md
  - docs/index.md
priority: high
type: docs
ordinal: 21000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Deployment and index prose say the operator console is available after the default quickstart and is on by default. The runtime flag defaults false and main serves only the minimal landing page unless the console is explicitly enabled. Operators following the documented command cannot reach the Config, Devices or ifIndex views, and the exposure guidance overstates the default HTTP surface.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Every quickstart or deployment path that promises the console explicitly enables it, or says the default landing page is all that is served
- [x] #2 Security and exposure prose distinguishes the default landing page from the opt-in operator console
- [x] #3 Generated flag tables remain source-derived and unchanged except through the normal generator
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Correct the hand-written deployment and index prose around the existing opt-in default, validate documentation tokens and generation staleness, and do not change runtime behavior.

The repository README repeats the same quickstart promise, so update its command and prose in the same documentation-only correction.
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Fixed by 1b5fb2d1. README and deployment quickstarts now enable the opt-in console explicitly, and exposure prose matches the off-by-default runtime. just docs-check and integrated just check passed. Tests and CodeRabbit were intentionally skipped for prose-only documentation.
<!-- SECTION:FINAL_SUMMARY:END -->
