---
id: OPN-0054
title: CodeQL initialization fails with repository Contents API 404
status: To Do
assignee: []
created_date: '2026-09-02 00:26'
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
- [ ] #1 Identify why CodeQL initialization cannot read repository content
- [ ] #2 Restore successful initialization and analysis for Go, Python, and Actions
- [ ] #3 Verify a terminal CodeQL run at the exact repaired SHA
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Evidence: runs 33572390041 (attempts 1 and 2) and 33574848860 all failed during Initialize CodeQL with: Not Found - https://docs.github.com/rest/repos/contents#get-repository-content. Autobuild and analysis did not run. Resume by inspecting workflow permissions and CodeQL action inputs at those run attempts, then make the narrowest workflow repair and prove it on the exact pushed SHA.
<!-- SECTION:NOTES:END -->
