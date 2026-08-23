---
id: OPN-0004
title: Upgrade Go toolchain to 1.27
status: Done
assignee: []
created_date: '2026-08-23 19:06'
updated_date: '2026-08-23 20:37'
labels: []
dependencies: []
ordinal: 4000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Adopt Go 1.27 consistently across the application, nested modules, build images, CI configuration, setup automation, and version-specific contributor documentation.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 All active Go module and toolchain pins require Go 1.27
- [x] #2 Build images, CI jobs, setup automation, and current documentation agree with the Go 1.27 requirement
- [x] #3 The repository green-bar validation passes under Go 1.27
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
1. Inventory every active Go version pin, including nested modules and container or CI toolchains. 2. Update the pins and version-specific documentation to Go 1.27.0 without changing historical records or fixtures. 3. Run the repository-defined validation gate, review the diff, commit to main, push, and confirm hosted CI.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Local Go 1.27.0 evidence: build, make test, vet, lint with 0 issues, docs-check, check-public-ips, and grafana-check all passed. Generated docs were brought back to their existing exact wording contract. Paid-plan CodeRabbit review completed; the valid fuzz-cache and punctuation findings were fixed, while the systemd enforcement finding was already covered by the root Go 1.27 module requirement.

The cloud setup golangci-lint pin was aligned from v2.12.2 to current v2.13.1 after the campaign's Linux checks showed v2.12.2 analyzers panic on Go 1.27 syntax. The hosted workflow already used v2.13.1. Linux-target v2.13.1 lint remained clean with 0 issues and the setup script passed shell syntax validation.

Exact-head hosted evidence: GitHub Actions run 32664206755 passed at a1a81a043413eab18586dfecd3019fec20e3acf3.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Upgraded the active Go application surfaces to Go 1.27 and validated the change locally and in exact-head hosted CI run 32664206755 at a1a81a043413eab18586dfecd3019fec20e3acf3.
<!-- SECTION:FINAL_SUMMARY:END -->
