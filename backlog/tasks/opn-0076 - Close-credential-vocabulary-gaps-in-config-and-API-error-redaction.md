---
id: OPN-0076
title: Close credential-vocabulary gaps in config and API-error redaction
status: Done
assignee:
  - '@codex'
created_date: '2026-09-04 12:47'
updated_date: '2026-09-04 18:22'
labels: []
dependencies: []
modified_files:
  - opnsense/config_snapshot.go
  - opnsense/config_snapshot_test.go
  - opnsense/client.go
  - opnsense/client_test.go
  - internal/logship/configchange_test.go
  - internal/logship/pipeline_test.go
priority: high
type: bug
ordinal: 30000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The shared SensitiveConfigKey matcher misses supported OPNsense secret fields including otp_seed, LDAP bind passwords, Net-SNMP community strings and enckey, so config-change bodies can ship them. APICallError separately regex-scrubs malformed response keys with a weaker vocabulary; now that source poll errors are forwarded, missed keys can also leave the process in the err attribute.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 The shared normalized matcher treats otp_seed, ldap_bindpw, enckey and exact community fields as sensitive without broad false-positive substring matching
- [x] #2 Malformed API error bodies classify key-value fields through SensitiveConfigKey while retaining URL/userinfo value scrubbing
- [x] #3 Table-driven tests pin the shared vocabulary and end-to-end config-change and forwarded poll-error redaction
- [x] #4 An independent security review completes with every confidentiality finding resolved before commit
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Extend the single shared matcher with normalized exact/term cases backed by upstream-supported field evidence; replace the API-error key regex with SensitiveConfigKey while retaining value scrubbing; add shared vocabulary, config-change and poll-error sink regressions; run focused tests, full gate and a separate SECURITY review.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Implemented at 2389ac3b. Independent security review iteratively found credential-vocabulary, malformed JSON, URL, HTML-entity, whitespace and truncation boundary leaks; every reported case received a failing-before regression and passed after repair. Final CodeRabbit source and support slices completed with zero findings, and final just check passed.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Fixed at 2389ac3b. Config and API-error redaction now share the sensitive-key vocabulary and fail closed across malformed JSON, encoded query/userinfo forms, HTML attribute boundaries and the 4 KiB truncation edge. Independent security findings were resolved with regressions; final CodeRabbit slices were clean and final just check passed.
<!-- SECTION:FINAL_SUMMARY:END -->
