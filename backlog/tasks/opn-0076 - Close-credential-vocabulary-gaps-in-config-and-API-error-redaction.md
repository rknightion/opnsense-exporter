---
id: OPN-0076
title: Close credential-vocabulary gaps in config and API-error redaction
status: In Progress
assignee:
  - '@codex'
created_date: '2026-09-04 12:47'
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
- [ ] #1 The shared normalized matcher treats otp_seed, ldap_bindpw, enckey and exact community fields as sensitive without broad false-positive substring matching
- [ ] #2 Malformed API error bodies classify key-value fields through SensitiveConfigKey while retaining URL/userinfo value scrubbing
- [ ] #3 Table-driven tests pin the shared vocabulary and end-to-end config-change and forwarded poll-error redaction
- [ ] #4 An independent security review completes with every confidentiality finding resolved before commit
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Extend the single shared matcher with normalized exact/term cases backed by upstream-supported field evidence; replace the API-error key regex with SensitiveConfigKey while retaining value scrubbing; add shared vocabulary, config-change and poll-error sink regressions; run focused tests, full gate and a separate SECURITY review.
<!-- SECTION:PLAN:END -->
