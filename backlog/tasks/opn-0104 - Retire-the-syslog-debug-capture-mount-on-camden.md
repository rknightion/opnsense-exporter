---
id: OPN-0104
title: Retire the syslog debug-capture mount on camden
status: In Progress
assignee:
  - '@codex'
created_date: '2026-09-06 14:30'
updated_date: '2026-09-06 18:44'
labels: []
dependencies: []
references:
  - >-
    backlog/docs/doc-0004 -
    Camden-capture-parser-and-pass-through-review-OPN-0104.md
priority: low
type: chore
ordinal: 58000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The camden compose bind-mounts /opt/opnsense2otel/capture and sets OPN2OTEL_LOGS_{SYSLOG,ZENARMOR}_DEBUG_CAPTURE=true with a comment to remove both "once the #331 _alias/_settings work is done". #331 closed, but the syslog capture is still active: 120 NDJSON files (4.6 MB) as of 2026-09-06, the newest written that day, and the only program in the recent files is dhclient ("dhclient-script: New Hostname", "Creating resolv.conf"), i.e. lines the parser registry has no parser for. The capture is doing its job of surfacing unmodelled programs, so the mount cannot simply be deleted without first deciding what to do with what it found. The Zenarmor capture has not written anything recent.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Every distinct program/shape present in the camden syslog capture files has an explicit disposition: either a parser (or a documented pass-through) in internal/logship/syslog, or a documented reason it is dropped
- [x] #2 dhclient lines specifically are either parsed into a structured record or deliberately ignored, with a test pinning the choice
- [ ] #3 Once nothing new appears in the capture for a week, the camden compose drops OPN2OTEL_LOGS_SYSLOG_DEBUG_CAPTURE, OPN2OTEL_LOGS_ZENARMOR_DEBUG_CAPTURE, OPN2OTEL_LOGS_DEBUG_CAPTURE_DIR and the /capture bind mount, and the capture directory is archived rather than deleted
- [x] #4 The NetFlow "unidentified" capture is reviewed at the same time and kept only if it is still bounded and useful
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Download a private, complete snapshot of the existing Camden receiver captures without altering the running deployment. Inventory every receiver, program and message shape; compare with current parser and known-unstructured handling. Record evidence-backed parser candidates and narrow never-parse dispositions, with implementation and tests where justified. Review NetFlow capture bounds and usefulness. Preserve the one-week observation prerequisite before any deployment retirement.

User authorised implementation and live delivery on 2026-09-06. Implement captured parsers plus narrow known-pass-through classification preserving shipped records; redact credential-bearing API failures at ingress; replay full private corpus with unknown positive controls; pass just check and CodeRabbit; commit/push with exact-SHA CI green; deploy verified artifact to Camden; archive old corpus and prove future capture admits new unknowns while known records keep shipping. Preserve shared capture mount and leave OPN-0104 open for the observation week. Detailed run contract: codex/goal-20260906-opn0104-parsers.md.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-09-06 full retained-capture investigation is recorded in doc-0004. Private snapshot and replay evidence: ~/capture-reviews/opn-0104-20260906/ (archives, manifest, replay harness, replay.jsonl and test log). At source SHA 6406f359195b2a1768933d682ba0d2269fdd4106, all 4,082 debug envelopes parsed; 1,077 messages now have structured parser coverage and 3,005 remain generic across a total census of 36 programs. The task description is stale: dhclient already has a parser and tests deliberately leave the two script notices generic; two other packet diagnostics were also captured. The separate raw syslog archive is UniFi traffic and is excluded from OPNsense parser decisions. doc-0004 records candidate grammars and known pass-through families without publishing raw values. No runtime classifier or new parser was implemented in this investigation. NetFlow has no retained unidentified payloads, current decode/unidentified/drop counters show healthy intake, and the default shared cap has headroom; retain unidentified capture. AC3 conflicts with retaining NetFlow capture because the directory and mount are shared. Resolve that storage contract before retiring anything. Remaining work: implement or explicitly settle candidate grammars, add a narrowly tested known-pass-through classifier if wanted, then observe one week with no new unclassified shapes. No deployment settings or retained remote files were changed.

Investigation validation: the complete corpus replay passed via just test TestCaptureAuditScratch; the temporary harness was archived with private evidence and is not part of the repository change. The documented 36-program census was checked programmatically against all 4,082 replay results. just check passed on 2026-09-06 with the final documentation content (log in the private evidence directory). No new regression tests or CodeRabbit review were added for this documentation-only delivery. No acceptance criterion is claimed complete for the unimplemented parser/classifier and deployment work.

Implementation checkpoint 2026-09-06: added program-scoped captured-event rules and complete-grammar known-pass-through reasons, with syslog.parse_status/parse_reason distinguishing parsed, known and unknown without dropping generic records. Historical corpus ingress replay: files=121 received=4082 shipped=4082 parsed=1429 known=2653; refreshed corpus: files=122 received=4093 shipped=4093 parsed=1429 known=2664. In each replay exactly one deliberately unknown control was captured and no corpus record was capture-eligible. Evidence: private corpus-ingress-evidence.log and archived corpus_ingress_scratch_test.go. Correction to doc-0004: Unbound query/reply parsing already exists behind a disabled-by-default opt-in; the 730 examples were not a missing implementation. Preserve the flag and classify only complete supported-but-disabled grammars as known. API supplied-key suffix redaction covers malformed envelopes and multiline bodies before capture/shipping; synthetic security tests first failed for credential exposure. First just check found historical CARP/PPP tests insisting newly modelled diagnostics remain generic; those are being updated to retain no-false-derived-event assertions. Second integrated gate and CodeRabbit review are pending. No implementation commit or deployment yet.

Pre-publication review: two CodeRabbit reviews reached terminal complete. Fixed optional kernel PRI prefix coverage (new test failed before fix), documented prefix-only console notices, and strengthened API shipping/capture assertions independently. Final review also claimed Go does not support non-capturing regex groups; dismissed as false: regexp supports (?:...), every rule compiled during startup and the complete Go suite passed. No review finding is left unresolved. Runtime behavior and replay evidence are unchanged; final integrated gate is running after the API test strengthening.

Final pre-commit gate passed: just check exited 0 after all review fixes, including Go race tests, bounded fuzz, lint, documentation and Grafana generation checks and govulncheck. Evidence: private implementation-check-reviewed.log. Separate strengthened API test passed in review-api-green.log. Ready for implementation publication and live proof; observation task remains open.

Live implementation delivered at 22a903c4bde60cf0d21ce9e85dfb6e994dd50971. CI run 34051948847 completed success with every job successful; image publication run 34051948938 completed success (release-only jobs skipped, not counted as tests). Multi-architecture image digest sha256:4001dbec01fa64cc786d4b5c67bef889869d3390329d002cb3bd0f423d4b457b; running image ID sha256:49933e8c51207047728ba6cc4e0f6b1067767b8263605fa822eacdcc2ea2ea46, revision verified. Existing automatic updater picked the image at 18:35 UTC; after CI passed, old corpus and exact Compose were archived outside active storage under backups/opn0104-20260906T183937Z. Fresh process/observation window began 2026-09-06T18:39:47.903273159Z, restarts 0. Compose is byte-identical; shared mount and all existing capture modes remain enabled.

Live proof: three marked receiver-local synthetic UDP controls arrived in Loki as parsed/package_upgraded, known/dhclient_script_side_effect and unknown; only the unknown control entered active capture (one file, one record). Initial loopback TCP control was correctly peer-rejected; no receiver/firewall allowlist was changed. UDP controls used the configured permitted source address and were explicitly synthetic, not genuine firewall evidence. Separate authenticated read-back found 10 recent genuine parsed syslog records from service version 22a903c after the fresh restart. At the sampled boundary syslog shipped=8318, Zenarmor shipped=9271, NetFlow decoded=14159; log shipping errors, pipeline drops and capture drops were zero. NetFlow had 943 no_template records during startup and 527 intentional vlan_duplicate records, so do not claim zero flow drops. No new retained unidentified NetFlow payload required decoding.

Evidence remains private in the capture-review directory: ci-implementation-green.json, publication-implementation.json, image-pull.log, loki-controls-udp.json, loki-genuine-live.json and metrics-live-proof.prom. All 4093 refreshed corpus records had prior ingress proof, with 1429 parsed and 2664 known. Keep OPN-0104 In Progress: AC3 remains unfulfilled pending a full observation week. The active corpus currently includes the clearly marked unknown positive control. Earliest quiet-week review is 2026-09-13 after 18:39 UTC, reset by any genuine new unknown shape. Retain the shared capture directory/mount while NetFlow unidentified capture uses it; no retirement action was taken.
<!-- SECTION:NOTES:END -->
