---
id: OPN-0104
title: Retire the syslog debug-capture mount on camden
status: In Progress
assignee:
  - '@codex'
created_date: '2026-09-06 14:30'
updated_date: '2026-09-06 17:33'
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
- [ ] #1 Every distinct program/shape present in the camden syslog capture files has an explicit disposition: either a parser (or a documented pass-through) in internal/logship/syslog, or a documented reason it is dropped
- [ ] #2 dhclient lines specifically are either parsed into a structured record or deliberately ignored, with a test pinning the choice
- [ ] #3 Once nothing new appears in the capture for a week, the camden compose drops OPN2OTEL_LOGS_SYSLOG_DEBUG_CAPTURE, OPN2OTEL_LOGS_ZENARMOR_DEBUG_CAPTURE, OPN2OTEL_LOGS_DEBUG_CAPTURE_DIR and the /capture bind mount, and the capture directory is archived rather than deleted
- [ ] #4 The NetFlow "unidentified" capture is reviewed at the same time and kept only if it is still bounded and useful
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Download a private, complete snapshot of the existing Camden receiver captures without altering the running deployment. Inventory every receiver, program and message shape; compare with current parser and known-unstructured handling. Record evidence-backed parser candidates and narrow never-parse dispositions, with implementation and tests where justified. Review NetFlow capture bounds and usefulness. Preserve the one-week observation prerequisite before any deployment retirement.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
2026-09-06 full retained-capture investigation is recorded in doc-0004. Private snapshot and replay evidence: ~/capture-reviews/opn-0104-20260906/ (archives, manifest, replay harness, replay.jsonl and test log). At source SHA 6406f359195b2a1768933d682ba0d2269fdd4106, all 4,082 debug envelopes parsed; 1,077 messages now have structured parser coverage and 3,005 remain generic across a total census of 36 programs. The task description is stale: dhclient already has a parser and tests deliberately leave the two script notices generic; two other packet diagnostics were also captured. The separate raw syslog archive is UniFi traffic and is excluded from OPNsense parser decisions. doc-0004 records candidate grammars and known pass-through families without publishing raw values. No runtime classifier or new parser was implemented in this investigation. NetFlow has no retained unidentified payloads, current decode/unidentified/drop counters show healthy intake, and the default shared cap has headroom; retain unidentified capture. AC3 conflicts with retaining NetFlow capture because the directory and mount are shared. Resolve that storage contract before retiring anything. Remaining work: implement or explicitly settle candidate grammars, add a narrowly tested known-pass-through classifier if wanted, then observe one week with no new unclassified shapes. No deployment settings or retained remote files were changed.

Investigation validation: the complete corpus replay passed via just test TestCaptureAuditScratch; the temporary harness was archived with private evidence and is not part of the repository change. The documented 36-program census was checked programmatically against all 4,082 replay results. just check passed on 2026-09-06 with the final documentation content (log in the private evidence directory). No new regression tests or CodeRabbit review were added for this documentation-only delivery. No acceptance criterion is claimed complete for the unimplemented parser/classifier and deployment work.
<!-- SECTION:NOTES:END -->
