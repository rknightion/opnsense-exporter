---
id: OPN-0104
title: Retire the syslog debug-capture mount on camden
status: To Do
assignee: []
created_date: '2026-09-06 14:30'
labels: []
dependencies: []
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
