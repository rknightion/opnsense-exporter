---
id: OPN-0036
title: Set SO_RCVBUF on syslog and NetFlow UDP sockets
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 09:09'
updated_date: '2026-09-02 03:59'
labels: []
milestone: m-4
dependencies: []
priority: medium
type: enhancement
ordinal: 503
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
No `SetReadBuffer` call exists anywhere; OS-default UDP buffers (~208KB) are the classic source of invisible kernel-level drops that the pipeline's otherwise-exhaustive loss accounting cannot see. Set a sane default with a flag override on both receivers, and Warn when the OS clamps the requested size (Linux caps at net.core.rmem_max).
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Both UDP sockets request a configurable receive buffer; clamped requests produce a Warn naming the sysctl
- [x] #2 Flags documented via just docs
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Add a configurable UDP receive-buffer request across syslog and NetFlow, detect effective-buffer clamping with the documented sysctl warning, test the socket seam, and return any root-owned option wiring exactly.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 1 staged WIP wires configurable receive buffers into syslog and NetFlow, rejects negatives, handles Linux doubled SO_RCVBUF read-back with overflow protection, and uses portable clamp warnings. Targeted tests, release-target cross-builds, and integrated just check passed; post-correction L14 found no remaining issue. Not landed because CodeRabbit produced no complete event. Resume: obtain a complete review, commit explicitly, integrate current origin/main, rerun just check, push, verify exact-SHA CI, then validate effective buffers on deployed target operating systems.

Landed configurable 4 MiB receive-buffer requests, effective-size read-back, Linux doubled-value handling, clamp warnings naming net.core.rmem_max, and generated flag documentation in 4b94082ba901dfc09edd76893a5b49e96346f5f4. Exact-head CI run 33587776757 exposed three NetFlow capture tests that counted the new startup warning; repair deb7b543b3eead256be0299eb13ced305516368f scopes them to unidentified-flow records. Both CodeRabbit passes had zero findings.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Syslog and NetFlow UDP sockets now request configurable receive buffers and warn when the operating system clamps them. just check passed; repair exact-head CI run 33588588706 succeeded at deb7b543b3eead256be0299eb13ced305516368f with implementation commit 4b94082ba901dfc09edd76893a5b49e96346f5f4 included. Deployed effective-buffer behavior and throughput improvement remain unproven.
<!-- SECTION:FINAL_SUMMARY:END -->
