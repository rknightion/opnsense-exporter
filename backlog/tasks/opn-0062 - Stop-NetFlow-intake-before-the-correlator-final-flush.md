---
id: OPN-0062
title: Stop NetFlow intake before the correlator final flush
status: Done
assignee:
  - '@codex'
created_date: '2026-09-04 05:38'
updated_date: '2026-09-04 07:26'
labels:
  - needs-triage
dependencies: []
modified_files:
  - main.go
priority: high
type: bug
ordinal: 16000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The log shutdown path flushes and stops the flow correlator while the NetFlow socket and workers are still active. A datagram accepted in that interval is counted into metrics and inserted into an already-stopped correlator; held repair records are also flushed into it later. No second correlator flush or dropped-record accounting occurs, so per-flow logs can disappear during ordinary graceful shutdown.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 A regression injects or releases a NetFlow record during shutdown and fails against the pre-fix ordering
- [x] #2 Shutdown first quiesces NetFlow intake and workers, then performs exactly one final processor and correlator drain while the log pipeline is still accepting records
- [x] #3 Every accepted record during shutdown is delivered or reflected in an existing dropped counter; none can remain stranded in the stopped correlator
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Add a lifecycle regression around the shutdown seam, watch it fail for the post-flush intake window, then reorder shutdown ownership so the listener and processor quiesce before the final correlator flush and before the log pipeline drain.
<!-- SECTION:PLAN:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Fixed by 8962f470. Shutdown now waits for log push sources, NetFlow listener/workers and the release ticker, then performs one processor flush and one correlator flush before the log queue closes. The pre-fix regression failed with a stranded held record; targeted checks passed: just test TestShutdownFlowQuiescesBeforeFinalFlush and just test TestPushSourceDoesNotBlockStop. Integrated just check passed. CodeRabbit took two completed passes: pass 1 found the valid Zenarmor quiescence gap; pass 2 completed with zero findings.
<!-- SECTION:FINAL_SUMMARY:END -->
