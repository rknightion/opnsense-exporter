---
id: OPN-0099
title: >-
  Document and harness the Loki visibility delay for historical config revision
  events
status: Parked
assignee:
  - '@codex'
created_date: '2026-09-05 22:47'
updated_date: '2026-09-06 11:07'
labels:
  - docs
  - testbed
dependencies:
  - OPN-0060
priority: medium
ordinal: 53000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OPN-0060 resolution 2026-09-05. Three proof runs each shipped a configchange record whose timestamp was the retained revision time, roughly 35h in the past, and each run then queried Loki within a minute and saw nothing. The records were there: wave 7 records became visible hours later, and the Loki querier does not send a query to ingesters beyond query_ingesters_within (default 3h), so an old-stamped entry lives only in an unflushed ingester chunk until max_chunk_age or the idle flush moves it to the store. Two consequences. Operators: after a restart with a persisted or seeded configchange cursor, replayed historical revision diffs will not appear in Grafana for up to about two hours, and anything older than the tenant reject_old_samples_max_age (7d on Grafana Cloud by default) is rejected, which the sink now reports as logs_dropped_total{reason=rejected} via partialSuccess. Neither is written anywhere in docs/log-shipping.md or the troubleshooting pages. Harness: scripts/testbed/live_delivery_proof.py asserts its own configchange arrival within one run and therefore can never pass for a historical diff; it should either assert on the previous instance whose records have flushed (query the configchange stream over the seed window without the instance label and verify those bodies), or bound its expectation and report visibility-pending rather than absent.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 docs/log-shipping.md (or the troubleshooting page) states that historical configchange records surface in Loki only after the ingester chunk flush, with the 3h querier lookback and 7d rejection horizon named and their sources cited
- [ ] #2 The live delivery proof distinguishes visibility-pending from absent for a historical record, and its configchange redaction assertion runs over the delivered bodies of the most recent flushed instance
- [x] #3 The proof still fails on a genuine drop: logs_shipped_total zero, a drop reason, or partialSuccess rejection
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 9: offline harness lane implements present/visibility-pending/absent outcomes with fail-first genuine-drop regressions and verifies delivered bodies of the most recent flushed instance using the shared redaction vocabulary; document sourced Loki defaults. Root lands the fix after OPN-0033, takes up 10800 hold, dispatches once at the fix SHA, records counts and retains hold for OPN-0057.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 9 source verification: 35 offline proof tests pass. Three outcomes are present (exit 0 with other assertions passing), visibility-pending (exit 0 only with emitted/shipped records, zero drops and complete shutdown diagnostics plus delivered redaction proof), and genuine loss/query failure (exit 1). New shutdown-abandonment regression failed before its fix with AssertionError: 0 != 1. Original genuine-drop subcases were verified failing against isolated HEAD after initial implementation, not claimed to have been written first. Sourced Loki defaults are documented. CodeRabbit source slice completed; its older-Python timestamp parsing suggestion is left because the dispatched ubuntu-latest proof runs modern Python and invalid timestamp fallback retains numeric workflow-run ordering. Live dispatch remains pending at the fix SHA.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Wave 9 source landed at 0d2e6b567d7b88b36ffbd6d621f5d7592b534ed8; live run 34029094742 at that exact SHA completed with failure/exit 1. Observed: configchange delivery outcome visibility-pending, emitted records 1, shipped configchange 1, every configchange drop reason 0, terminal/shutdown rejection counters 0, forced kill no. Delivered configstate bodies 168; selected configchange instance none, selected delivered bodies 0, historical delivered records 0, delivered bodies redacted no. No current-record absence/loss is inferred from the empty query. AC1 and AC3 proven by sourced docs, 35 offline tests and full just check; AC2 remains incomplete because no flushed configchange body was selected for verification. PARKED RESUME BOUNDARY: inspect the categorized historical seed-window result to establish a queryable prior proof instance and whether its identity is carried in labels or structured metadata; verify delivered bodies with the shared redaction checker and rerun the proof under a new authorized hold. No second started proof was dispatched. The raw-SHA dispatch attempt was rejected with HTTP 422 and created no run; main was verified at the fix SHA before the successful branch-ref dispatch.
<!-- SECTION:FINAL_SUMMARY:END -->
