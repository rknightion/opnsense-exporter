---
id: OPN-0099
title: >-
  Document and harness the Loki visibility delay for historical config revision
  events
status: To Do
assignee: []
created_date: '2026-09-05 22:47'
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
- [ ] #1 docs/log-shipping.md (or the troubleshooting page) states that historical configchange records surface in Loki only after the ingester chunk flush, with the 3h querier lookback and 7d rejection horizon named and their sources cited
- [ ] #2 The live delivery proof distinguishes visibility-pending from absent for a historical record, and its configchange redaction assertion runs over the delivered bodies of the most recent flushed instance
- [ ] #3 The proof still fails on a genuine drop: logs_shipped_total zero, a drop reason, or partialSuccess rejection
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
