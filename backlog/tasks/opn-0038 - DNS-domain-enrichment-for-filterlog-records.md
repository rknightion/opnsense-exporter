---
id: OPN-0038
title: DNS-domain enrichment for filterlog records
status: To Do
assignee: []
created_date: '2026-08-30 09:09'
updated_date: '2026-09-02 16:04'
labels: []
milestone: m-4
dependencies: []
priority: medium
type: enhancement
ordinal: 505
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
`internal/logship/syslog/filterlog.go:165-169` adds geo enrichment but never consults `flow.DNSCache`, which the flow path already maintains and which is reachable from the receiver wiring (`internal/logship/source.go:112-116`, `internal/flow/processor.go`). The same address in a flow log resolves a domain; the firewall log line does not. Add domain enrichment parity for filterlog.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 filterlog records carry the resolved domain attribute when the shared DNS cache has one
- [ ] #2 No new DNS lookups introduced on the hot path (cache-read only); test covers hit and miss
- [ ] #3 The domain never becomes a Loki stream label; a test asserts the stream-label set is unchanged by enrichment
- [ ] #4 Per-domain metric is capped at the top 50 domains by volume, with every other domain folded into a single other series; a test drives more than 50 distinct domains and asserts the series count stays bounded
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 2 did not start this lane because OPN-0056 could not land through the required CodeRabbit gate. Resume after OPN-0056 lands, then explicitly bound expected DNS-domain cardinality before implementation; do not add an unbounded per-domain Loki stream label.

Unblocked and unparked 2026-09-02: OPN-0056 landed on main in `a482f637`.

FROZEN CARDINALITY CONTRACT, owner decision 2026-09-02. This was the open question that kept the task parked; it is now closed and is not to be re-litigated.

1. The resolved domain ships as an OTLP log attribute, which reaches Loki as structured metadata. Structured metadata is not indexed as a stream, so it carries no cardinality ceiling and needs none.
2. The domain MUST NOT be promoted to a Loki stream label, and MUST NOT be added to any annotation `tag_keys`. The existing label set is closed; enrichment does not open it.
3. A per-domain Prometheus metric is in scope, capped at the top 50 domains by volume with all remaining domains folded into a single `other` series. Ceiling is 51 series. Overflow behaviour is fold-into-other, never drop and never a new series.
4. Cache-read only on the hot path, as AC2 already requires. The cap is applied where the metric is built, not by evicting from the shared DNS cache.
<!-- SECTION:NOTES:END -->
