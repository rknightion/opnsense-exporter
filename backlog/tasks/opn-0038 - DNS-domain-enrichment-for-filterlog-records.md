---
id: OPN-0038
title: DNS-domain enrichment for filterlog records
status: Done
assignee: []
created_date: '2026-08-30 09:09'
updated_date: '2026-09-03 19:36'
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
- [x] #1 filterlog records carry the resolved domain attribute when the shared DNS cache has one
- [x] #2 No new DNS lookups introduced on the hot path (cache-read only); test covers hit and miss
- [x] #3 The domain never becomes a Loki stream label; a test asserts the stream-label set is unchanged by enrichment
- [x] #4 Per-domain metric is capped at the top 50 domains by volume, with every other domain folded into a single other series; a test drives more than 50 distinct domains and asserts the series count stays bounded
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Add cache-read-only dst.domain enrichment for parsed filterlog records, observe cache hits into a bounded heavy-hitter counter, emit exactly the top 50 domains plus one other series, prove hit/miss and label invariants, add dashboard/docs coverage, regenerate artifacts, run targeted and full gates, then finalize and land as one task commit.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 2 did not start this lane because OPN-0056 could not land through the required CodeRabbit gate. Resume after OPN-0056 lands, then explicitly bound expected DNS-domain cardinality before implementation; do not add an unbounded per-domain Loki stream label.

Unblocked and unparked 2026-09-02: OPN-0056 landed on main in `a482f637`.

FROZEN CARDINALITY CONTRACT, owner decision 2026-09-02. This was the open question that kept the task parked; it is now closed and is not to be re-litigated.

1. The resolved domain ships as an OTLP log attribute, which reaches Loki as structured metadata. Structured metadata is not indexed as a stream, so it carries no cardinality ceiling and needs none.
2. The domain MUST NOT be promoted to a Loki stream label, and MUST NOT be added to any annotation `tag_keys`. The existing label set is closed; enrichment does not open it.
3. A per-domain Prometheus metric is in scope, capped at the top 50 domains by volume with all remaining domains folded into a single `other` series. Ceiling is 51 series. Overflow behaviour is fold-into-other, never drop and never a new series.
4. Cache-read only on the hot path, as AC2 already requires. The cap is applied where the metric is built, not by evicting from the shared DNS cache.

Implemented cache-read-only dst.domain enrichment for parsed filterlog records using the existing shared flow DNS cache. Cache hits feed a bounded heavy-hitter store: 4,096 in-memory candidates, exactly the top 50 emitted domain series, and one lossless other aggregate; late heavy hitters remain admissible and the aggregate remains monotonic. Domain stays record structured metadata and never enters stream shaping or the existing firewall metric labels. Added dashboard and generated docs/artifacts. Verification: focused race tests passed for cache hit/miss, unchanged stream-shaping attributes, 51-series bound, reserved other folding, late-heavy-hitter admission, and rank-change monotonicity. just gen completed with 1,052/1,052 dashboard metric coverage and 179 schemas; just check passed, including 427 Grafana tests, fuzz legs, PromQL/manifest/generated-file validation, public-IP scan, and govulncheck. CodeRabbit source coverage: phase1-opnsense-collector covered internal/collector files and completed with zero findings after the top-N monotonicity fix; phase1-logship-options covered internal/logship files and completed with the documented docs/dashboard-exclusion false positive; phase1-grafana covered grafana/tabs/log_events.py and completed with zero findings after fixes.

Wave 4 OPN-0060 live-proof disposition: NOT PROVEN. The testbed became ready, but its API credentials were unavailable to the mandated local process and exist only in the protected CI environment; CI was forbidden as a substitute. No exporter delivery run, Loki query, or on-wire result occurred for this source. Resume through OPN-0060 after an authorised local testbed credential launcher exists.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added filterlog destination-domain enrichment from the existing DNS cache and a bounded top-50-plus-other Prometheus counter. No lookup I/O or Loki label was introduced. Targeted race tests, just gen, and the full just check gate passed.
<!-- SECTION:FINAL_SUMMARY:END -->
