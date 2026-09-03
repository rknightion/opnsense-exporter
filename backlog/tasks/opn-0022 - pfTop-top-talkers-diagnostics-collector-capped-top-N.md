---
id: OPN-0022
title: 'pfTop / top-talkers diagnostics collector, capped top-N'
status: Done
assignee:
  - '@codex'
created_date: '2026-08-30 09:08'
updated_date: '2026-09-03 20:47'
labels: []
milestone: m-3
dependencies: []
priority: medium
type: feature
ordinal: 403
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
DECIDED 2026-08-30: build, opt-in, capped top-N (Rob). `api/diagnostics/firewall/queryPfTop` + `api/diagnostics/traffic/top`: top-N states/talkers for boxes WITHOUT the NetFlow receiver (flow logs already cover the rest). Use the existing boundedinventory/cappedcounter pattern for cardinality; `exporter.enable-*` (default-off) flag family per AGENTS.md step 4 since this has extra per-scrape cost and cardinality.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Opt-in collector exports capped top-N talkers/states with a documented, bounded cardinality ceiling
- [x] #2 Docs state the NetFlow-receiver overlap and when to prefer which
- [x] #3 AGENTS.md new-collector steps complete; gates clean
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 4: derive and record ranking, tie-breaking, merge, and overflow semantics before implementation; then build the default-off bounded API collector against that frozen contract.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 3 park: the current task does not freeze the exact top-N ranking key, tie-breaking, state/talker merge behavior, or overflow aggregation semantics. Resume by recording those bounded-cardinality semantics on this task first; then implement the default-off pfTop diagnostics collector and document its overlap with the NetFlow receiver. Existing internal/flow/toptalkers.go is not the requested API collector.

FROZEN WAVE 4 CONTRACT, source-derived from released OPNsense 26.7.3 before implementation. Build a default-off pftop API fallback only for installations without the NetFlow receiver; never merge it with internal/flow/toptalkers.go because PF-state byte totals and the two-second iftop rate sample have incompatible units. Use N=100 as a code constant for each independent board. State fetch: POST queryPfTop with current=1, rowCount=-1 and empty searchPhrase, then rank locally. State identity is proto, dir, source address and port, destination address and port, optional gateway address and port, rule. State is mutable: group duplicate identities, sum bytes, packets and record count, and choose displayed state from the greatest-byte record, then greatest packets, then lexical state. Rank by summed bytes descending then the full identity tuple lexically. Emit named bytes, packets and records gauges; omit age, expire, avg, label and descr. Talker fetch: call traffic top once with lexically sorted non-empty enabled interface identifiers from the interface overview and skip when none exist. Include only status=ok interfaces; timeout means exclusion, not synthetic zero. Talker identity is interface plus address, never merged across interfaces. Rank globally by total rate_bits descending, then interface and address lexically. Emit in, out and total rate_bits gauges only; omit cumulative values, rname, tags, formatted strings and details. Keep two bounded inventories, cap 100 each, TTL five minutes, prune before admission, and emit only current identities. Current-snapshot overflow includes every source group outside top 100 plus selected novel groups refused by the inventory. State overflow sums bytes, packets and records. Talker overflow sums in, out and total rate_bits plus records. Named series plus overflow must equal the successful returned snapshot for covered fields, without claiming completeness beyond the endpoint response. Emit cardinality denied-total and live-key diagnostics for state and talker, including zero from first successful scrape. Hard ceiling is 611 series per target: 3N state, 3N talker, 3 state overflow, 4 talker overflow and 4 cardinality diagnostics. Correct the stale traffic-top no-cap note and document that this is a bounded sampled API view, with NetFlow preferred when enabled.

Wave 4 implementation completed the frozen contract: form POST pfTop plus parameterized traffic-top fetch, deterministic independent top-100 state and talker boards, five-minute bounded inventories, exact overflow equality, candidate-refusal accounting, default-off slow-tier wiring, and a hard 611-series ceiling. The canary resolver uses sorted enabled interface identifiers. Released-source review also proved label and descr are conditional box state, so both paths carry missingOK entries with a testbed-state prune trigger. The review found and fixed rejected updates that could otherwise increment refusals while still being emitted, and documented the additional interfacesOverview ACL requirement. Focused packages passed; just gen reported 82 collectors, 1,046 metrics, 1087/1087 dashboard coverage and 10/10 log sources; the full just check passed including 427 Grafana tests and no vulnerabilities. Two fresh source-only CodeRabbit passes completed with zero findings across all 20 reviewed files.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Added the default-off bounded pfTop API fallback with deterministic top-100 state and sampled talker boards, overflow accounting, a 611-series ceiling, live-canary path resolution, dashboard coverage, ACL guidance, and NetFlow preference documentation. Verified with focused race tests, two completed zero-finding CodeRabbit passes, just gen, and the full just check.
<!-- SECTION:FINAL_SUMMARY:END -->
