---
id: OPN-0038
title: DNS-domain enrichment for filterlog records
status: Parked
assignee: []
created_date: '2026-08-30 09:09'
updated_date: '2026-09-02 07:02'
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
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 2 did not start this lane because OPN-0056 could not land through the required CodeRabbit gate. Resume after OPN-0056 lands, then explicitly bound expected DNS-domain cardinality before implementation; do not add an unbounded per-domain Loki stream label.
<!-- SECTION:NOTES:END -->
