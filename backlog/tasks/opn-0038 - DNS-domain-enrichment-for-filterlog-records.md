---
id: OPN-0038
title: DNS-domain enrichment for filterlog records
status: To Do
assignee: []
created_date: '2026-08-30 09:09'
updated_date: '2026-08-30 09:35'
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
