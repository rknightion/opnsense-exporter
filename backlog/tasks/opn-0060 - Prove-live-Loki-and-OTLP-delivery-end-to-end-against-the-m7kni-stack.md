---
id: OPN-0060
title: Prove live Loki and OTLP delivery end to end against the m7kni stack
status: Parked
assignee:
  - '@codex'
created_date: '2026-09-03 18:47'
updated_date: '2026-09-03 19:34'
labels: []
dependencies: []
priority: high
ordinal: 14000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Eight shipped log sources have never been exercised against a real backend. Waves 1 to 3 landed configchange, configstate, device inventory, security posture, routing changes, unparsed-syslog, DNS-domain enrichment and exporter self-logs, and every one of those closed with "live Loki delivery was not run" recorded as not proven. Unit tests pin the record construction; nothing has yet proved a record leaves the process, authenticates, and arrives with the labels and structured metadata the dashboards and annotations query by.

The gap is a class, not a task: the same OTLP export path carries all of them, so one proof run covers all eight, and a single wrong resource attribute or promoted-label assumption would be invisible in unit tests and fatal in a dashboard.

Target is the m7kni stack, owner decision 2026-09-03. The OTLP gateway is `https://otlp-gateway-prod-gb-south-1.grafana.net/otlp` authenticating as the stack id, and Loki is `https://logs-prod-035.grafana.net` with its own tenant id. The gateway speaks OTLP only; the two id spaces do not cross, and a Loki tenant id will 401 at the gateway.

The proof runs locally against the testbed rather than in CI, and the evidence is recorded on this task and on each covered task.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Each of the eight sources is observed arriving in the m7kni stack, identified by its opnsense.source value, with the query used and a redacted result recorded
- [ ] #2 The promoted stream-label set observed in Loki matches the documented table in docs/log-shipping.md, and any divergence is written up rather than silently accepted
- [ ] #3 OPN-0038 domain enrichment is confirmed present as structured metadata and confirmed ABSENT from the stream-label set, per its frozen contract
- [ ] #4 Config revision and config snapshot bodies are confirmed redacted in the delivered record, not merely in the unit test
- [ ] #5 No credential value appears in any commit, tracker entry, log or report; the run is identifiable by its instance label so the data can be pruned
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 4: under one root-owned testbed hold, run the local exporter against the testbed with a unique instance label and m7kni OTLP credentials read only at point of use; generate each in-scope source, query Loki independently, and record per-source arrival, promoted labels, domain metadata placement, and on-wire redaction.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 4 live attempt: the single testbed hold opened at 2026-09-03T19:29:39Z, all six guests reached running and both firewalls were ready, and the hold was released at 2026-09-03T19:33:46Z before any delivery traffic. The required firewall API address/key/secret are absent from the local process and repository; per the repository operating model they exist only in the protected CI environment. D3 requires this proof locally and forbids substituting CI, while D9 forbids seeking or minting another credential. No exporter ran, no OTLP record was written, no Loki query result was observed, and no instance label was used. PARKED RESUME BOUNDARY: provide a pre-authorized local secret-file or brokered launcher for the testbed API credentials, plus safe reversible config-revision and route-change triggers and a real sensitive snapshot input; then repeat under one hold with a unique instance label and record the eight per-source delivery rows.
<!-- SECTION:NOTES:END -->
