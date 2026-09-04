---
id: OPN-0060
title: Prove live Loki and OTLP delivery end to end against the m7kni stack
status: Parked
assignee:
  - '@codex'
created_date: '2026-09-03 18:47'
updated_date: '2026-09-04 07:48'
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
- [x] #5 No credential value appears in any commit, tracker entry, log or report; the run is identifiable by its instance label so the data can be pruned
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 4: under one root-owned testbed hold, run the local exporter against the testbed with a unique instance label and m7kni OTLP credentials read only at point of use; generate each in-scope source, query Loki independently, and record per-source arrival, promoted labels, domain metadata placement, and on-wire redaction.

Wave 5: add a manual protected-environment workflow modelled on live-canary, build the current tree, emit the four still-unproven source families under one unique instance label, perform one reversible secret-bearing testbed configuration change, and query the backend for per-source arrival, structured domain metadata, on-wire redaction, and the current-build promoted label set. The root alone dispatches the workflow and owns the testbed hold, backend writes, tracker updates, commit and push.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 4 live attempt: the single testbed hold opened at 2026-09-03T19:29:39Z, all six guests reached running and both firewalls were ready, and the hold was released at 2026-09-03T19:33:46Z before any delivery traffic. The required firewall API address/key/secret are absent from the local process and repository; per the repository operating model they exist only in the protected CI environment. D3 requires this proof locally and forbids substituting CI, while D9 forbids seeking or minting another credential. No exporter ran, no OTLP record was written, no Loki query result was observed, and no instance label was used. PARKED RESUME BOUNDARY: provide a pre-authorized local secret-file or brokered launcher for the testbed API credentials, plus safe reversible config-revision and route-change triggers and a real sensitive snapshot input; then repeat under one hold with a unique instance label and record the eight per-source delivery rows.

PARTIAL PROOF OBTAINED 2026-09-04, attended, before wave 5. Wave 4 could not start this because it was told to run locally and the firewall API credentials exist only as `tailnet` GitHub environment secrets. That mandate was the blocker, not the task.

Discharged tonight by querying the m7kni backend directly:

1. THE OTLP TRANSPORT IS PROVEN END TO END. Four sources are live in m7kni Loki right now: `merged`, `netflow`, `syslog`, `zenarmor`. They arrive from the deployed production exporter, so auth, endpoint selection, resource attributes and the export path are all working against the real backend. AC1 remains open only for the four sources that deployment does not run.

2. AC2 PASSES. The observed promoted stream-label set is exactly seven keys: `opnsense_action`, `opnsense_device_category`, `opnsense_interface`, `opnsense_source`, `opnsense_subsystem`, `service_instance_id`, `service_name`. That matches the documented table in `docs/log-shipping.md` including its negatives: `service.version` is documented as not promoted and is absent. The doc was an untested assertion until now; it is correct.

3. AC3 NEGATIVE HALF HOLDS. No domain key appears anywhere in the promoted label set, so the frozen OPN-0038 contract is not violated on live data. This is weaker than it looks: the deployed exporter predates OPN-0038, so it is evidence that nothing promotes a domain label, not yet evidence that the enriching build does not. The positive half, domain present as structured metadata, is still unproven and needs a current build.

STILL UNPROVEN and owned by the next run: arrival of `configchange`, `configstate` (all three families) and `exporter`; domain present as structured metadata; and config-revision/config-snapshot redaction on the wire.

RESUME PATH IS NOW CI, NOT LOCAL. `DEVBOX_HOST`, `DEVBOX_API_KEY` and `DEVBOX_API_SECRET` already exist in the `tailnet` environment, and `GRAFANA_OTLP_USER`, `GRAFANA_LOKI_USER` and `GRAFANA_CAP_TOKEN` were added there on 2026-09-04. A workflow modelled on `live-canary.yml` joins the tailnet, runs the current build against the testbed with the new sources enabled, exports to the m7kni gateway under a unique instance label, then queries Loki back for each source.

Wave 5 CI evidence. Full delivery run 33849420068 at b360e86b used instance delivery-proof-33849420068. Query {service_name="opnsense2otel",service_instance_id="delivery-proof-33849420068",opnsense_source="<source>"}: exporter=yes, syslog=yes, configchange=no with other instance data present, configstate=no with other instance data present; local configstate poll-error counter=yes and configchange poll-error counter=no. Domain structured-metadata assertion=no. Broad query {service_name="opnsense2otel",service_instance_id="delivery-proof-33849420068"}: seven-key-only assertion=no; 202 unexpected key names were observed, including dst_domain, so the current-build result does not match the previously proven production label set. Config revision/snapshot on-wire redaction=no because neither source arrived; no inference was made from empty queries. All gateway and Loki response bodies remained suppressed.

The reversible Auth-user trigger exposed a testbed API authority defect. Search succeeds only as POST with an empty JSON body; deletion failed in deployed path, query-parameter and JSON-body forms. Runs 33843852532, 33848582974 and 33849420068 each created one disabled deliveryproof account and could not remove it; cleanup-only guarded run 33850228416 observed exactly three, attempted all three forms three times for every account, failed, and stopped before exporter startup or any new mutation. PARKED RESUME BOUNDARY: grant the tailnet credential a deletion path that succeeds on the deployed testbed, or remove the three matching non-system proof accounts through an authorised firewall administration path; then diagnose configstate API poll errors and the current-build 202-key label expansion before rerunning the four assertions. Do not create another proof user until cleanup is confirmed.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Partial proof only. Exporter and syslog delivery were observed, but configchange/configstate arrival, domain metadata placement, on-wire config redaction and the seven-key label contract all answered no. Three disabled proof accounts remain because the protected credential can create/search but cannot delete; the guarded final run stopped before another mutation. Resume at authorised cleanup plus configstate poll-error and label-promotion diagnosis.
<!-- SECTION:FINAL_SUMMARY:END -->
