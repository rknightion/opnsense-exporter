---
id: OPN-0060
title: Prove live Loki and OTLP delivery end to end against the m7kni stack
status: In Progress
assignee:
  - '@codex'
created_date: '2026-09-03 18:47'
updated_date: '2026-09-05 17:23'
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

Wave 6: replace the forbidden user-account trigger with a reversible description edit on the dedicated throwaway firewall alias; dispatch the protected live proof under one root-owned testbed hold; query the exporter stream first for the configstate poll-error err attribute; then diagnose and repair only from observed evidence, rerun as needed, and answer the two remaining arrival/redaction assertions. Do not retry through any user-account path.

Wave 7 supersedes the alias prerequisite: delete all alias mutation and obsolete proof assertions, read retained revisions, seed the source cursor through the existing pipeline state-file envelope, then ship historical configchange and heartbeat configstate to m7kni and assert arrival before on-wire redaction. Use the shared sensitive-key vocabulary in a credential-safe delivered-body verifier; preserve categorized Loki metadata and bounded diagnostics. Root owns justfile integration, completed source-only CodeRabbit, just check, commit/push, serialized testbed hold and workflow dispatch. Two same-shape failures stop that approach. No firewall configuration object may be created, edited or deleted.
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

## Wave 5 assertion results corrected, 2026-09-04 (attended re-query)

Two of the four Wave 5 'no' results were harness measurement artifacts, not exporter defects. Re-queried m7kni Loki directly for the same three proof instances with X-Loki-Response-Encoding-Flags: categorize-labels. Cause and fix: OPN-0070.

| Assertion | Wave 5 said | Corrected | Evidence |
| --- | --- | --- | --- |
| Current build promotes nothing outside the documented seven keys | No (202 unexpected) | **Yes** | Stream labels are exactly opnsense_action, opnsense_source, opnsense_subsystem, service_instance_id, service_name in all three instances. All five are inside the documented seven. The 202 were structured-metadata keys that Loki's default response encoding merges into the stream map. |
| Domain is structured metadata on the enriched record | No | **Yes** | dst_domain present in structuredMetadata with the expected value delivery-proof.example, and absent from stream labels in every stream of all three instances. Under the default encoding the metadata element is omitted entirely, so this assertion was structurally incapable of passing. |
| configchange and the three configstate families arrive | No | **Still no** | Genuine. Sources observed in the proof instances are exporter, syslog and zenarmor only. |
| Config revision and snapshot bodies arrive redacted on the wire | No | **Still unproven** | No body arrived to inspect. Blocked behind the assertion above. |

Note also that zenarmor DID arrive in all three runs. Wave 5 reported only exporter and syslog because its per-source queries covered configchange, configstate, exporter and syslog only.

## Why configstate could not be diagnosed, and what changed

Its poll-error counter was positive and no reason reached the backend. pollOnce logs the reason via p.log.Warn("log source poll error", source, err), and Start had routed every pipeline diagnostic to the non-forwarding handler, so it existed only on the exporter's stderr. Read back from the run's own shipped exporter records: 48 entries covering the whole process lifecycle, startup through 'received signal, shutting down gracefully', with no poll-error warning among them.

Fixed by OPN-0069. The next proof run ships the reason, so configstate's failure becomes self-diagnosing instead of a bare counter.

## Still open

- The three disabled deliveryproof users on the testbed. No local firewall credential exists on this machine, so cleanup still needs the testbed's own delete authority. Do not create a fourth proof user before this is cleared.
- configchange showed poll errors=no yet emitted nothing. It baselines on first poll and only emits past its cursor, so the open question is whether a new backup revision appeared at all in the ~20s window after the user add.

Wave 6 run 33863315389 at 40e68d6c failed before exporter startup or any testbed mutation. Instance label delivery-proof-33863315389. The harness emitted proof_completed=no but no bounded preflight stage, so this run cannot distinguish alias lookup absence from API or revision-list failure. No assertion was answered; do not treat the empty run as delivery evidence. Next action: add credential-safe stage diagnostics, then rerun under the existing hold.

Wave 6 diagnostic run 33864111463 at 8615d475 failed at proof_stage=resolving_alias before exporter startup or mutation. Root diagnosis against upstream AliasController.php: the action is getAliasUUIDAction, and OPNsense spells capital acronyms one letter at a time in routes (the repository already carries getGeoIPAction as get_geo_i_p). The harness used get_alias_uuid; next action is the narrow route correction to get_alias_u_u_i_d, followed by a newly reviewed rerun.

Wave 6 run 33864893085 at 68cbde58 still failed at proof_stage=resolving_alias before exporter startup or mutation after the acronym route correction. This proves the hard-coded exact alias lookup did not resolve; it does not prove whether only the spelling differs or the object is absent. Next action: replace direct lookup with a POST search_item selection that accepts exactly one alias whose name normalizes to deliveryproof, emits only that safe matched name, and fails on zero/multiple matches. No object creation is authorised.

Wave 6 run 33867334131 at 47f47313 failed at proof_stage=resolving_alias before exporter startup, alias mutation or m7kni write. The harness still suppressed which safe failure class occurred. Next action: ship bounded response-shape and HTTP failure codes that cannot include response data, rerun under the existing hold, and diagnose from the code.

Wave 6 diagnostic run 33869285754 at 19b8625a failed at proof_stage=resolving_alias with proof_failure=alias_search_no_approved_match. The alias API request and complete pagination succeeded; none of the three lowercase approved spellings matched. No exporter started, no alias was mutated, and no m7kni write occurred. Next action: accept only the same two-word dedicated name with optional single hyphen or underscore and case-insensitive letters, retain exactly-one selection and near-collision rejection, then rerun.

Wave 6 run 33870211682 at 21a824b2 again failed at proof_stage=resolving_alias with proof_failure=alias_search_no_approved_match after allowing case variants of the exact delivery-proof stem. No exporter started, no alias was mutated, and no m7kni write occurred. Final bounded identification attempt: allow one safe prefix and/or suffix token around the exact stem while retaining exactly-one selection and near-collision rejection. If that still finds nothing, park at dedicated alias absent or differently named.

Wave 6 final bounded run 33870791765 at 1cda1d2b failed at proof_stage=resolving_alias with proof_failure=alias_search_no_approved_match after allowing one safe prefix and/or suffix around the delivery-proof stem. This establishes that the dedicated alias is absent or differently named; no exporter started, no alias was mutated or restored, no m7kni write occurred, and no user account was created. The testbed hold was released at 2026-09-04T12:04:54Z. PARKED RESUME BOUNDARY: create or identify the dedicated throwaway firewall alias and record its exact safe name, then dispatch the current proof workflow; do not fall back to any user-account trigger.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Partial proof only. Exporter and syslog delivery were observed, but configchange/configstate arrival, domain metadata placement, on-wire config redaction and the seven-key label contract all answered no. Three disabled proof accounts remain because the protected credential can create/search but cannot delete; the guarded final run stopped before another mutation. Resume at authorised cleanup plus configstate poll-error and label-promotion diagnosis.

Wave 6 supersession: five assertions are discharged and were not rerun: end-to-end transport for merged/netflow/syslog/zenarmor; documented production stream-label set; no domain stream label; current build promotes nothing outside the documented seven; dst_domain is structured metadata rather than a stream label. Wave 6 final run 33870791765 stopped at proof_stage=resolving_alias with proof_failure=alias_search_no_approved_match before exporter startup. Therefore configchange/configstate arrival and on-wire config redaction remain unproven; their Loki queries were not executed and no configstate err attribute was observable. No alias was edited or restored, no account was created, and no m7kni telemetry was written. PARKED RESUME BOUNDARY: create or identify the dedicated throwaway firewall alias and record its exact safe name, then rerun without any user-account trigger.
<!-- SECTION:FINAL_SUMMARY:END -->
