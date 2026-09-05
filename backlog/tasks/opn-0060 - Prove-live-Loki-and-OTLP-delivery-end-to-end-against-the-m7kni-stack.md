---
id: OPN-0060
title: Prove live Loki and OTLP delivery end to end against the m7kni stack
status: Parked
assignee:
  - '@codex'
created_date: '2026-09-03 18:47'
updated_date: '2026-09-05 22:22'
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
- [x] #2 The promoted stream-label set observed in Loki matches the documented table in docs/log-shipping.md, and any divergence is written up rather than silently accepted
- [x] #3 OPN-0038 domain enrichment is confirmed present as structured metadata and confirmed ABSENT from the stream-label set, per its frozen contract
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

Wave 8: root owns integration, tracker, all external writes and serial testbed holds. Terra/high delivery lane owns the proof helper and ConfigChangeSource diagnostics; record fixed-schema metrics before Loki, exercise Poll self-log read-back and historical unlabelled disambiguation, inspect existing partial-success attribution, then one reviewed fix-SHA dispatch. Luna/max independently owns internal/webui for OPN-0053. Root runs just check and source-only CodeRabbit before commits; Phase 2 testbed use follows Phase 1 release. No firewall object mutation. Session root route differs from Sol because of the explicit conversation model-switch instruction; prescribed child routes remain unchanged.
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

Wave 7 run 33982574173 reached exporter startup and backend records, but configchange and configstate were absent under its instance. The configstate exporter-stream poll error identifies duplicate filter-rule identity (OPN-0085). No configchange poll error was observed. The proof discarded stderr, so sink rejection and state-load diagnostics were unobservable; add fixed-vocabulary in-memory stderr classification before the next changed-source dispatch. No raw local log line or credential may be retained or rendered.

Added bounded concurrent JSON stderr classification without retaining or rendering raw log lines; only fixed counters identify state-load errors, configchange rebaseline/poll errors, terminal destination rejection and explicit historical-age/order markers. Unknown rejection remains unknown. Final source cursor is compared to the selected successor in memory before state-file removal. Offline proof suite: Ran 63 tests in 0.345s / OK; real nonblocking pipe framing included. These diagnostics do not replace Loki delivery/redaction assertions.

Decisions by Rob 2026-09-05 (post wave 7): (1) The revised observation boundary is APPROVED for wave 8. Add fixed-schema, credential-free observations to the proof: per-source admission, emitted, shipped and dropped counts read from the exporter's own metrics or a bounded stderr classification, plus configchange diff length and diff count as numbers only; then ONE dispatch under one root-owned testbed hold. Distinguish empty source output, downstream discard after gateway acceptance, and arrival under another identity or time before concluding. No mutation trigger; nothing on the testbed is created, edited or deleted. Two same-shape missing-configchange results stop the approach again. (2) Release 4.2.0 (PR 679) is HELD on this task: it is not merged until the two remaining assertions are each answered yes or no with a query and result. Unparked to To Do because the blocker was a human decision and that decision is now taken.

Authority granted by Rob 2026-09-05 for wave 8: if BOTH remaining assertions are answered yes with query and result recorded here, the campaign root may merge release PR 679 (4.2.0) unattended. Any no or unproven leaves the PR for Rob.

Wave 8 revised observation boundary implemented: exporter receives a numeric loopback web listen address, harness scrapes actual required log counters before any Loki read, preserves missing last-export gauges as missing, and reads fixed numeric Poll branch/count/body-length observations back through exporter selflogs. Body byte/line counts describe emitted redacted/capped records; raw diffs are not retained for observations. Existing OTLP protobuf partialSuccess handling already splits acknowledged/rejected records, increments dropped reason rejected and emits the terminal warning; focused existing tests passed (internal/logship 5.858s), so no sink rewrite. Root corrected realistic metrics and categorized Loki metadata parsing before live use; unrelated series/transport metadata are ignored but missing required counters never become zeros. Empty observation readback remains explicitly unavailable. Historical query separates matching, other and absent instance counts without exposing other identities. Whole offline testbed suite: Ran 74 tests in 0.559s, OK. CodeRabbit six-file source slice completed/review_completed with zero findings. Live dispatch pending isolated just check and fix-SHA push under the root hold.

Wave 8 one live dispatch 33995443013 at 7a34b51bdbbe863d07af30360ca494df696bebb4 completed its proof (workflow failure reflects two NO assertions, not startup failure). Instance delivery-proof-33995443013. Before Loki, metrics showed shipped configchange=1, configstate=168, exporter=35; dropped overflow/record_too_large/rejected/ship_failed/ship_failed_permanent=0 for both config sources; poll errors=0 both, global ship errors=0. Last exported timestamps configchange=1788646643.9679756, configstate=1788646647.8044593. Poll selflogs: emitted branch 28 polls, one total record (poll1/record1), emitted redacted/capped body 1472 bytes / 43 lines; no_revisions/baseline/cursor_not_in_history=0. All stderr classifier counts zero; cursor advanced. Later selflog/query observations are not simultaneous with the earlier metric snapshot. Source produced and pipeline counted one acknowledged record, with no partialSuccess rejection observed. Arrival under this identity remains NO; do not identify two other-instance historical records as ours. Redaction combined assertion NO because no change body arrived; 693 configstate bodies across device_inventory/firewall/security_posture passed expanded SensitiveConfigKey vocabulary (c67a6060), sensitive keys=0, unexpected families=0; change bodies=0, sensitive elements=0 is not a clean result.

Exact Loki reads all sent X-Loki-Response-Encoding-Flags: categorize-labels. Shared start_ns=1788507338130000128. Assertion1 query {service_name="opnsense2otel",service_instance_id="delivery-proof-33995443013",opnsense_source="configchange"}, end_ns=1788646776456325527: zero records, source_absent_in_instance_window. Assertion2 uses that query plus {service_name="opnsense2otel",service_instance_id="delivery-proof-33995443013",opnsense_source="configstate"}, end_ns=1788646776875617513: 693 verified snapshot bodies, zero change bodies, combined NO. Broad {service_name="opnsense2otel",service_instance_id="delivery-proof-33995443013"}, end_ns=1788646778350878588: other instance data exists but configchange absent. Exporter observation query same instance with opnsense_source="exporter", end_ns=1788646779869432230: numeric Poll observations above. Historical {service_name="opnsense2otel",opnsense_source="configchange"}, start_ns=1788503798130000128, end_ns=1788510998130000128: total2, matching_instance0, other_instance2, without_instance0. Seed config-1788506738.3272.xml timestamp1788506738.33, successor config-1788507398.1255.xml timestamp1788507398.13; 100 retained, expected1 diff. No raw bodies or other identities retained in artifacts.

Wording clarification: the broad instance query found OTHER SOURCE data within this same run instance, not data from another instance. Only the separate historical query found two other-instance configchange records; neither is attributed to this run.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Partial proof only. Exporter and syslog delivery were observed, but configchange/configstate arrival, domain metadata placement, on-wire config redaction and the seven-key label contract all answered no. Three disabled proof accounts remain because the protected credential can create/search but cannot delete; the guarded final run stopped before another mutation. Resume at authorised cleanup plus configstate poll-error and label-promotion diagnosis.

Wave 6 supersession: five assertions are discharged and were not rerun: end-to-end transport for merged/netflow/syslog/zenarmor; documented production stream-label set; no domain stream label; current build promotes nothing outside the documented seven; dst_domain is structured metadata rather than a stream label. Wave 6 final run 33870791765 stopped at proof_stage=resolving_alias with proof_failure=alias_search_no_approved_match before exporter startup. Therefore configchange/configstate arrival and on-wire config redaction remain unproven; their Loki queries were not executed and no configstate err attribute was observable. No alias was edited or restored, no account was created, and no m7kni telemetry was written. PARKED RESUME BOUNDARY: create or identify the dedicated throwaway firewall alias and record its exact safe name, then rerun without any user-account trigger.

Wave 7 supersedes every alias/user cleanup prerequisite. Read-only harness 809ba1b9 and snapshot/diagnostic repair 6e39983a are committed. Runs 33982574173 and 33984106411 both selected penultimate retained revision config-1788506738.3272.xml from 100 revisions, with one expected successor diff and zero delivered configchange diffs. Final instance delivery-proof-33984106411: all three configstate families arrived; configchange remained source_absent_in_instance_window. Cursor advanced=yes; classified configchange poll, rebaseline, state-load, ingest-oversize, terminal-rejection and historical-rejection counts all zero. Therefore combined arrival assertion=no and combined delivered-redaction assertion=no, still unproven rather than evidence of clean absent bodies. Snapshot-only read-back observed 693 bodies, verifier configstate_bodies_redacted=true and configstate_sensitive_keys=0. Queries use service_name=opnsense2otel, service_instance_id=delivery-proof-33984106411 and opnsense_source=configchange or configstate; start_ns=1788507338130000128, workflow ends=1788633047338757325 and 1788633047740222317; broad instance end=1788633048943607574; snapshot-only verifier end=1788633173441104000. All reads used categorize-labels and per-entry structuredMetadata. First run shipped duplicate filter-rule identity error; OPN-0085 fixed it and all snapshot families now arrive. The five already discharged assertions were not redone; AC2/AC3 reconciled from authoritative attended evidence. No firewall object was created, edited or deleted. PARKED RESUME BOUNDARY: diagnose the emitted configchange record and sink outcome with source admission/shipped/drop counters plus a fixed-schema non-body diff-length/count observation; determine whether the existing historical record is empty, accepted but discarded downstream, or queried under another identity/time. Do not infer a timestamp rejection from absence or zero classified errors. Two same-shape missing-configchange results stop this brief: no third dispatch occurred. A revised proof approach is required; no mutation trigger is permitted.

Later Wave 7 source audit found the bare key vocabulary gap (OPN-0094) and two fixture-reproduced scanner gaps (OPN-0092/0093). The observed 693 snapshot bodies passed the verifier at source SHA 6e39983a, before that vocabulary expansion; retain that exact scope, not a claim that the final redactor was exercised live. No third dispatch or new live confirmation followed. Combined redaction assertion remains no/unproven.

Wave 8 supersedes prior resume prerequisites: source emission and pipeline acknowledgment now observed, but configchange arrival NO and combined config-body redaction NO. Snapshot-only 693-body redaction is now proven using expanded SensitiveConfigKey. PR679 remains held and untouched. PARKED RESUME: obtain m7kni tenant historical-sample policy (including reject_old_samples_max_age) and backend disposition for this acknowledged historical record; correlate safe revision metadata before attributing the two other-instance records to this run. No third or repeated unchanged dispatch, no mutation trigger. Root hold released 2026-09-05T22:20:36Z; nothing on the testbed created, edited or deleted. Source review complete in two six-file passes, just check passed; no credential value reached an artifact.
<!-- SECTION:FINAL_SUMMARY:END -->
