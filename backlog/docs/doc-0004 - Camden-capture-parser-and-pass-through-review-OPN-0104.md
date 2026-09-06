---
id: doc-0004
title: Camden capture parser and pass-through review - OPN-0104
type: other
created_date: '2026-09-06 17:28'
updated_date: '2026-09-06 18:25'
---
## Scope and evidence

OPN-0104 investigation, 2026-09-06. Downloaded the complete retained `/opt/opnsense2otel/capture` tree: 121 NDJSON files, 4,082 records, 36 programs, captured between 2026-08-04 08:46 UTC and 2026-09-06 15:37 UTC. These are retained, deduplicated debug examples, not a complete traffic recording or a frequency sample. The source remained live during the read; later arrivals are outside this snapshot.

Private evidence is in `~/capture-reviews/opn-0104-20260906/`: original tar archives, extracted files, SHA-256 manifest, replay harness, replay-test.log and per-record replay.jsonl. None of the payloads belongs in this public repository. Capture contains identity and credential-bearing text; fixtures must substitute synthetic values before being committed or sent for external review.

Replayed every debug record through ParseEnvelope and buildRecord at source SHA `6406f359195b2a1768933d682ba0d2269fdd4106`, using no live enrichment snapshot. All envelopes parsed. Current parsers recognise 1,077 records; 3,005 remain generic. The capture normaliser produces 922 distinct program/shape keys, but these are NOT 922 grammars: it retains domain names and paths and truncates at 120 runes. Full messages were retained for investigation. Replay checks parser recognition, not delivery, enrichment or derived-metric correctness.

Also preserved `/opt/syslog-capture` in full: its 10,462 records are a separate UniFi-oriented corpus, not this exporter's OPNsense debug capture. Do not import its device-tag/envelope incompatibilities into the OPNsense parser backlog or a global never-parse exemption. No new UniFi implementation is proposed here.

## Parser candidates

Priority is operational value, not captured volume. These are implementation candidates, not completed parsers.

1. **dpinger alarm coverage:** seven captured transitions remain generic because `loss` and/or the `ALERT:` prefix are unsupported. Model the observed none/loss/down edges while retaining the previous/current states and distinguishing loss-to-down from recovery. One sendto-error line is a separate diagnostic candidate. Existing comments saying these transitions lack capture evidence are now stale.
2. **Explicit failures:** cron bad-minute errors; configd timeout/disconnect/socket failures; configctl socket failure; lighttpd backend-connect/TLS errors; syslog-ng destination connection refusal; DHCP packet send/address-removal failures; lldpd buffer exhaustion; firewall GeoIP download failure; backup-provider connection failure. These must stay visible and must not receive a blanket known-benign exemption.
3. **DNS transactions:** 418 Unbound query and 312 reply examples contain query name/type/class, client and reply outcome/timing. Dnsmasq query/config-answer variants also exist. Useful structured logs, but no DNS-name metric labels and no assumption that query plus reply represents two requests. Correction after implementation review: Unbound query/reply parsing already exists behind the disabled-by-default per-query opt-in. The baseline replay used that default; these 730 records are not missing parser coverage.
4. **Network and clock lifecycle:** kernel link up/down, OPNsense interface attach/detach and routing changes, selected devd IFNET notifications, DHCPv6 prefix release/restart, and ntpd unsynchronised/synchronised/peer-state events. Avoid counting the same link event from kernel, devd and opnsense three times.
5. **Change audit:** package upgrades from pkg/pkg-static, firmware-update audit and requested reboot. Package old/new versions are useful log attributes; a reboot request is not evidence that reboot completed.
6. **PPP diagnostics:** LCP/IPCP/IPv6CP state changes and CHAP outcome shapes are potentially useful, but option dumps and CHAP peer-supplied text are not reliable tunnel outcomes. In particular a text string mentioning an attack is carried inside a successful CHAP exchange; do not infer an attack event from its wording.
7. **API authentication failure:** the captured message contains a credential-bearing suffix. Structure the failure only with a deliberate redaction boundary covering both shipped body and debug capture; never extract the credential as an attribute. This needs a security review before implementation, not an allowlist entry.

## Known pass-through decisions

Here, known pass-through means the raw record continues to ship with its normal envelope and enrichment. It never means dropping the log, pretending the parser succeeded, or hiding all future messages from that program. There is currently no runtime known-unparsed registry: source.go captures every buildRecord miss. The decisions below are the documented baseline for a future narrow classifier.

| Message family | Disposition and reason |
|---|---|
| dhclient script New Hostname and Creating resolv.conf | Known pass-through. Script side effects, not lease transitions; already documented in dhclient.go and pinned by TestDHCPClientUnmodelledLinesAreNotClaimed. 108 of the 110 dhclient examples. |
| dhclient IP-length disagreement and accepting trailing UDP data | Retain as visible generic packet diagnostics for now. Two separate shapes, not script chatter and not proof of lease failure; do not include them in the benign script exemption. |
| configd successful template generation; configctl forwarded config-event wrapper | Known pass-through for these successful progress/wrapper shapes. Structuring every generated file adds little beyond existing configuration events. Socket failures remain candidates. |
| Unbound recursion statistics/histogram rows | Known pass-through. Multi-line partial dumps would need stateful assembly and overlap polled statistics; single rows must not become independent metrics. |
| Unbound logger/module startup and database auto-restore housekeeping | Known pass-through for these specific notices. They describe internal housekeeping rather than a DNS transaction or failure. |
| kernel copyright, boot hardware enumeration, console progress and identity output | Known pass-through for these observed informational families. The kernel tag also carries rc-script output; it cannot be exempted wholesale. Link transitions and explicit faults remain visible candidates. |
| PPP option/negotiation continuation rows | Known pass-through. Their meaning depends on surrounding protocol state and they are not independent success/failure events. |
| devd table push/pop, rule testing and execution trace | Known pass-through. Internal dispatch detail; keep IFNET event and error shapes separate. |
| sshd listener/start-stop notices | Known pass-through. No authentication decision is present. sshd-session transport errors remain visible diagnostics, not login failures. |
| syslog-ng successful reload/start-stop notices | Known pass-through. Preserve the progress notices; destination connection errors remain candidates. |
| dnsmasq local-zone/configuration/start-stop announcements; DHCP range declaration | Known pass-through. Configuration chatter, not per-client leases. Query/answer and explicit warning/error messages remain separate. |
| kea prefix watcher startup | Known pass-through. Helper startup, not DHCP allocation or lease outcome. |
| radvd successful configuration reload/start-stop, miniupnpd listener/start-stop, rtsold interface/probe notices | Known pass-through for those lifecycle/probe notices. Address/send failures remain visible and are excluded from the exemption. |
| charon KNL address/interface appeared/disappeared notices | Known pass-through. Host interface observations, not IKE/CHILD tunnel transitions. |
| ntpd banner, listener and initial configuration output | Known pass-through. Clock health transitions remain parser candidates. |
| opnsense plugin invocation/template plumbing, unchanged route notices and trust-intermediate skips | Known pass-through for these observed progress shapes. Actual route changes, interface transitions and warnings/errors remain separate. |
| root bogon-update start/end/no-change notices | Known pass-through. Successful housekeeping. Added/deleted-address summaries can remain generic until a concrete structured-log consumer needs them. |
| firewall old-alias removal notices | Known pass-through. Housekeeping; download failures are not exempted. |

Any classifier should match program plus a complete, anchored grammar, carry a reason, and have negative tests showing nearby failures remain unknown. Do not match capture.NormaliseShape keys: truncation and identity-bearing tokens make them unsuitable as an allowlist contract. Unknown messages must still be captured. Known pass-through must remain distinguishable from successfully parsed records in coverage accounting.

## Program census

Counts are examples in the downloaded debug corpus. Parsed means current buildRecord recognised the message. All other records still receive generic handling; candidates above remain unimplemented.

| Program | Captured | Parsed now | Remaining disposition |
|---|---:|---:|---|
| /usr/sbin/cron | 14 | 0 | Bad-minute error candidate |
| DhcpLFC | 567 | 567 | Already covered |
| api | 1 | 0 | Authentication/redaction candidate |
| audit | 1 | 0 | Firmware audit candidate |
| charon | 50 | 0 | KNL pass-through |
| config | 6 | 6 | Already covered |
| configctl | 39 | 0 | Forwarded events pass through; socket error candidate |
| configd.py | 588 | 0 | Generation pass-through; four explicit failure examples |
| devd | 68 | 0 | Trace pass-through; IFNET candidate |
| dhclient | 110 | 0 | 108 known script notices; two visible packet diagnostics |
| dhcp6c | 17 | 0 | Prefix/lifecycle and address-removal candidates |
| dnsmasq | 170 | 0 | Configuration pass-through; DNS transactions and warning candidates |
| dnsmasq-dhcp | 14 | 0 | 11 range announcements; three send failures |
| dpinger | 17 | 9 | Seven alarm transitions plus one send error |
| firewall | 5 | 0 | Two alias-removal notices; three download failures |
| kea-dhcp6 | 165 | 162 | Three helper-start notices |
| kernel | 305 | 4 | Boot/console pass-through; link and diagnostic candidates |
| lighttpd | 68 | 0 | Lifecycle pass-through; backend/TLS failure candidates |
| lldpd | 6 | 0 | Buffer and control-socket diagnostics |
| miniupnpd | 5 | 0 | Four lifecycle notices; one interface-address failure |
| ntpd | 67 | 0 | Banner/config pass-through; clock/peer candidates |
| opnsense | 228 | 0 | Plugin progress pass-through; routing/interface/failure candidates |
| php | 33 | 0 | Backup-provider connection failure candidate |
| pkg | 2 | 0 | Upgrade audit candidate |
| pkg-static | 15 | 0 | Upgrade audit candidate |
| ppp | 62 | 0 | Negotiation detail pass-through; state/outcome candidates |
| radvd | 18 | 0 | 17 lifecycle notices; one send failure |
| root | 101 | 0 | Bogon-update pass-through |
| rtsold | 7 | 0 | Interface/probe pass-through |
| rule-updater.py | 39 | 39 | Already covered |
| shutdown | 1 | 0 | Reboot-request audit candidate |
| sshd | 13 | 0 | Listener/start-stop pass-through |
| sshd-session | 5 | 0 | Transport-error diagnostics, not authentication verdicts |
| sudo | 1 | 1 | Already covered |
| syslog-ng | 431 | 289 | 141 lifecycle/reload notices; one destination failure |
| unbound | 843 | 0 | 730 DNS transactions; 113 stats/lifecycle/housekeeping |

## NetFlow, Zenarmor and retirement

The live container mounts the reviewed directory at /capture. Syslog and Zenarmor debug capture are enabled; NetFlow is `unidentified`. No NetFlow or Zenarmor files exist in the retained mounted capture tree, so there are no payloads to decode from either receiver in this snapshot.

Read-only live metrics on 2026-09-06 showed 36,129 accepted NetFlow datagrams and 779,974 decoded records; malformed and unsupported-version counters were zero, as were unknown-field, unknown-flowset and options-template counters. A subsequent read showed zero capture buffer, byte-budget, disk-cap and write-error drops for all three receivers. These are current-process counters, not proof of uninterrupted historical capture.

The shared capture cap is the default 256 MiB: no environment or command-line override was configured. The retained tree uses about 4.6 MiB. Keep NetFlow unidentified capture: it is bounded, has headroom and remains useful for future template changes. No evidence justifies a new NetFlow decoder or a never-decode entry.

OPN-0104 must remain open. The recent week contains more than dhclient, and the historical corpus contains substantive parser candidates. A quiet newest file does not prove coverage. Before retirement, implement or explicitly settle the remaining candidates, then observe a full week with no new unclassified shapes. Keeping NetFlow capture also requires keeping its shared directory and mount; retire only the syslog/Zenarmor enable flags unless NetFlow gets an explicitly configured replacement destination. Archive retained files rather than deleting them. The existing acceptance criterion that removes the shared mount needs reconciling with retained NetFlow capture before deployment.


## Implemented dispositions (2026-09-06)

The preceding census is the historical baseline, not the current implementation. Supplemental program-scoped parsers now cover explicit service failures, DNSmasq transactions, gateway loss/ALERT transitions, interface/routing/clock events, DHCPv6 and PPP diagnostics, package/firmware/reboot audit and API authentication failures. New supplemental events are log-only and do not create lease, session, authentication or CARP counters. Alarm-to-alarm gateway transitions emit alarm_changed rather than recovery.

Complete, anchored known-pass-through grammars now implement the informational families above with code-defined reasons. They preserve shipping and enrichment while excluding those records from debug capture and unknown-coverage counts. No whole-program exemptions or capture-normalisation allowlist was added. Unbound query/reply opt-in remains unchanged; complete supported-but-disabled messages are known with reason unbound_per_query_disabled, while malformed/new shapes remain unknown. dhclient script notices are known; both packet diagnostics are structured.

API supplied-key suffixes are removed before envelope parsing, capture, enrichment and shipping, including multiline or malformed input. Fixtures use synthetic values; private payloads are not committed.

Production-ingress replay classified the original 4,082 records as 1,429 parsed and 2,653 known, and the refreshed 4,093 records as 1,429 parsed and 2,664 known. Every record shipped. Each replay captured exactly one deliberately unknown positive control and no corpus record. Private evidence: corpus-ingress-evidence.log and archived corpus_ingress_scratch_test.go in the evidence directory above. This proves corpus disposition and ingress behaviour; deployment and backend read-back are recorded separately in OPN-0104.

No retained NetFlow/Zenarmor unknown payload required a decoder. Their existing capture modes and the shared mount remain enabled. OPN-0104 stays open for observation; archive the previous corpus outside the active tree when deploying.
