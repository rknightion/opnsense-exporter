---
id: OPN-0096
title: >-
  Triage the standing nightly and release-vm canary drift findings open since
  2026-09-01
status: To Do
assignee: []
created_date: '2026-09-05 19:54'
labels:
  - api-drift
  - canary
dependencies: []
references:
  - 'https://github.com/rknightion/opnsense2otel/issues/727'
  - 'https://github.com/rknightion/opnsense2otel/issues/726'
priority: medium
ordinal: 50000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
The daily live-box schema canary has reported the same findings on both testbed profiles every run since 2026-09-01 (GitHub issues 727 nightly and 726 release-vm, refreshed daily by the workflow) and nobody has assigned a verdict, so real drift would now be invisible under the standing noise. Apply the five-verdict taxonomy in AGENTS.md (box-state first, then absorb, chase, drop, opportunity) to every finding, verifying each against the OPNsense controller or script that builds the payload before assigning it. Findings as of the 2026-09-05 run, both profiles unless noted: unexpected top-level keys tailscaleStatus ExtraRecords, qemuGuestAgentServiceStatus widget, quaggaBgpRoute4 and quaggaBgpRoute6 subtitle; unexpected nested keys tailscaleStatus Peer.*.NodeID and Self.NodeID, and eighteen keaReservations4 rows[].* fields (client_id, description, hostname, hw_address, ip_address, next_server, option, option_data.*, uuid) that the OPN-0015 struct does not model; missing paths interfacesOverview rows[].link_typev6 (appeared 2026-09-02, see OPN-0013 which introduced the field) and quaggaBgpRoute4/6 totalPaths and totalRoutes (appeared 2026-09-03 with the OPN-0017 BGP route tables); one probe error zerotierNetworkInfo HTTP 0 resolving path parameter: HTTP 404 (nightly only; likely the same dynamic per-network 404 OPN-0089 classified in the collector, now surfacing in the canary prober at cmd/apidrift/probe.go:242). The prod profile (issue 693) is clean and needs nothing. Two of the OPN-0015 and OPN-0017 findings are self-inflicted by fast-wave structs written without a live capture; check whether the OPN-0017 BGP struct modelled totalPaths/totalRoutes as unconditional when upstream emits them only with a populated table. Every exemption gets a missingOK or knownExtraTopKeys/knownExtraPaths entry whose note names the box state or the generation and the prune trigger, per the exemptions ledger conventions. Golden schemas stay structure-only. The GitHub issues stay open; they are the workflow output channel, not the tracker.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [ ] #1 Every finding listed in the 2026-09-05 nightly and release-vm canary comments carries one of the five verdicts, each justified against upstream source in the notes
- [ ] #2 box-state and opportunity verdicts are exempted in opnsense/testdata/schemas/exemptions.json with a note naming the box state or generation and the prune trigger; chase and absorb verdicts change the struct with a fixture derived from source or a real capture
- [ ] #3 The zerotierNetworkInfo probe error is classified: either the prober tolerates the dynamic per-network 404 the way OPN-0089 does in the collector, or the verdict records why it must stay a probe error
- [ ] #4 A dispatched live-canary run at the fix SHA reports zero missing paths, zero unexpected keys and zero probe errors on both testbed profiles, or every remainder is named with its verdict
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [ ] #1 just check
- [ ] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->
