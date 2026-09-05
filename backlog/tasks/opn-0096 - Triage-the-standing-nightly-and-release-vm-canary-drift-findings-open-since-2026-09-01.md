---
id: OPN-0096
title: >-
  Triage the standing nightly and release-vm canary drift findings open since
  2026-09-01
status: In Progress
assignee:
  - '@codex'
created_date: '2026-09-05 19:54'
updated_date: '2026-09-05 21:57'
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
- [x] #1 Every finding listed in the 2026-09-05 nightly and release-vm canary comments carries one of the five verdicts, each justified against upstream source in the notes
- [x] #2 box-state and opportunity verdicts are exempted in opnsense/testdata/schemas/exemptions.json with a note naming the box state or generation and the prune trigger; chase and absorb verdicts change the struct with a fixture derived from source or a real capture
- [x] #3 The zerotierNetworkInfo probe error is classified: either the prober tolerates the dynamic per-network 404 the way OPN-0089 does in the collector, or the verdict records why it must stay a probe error
- [ ] #4 A dispatched live-canary run at the fix SHA reports zero missing paths, zero unexpected keys and zero probe errors on both testbed profiles, or every remainder is named with its verdict
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 8: prepare source-verified five-verdict triage without testbed use while Phase 1 is implemented. Verify master and supported stable payload-producing controllers/scripts, box-state first; root owns compatibility ledger and any generation. Prober dynamic resource-404 behavior gets a failing-before regression if repaired. Live-canary dispatch waits until Phase 1 releases the testbed, then runs at the reviewed fix SHA under its own root hold; record both profile remainders and never comment on GitHub issues.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Root challenge to initial BGP box-state verdict: DiagnosticsController searchBgproute4/6 copies FRR scalar headers into rows only, then returns searchRecordsetBase plus optional subtitle. Core ApiControllerBase searchRecordsetBase returns only total/rowCount/current/rows (stable/26.7 lines 175-180). Thus top-level totalPaths/totalRoutes appear to be an invented compatibility shape, not conditional empty-table fields. Rechecking supported branches before ledger changes; do not hide this with a box-state exemption.

Source-verified triage correction: top-level BGP totals are CHASE in the sense of correcting our wrong path to the existing row fields, not an upstream move. No supported controller ever emitted the modeled envelope fields: master/stable-26.7/stable-26.1 DiagnosticsController lines 105-175 flatten headers into rows; ApiControllerBase lines 175-180 emits only bootgrid metadata and rows. Remove the invented envelope branch and synthetic fixture; do not write a false box-state or legacy-generation exemption. The five-verdict vocabulary does not separately name a self-inflicted schema path; report this distinction explicitly.

Wave 8 source verdicts (master, stable/26.7 and stable/26.1 verified): BGP totalPaths/totalRoutes CHASE-local-schema correction, never envelope fields; FRR DiagnosticsController.php lines 105-175 copies scalar headers into rows, core ApiControllerBase.php lines 175-180 returns bootgrid metadata. subtitle is OPPORTUNITY GUI text. All eighteen Kea row extras are OPPORTUNITY: Dhcpv4Controller.php lines 95-98 searchBase plus KeaDhcpv4.xml lines 272-384 return configured identity/options; collector deliberately counts only. tailscale ExtraRecords and Peer/Self NodeID are OPPORTUNITY outside node-local policy: StatusController.php lines 39-45 directly proxies actions_tailscale.conf lines 26-29 status JSON. QEMU widget is OPPORTUNITY: ServiceController.php lines 40-45 inherits ApiMutableServiceControllerBase.php lines 234-260 GUI captions. interfacesOverview link_typev6 is CHASE already handled: OverviewController.php 26.1 lines 181-196 has no field; 26.7/master emits it unconditionally including none. Release-vm compatibility entry prunes when 26.1 leaves support. ZeroTier is BOX-STATE plugin absence, not dynamic installed-network 404: NetworkController.php lines 45-84 returns empty 200 for unknown configured UUID; absent search route 404 now skips dependent info probe. Ledger entries carry generation and prune triggers. Failing-before BGP schema reported Missing [totalPaths totalRoutes] for both AFs; after focused tests cmd/apidrift 0.305s, opnsense 0.207s. just schemas: wrote 202 golden schemas to opnsense/testdata/schemas (0 orphans removed). Live remainder pending root dispatch after Phase 1.

Integrated just check completed exit 0 in an isolated worktree whose 15-file source/schema patch SHA-256 matches the primary checkout. CodeRabbit canary four-file slice: first complete pass found one minor incomplete bootgrid fixture, fixed; second complete pass zero findings. Live AC4 remains open for the post-Phase-1 dispatch.
<!-- SECTION:NOTES:END -->
