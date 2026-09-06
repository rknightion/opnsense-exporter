---
id: OPN-0057
title: >-
  Measure UDP receiver throughput: same-harness before/after for buffers and
  worker pool
status: Done
assignee:
  - '@claude'
created_date: '2026-09-02 05:20'
updated_date: '2026-09-06 13:39'
labels:
  - needs-triage
milestone: m-4
dependencies:
  - OPN-0035
priority: low
type: task
ordinal: 11000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
OPN-0036 landed a configurable 4 MiB SO_RCVBUF default plus a clamp warning that names net.core.rmem_max, and OPN-0035 will land a bounded queue and worker pool for the syslog UDP read loop. Neither change carries a throughput measurement: OPN-0036's report explicitly makes no performance claim, and the effective buffer size has never been read back on a deployed Linux or BSD target. Establish what the two changes actually bought, so the next receiver change has a baseline to move.

Deferred deliberately at wave 1 closeout (decision by Rob 2026-09-02): the clamp warning is the operationally useful half and it shipped; the number is worth having but is not worth blocking a receiver fix on.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 Before and after come from the SAME harness at the SAME offered load and packet size - a better number produced by a changed measurement method is a false pass, not a result
- [x] #2 Effective SO_RCVBUF is read back on a deployed Linux target (accounting for the kernel doubling the requested value) and on a BSD target, and both are reported as numbers
- [x] #3 Drop counts at the socket and at the worker queue are reported alongside throughput, so a throughput gain that is really a drop is visible
- [x] #4 The measured numbers are recorded on this task; no throughput claim is made anywhere in docs or release notes that this task has not measured
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Plan

<!-- SECTION:PLAN:BEGIN -->
Wave 4: in the same testbed hold but only after live-delivery traffic stops, run one controlled identical-load harness for before and after, read effective Linux and BSD receive buffers, and record throughput plus socket and worker-queue drops as measured numbers or park at the exact missing observation.

Wave 5: first commit a deterministic UDP throughput contract naming the sender command, fixed payload, packet size, offered rate, duration, immutable before/current binaries, isolated Linux and BSD receiver targets, successful numeric SO_RCVBUF read-back, and attributable socket plus worker-queue drop counters. Only after that contract lands may the root take the shared testbed hold and measure; otherwise re-park with the exact missing observation.

Wave 6: expose opnsense_exporter_syslog_udp_accepted_total immediately after successful UDP queue admission and a positive opnsense_exporter_syslog_udp_receive_buffer_bytes gauge from the actual getsockopt read-back. Preserve Linux doubled and FreeBSD undoubled semantics without equality assertions. Regenerate owned docs/dashboard after source integration, but do not run the throughput harness; re-park on the two missing isolated host roles.

Wave 7 D15 supersedes isolated-host provisioning: use guest 105 as Linux LXC receiver and an OPNsense FreeBSD VM as the other receiver, with a different guest as sender for each trial. Preserve the committed 256-byte, 5000 packets/s, 60-second method and require observed counters; report shared-host noise, host rmem_max ceiling, and Linux doubled versus FreeBSD undoubled SO_RCVBUF beside every number. Phase 1 released the root testbed hold before this disposition.

Wave 9 D3 supersedes the former access-route park. Implement and test allowlisted power-script exec and CT-only put, including guest exit-envelope decoding; root commits and deploys with timestamped backup, then measures the four frozen guest-role/version observations under the hold opened for OPN-0099. Missing prerequisites park at the exact observation; no packages or firewall configuration objects are changed; guest temporary directories are removed before root releases its hold.

Attended 2026-09-06: api-key must be set is a presence check; with --exporter.instance-label set startup makes no API call, so a dummy key/secret starts the receiver with no real credential and no firewall change. Run the four-observation contract under one hold after the OPN-0099 proof.
<!-- SECTION:PLAN:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Wave 3 park: resume with one controlled harness that applies identical offered UDP load and packet size before and after the buffer/worker-pool changes. Read back numeric effective SO_RCVBUF on deployed Linux and BSD, accounting for Linux doubling, and capture both socket drops and bounded worker-queue drops alongside throughput. Do not make a throughput claim until all four measurements are recorded here.

Wave 4 feasibility result: no throughput trial ran. The testbed hold was released before L2 traffic because the repository has no committed identical-load sender harness, receiver deployment topology, or fixed payload/rate/duration contract. Current code exposes queue_full loss but not a successful numeric effective SO_RCVBUF read-back; the BSD candidate socket-drop counter is system-wide unless receiver isolation is proved. A comparison without those facts would fail acceptance criteria 1 through 3 and any number would be manufactured. PARKED RESUME BOUNDARY: define one committed same-payload/rate/duration harness runnable against immutable pre-feature and current binaries, name the deployed Linux and BSD receiver targets, expose or trace numeric getsockopt SO_RCVBUF on both, and prove attributable socket-drop deltas before running the comparison.

Wave 5 contract landed in 8c4d92ce. The fixed 256-byte, 5,000 packets/s, 60-second sender and fail-closed four-observation verifier passed 11 focused tests and the full just check gate. CodeRabbit completed three source-only passes: pass 1 found a major before/current socket-drop-scope gap plus a major non-JSON socket-failure path and a minor formatting issue; pass 2 found non-finite elapsed values could pass validation; pass 3 completed with zero findings after all were fixed. No traffic ran and no throughput number was observed. PARKED RESUME BOUNDARY: expose an ingress-accepted counter immediately after successful syslog UDP queue admission and a successful numeric getsockopt SO_RCVBUF read-back on each deployed receiver; provide immutable before/current deployments on the named isolated Linux and FreeBSD roles with the same instance and counter-capture method; then run the committed four-observation contract under one testbed hold and record buffer, accepted rate, socket drops, and queue drops. A CI-only API credential does not provide the missing FreeBSD binary deployment or receiver-local counters.

Wave 6 implementation: added opnsense_exporter_syslog_udp_accepted_total at successful non-empty, allowlisted bounded-queue admission and opnsense_exporter_syslog_udp_receive_buffer_bytes from the positive getsockopt(SO_RCVBUF) read-back. The read-back is surfaced unchanged: Linux commonly reports roughly double the request while FreeBSD does not, and no equality assertion was added. Generated self-metric documentation and two dashboard panels; just gen and the complete just check gate passed. CodeRabbit source review completed for the syslog slice in one pass with zero findings; the dashboard-only pass raised one major slice-context false positive because the listener source that registers the gauge was excluded, and the combined four-file pass completed with zero findings. No traffic ran and no throughput, drop or buffer number was observed; acceptance criteria 1 through 4 remain unproven. PARKED RESUME BOUNDARY: provide the two isolated receiver host roles required by the committed contract, one Linux and one FreeBSD, then run that contract.

Decision by Rob 2026-09-05 (post wave 7): stays Parked and is excluded from wave 8 and later waves until an approved direct guest-shell/deployment route for guest 105 and one OPNsense VM exists. No lane should pick this up on its own initiative; the resume boundary is unchanged.

Wave 9 route source: allowlisted exec and CT-only put are implemented. VM execution decodes integer guest exitcode and optional QGA stdout/stderr; absent streams mean empty, malformed fields or incomplete/time-out envelopes fail. Two original refusal regressions failed before dispatch existed; the optional-stream regression also failed before its correction after current Proxmox source verification. 12 route tests and 25 complete power tests pass; bash -n and shellcheck pass. CodeRabbit completed the source slice with no power-route findings. Deployment and guest observations remain pending under the existing root hold.

Final Wave 9 power read-back after release and down: hold none; all six allowlisted guests stopped. The only guest temporary directory and the oli binary transport directory were both removed and absence verified before the hold was released. Final tracker closeout just check passed.

Attended trial 2026-09-06, Linux receiver role (guest 105 eth1, sender guest 112, contract sender 256 B at 5000 pps for 60 s, 300000 packets, both runs elapsed 59.9999 s, stdout sink, API unreachable by design with a dummy key and explicit --exporter.instance-label). before v4.1.0 (executable sha256 b0c07a16...c1fc8519): effective SO_RCVBUF 212992 read from ss skmem rb (the OS default; v4.1.0 requests nothing), per-socket sk_drops 0 to 0, pipeline overflow drops 0 to 0, legacy accepted counter logs_shipped_total{source=syslog} 0 to 300000. current v4.2.0 (0dedbbe0...6dd6ff... see evidence): effective SO_RCVBUF 8388608 read from ss skmem rb and equal to the exporter gauge (4194304 requested, Linux doubled read-back, host net.core.rmem_max 4194304 so the request fits exactly), sk_drops 0 to 0, queue_full rejections 0 to 0, syslog_udp_accepted_total 0 to 300000. Verdict at this offered load: no loss in either phase; the buffer change bought 39x headroom (212992 to 8388608 bytes) with no measurable throughput difference because 5000 pps does not stress a 212 KiB buffer on this host. Caveats carried: shared hypervisor host, host rmem_max ceiling, Linux doubled read-back. The pre-worker-pool binary has no udp_accepted_total or queue_full series, so its accepted and loss counters are the documented legacy predecessors (logs_shipped_total{source=syslog}, logs_dropped_total{reason=overflow}); the verifier now accepts those for the before phase only and marks counter_source=legacy.

Attended trial 2026-09-06, FreeBSD receiver role before phase (guest 102 vtnet2 LAN side, sender guest 105 eth0, same contract sender, 300000 packets in 59.9999 s). v4.1.0 (executable sha256 23381839...eac582b, archive verified against checksums.txt in-guest): effective SO_RCVBUF 42080 read from netstat -x R-HIWA (the net.inet.udp.recvspace default; v4.1.0 requests nothing), host-wide dropped-due-to-full-socket-buffers 0 to 0, pipeline overflow 0 to 0, legacy accepted counter logs_shipped_total{source=syslog} 0 to 300000, host-wide datagrams received moved 300098 so background UDP during the trial was 98 datagrams (recorded as the shared-host caveat). FreeBSD current phase is blocked on OPN-0101: v4.2.0 exits at startup on this box (setsockopt ENOBUFS at 4 MiB against kern.ipc.maxsockbuf 4262144), so the current binary for FreeBSD must be the first release candidate carrying the fallback (a86cbb65), verified against its checksums.txt; the Linux current stays v4.2.0. Guest temporary directories still present under the live hold; removed before release.

Attended trial 2026-09-06, FreeBSD receiver role current phase: v5.0.0-rc.3 (first candidate carrying the OPN-0101 fallback; archive sha256 6ce41819...9c4df2 verified in-guest against the release checksums.txt, executable e1863937...5a8153). Startup logged the fallback: kernel refused 4194304, accepted 2097152, limit_setting kern.ipc.maxsockbuf. Effective SO_RCVBUF 2097152 read from netstat -x R-HIWA, host-wide full-socket-buffer drops 0 to 0, queue_full rejections 0 to 0, syslog_udp_accepted_total 0 to 300000, background UDP 113 datagrams. Verifier over all four observations: status accepted, zero violations (linux before 212992 bytes legacy counters, linux current 8388608, freebsd before 42080 legacy counters, freebsd current 2097152; every phase 300000 accepted at 5000 pps with 0 socket and 0 queue drops). Cleanup verified: /tmp/opn57 absent on 105, 112 and 102, no exporter process left, oli transport directory removed, hold released 13:37:30Z and the lab powered down 13:38:48Z. Evidence files stay in the ignored session scratch area; guest addresses never reached the tracker.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Committed the deterministic OPN-0057 measurement contract at 8c4d92ce; numeric measurement remains unproven and is parked at the exact missing receiver observations.

Wave 6 supersession: observability shipped at b10ffbb5. opnsense_exporter_syslog_udp_accepted_total counts successful bounded-queue admission and opnsense_exporter_syslog_udp_receive_buffer_bytes exposes the positive getsockopt SO_RCVBUF read-back. Linux commonly reports roughly double the request while FreeBSD does not; no equality assertion was added. No traffic ran and no throughput, drop or buffer number was observed. PARKED RESUME BOUNDARY: provide the two isolated receiver host roles required by the committed contract, one Linux and one FreeBSD, then run it.

Wave 7 measurement remains PARKED before sender/receiver startup. Isolation is no longer the prerequisite: the supplied shared guest roles are accepted with mandatory caveats. The missing prerequisite is an existing approved guest-shell and binary-deployment/counter-capture path. Repository and local SSH inventory documented only the allowed oli power script; the traffic-generator runbook identifies guest 105 as a jump host but no login/deployment path; protected-environment secret-name inventory has firewall API credentials but no guest SSH/deployment credential; local tailnet peer inventory found no matching documented nightly/traffic-generator peer. No alternative hypervisor guest execution or production-host substitution was used. No throughput, socket-drop, worker-queue-drop or effective-buffer value was observed; no zero or comparison is claimed and the verifier was not run with fabricated inputs. No guest filled a sender/receiver role. Linux receiver remains assigned to 105; the FreeBSD receiver and independent sender are pending access. PARKED RESUME BOUNDARY: document an approved direct guest-shell/deployment route for guest 105 and one OPNsense VM, plus the distinct sender guest; deploy immutable before/current binaries and capture actual receiver-socket and queue counters around the unchanged sender. Retain all three D15 caveats alongside any observed number; a shared-host FreeBSD system-wide drop counter cannot establish exporter-attributable loss.

Wave 9 route source landed at aae0b728ada8a407efe683cb6c55aa0c9162e770 and was deployed to oli. Timestamped backup retained at /usr/local/bin/opnsense-testbed-power.sh.bak-20260906T111114Z; deployed SHA-256 66f7262466314ac69913da217dc05dfcdcf245a5a6640aab4257383efb85b76c equals the committed local script. Before/after status showed the same active hold expiry. CodeRabbit completed with no power-route findings; 12 focused route and 25 complete power tests, bash -n, shellcheck and just check passed.

Observed prerequisite results: sender guests 112 and 105 each report Python 3.13.5. The immutable current Linux executable was placed through CT-only put in a temporary directory and its in-guest SHA-256 matched the locally verified archive. pct push did not retain execute permission; the first help call exited 126, then chmod on the temporary file made help succeed. The binary's actual flags are opnsense.protocol/opnsense.address, not the goal's older ops spelling. Credential-free startup exited 1 with api-key must be set before a receiver was available.

PARKED at the Linux current receiver startup prerequisite. No sender ran; none of the four throughput observations ran. Effective SO_RCVBUF, receiver accepted rate, socket drops and worker-queue drops are UNOBSERVED, not zero; the four-file verifier was not run with fabricated data. No FreeBSD executable was fetched or started. The before binary's wave-6 self-metrics remain absent by contract; future before buffer/drop values must be OS-sourced and labelled accordingly. Every future number must retain shared-host noise, host rmem_max ceiling and Linux doubled versus FreeBSD undoubled read-back caveats; FreeBSD system-wide UDP drops cannot establish receiver-attributable loss on a shared host.

Linux archive/executable verification against each release checksums.txt (archive then executable): v4.1.0 5bb96d1b47386f3430b2be7dd6f2b7767b26bb8c3405a5eafff00526c6f6612c / b0c07a16315509e46a03d69c64757bd0a41a5abdebc645729ef0d998c1fc8519; v4.2.0 7dc4ee1ec2049ca96485674db629fb4811eb68ec6be2c8d3af34dbb6f7c211fa / 0dedbbe05b232358b2406b83c07ccadbf51d200c12ba345f4a89a5365b6dd4e7. These are integrity observations, not throughput measurements. Only the current executable was additionally verified inside the guest.

The only guest temporary directory, on 105, was removed and its absence verified through exec before release. The oli transport directory was removed and absence verified. No package was installed and no firewall configuration object was created, edited or deleted. Root hold was released after cleanup. Guest addresses remain only in ignored evidence, not in this tracker.

RESUME BOUNDARY: provide an approved way for the immutable before/current receivers to pass required API authentication validation without exposing credentials or changing firewall configuration; then repeat startup proof on Linux and FreeBSD and run the unchanged four-observation contract with actual OS/exporter counters. No performance claim is made. Acceptance criteria 1-4 remain unproven; only route deployment and validation are complete.

Measured 2026-09-06 with the committed harness (256 B, 5000 pps, 60 s, 300000 packets) through the wave 9 guest route. Linux (guest 105): before v4.1.0 effective SO_RCVBUF 212992, current v4.2.0 8388608 (4 MiB requested, doubled read-back); FreeBSD (guest 102): before v4.1.0 42080, current v5.0.0-rc.3 2097152 after the OPN-0101 fallback. All four phases: 300000 accepted, 0 socket drops, 0 queue drops, so at this offered load neither change altered throughput and the buffer change bought 39x (Linux) and 50x (FreeBSD) headroom. Caveats recorded beside every number: shared hypervisor host, host rmem_max ceiling, Linux doubled versus FreeBSD undoubled read-back, FreeBSD system-wide drop counter with measured background UDP (98 and 113 datagrams), legacy counters for the pre-worker-pool binary. Verifier accepted with zero violations (19fc9129 verifier). No throughput claim is made in docs or release notes.
<!-- SECTION:FINAL_SUMMARY:END -->
