---
id: OPN-0101
title: >-
  Syslog UDP receiver refuses to start on FreeBSD when the requested receive
  buffer exceeds the kernel limit
status: Done
assignee:
  - '@claude'
created_date: '2026-09-06 12:47'
updated_date: '2026-09-06 13:39'
labels:
  - bug
  - syslog
  - freebsd
dependencies: []
priority: high
ordinal: 55000
---

## Description

<!-- SECTION:DESCRIPTION:BEGIN -->
Found 2026-09-06 while running the OPN-0057 trial on the testbed FreeBSD receiver (OPNsense 26.7 nightly, kern.ipc.maxsockbuf at its 4262144 default). v4.2.0 with --logs.syslog.enabled exits at startup: failed to start log shipping: build push log sources: syslog: configure UDP receive buffer: set UDP receive buffer to 4194304 bytes: setsockopt: no buffer space available. FreeBSD does not clamp SO_RCVBUF the way Linux does; it rejects any request above sb_max_adj (maxsockbuf scaled by MCLBYTES/(MSIZE+MCLBYTES), about 3.79 MiB at the default), so the OPN-0036 4 MiB default is fatal on every stock OPNsense box and on the firewall the exporter is documented to run beside. v4.1.0 starts on the same box. configureUDPReceiveBufferObserved in internal/logship/syslog/listener.go returns the setsockopt error as fatal instead of falling back. Linux behaviour (silent clamp plus the existing warning) must stay unchanged.
<!-- SECTION:DESCRIPTION:END -->

## Acceptance Criteria
<!-- AC:BEGIN -->
- [x] #1 On a kernel that rejects the requested SO_RCVBUF, the receiver falls back to a smaller buffer, warns with the requested and effective sizes and names the limiting sysctl (kern.ipc.maxsockbuf on FreeBSD), and starts
- [x] #2 A failing-before unit test covers the refused-then-accepted path; the existing all-sizes-refused test still fails startup
- [x] #3 The effective read-back gauge reports the buffer actually granted
<!-- AC:END -->

## Definition of Done
<!-- DOD:BEGIN -->
- [x] #1 just check
- [x] #2 just gen (if any generated artifact changed) and the diff committed
<!-- DOD:END -->

## Implementation Notes

<!-- SECTION:NOTES:BEGIN -->
Fix landed a86cbb65: configureUDPReceiveBufferObserved halves the request down to a 64 KiB floor until the kernel accepts one, warns with requested_bytes, accepted_bytes, effective_bytes, err and limit_setting (kern.ipc.maxsockbuf on freebsd, net.core.rmem_max on linux), and keeps the read-back gauge on the granted size. Failing-before tests TestConfigureUDPReceiveBufferFallsBackWhenKernelRefusesRequest (attempts [4194304, 2097152]) and TestConfigureUDPReceiveBufferFallsBackToFloorThenFails (attempts stop at 65536, error returned); TestConfigureUDPReceiveBufferReturnsSetError unchanged. go test ./internal/logship/syslog/ ok, golangci-lint 0 issues, just check exit 0. Live proof on the testbed FreeBSD VM pending the first release candidate that carries the fix (auto-rc classifies only the head commit of a push and skipped 19fc9129 because that commit touched scripts and docs only).

Live proof 2026-09-06 on the testbed FreeBSD VM with v5.0.0-rc.3: the receiver started, logged the fallback warning (requested_bytes=4194304 accepted_bytes=2097152 limit_setting=kern.ipc.maxsockbuf), netstat -x R-HIWA read back 2097152, and it accepted 300000 datagrams at 5000 pps with zero host-wide full-buffer drops.
<!-- SECTION:NOTES:END -->

## Final Summary

<!-- SECTION:FINAL_SUMMARY:BEGIN -->
Fixed in a86cbb65: the syslog UDP listener halves a refused SO_RCVBUF request down to a 64 KiB floor, warns with requested and accepted sizes and the limiting sysctl, and reports the granted size on the gauge. Proven by failing-before unit tests and live on the testbed OPNsense VM with v5.0.0-rc.3 (accepted 2 MiB, receiver started and took 300000 datagrams without loss).
<!-- SECTION:FINAL_SUMMARY:END -->
