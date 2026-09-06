# UDP receiver throughput harness

This is the OPN-0057 measurement contract. It creates no throughput claim and
contains no testbed address, account, or result. A comparison is valid only when
the verifier emits `"status":"accepted"` for four observations: before/current
on a named isolated Linux receiver role and before/current on a named isolated
FreeBSD receiver role. A rejected result has `"comparison":null`; absent,
skipped, or unobserved data can never be mistaken for zero drops or a pass.

## Fixed traffic method

This is the only traffic-producing command. Substitute a locally supplied
receiver address only. Do not add a rate, duration, packet-size, or payload
option, since doing so creates a different harness.

```sh
python3 scripts/testbed/udp_throughput.py send --target "$UDP_RECEIVER_HOST" --port 5514
```

It sends byte-identical 256-byte RFC5424 UDP datagrams at 5,000 packets/sec for
60 seconds. It exits nonzero unless it sent exactly 300,000 packets within 250
ms of the fixed duration. Preserve its JSON stdout in that observation.
`python3 scripts/testbed/udp_throughput.py shape` prints the immutable payload
digest and load without sending traffic.

## Guest access route

Guest access for this measurement uses the host-side
`scripts/testbed/opnsense-testbed-power.sh` allowlist. The route does not change
guest power state. `exec <id> -- <command...>` runs an allowlisted command and
returns the guest's exit status, stdout, and stderr. It uses `pct exec` for the
Linux container and `qm guest exec --timeout <n> --` for the VM. The VM route
decodes and validates a completed integer `exitcode` in the JSON envelope.
QEMU Guest Agent may omit empty `out-data` or `err-data`, which the route
returns as empty streams; present stream fields must be strings. A successful
`qm` call without a valid completed envelope is a failure.

`put <id> <local-path> <remote-path>` is available for the container only and
uses `pct push`. VMs have no `qm` guest file-write route. Fetch a release inside
the VM with `exec <id> -- fetch -o <tmp> <release-url>`, then verify its
in-guest SHA-256 against `checksums.txt`. The root operator removes temporary
guest directories before releasing the testbed hold; this procedure installs no
packages.

The role assignment is frozen for both binary phases:

| receiver role | receiver guest | sender guest | binary phase |
| --- | ---: | ---: | --- |
| Linux receiver | 105 | 112 | before `v4.1.0` / current `v4.2.0` |
| FreeBSD receiver | 102 | 105 (LAN) | before `v4.1.0` / current `v4.2.0` |

Use the same receiver and sender roles for the before/current pair, while
keeping the sender command and packet method from this document unchanged.

Supply generic role names such as `udp-throughput-linux-receiver` and
`udp-throughput-freebsd-receiver`; do not commit instance data. Observations
carry evidence and instance SHA-256 digests instead of raw private captures.
The before/current instance digest must match on each target.

## Required observation schema

Capture all values immediately around the sender command, one JSON object per
OS/phase. Each `state` must be exactly `"observed"`; `"skipped"` or
`"unobserved"` is rejected. This compact outline names every field (all
`<sha256>` placeholders are actual 64-hex SHA-256 digests at measurement time).

```json
{
  "phase": "before", "receiver_os": "linux",
  "harness": {"schema_version": "opn-0057.udp-throughput.v1", "transport": "udp", "packet_size_bytes": 256, "payload_sha256": "<value from shape>", "offered_rate_packets_per_second": 5000, "duration_seconds": 60},
  "receiver": {"role": "udp-throughput-linux-receiver", "instance_identity_sha256": "<sha256>", "method_identity_sha256": "<sha256>"},
  "binary": {"sha256": "<sha256 of executable>", "source_revision_sha256": "<sha256 of source revision>", "version": "<reported version>"},
  "socket_buffer": {"state": "observed", "method": "getsockopt_so_rcvbuf", "requested_bytes": 4194304, "effective_bytes": 8388608, "linux_readback_is_doubled": true, "evidence_sha256": "<sha256>"},
  "isolation": {"state": "observed", "receiver_role": "udp-throughput-linux-receiver", "scope": "dedicated-host-and-exclusive-udp-traffic", "statement": "<proof for the interval>", "evidence_sha256": "<sha256>"},
  "socket_drop": {"state": "observed", "scope": "receiver_socket", "method": "<capture command>", "start": 0, "end": 0, "evidence_sha256": "<sha256>"},
  "worker_queue_drop": {"state": "observed", "metric": "opnsense_exporter_logs_rejected_total{source=\"syslog\",reason=\"queue_full\"}", "start": 0, "end": 0, "evidence_sha256": "<sha256>"},
  "receiver_accepted": {"state": "observed", "metric": "opnsense_exporter_syslog_udp_accepted_total", "start": 0, "end": 300000, "evidence_sha256": "<sha256>"},
  "sender": {"schema_version": "opn-0057.udp-throughput.v1", "state": "observed", "sent_packets": 300000, "elapsed_seconds": 60.0, "packet_size_bytes": 256, "payload_sha256": "<value from send>", "offered_rate_packets_per_second": 5000, "duration_seconds": 60}
}
```

Replace the placeholders and illustrative sender values with the JSON object
printed by `send`. A zero drop is valid only when both counter endpoints were observed.
`method_identity_sha256` hashes the normalized receiver setup and counter
capture commands, excluding the executable and buffer/worker settings under
test. It prevents a topology or measurement-method change becoming a false
before/after improvement.

The executable digest is the immutable binary identity. The revision digest and
version give human-auditable attribution; before/current executable digests must
differ. `effective_bytes` is a successful `getsockopt(SO_RCVBUF)` read-back on
the bound socket, not a configured request or a clamp warning. Linux reports
the read-back doubled, including after a clamp, so that boolean is true on Linux
and false on FreeBSD.

Linux socket drops must be scoped to the listening receiver socket. A FreeBSD
`system_udp` counter is accepted only where isolation proves the dedicated host
had exclusive UDP traffic for the interval; a system-wide BSD count on a shared
receiver is rejected. The worker counter is exactly the named `queue_full`
Prometheus series.

`receiver_accepted` is an ingress counter incremented immediately after a UDP
datagram enters the worker queue. Do not substitute
`opnsense_exporter_logs_shipped_total`: it measures later OTLP acknowledgement,
not UDP receiver throughput. The exporter exposes that ingress counter and
`opnsense_exporter_syslog_udp_receive_buffer_bytes`, which reports the positive
`getsockopt(SO_RCVBUF)` read-back from the listening UDP socket. The buffer metric
is absent when UDP is disabled or the read-back fails; absence is not zero.
Both observations must still be captured on each deployed receiver for a
measurement to be valid. Their availability alone is not a throughput result.

## Binaries that predate the receiver counters

A `before` binary older than v4.2.0 exposes neither
`opnsense_exporter_syslog_udp_accepted_total` nor the `queue_full` rejection
series. For the `before` phase only, an observation may add a `legacy_metric`
field beside `metric` naming the documented predecessor that counts the same
event one stage later: `opnsense_exporter_logs_shipped_total{source="syslog"}`
for accepted datagrams (every datagram that reached the pipeline is shipped to
the stdout sink) and
`opnsense_exporter_logs_dropped_total{source="syslog",reason="overflow"}` for
receiver-side loss. The verifier rejects `legacy_metric` in the `current`
phase and rejects any other name, and an accepted result carries
`counter_source: legacy` so the substitution is never silent.

## Shared-host FreeBSD receivers

FreeBSD has no per-socket drop counter; `netstat -s -p udp` reports
"dropped due to full socket buffers" for the whole host. On a dedicated host
the observation claims `dedicated-host-and-exclusive-udp-traffic`. On a shared
host, such as an OPNsense VM that also carries its own DNS, NTP and syslog, the
isolation scope is `shared-host-background-udp-observed` and the observation
must record `background_udp_datagrams`: the host-wide "datagrams received"
delta minus the 300,000 offered. The accepted result then carries a
`socket_drop_attribution` caveat naming that background volume; a system-wide
drop delta on a shared host bounds the receiver's loss, it does not attribute it.

Read the effective FreeBSD buffer from `netstat -an -x -p udp` (`R-HIWA`,
`so_rcv.sb_hiwat`) and the Linux one from `ss -ulnpm` (`skmem rb`,
`sk_rcvbuf`, which Linux reports doubled). Both are kernel read-backs of the
socket, not the requested value. Note that v4.2.0 cannot start on a stock
FreeBSD `kern.ipc.maxsockbuf` because the kernel refuses a 4 MiB `SO_RCVBUF`
outright rather than clamping it (OPN-0101); the `current` FreeBSD binary must
carry that fallback.

## Verify both platforms and phases

This performs no network I/O. Retain accepted JSON as measurement evidence, then
record its numbers on OPN-0057 rather than in docs or release notes.

```sh
python3 scripts/testbed/udp_throughput.py verify \
  --linux-before /secure/udp-before-linux.json \
  --linux-current /secure/udp-current-linux.json \
  --freebsd-before /secure/udp-before-freebsd.json \
  --freebsd-current /secure/udp-current-freebsd.json
```

Accepted output carries each phase's effective buffer, socket-drop delta,
worker-queue-drop delta, receiver-accepted delta and receiver packets/sec beside
the fixed sender rate. It also enforces identical receiver role, receiver
instance, and measurement method across each before/current pair.
