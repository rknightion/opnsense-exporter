#!/usr/bin/env python3
"""Fail-closed OPN-0057 UDP throughput contract.

``send`` is the only traffic-producing command.  It has no tunable traffic
arguments. ``verify`` makes no network call; it validates four local JSON
observations and emits a result which is accepted or rejected, never partial.
"""

import argparse
import hashlib
import json
import math
import socket
import sys
import time
from pathlib import Path


SCHEMA_VERSION = "opn-0057.udp-throughput.v1"
PACKET_SIZE_BYTES = 256
OFFERED_RATE_PACKETS_PER_SECOND = 5_000
DURATION_SECONDS = 60
MAX_SEND_OVERRUN_SECONDS = 0.250
QUEUE_DROP_METRIC = 'opnsense_exporter_logs_rejected_total{source="syslog",reason="queue_full"}'
# Deliberately not logs_shipped_total: that counts later OTLP acknowledgement.
RECEIVER_ACCEPTED_METRIC = "opnsense_exporter_syslog_udp_accepted_total"
# A binary that predates OPN-0035/OPN-0036 (v4.1.x and earlier) exposes neither
# series above. Its documented predecessors count the same events one stage
# later: every datagram that reached the pipeline was shipped (stdout sink), and
# the only receiver-side loss point was the pipeline overflow reason. They are
# accepted for the "before" phase only, and the result names the substitution.
RECEIVER_ACCEPTED_LEGACY_METRIC = 'opnsense_exporter_logs_shipped_total{source="syslog"}'
QUEUE_DROP_LEGACY_METRIC = 'opnsense_exporter_logs_dropped_total{source="syslog",reason="overflow"}'
SHARED_HOST_ISOLATION_SCOPE = "shared-host-background-udp-observed"
_PREFIX = b"<134>1 2026-09-04T00:00:00Z udp-throughput opnsense2otel - - - OPN-0057 "
PAYLOAD = _PREFIX + b"x" * (PACKET_SIZE_BYTES - len(_PREFIX))
PAYLOAD_SHA256 = hashlib.sha256(PAYLOAD).hexdigest()


def harness_shape():
    return {"schema_version": SCHEMA_VERSION, "transport": "udp",
            "packet_size_bytes": PACKET_SIZE_BYTES, "payload_sha256": PAYLOAD_SHA256,
            "offered_rate_packets_per_second": OFFERED_RATE_PACKETS_PER_SECOND,
            "duration_seconds": DURATION_SECONDS}


def _sha(value):
    return isinstance(value, str) and len(value) == 64 and all(c in "0123456789abcdef" for c in value.lower())


def _string(value, path, errors):
    if not isinstance(value, str) or not value.strip():
        errors.append(f"{path} must be a non-empty string")
        return None
    return value


def _digest(value, path, errors):
    if not _sha(value):
        errors.append(f"{path} must be a SHA-256 digest")
        return None
    return value.lower()


def _counter(value, path, errors):
    if not isinstance(value, dict) or value.get("state") != "observed":
        errors.append(f"{path} must be an observed counter, not skipped or unobserved")
        return None
    start, end = value.get("start"), value.get("end")
    if any(isinstance(v, bool) or not isinstance(v, int) or v < 0 for v in (start, end)):
        errors.append(f"{path}.start and {path}.end must be non-negative integers")
        return None
    if end < start:
        errors.append(f"{path}.end must not be less than {path}.start")
        return None
    return end - start


def validate_observation(observation, target_os, phase):
    """Return normalized measurements or errors, without fabricating missing zeroes."""
    errors = []
    if not isinstance(observation, dict):
        return None, ["observation must be a JSON object"]
    if observation.get("phase") != phase:
        errors.append(f"phase must be {phase!r}")
    if observation.get("receiver_os") != target_os:
        errors.append(f"receiver_os must be {target_os!r}")
    if observation.get("harness") != harness_shape():
        errors.append("harness does not exactly match the fixed contract")

    receiver = observation.get("receiver") if isinstance(observation.get("receiver"), dict) else {}
    if not receiver:
        errors.append("receiver must be an object")
    role = _string(receiver.get("role"), "receiver.role", errors)
    instance = _digest(receiver.get("instance_identity_sha256"), "receiver.instance_identity_sha256", errors)
    method = _digest(receiver.get("method_identity_sha256"), "receiver.method_identity_sha256", errors)

    binary = observation.get("binary") if isinstance(observation.get("binary"), dict) else {}
    if not binary:
        errors.append("binary must be an object")
    binary_id = _digest(binary.get("sha256"), "binary.sha256", errors)
    _digest(binary.get("source_revision_sha256"), "binary.source_revision_sha256", errors)
    _string(binary.get("version"), "binary.version", errors)

    buffer = observation.get("socket_buffer") if isinstance(observation.get("socket_buffer"), dict) else {}
    if buffer.get("state") != "observed":
        errors.append("socket_buffer must be observed; a request or clamp warning is not read-back")
    else:
        if buffer.get("method") != "getsockopt_so_rcvbuf":
            errors.append("socket_buffer.method must be getsockopt_so_rcvbuf")
        if buffer.get("requested_bytes") != 4 * 1024 * 1024:
            errors.append("socket_buffer.requested_bytes must be 4194304")
        effective = buffer.get("effective_bytes")
        if isinstance(effective, bool) or not isinstance(effective, int) or effective <= 0:
            errors.append("socket_buffer.effective_bytes must be a positive integer")
        if buffer.get("linux_readback_is_doubled") != (target_os == "linux"):
            errors.append("socket_buffer.linux_readback_is_doubled does not match receiver_os")
        _digest(buffer.get("evidence_sha256"), "socket_buffer.evidence_sha256", errors)

    isolation = observation.get("isolation") if isinstance(observation.get("isolation"), dict) else {}
    background_udp = None
    if isolation.get("state") != "observed":
        errors.append("isolation must be observed")
    else:
        if isolation.get("receiver_role") != role:
            errors.append("isolation.receiver_role must equal receiver.role")
        _string(isolation.get("statement"), "isolation.statement", errors)
        _digest(isolation.get("evidence_sha256"), "isolation.evidence_sha256", errors)
        if isolation.get("scope") == SHARED_HOST_ISOLATION_SCOPE:
            # A shared host cannot prove exclusive UDP traffic; the contract instead
            # requires the background volume to be measured and carried as a caveat.
            background_udp = isolation.get("background_udp_datagrams")
            if isinstance(background_udp, bool) or not isinstance(background_udp, int):
                errors.append("shared-host isolation must record isolation.background_udp_datagrams as an integer")

    socket_drop = observation.get("socket_drop")
    socket_delta = _counter(socket_drop, "socket_drop", errors)
    if isinstance(socket_drop, dict):
        scope = socket_drop.get("scope")
        if target_os == "linux" and scope != "receiver_socket":
            errors.append("Linux socket_drop.scope must be receiver_socket")
        if target_os == "freebsd" and scope not in {"receiver_socket", "system_udp"}:
            errors.append("FreeBSD socket_drop.scope must be receiver_socket or system_udp")
        if scope == "system_udp" and isolation.get("scope") not in {"dedicated-host-and-exclusive-udp-traffic", SHARED_HOST_ISOLATION_SCOPE}:
            errors.append("a system_udp counter requires dedicated-host-and-exclusive-udp-traffic isolation")
        _string(socket_drop.get("method"), "socket_drop.method", errors)
        _digest(socket_drop.get("evidence_sha256"), "socket_drop.evidence_sha256", errors)

    counter_source = "current"

    def legacy_counter(section, path, expected, description):
        nonlocal counter_source
        if "legacy_metric" not in section:
            return
        if phase != "before":
            errors.append(f"{path}.legacy_metric is only valid for the before phase")
        elif section.get("legacy_metric") != expected:
            errors.append(f"{path}.legacy_metric must name the documented {description}")
        else:
            counter_source = "legacy"

    queue_drop = observation.get("worker_queue_drop")
    queue_delta = _counter(queue_drop, "worker_queue_drop", errors)
    if isinstance(queue_drop, dict):
        if queue_drop.get("metric") != QUEUE_DROP_METRIC:
            errors.append("worker_queue_drop.metric must identify syslog queue_full")
        legacy_counter(queue_drop, "worker_queue_drop", QUEUE_DROP_LEGACY_METRIC, "pre-worker-pool counter")
        _digest(queue_drop.get("evidence_sha256"), "worker_queue_drop.evidence_sha256", errors)

    accepted = observation.get("receiver_accepted")
    accepted_delta = _counter(accepted, "receiver_accepted", errors)
    if isinstance(accepted, dict):
        if accepted.get("metric") != RECEIVER_ACCEPTED_METRIC:
            errors.append("receiver_accepted.metric must be the receiver ingress counter")
        legacy_counter(accepted, "receiver_accepted", RECEIVER_ACCEPTED_LEGACY_METRIC, "pre-worker-pool counter")
        _digest(accepted.get("evidence_sha256"), "receiver_accepted.evidence_sha256", errors)

    sender = observation.get("sender") if isinstance(observation.get("sender"), dict) else {}
    if sender.get("state") != "observed":
        errors.append("sender must be an observed result from the fixed send command")
    else:
        if sender.get("schema_version") != SCHEMA_VERSION:
            errors.append("sender.schema_version does not match the fixed harness")
        if sender.get("sent_packets") != OFFERED_RATE_PACKETS_PER_SECOND * DURATION_SECONDS:
            errors.append("sender.sent_packets does not match the fixed offered load")
        if sender.get("packet_size_bytes") != PACKET_SIZE_BYTES:
            errors.append("sender.packet_size_bytes does not match the fixed packet size")
        if sender.get("duration_seconds") != DURATION_SECONDS:
            errors.append("sender.duration_seconds does not match the fixed duration")
        elapsed = sender.get("elapsed_seconds")
        if not isinstance(elapsed, (int, float)) or isinstance(elapsed, bool):
            errors.append("sender.elapsed_seconds must be numeric")
        elif not math.isfinite(elapsed):
            errors.append("sender.elapsed_seconds must be finite")
        elif abs(elapsed - DURATION_SECONDS) > MAX_SEND_OVERRUN_SECONDS:
            errors.append("sender.elapsed_seconds does not conform to the fixed duration")
        if sender.get("payload_sha256") != PAYLOAD_SHA256:
            errors.append("sender.payload_sha256 does not match the fixed payload")
        if sender.get("offered_rate_packets_per_second") != OFFERED_RATE_PACKETS_PER_SECOND:
            errors.append("sender.offered_rate_packets_per_second does not match the fixed rate")

    if errors:
        return None, errors
    attribution = "per-socket"
    if socket_drop["scope"] == "system_udp":
        attribution = ("system-wide on a shared host; background UDP datagrams " + str(background_udp)
                       if background_udp is not None else "system-wide with exclusive UDP traffic")
    return {"receiver_role": role, "receiver_instance_identity_sha256": instance,
            "receiver_method_identity_sha256": method, "binary_sha256": binary_id,
            "effective_socket_buffer_bytes": buffer["effective_bytes"],
            "socket_drop_scope": socket_drop["scope"], "socket_drop_attribution": attribution,
            "counter_source": counter_source,
            "socket_drop_delta": socket_delta, "worker_queue_drop_delta": queue_delta,
            "receiver_accepted_delta": accepted_delta,
            "receiver_accepted_packets_per_second": accepted_delta / DURATION_SECONDS,
            "sent_packets": sender["sent_packets"],
            "sent_packets_per_second": OFFERED_RATE_PACKETS_PER_SECOND}, []


def verify(paths):
    normalized, violations = {}, []
    for target_os in ("linux", "freebsd"):
        for phase in ("before", "current"):
            key = f"{target_os}_{phase}"
            try:
                with Path(paths[key]).open(encoding="utf-8") as file:
                    raw = json.load(file)
            except (OSError, json.JSONDecodeError) as exc:
                violations.append({"observation": key, "error": f"cannot load JSON: {exc}"})
                continue
            value, errors = validate_observation(raw, target_os, phase)
            violations.extend({"observation": key, "error": error} for error in errors)
            if value:
                normalized[key] = value
    if not violations:
        for target_os in ("linux", "freebsd"):
            before, current = normalized[f"{target_os}_before"], normalized[f"{target_os}_current"]
            for key, message in (("receiver_role", "receiver roles differ"),
                                 ("receiver_instance_identity_sha256", "receiver instances differ"),
                                 ("receiver_method_identity_sha256", "receiver methods differ"),
                                 ("socket_drop_scope", "socket-drop scopes differ")):
                if before[key] != current[key]:
                    violations.append({"observation": target_os, "error": f"before/current {message}"})
            if before["binary_sha256"] == current["binary_sha256"]:
                violations.append({"observation": target_os, "error": "before/current binary identities must differ"})
    if violations:
        return 2, {"schema_version": SCHEMA_VERSION, "status": "rejected", "comparison": None, "violations": violations}
    return 0, {"schema_version": SCHEMA_VERSION, "status": "accepted",
               "comparison": {"method": harness_shape(),
                              "linux": {"before": normalized["linux_before"], "current": normalized["linux_current"]},
                              "freebsd": {"before": normalized["freebsd_before"], "current": normalized["freebsd_current"]}},
               "violations": []}


def send(target, port):
    count, interval, sent = OFFERED_RATE_PACKETS_PER_SECOND * DURATION_SECONDS, 1 / OFFERED_RATE_PACKETS_PER_SECOND, 0
    start = time.monotonic()
    send_error = None
    try:
        address = socket.getaddrinfo(target, port, type=socket.SOCK_DGRAM)[0]
        with socket.socket(address[0], socket.SOCK_DGRAM) as conn:
            for sequence in range(count):
                delay = start + sequence * interval - time.monotonic()
                if delay > 0:
                    time.sleep(delay)
                conn.sendto(PAYLOAD, address[4])
                sent += 1
    except OSError as exc:
        # Preserve a machine-readable failed observation without echoing the
        # supplied target or the platform's potentially target-bearing message.
        send_error = {"type": type(exc).__name__, "errno": exc.errno}
    elapsed = time.monotonic() - start
    conforming = send_error is None and sent == count and abs(elapsed - DURATION_SECONDS) <= MAX_SEND_OVERRUN_SECONDS
    result = {"schema_version": SCHEMA_VERSION,
        "state": "observed" if conforming else "nonconforming", "sent_packets": sent,
        "elapsed_seconds": elapsed, "packet_size_bytes": PACKET_SIZE_BYTES,
        "payload_sha256": PAYLOAD_SHA256, "offered_rate_packets_per_second": OFFERED_RATE_PACKETS_PER_SECOND,
        "duration_seconds": DURATION_SECONDS}
    if send_error is not None:
        result["send_error"] = send_error
    return (0 if conforming else 2), result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("shape", help="print immutable traffic shape without sending")
    sender = commands.add_parser("send", help="send the fixed UDP stream")
    sender.add_argument("--target", required=True)
    sender.add_argument("--port", required=True, type=int)
    verifier = commands.add_parser("verify", help="validate all four observations")
    for target_os in ("linux", "freebsd"):
        for phase in ("before", "current"):
            verifier.add_argument(f"--{target_os}-{phase}", required=True, dest=f"{target_os}_{phase}")
    args = parser.parse_args(argv)
    if args.command == "shape":
        print(json.dumps(harness_shape(), sort_keys=True))
        return 0
    if args.command == "send":
        if not 1 <= args.port <= 65535:
            parser.error("--port must be between 1 and 65535")
        code, result = send(args.target, args.port)
    else:
        code, result = verify({key: getattr(args, key) for key in ("linux_before", "linux_current", "freebsd_before", "freebsd_current")})
    print(json.dumps(result, sort_keys=True))
    return code


if __name__ == "__main__":
    sys.exit(main())
