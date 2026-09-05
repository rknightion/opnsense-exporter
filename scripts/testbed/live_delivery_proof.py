#!/usr/bin/env python3
"""Run the bounded, read-only live-delivery proof from CI."""

import argparse
import base64
import binascii
import hashlib
import json
import math
import os
import re
import secrets
import select
import signal
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

OTLP_ENDPOINT = "https://otlp-gateway-prod-gb-south-1.grafana.net/otlp"
LOKI_ENDPOINT = "https://logs-prod-035.grafana.net"
SENSITIVE_DIAGNOSTIC = re.compile(
    r"(?:password|passphrase|secret|private.?key|privkey|shared.?key|token|api.?key|auth.?key|credential|"
    r"(?:basic|bearer)\s+\S+|\b[a-z][a-z0-9+.-]*://\S+)", re.I)
SAFE_REVISION_ID = re.compile(r"config-[0-9]+(?:\.[0-9]+)?\.xml\Z")
PROOF_SOURCES = ("configchange", "configstate")
REQUIRED_CONFIGSTATE_FAMILIES = {"firewall", "device_inventory", "security_posture"}
STDERR_LINE_LIMIT_BYTES = 64 * 1024
STATE_FILE_LIMIT_BYTES = 1024 * 1024
STDERR_DRAIN_TIMEOUT_SECONDS = 2

# These are the source-owned messages emitted by the current pipeline. The
# monitor deliberately matches the complete message and retains only counters;
# arbitrary JSON fields (including err, path and source values) never leave the
# reader thread. Keep the values in sync with internal/logship/pipeline.go.
STDERR_MESSAGES = {
    "state_file_unreadable": "could not read log state file; resuming from now",
    "state_file_corrupt": "log state file is corrupt; resuming from now",
    "state_entry_corrupt": "log state entry is corrupt; resuming from now",
    "configchange_rebaseline": "config-change log source cursor is no longer in backup history; re-baselining without replay",
    "endpoint_terminal_rejection": "log endpoint terminally rejected records; they are lost and will NOT be retried (a permanent protocol response, or an OTLP partial-success rejection)",
    "max_retries": "log sink refused a batch for the maximum number of attempts; dropping it so delivery of later batches continues; records lost",
    "ingest_oversize": "log record exceeds the per-record size cap; rejected at ingest",
    "source_poll_error": "log source poll error",
}
HISTORICAL_REJECTION_SUBSTRINGS = (
    "greater_than_max_sample_age",
    "too old",
    "too far behind",
    "out of order",
)
STDERR_DIAGNOSTIC_KEYS = (
    "stderr_state_file_unreadable_count",
    "stderr_state_file_corrupt_count",
    "stderr_state_entry_corrupt_count",
    "stderr_configchange_rebaseline_count",
    "stderr_endpoint_terminal_rejection_count",
    "stderr_endpoint_historical_rejection_count",
    "stderr_max_retries_count",
    "stderr_ingest_oversize_count",
    "stderr_configchange_poll_error_count",
    "stderr_oversized_line_count",
    "stderr_reader_incomplete_count",
)
_OVERSIZED_LINE = object()


class ProofFailure(RuntimeError):
    """A bounded failure whose code is safe to render without response data."""
    def __init__(self, code, message):
        super().__init__(message)
        self.code = code


def _read_bounded_line(stream, limit=STDERR_LINE_LIMIT_BYTES):
    """Read one bounded line, draining but never retaining an oversized line."""
    try:
        line = stream.readline(limit + 1)
    except (OSError, ValueError):
        return None
    if not line:
        return None

    if isinstance(line, bytes):
        newline = b"\n"
        byte_length = len(line)
    elif isinstance(line, str):
        newline = "\n"
        byte_length = len(line.encode("utf-8", errors="replace"))
    else:
        return None

    if byte_length <= limit:
        return line

    # readline(limit + 1) consumed at most the first bounded fragment. Drain
    # through the delimiter so the next valid JSON line remains aligned, while
    # retaining no part of this line.
    if newline not in line:
        while True:
            try:
                fragment = stream.readline(limit + 1)
            except (OSError, ValueError):
                break
            if not fragment or not isinstance(fragment, type(line)) or newline in fragment:
                break
    return _OVERSIZED_LINE


def classify_stderr_line(line):
    """Return fixed diagnostic names recognized from one JSON log line.

    This parser intentionally has no fallback text matching. In particular, a
    terminal rejection with an unrecognized error remains only a terminal
    rejection; it does not become a guessed historical rejection.
    """
    if isinstance(line, bytes):
        try:
            line = line.decode("utf-8")
        except UnicodeDecodeError:
            return ()
    if not isinstance(line, str):
        return ()
    try:
        record = json.loads(line)
    except (json.JSONDecodeError, UnicodeDecodeError):
        return ()
    if not isinstance(record, dict):
        return ()

    message = record.get("msg")
    if not isinstance(message, str):
        return ()
    events = []
    for name in (
            "state_file_unreadable", "state_file_corrupt", "state_entry_corrupt",
            "configchange_rebaseline", "max_retries", "ingest_oversize"):
        if message == STDERR_MESSAGES[name]:
            events.append(name)

    if message == STDERR_MESSAGES["source_poll_error"] and record.get("source") == "configchange":
        events.append("configchange_poll_error")

    if message == STDERR_MESSAGES["endpoint_terminal_rejection"]:
        events.append("endpoint_terminal_rejection")
        error = record.get("err")
        if isinstance(error, str):
            folded = error.casefold()
            if any(marker in folded for marker in HISTORICAL_REJECTION_SUBSTRINGS):
                events.append("endpoint_historical_rejection")
    return tuple(events)


class StderrDiagnostics:
    """Thread-safe fixed counters for source-owned exporter diagnostics."""
    def __init__(self):
        self._counts = {key: 0 for key in STDERR_DIAGNOSTIC_KEYS}
        self._lock = threading.Lock()

    def increment(self, event):
        key = "stderr_" + event + "_count"
        if key not in self._counts:
            return
        with self._lock:
            self._counts[key] += 1

    def oversized_line(self):
        self.increment("oversized_line")

    def snapshot(self):
        with self._lock:
            return dict(self._counts)


class StderrMonitor:
    """Consume a child stderr pipe concurrently without retaining its contents."""
    def __init__(self, stream):
        self.stream = stream
        self.diagnostics = StderrDiagnostics()
        self._thread = None
        self._closed = False
        self._stop = threading.Event()
        self._fd = self._stream_fd()

    def _stream_fd(self):
        if self.stream is None or not hasattr(self.stream, "fileno"):
            return None
        try:
            fd = self.stream.fileno()
            if not isinstance(fd, int) or fd < 0:
                return None
            os.set_blocking(fd, False)
            return fd
        except (OSError, ValueError, TypeError, AttributeError):
            return None

    def start(self):
        if self.stream is None or not hasattr(self.stream, "readline"):
            return
        self._thread = threading.Thread(target=self._consume, name="live-proof-stderr", daemon=True)
        self._thread.start()

    def _consume(self):
        if self._fd is not None:
            self._consume_fd()
            return
        self._consume_lines()

    def _consume_lines(self):
        while True:
            line = _read_bounded_line(self.stream)
            if line is None:
                return
            if line is _OVERSIZED_LINE:
                self.diagnostics.oversized_line()
                continue
            for event in classify_stderr_line(line):
                self.diagnostics.increment(event)

    def _consume_fd(self):
        pending = bytearray()
        oversized = False
        while not self._stop.is_set():
            try:
                readable, _, _ = select.select([self._fd], [], [], 0.25)
            except (OSError, ValueError):
                break
            if not readable:
                continue
            try:
                chunk = os.read(self._fd, 64 * 1024)
            except BlockingIOError:
                continue
            except (OSError, ValueError):
                break
            if not chunk:
                break

            while chunk:
                delimiter = chunk.find(b"\n")
                if delimiter < 0:
                    if not oversized:
                        pending.extend(chunk)
                        if len(pending) > STDERR_LINE_LIMIT_BYTES:
                            pending.clear()
                            oversized = True
                    break
                fragment, chunk = chunk[:delimiter + 1], chunk[delimiter + 1:]
                if oversized or len(pending) + len(fragment) > STDERR_LINE_LIMIT_BYTES:
                    self.diagnostics.oversized_line()
                else:
                    pending.extend(fragment)
                    for event in classify_stderr_line(bytes(pending)):
                        self.diagnostics.increment(event)
                pending.clear()
                oversized = False

        if oversized:
            self.diagnostics.oversized_line()
        elif pending:
            for event in classify_stderr_line(bytes(pending)):
                self.diagnostics.increment(event)

    def _close_stream(self):
        if self._closed or self.stream is None:
            return
        self._closed = True
        try:
            self.stream.close()
        except (OSError, ValueError):
            pass

    def finish(self):
        """Drain after process shutdown, then close a pipe that has no writer."""
        if self._thread is None:
            self._close_stream()
            return self.diagnostics.snapshot()

        # A normal child exit closes the pipe and lets the reader consume the
        # final buffered line. If a descendant inherited the descriptor, signal
        # the nonblocking reader after the bounded drain so cleanup cannot
        # deadlock the proof.
        self._thread.join(timeout=STDERR_DRAIN_TIMEOUT_SECONDS)
        if self._thread.is_alive():
            self._stop.set()
            self._thread.join(timeout=STDERR_DRAIN_TIMEOUT_SECONDS)
        if self._thread.is_alive():
            self.diagnostics.increment("reader_incomplete")
        else:
            self._close_stream()
        return self.diagnostics.snapshot()


def state_cursor_advanced(path, expected_revision):
    """Compare the final configchange cursor in memory without rendering it."""
    if not isinstance(expected_revision, str) or not expected_revision:
        return False
    try:
        with open(path, "rb") as state_file:
            encoded_state = state_file.read(STATE_FILE_LIMIT_BYTES + 1)
        if len(encoded_state) > STATE_FILE_LIMIT_BYTES:
            return False
        envelope = json.loads(encoded_state)
        if not isinstance(envelope, dict):
            return False
        encoded_cursor = envelope.get("configchange")
        if not isinstance(encoded_cursor, str):
            return False
        cursor_data = base64.b64decode(encoded_cursor, validate=True)
        cursor = json.loads(cursor_data)
        if not isinstance(cursor, dict):
            return False
        revision = cursor.get("last_revision")
        if not isinstance(revision, str) or not revision or len(revision) > 512:
            return False
        return revision == expected_revision
    except (OSError, ValueError, TypeError, binascii.Error, json.JSONDecodeError, UnicodeDecodeError):
        return False


class RetainedRevision:
    def __init__(self, revision_id, timestamp):
        self.id = revision_id
        self.timestamp = timestamp


def required(name):
    value = os.environ.get(name, "")
    if not value:
        raise RuntimeError("required CI secret is unavailable: " + name)
    return value


def basic(user, token):
    return "Basic " + base64.b64encode((user + ":" + token).encode()).decode()


class API:
    def __init__(self, host, key, secret_value):
        self.base = "https://" + host.rstrip("/")
        self.auth = basic(key, secret_value)
        self.tls = ssl.create_default_context()
        self.tls.check_hostname = False
        self.tls.verify_mode = ssl.CERT_NONE

    def get(self, path):
        request = urllib.request.Request(self.base + path, headers={"Authorization": self.auth})
        try:
            with urllib.request.urlopen(request, timeout=20, context=self.tls) as response:
                if response.status // 100 != 2:
                    raise ProofFailure("testbed_api_non_2xx", "testbed API returned non-2xx")
                return json.load(response)
        except urllib.error.HTTPError as err:
            raise ProofFailure("testbed_api_http_status_" + str(err.code), "testbed API request failed") from err
        except urllib.error.URLError as err:
            raise ProofFailure("testbed_api_unreachable", "testbed API request failed") from err
        except (json.JSONDecodeError, UnicodeDecodeError) as err:
            raise ProofFailure("testbed_api_response_not_json", "testbed API request failed") from err


def retained_revisions(api):
    """Read and order revisions exactly as ConfigChangeSource does in Go."""
    payload = api.get("/api/core/backup/backups/this")
    items = payload.get("items") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        raise ProofFailure("retained_revisions_invalid", "configuration revision list was not available")
    revisions, ids = [], set()
    for item in items:
        revision_id = item.get("id") if isinstance(item, dict) else None
        raw_time = item.get("time") if isinstance(item, dict) else None
        if (not isinstance(revision_id, str) or not revision_id or len(revision_id) > 512 or
                any(ord(char) < 32 for char in revision_id) or revision_id in ids):
            raise ProofFailure("retained_revisions_invalid", "configuration revision list was not available")
        try:
            timestamp = float(raw_time)
        except (TypeError, ValueError):
            raise ProofFailure("retained_revisions_invalid", "configuration revision list was not available") from None
        if not math.isfinite(timestamp) or timestamp <= 0:
            raise ProofFailure("retained_revisions_invalid", "configuration revision list was not available")
        ids.add(revision_id)
        revisions.append(RetainedRevision(revision_id, timestamp))
    revisions.sort(key=lambda revision: (revision.timestamp, revision.id))
    return revisions


def seed_revision_state(revision):
    """Write the pipeline envelope whose configchange entry is its source blob."""
    inner = json.dumps({"last_revision": revision.id}, separators=(",", ":")).encode()
    encoded = base64.b64encode(inner).decode()
    descriptor, path = tempfile.mkstemp(prefix="opnsense2otel-delivery-state-", suffix=".json")
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as state_file:
            json.dump({"configchange": encoded}, state_file, separators=(",", ":"))
    except Exception:
        os.unlink(path)
        raise
    return path


def revision_report_value(revision, rank):
    if SAFE_REVISION_ID.fullmatch(revision.id):
        return revision.id
    return "nonreportable-rank-" + str(rank) + "-sha256-" + hashlib.sha256(revision.id.encode()).hexdigest()[:12]


def query_start_ns(successor, startup_time_ns):
    """Cover the successor event and anything emitted since this proof started."""
    successor_start_ns = int((successor.timestamp - 60) * 1_000_000_000)
    startup_start_ns = startup_time_ns - 60_000_000_000
    return min(successor_start_ns, startup_start_ns)


def loki_query(query, user, token, start_ns, end_ns, attempts=12):
    succeeded = False
    actual_end_ns = end_ns
    # Leave room for every query and the final summary within the workflow's
    # deadline even when both connection timeouts and backoff are exhausted.
    deadline = time.monotonic() + 120
    for attempt in range(attempts):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        actual_end_ns = max(end_ns, time.time_ns())
        params = urllib.parse.urlencode({"query": query, "limit": "1000", "direction": "FORWARD",
                                         "start": str(start_ns), "end": str(actual_end_ns)})
        request = urllib.request.Request(
            LOKI_ENDPOINT + "/loki/api/v1/query_range?" + params,
            headers={"Authorization": basic(user, token),
                     "X-Loki-Response-Encoding-Flags": "categorize-labels"})
        try:
            with urllib.request.urlopen(request, timeout=min(20, remaining)) as response:
                payload = json.load(response)
            succeeded = payload.get("status") == "success"
            result = payload.get("data", {}).get("result", [])
            if result:
                return {"streams": result, "succeeded": succeeded,
                        "start_ns": start_ns, "end_ns": actual_end_ns}
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError):
            succeeded = False
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        if attempt + 1 < attempts:
            time.sleep(min(10, remaining))
    return {"streams": [], "succeeded": succeeded,
            "start_ns": start_ns, "end_ns": actual_end_ns}


def records(streams):
    """Yield labels, body and categorized structured metadata without output."""
    for stream in streams:
        labels = stream.get("stream", {})
        for value in stream.get("values", []):
            if len(value) < 2:
                continue
            categories = value[2] if len(value) > 2 and isinstance(value[2], dict) else {}
            metadata = categories.get("structuredMetadata") or {}
            yield labels, value[1], metadata if isinstance(metadata, dict) else {}


def safe_diagnostic(value):
    if not isinstance(value, str) or not value.strip():
        return "missing"
    value = " ".join(value.split())
    return "redacted" if len(value) > 240 or SENSITIVE_DIAGNOSTIC.search(value) else value


def exporter_poll_error_diagnostic(rows, source):
    for labels, body, metadata in rows:
        if (labels.get("opnsense_source") == "exporter" and body == "log source poll error" and
                metadata.get("source") == source):
            return safe_diagnostic(metadata.get("err"))
    return "not_observed"


def query_diagnostic(source, specific, broad=None):
    """Classify an empty source query using one same-window broad query."""
    if specific["streams"]:
        return "arrived"
    if broad is None:
        return "query_failed" if not specific["succeeded"] else "instance_absent_in_explicit_window"
    if not specific["succeeded"] or not broad["succeeded"]:
        return "query_failed"
    for stream in broad["streams"]:
        labels = stream.get("stream", {}) if isinstance(stream, dict) else {}
        if isinstance(labels, dict) and labels.get("opnsense_source") == source:
            return "arrived_with_unexpected_labels"
        for _, _, metadata in records([stream]):
            if metadata.get("opnsense_source") == source:
                return "arrived_with_unexpected_labels"
    if broad["streams"]:
        return "source_absent_in_instance_window"
    return "instance_absent_in_explicit_window"


def configstate_families(rows):
    return {
        family for _, _, metadata in rows
        for family in [metadata.get("snapshot_family")]
        if isinstance(family, str) and family
    }


def configstate_family_summary(rows):
    observed = configstate_families(rows)
    expected = observed & REQUIRED_CONFIGSTATE_FAMILIES
    return {
        "families": "none" if not expected else ",".join(sorted(expected)),
        "unexpected_count": len(observed - REQUIRED_CONFIGSTATE_FAMILIES),
    }


def redaction_assertion_passes(redaction, configchange_arrived, observed_families):
    if not isinstance(redaction, dict) or not configchange_arrived:
        return False
    if not REQUIRED_CONFIGSTATE_FAMILIES.issubset(observed_families):
        return False
    return (redaction.get("configchange_bodies_redacted") is True and
            redaction.get("configstate_bodies_redacted") is True)


def verify_redaction(verifier, configchange, configstate):
    request = json.dumps({"configchange": [body for _, body, _ in configchange],
                          "configstate": [body for _, body, _ in configstate]}).encode()
    try:
        completed = subprocess.run([verifier], input=request, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                   timeout=30, check=False)
        parsed = json.loads(completed.stdout)
    except (OSError, subprocess.TimeoutExpired, json.JSONDecodeError):
        return None
    keys = {"configchange_bodies", "configchange_sensitive_elements", "configchange_bodies_redacted",
            "configstate_bodies", "configstate_sensitive_keys", "configstate_bodies_redacted"}
    integer_keys = {"configchange_bodies", "configchange_sensitive_elements",
                    "configstate_bodies", "configstate_sensitive_keys"}
    boolean_keys = {"configchange_bodies_redacted", "configstate_bodies_redacted"}
    if completed.returncode != 0 or not isinstance(parsed, dict) or set(parsed) != keys:
        return None
    if any(isinstance(parsed[key], bool) or not isinstance(parsed[key], int) for key in integer_keys):
        return None
    if any(not isinstance(parsed[key], bool) for key in boolean_keys):
        return None
    return parsed


def stop_process_group(process):
    if process.poll() is not None:
        process.wait()
        return
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        process.wait()
        return
    try:
        process.wait(timeout=20)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.wait()


def main(argv=None):
    parser = argparse.ArgumentParser()
    parser.add_argument("--exporter", required=True)
    parser.add_argument("--redaction-verifier", required=True)
    args = parser.parse_args(argv)
    startup_time_ns = time.time_ns()
    host, key, secret_value = required("DEVBOX_HOST"), required("DEVBOX_API_KEY"), required("DEVBOX_API_SECRET")
    otlp_user, loki_user, cap_token = required("GRAFANA_OTLP_USER"), required("GRAFANA_LOKI_USER"), required("GRAFANA_CAP_TOKEN")
    instance = "delivery-proof-" + os.environ.get("GITHUB_RUN_ID", secrets.token_hex(6))
    api, process, state_path, stderr_monitor = API(host, key, secret_value), None, None, None
    facts, diagnostics, stage = {"cursor_advanced": False}, {}, "initializing"
    query_window_start_ns = query_window_end_ns = None
    query_reports = []
    successor = None
    selector = 'service_name="opnsense2otel",service_instance_id="' + instance + '"'
    try:
        stage = "reading_retained_revisions"
        revisions = retained_revisions(api)
        if len(revisions) < 2:
            raise ProofFailure("retained_revisions_insufficient", "configuration revision list has no predecessor")
        cursor_index = len(revisions) - 2
        cursor, successor = revisions[cursor_index], revisions[cursor_index + 1]
        facts["retained_revision_count"] = len(revisions)
        facts["expected_configchange_diffs"] = len(revisions) - cursor_index - 1
        diagnostics["seeded revision"] = revision_report_value(cursor, cursor_index + 1)
        query_window_start_ns = query_start_ns(successor, startup_time_ns)
        stage = "seeding_configchange_cursor"
        state_path = seed_revision_state(cursor)
        env = os.environ | {"OPN2OTEL_OPS_API": host, "OPN2OTEL_OPS_API_KEY": key,
                            "OPN2OTEL_OPS_API_SECRET": secret_value, "OPN2OTEL_OPS_PROTOCOL": "https",
                            "OPN2OTEL_OPS_INSECURE": "true", "OPN2OTEL_INSTANCE_LABEL": instance,
                            "OPN2OTEL_OTLP_GRAFANA_CLOUD_INSTANCE_ID": otlp_user,
                            "OPN2OTEL_OTLP_GRAFANA_CLOUD_TOKEN": cap_token,
                            "OPN2OTEL_OTLP_GRAFANA_CLOUD_ENDPOINT": OTLP_ENDPOINT}
        command = [args.exporter, "--log.format=json", "--logs.enabled", "--logs.sink=otlp", "--logs.poll-interval=5s",
                   "--logs.state-file=" + state_path, "--logs.configchange.enabled",
                   "--logs.config-snapshot.firewall.enabled", "--logs.config-snapshot.devices.enabled",
                   "--logs.config-snapshot.security-posture.enabled", "--logs.self.enabled"]
        stage = "starting_exporter"
        process = subprocess.Popen(command, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
                                   start_new_session=True)
        stderr_monitor = StderrMonitor(process.stderr)
        stderr_monitor.start()
        stage = "waiting_for_delivery"
        time.sleep(20)
        query_window_end_ns = time.time_ns()
        stage = "querying_configchange_and_configstate"
        queries = {}
        for name in PROOF_SOURCES:
            query = '{' + selector + ',opnsense_source="' + name + '"}'
            result = loki_query(query, loki_user, cap_token, query_window_start_ns, query_window_end_ns)
            queries[name] = result
            query_reports.append((name, query, result))
        facts.update({name + "_arrived": bool(result["streams"]) for name, result in queries.items()})
        missing_sources = [name for name in PROOF_SOURCES if not queries[name]["streams"]]
        if missing_sources:
            broad_query_text = "{" + selector + "}"
            broad_query = loki_query(broad_query_text, loki_user, cap_token,
                                     query_window_start_ns, query_window_end_ns)
            query_reports.append(("source disambiguation", broad_query_text, broad_query))
            diagnostics.update({name: query_diagnostic(name, queries[name], broad_query)
                                for name in missing_sources})
        diagnostics.update({name: "arrived" for name in PROOF_SOURCES if name not in missing_sources})
        configchange, configstate = list(records(queries["configchange"]["streams"])), list(records(queries["configstate"]["streams"]))
        facts["configchange_delivered_diffs"] = len(configchange)
        families = configstate_families(configstate)
        facts["configstate_families_arrived"] = REQUIRED_CONFIGSTATE_FAMILIES.issubset(families)
        family_summary = configstate_family_summary(configstate)
        diagnostics["configstate families"] = family_summary["families"]
        facts["configstate_unexpected_family_count"] = family_summary["unexpected_count"]
        if not facts["configstate_families_arrived"]:
            stage = "querying_configstate_poll_error"
            exporter_query_text = '{' + selector + ',opnsense_source="exporter"}'
            exporter_query = loki_query(exporter_query_text, loki_user, cap_token,
                                        query_window_start_ns, query_window_end_ns)
            query_reports.append(("exporter diagnostic", exporter_query_text, exporter_query))
            diagnostics["configstate shipped poll error"] = exporter_poll_error_diagnostic(records(exporter_query["streams"]), "configstate")
        stage = "verifying_delivered_redaction"
        redaction = verify_redaction(args.redaction_verifier, configchange, configstate)
        if redaction is None:
            diagnostics["redaction verifier"] = "unavailable_or_invalid"
            facts["delivered_bodies_redacted"] = False
        else:
            facts["configchange_sensitive_elements"] = redaction["configchange_sensitive_elements"]
            facts["configstate_sensitive_keys"] = redaction["configstate_sensitive_keys"]
            facts["delivered_bodies_redacted"] = redaction_assertion_passes(
                redaction, facts["configchange_arrived"], families)
        facts["proof_completed"] = True
        stage = "complete"
    except ProofFailure as err:
        diagnostics["proof failure"] = err.code
        facts["proof_completed"] = False
    except Exception:
        facts["proof_completed"] = False
    finally:
        try:
            if process:
                stop_process_group(process)
        finally:
            if stderr_monitor is not None:
                facts.update(stderr_monitor.finish())
            if state_path is not None:
                if successor is not None:
                    facts["cursor_advanced"] = state_cursor_advanced(state_path, successor.id)
                try:
                    os.unlink(state_path)
                except FileNotFoundError:
                    pass
    print("## Live delivery proof")
    print("- instance label: `" + instance + "`")
    print("- proof stage: " + stage)
    for name, query, result in query_reports:
        start = result.get("start_ns", query_window_start_ns)
        end = result.get("end_ns", query_window_end_ns)
        print("- query " + name + ": " + query + " start=" + str(start) + " end=" + str(end))
    for name in sorted(facts):
        value = facts[name]
        print("- " + name.replace("_", " ") + ": " + (("yes" if value else "no") if isinstance(value, bool) else str(value)))
    for name in sorted(diagnostics):
        print("- " + name + " query result: " + diagnostics[name])
    return 0 if all(facts.get(name) for name in ("configchange_arrived", "configstate_families_arrived", "delivered_bodies_redacted")) else 1


if __name__ == "__main__":
    sys.exit(main())
