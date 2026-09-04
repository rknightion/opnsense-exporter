#!/usr/bin/env python3
"""Run the bounded, secret-safe live-delivery proof from CI.

The workflow owns credentials.  This program never prints an HTTP body, a
credential, a generated password hash, or a Loki line: its only output is a
yes/no summary suitable for a GitHub step summary.
"""

import argparse
import base64
import json
import os
import re
import secrets
import signal
import socket
import ssl
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

OTLP_ENDPOINT = "https://otlp-gateway-prod-gb-south-1.grafana.net/otlp"
LOKI_ENDPOINT = "https://logs-prod-035.grafana.net"
SENSITIVE_KEY = re.compile(r"password|passphrase|secret|private.?key|privkey|shared.?key|token|api.?key|auth.?key|credential|^(prv|psk|pass)$", re.I)
SENSITIVE_DIAGNOSTIC = re.compile(
    r"(?:password|passphrase|secret|private.?key|privkey|shared.?key|token|api.?key|auth.?key|credential|"
    r"(?:basic|bearer)\s+\S+|\b[a-z][a-z0-9+.-]*://\S+)",
    re.I,
)
PROOF_ALIAS_NAME = "deliveryproof"
PROOF_SOURCES = ("configchange", "configstate", "exporter", "syslog", "zenarmor")


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
        # The lab firewall uses the same private certificate contract as the
        # canonical live-canary workflow, which runs over an authenticated
        # tailnet path with certificate verification disabled. This is testbed
        # only; neither the production firewall nor a public route is in scope.
        self.tls = ssl.create_default_context()
        self.tls.check_hostname = False
        self.tls.verify_mode = ssl.CERT_NONE

    def request(self, method, path, payload=None):
        data = json.dumps(payload).encode() if payload is not None else (b"" if method == "POST" else None)
        request = urllib.request.Request(
            self.base + path, data=data, method=method,
            headers={"Authorization": self.auth, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(request, timeout=20, context=self.tls) as response:
                if response.status // 100 != 2:
                    raise RuntimeError("testbed API returned non-2xx")
                return json.load(response)
        except (urllib.error.URLError, json.JSONDecodeError) as err:
            raise RuntimeError("testbed API request failed without exposing its body") from err

    def get(self, path):
        return self.request("GET", path)

    def post(self, path, payload=None):
        return self.request("POST", path, payload)


def delivery_proof_alias(api):
    """Return the one pre-existing alias the proof is permitted to edit."""
    lookup = api.get("/api/firewall/alias/get_alias_uuid/" + PROOF_ALIAS_NAME)
    alias_uuid = lookup.get("uuid") if isinstance(lookup, dict) else None
    if not isinstance(alias_uuid, str) or not alias_uuid:
        raise RuntimeError("dedicated delivery-proof alias did not resolve to one UUID")
    item = api.get("/api/firewall/alias/get_item/" + urllib.parse.quote(alias_uuid, safe=""))
    alias = item.get("alias") if isinstance(item, dict) else None
    if not isinstance(alias, dict) or "description" not in alias:
        raise RuntimeError("dedicated delivery-proof alias did not return a restorable description")
    return alias_uuid, alias


def set_alias(api, alias_uuid, alias):
    result = api.post("/api/firewall/alias/set_item/" + urllib.parse.quote(alias_uuid, safe=""), {"alias": alias})
    if not isinstance(result, dict) or result.get("result") != "saved":
        raise RuntimeError("dedicated delivery-proof alias was not saved")


def edited_alias(alias, description):
    updated = dict(alias)
    updated["description"] = description
    return updated


class AliasDescriptionMutation:
    """Write a temporary alias description and restore its original payload."""
    def __init__(self, api, alias_uuid, original_alias, description):
        self.api = api
        self.alias_uuid = alias_uuid
        self.original_alias = original_alias
        self.description = description
        self.restored = False

    def __enter__(self):
        self.apply()
        return self

    def apply(self):
        set_alias(self.api, self.alias_uuid, edited_alias(self.original_alias, self.description))

    def __exit__(self, _type, _value, _traceback):
        self.restore()
        return False

    def restore(self):
        set_alias(self.api, self.alias_uuid, self.original_alias)
        self.restored = True


def revision_ids(api):
    payload = api.get("/api/core/backup/backups/this")
    items = payload.get("items") if isinstance(payload, dict) else None
    if not isinstance(items, list):
        raise RuntimeError("configuration revision list was not available")
    result = set()
    for item in items:
        revision_id = item.get("id") if isinstance(item, dict) else None
        if not isinstance(revision_id, str) or not revision_id:
            raise RuntimeError("configuration revision list contained no revision identity")
        result.add(revision_id)
    return result


def revision_list_grew(before, after):
    return bool(after - before)


def no_sensitive_keys(value):
    if isinstance(value, dict):
        return all(not SENSITIVE_KEY.search(str(key)) and no_sensitive_keys(item) for key, item in value.items())
    if isinstance(value, list):
        return all(no_sensitive_keys(item) for item in value)
    return True


def reject_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def loki_query(query, user, token, start_ns, attempts=12):
    succeeded = False
    for attempt in range(attempts):
        params = urllib.parse.urlencode({
            "query": query, "limit": "1000", "direction": "FORWARD",
            "start": str(start_ns), "end": str(time.time_ns()),
        })
        request = urllib.request.Request(
            LOKI_ENDPOINT + "/loki/api/v1/query_range?" + params,
            headers={
                "Authorization": basic(user, token),
                # Without this flag Loki MERGES structured metadata into each
                # stream's label map and omits the per-entry metadata element
                # entirely. Reading the default response therefore reports every
                # structured-metadata key as a promoted stream label, and makes
                # the "domain is structured metadata" assertion impossible to
                # satisfy. Both are measurement artifacts, not exporter
                # behaviour: Wave 5 recorded 202 phantom promoted labels this way.
                "X-Loki-Response-Encoding-Flags": "categorize-labels",
            },
        )
        try:
            with urllib.request.urlopen(request, timeout=20) as response:
                payload = json.load(response)
            succeeded = payload.get("status") == "success"
            result = payload.get("data", {}).get("result", [])
            if result:
                return {"streams": result, "succeeded": succeeded}
        except (urllib.error.URLError, json.JSONDecodeError):
            succeeded = False
        if attempt + 1 < attempts:
            time.sleep(10)
    return {"streams": [], "succeeded": succeeded}


def records(streams):
    """Yield labels, body and structured metadata without writing any of them.

    Requires the categorize-labels response encoding: the per-entry third
    element is then a category map whose "structuredMetadata" member holds the
    non-promoted attributes, and "stream" holds only true stream labels.
    """
    for stream in streams:
        labels = stream.get("stream", {})
        for value in stream.get("values", []):
            if len(value) < 2:
                continue
            categories = value[2] if len(value) > 2 and isinstance(value[2], dict) else {}
            metadata = categories.get("structuredMetadata") or {}
            if not isinstance(metadata, dict):
                metadata = {}
            yield labels, value[1], metadata


def safe_diagnostic(value):
    """Return an error detail only when it cannot carry credentials or a URL."""
    if not isinstance(value, str) or not value.strip():
        return "missing"
    value = " ".join(value.split())
    if len(value) > 240 or SENSITIVE_DIAGNOSTIC.search(value):
        return "redacted"
    return value


def exporter_poll_error_diagnostic(rows, source):
    """Find a shipped source-poll error without rendering arbitrary log bodies."""
    for labels, body, metadata in rows:
        if (labels.get("opnsense_source") == "exporter" and
                body == "log source poll error" and metadata.get("source") == source):
            return safe_diagnostic(metadata.get("err"))
    return "not_observed"


def send_zenarmor_dns(source, destination):
    """Seed the current process's bounded DNS cache through its real receiver."""
    index = "zenarmor_0000000000_deliveryproof_dns_write"
    action = json.dumps({"index": {"_index": index, "_id": secrets.token_hex(8)}})
    document = json.dumps({
        "ip_src_saddr": source, "query": "delivery-proof.example",
        "answers": destination, "is_request": 1, "is_response": 1,
        "resp_code": 0, "is_blocked": 0,
    })
    request = urllib.request.Request(
        "http://127.0.0.1:9200/_bulk", data=(action + "\n" + document + "\n").encode(),
        method="POST", headers={"Content-Type": "application/x-ndjson"},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status // 100 != 2:
                raise RuntimeError("local Zenarmor seed returned non-2xx")
            payload = json.load(response)
        if payload.get("errors") is not False:
            raise RuntimeError("local Zenarmor seed was not accepted")
    except (urllib.error.URLError, json.JSONDecodeError) as err:
        raise RuntimeError("local Zenarmor seed failed without exposing its body") from err


def filterlog_line(source, destination, epoch=None):
    # This is the repository's real OPNsense 26.7 UDP filterlog capture with only
    # the source/destination tuple substituted to match the live DNS-cache key.
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(epoch))
    return ("<134>1 " + timestamp + " proof filterlog 1 - - "
            "16,115,,0,vtnet2,match,pass,out,4,0x0,,64,0,0,DF,17,udp,48,"
            + source + "," + destination + ",55124,53,28")


def send_filterlog(source, destination):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as conn:
        conn.sendto(filterlog_line(source, destination).encode(), ("127.0.0.1", 5514))


def query_diagnostic(source, specific, broad):
    if specific["streams"]:
        return "arrived"
    if not specific["succeeded"]:
        return "query_failed"
    for labels, _, metadata in records(broad["streams"]):
        if labels.get("opnsense_source") == source or metadata.get("opnsense_source") == source:
            return "arrived_with_unexpected_labels"
    if broad["streams"]:
        return "source_absent_in_instance_window"
    if broad["succeeded"]:
        return "instance_absent_in_explicit_window"
    return "broad_query_failed"


def bodies_have_no_sensitive_keys(rows):
    if not rows:
        return False
    for _, body, _ in rows:
        try:
            value = json.loads(body, object_pairs_hook=reject_duplicate_keys)
        except (json.JSONDecodeError, ValueError):
            return False
        if not no_sensitive_keys(value):
            return False
    return True


def has_domain_metadata(rows, expected):
    return any(
        metadata.get("dst_domain") == expected and "dst_domain" not in labels
        for labels, _, metadata in rows
    )


def poll_error_observed(metrics, source):
    for line in metrics.splitlines():
        if not line.startswith("opnsense_exporter_logs_poll_errors_total{"):
            continue
        labels, _, value = line.partition("} ")
        if ('source="' + source + '"') not in labels:
            continue
        try:
            return float(value.split(None, 1)[0]) > 0
        except ValueError:
            return False
    return False


def read_local_metrics():
    try:
        with urllib.request.urlopen("http://127.0.0.1:8080/metrics", timeout=10) as response:
            return response.read().decode("utf-8", "replace")
    except urllib.error.URLError:
        return ""


def poll_error_diagnostic(metrics, source):
    if not metrics:
        return "unavailable"
    return "yes" if poll_error_observed(metrics, source) else "no"


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
    args = parser.parse_args(argv)
    host, key, secret_value = required("DEVBOX_HOST"), required("DEVBOX_API_KEY"), required("DEVBOX_API_SECRET")
    otlp_user, loki_user, cap_token = required("GRAFANA_OTLP_USER"), required("GRAFANA_LOKI_USER"), required("GRAFANA_CAP_TOKEN")
    instance = "delivery-proof-" + os.environ.get("GITHUB_RUN_ID", secrets.token_hex(6))
    api = API(host, key, secret_value)
    alias_uuid = None
    original_alias = None
    mutation = None
    revisions_before = None
    revisions_after_mutation = None
    process = None
    facts = {}
    diagnostics = {}
    query_start_ns = time.time_ns() - 5 * 60 * 1_000_000_000
    try:
        alias_uuid, original_alias = delivery_proof_alias(api)
        revisions_before = revision_ids(api)
        env = os.environ | {
            "OPN2OTEL_OPS_API": host, "OPN2OTEL_OPS_API_KEY": key, "OPN2OTEL_OPS_API_SECRET": secret_value,
            "OPN2OTEL_OPS_PROTOCOL": "https", "OPN2OTEL_OPS_INSECURE": "true",
            "OPN2OTEL_INSTANCE_LABEL": instance,
            "OPN2OTEL_OTLP_GRAFANA_CLOUD_INSTANCE_ID": otlp_user,
            "OPN2OTEL_OTLP_GRAFANA_CLOUD_TOKEN": cap_token,
            "OPN2OTEL_OTLP_GRAFANA_CLOUD_ENDPOINT": OTLP_ENDPOINT,
        }
        command = [args.exporter, "--logs.enabled", "--logs.sink=otlp", "--logs.poll-interval=5s",
                   "--logs.configchange.enabled", "--logs.config-snapshot.firewall.enabled",
                   "--logs.config-snapshot.devices.enabled", "--logs.config-snapshot.security-posture.enabled",
                   "--logs.self.enabled", "--logs.syslog.enabled",
                   "--logs.syslog.listen-udp=127.0.0.1:5514", "--logs.syslog.listen-tcp=",
                   "--logs.syslog.allowed-peers=127.0.0.1/32", "--logs.zenarmor.enabled",
                   "--logs.zenarmor.listen-http=127.0.0.1:9200",
                   "--logs.zenarmor.allowed-peers=127.0.0.1/32", "--logs.zenarmor.families=dns",
                   "--flow.enabled"]
        process = subprocess.Popen(
            command, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        time.sleep(8)  # baselines configchange; initial configstate and exporter records ship.
        mutation = AliasDescriptionMutation(api, alias_uuid, original_alias, "temporary live delivery proof " + instance)
        mutation.apply()
        revisions_after_mutation = revision_ids(api)
        facts["alias_description_revision_written"] = revision_list_grew(revisions_before, revisions_after_mutation)
        dns_source, dns_destination = "192.0.2.10", "192.0.2.20"
        send_zenarmor_dns(dns_source, dns_destination)
        send_filterlog(dns_source, dns_destination)
        time.sleep(20)
        selector = 'service_name="opnsense2otel",service_instance_id="' + instance + '"'
        queries = {name: loki_query('{' + selector + ',opnsense_source="' + name + '"}', loki_user, cap_token, query_start_ns)
                   for name in PROOF_SOURCES}
        broad = loki_query('{' + selector + '}', loki_user, cap_token, query_start_ns)
        diagnostics.update({name: query_diagnostic(name, result, broad) for name, result in queries.items()})
        facts.update({name + "_arrived": bool(result["streams"]) for name, result in queries.items()})
        configchange = list(records(queries["configchange"]["streams"]))
        facts["configchange_redacted"] = any("<password>[redacted]</password>" in body for _, body, _ in configchange)
        configstate = list(records(queries["configstate"]["streams"]))
        families = {metadata.get("snapshot_family", "") for _, _, metadata in configstate}
        facts["configstate_families_arrived"] = families == {"firewall", "device_inventory", "security_posture"}
        facts["configstate_sensitive_fields_absent"] = bodies_have_no_sensitive_keys(configstate)
        exporter_records = list(records(queries["exporter"]["streams"]))
        diagnostics["configstate shipped poll error"] = exporter_poll_error_diagnostic(exporter_records, "configstate")
        syslog_records = list(records(queries["syslog"]["streams"]))
        facts["domain_structured_metadata"] = has_domain_metadata(syslog_records, "delivery-proof.example")
        observed_labels = {key for labels, _, _ in records(broad["streams"]) for key in labels}
        expected = {"opnsense_action", "opnsense_device_category", "opnsense_interface", "opnsense_source", "opnsense_subsystem", "service_instance_id", "service_name"}
        unexpected_labels = sorted(observed_labels - expected)
        diagnostics["unexpected promoted label keys"] = "none" if not unexpected_labels else ",".join(unexpected_labels)
        diagnostics["configstate families"] = "none" if not families else ",".join(sorted(families))
        facts["labels_outside_allowlist_absent"] = bool(broad["streams"]) and not unexpected_labels
        metrics = read_local_metrics()
        diagnostics["configchange poll errors"] = poll_error_diagnostic(metrics, "configchange")
        diagnostics["configstate poll errors"] = poll_error_diagnostic(metrics, "configstate")
    except Exception:
        # Do not render exception text: HTTP/library errors can include a response
        # body and that body is outside this proof's redaction boundary.
        facts["proof_completed"] = False
    finally:
        # Keep exporter teardown in a nested finally: a failed rollback must never
        # leave its credential-bearing process alive on the runner.
        try:
            if mutation is not None:
                try:
                    mutation.restore()
                    facts["rollback"] = mutation.restored
                except Exception:
                    facts["rollback"] = False
                    facts["alias_description_restore_revision_written"] = False
                else:
                    try:
                        revisions_after_restore = revision_ids(api)
                        revision_floor = revisions_after_mutation if revisions_after_mutation is not None else revisions_before
                        facts["alias_description_restore_revision_written"] = revision_list_grew(revision_floor, revisions_after_restore)
                    except Exception:
                        facts["alias_description_restore_revision_written"] = False
        finally:
            if process:
                stop_process_group(process)
    print("## Live delivery proof")
    print("- instance label: `" + instance + "`")
    for name in sorted(facts):
        print("- " + name.replace("_", " ") + ": " + ("yes" if facts[name] else "no"))
    for name in sorted(diagnostics):
        print("- " + name + " query result: " + diagnostics[name])
    print("- configstate redaction exercise: no (the alias description trigger exercises configchange only)")
    required_facts = ("configchange_arrived", "configchange_redacted", "configstate_families_arrived",
                      "configstate_sensitive_fields_absent", "exporter_arrived", "syslog_arrived", "zenarmor_arrived",
                      "domain_structured_metadata", "labels_outside_allowlist_absent",
                      "alias_description_revision_written", "alias_description_restore_revision_written", "rollback")
    return 0 if all(facts.get(name) for name in required_facts) else 1


if __name__ == "__main__":
    sys.exit(main())
