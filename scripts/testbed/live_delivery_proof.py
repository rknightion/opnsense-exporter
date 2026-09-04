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


def proof_user_ids(payload):
    rows = payload.get("rows", []) if isinstance(payload, dict) else []
    result = []
    for row in rows:
        if not isinstance(row, dict) or row.get("scope") == "system":
            continue
        if re.fullmatch(r"deliveryproof[0-9a-f]{16}", str(row.get("name", ""))) and row.get("uuid"):
            result.append(str(row["uuid"]))
    return result


def delete_and_verify_user(api, user_uuid, attempts=3, diagnostic=None):
    for attempt in range(attempts):
        try:
            result = api.post("/api/auth/user/del/" + urllib.parse.quote(user_uuid, safe=""))
            outcome = str(result.get("result", "missing")) if isinstance(result, dict) else "non-object"
            if outcome not in {"deleted", "failed", "not found", "missing"}:
                outcome = "other"
        except Exception:
            outcome = "request-failed"
        try:
            present = user_uuid in proof_user_ids(api.get("/api/auth/user/search"))
            if diagnostic is not None:
                diagnostic.append("post:" + outcome + "/search:" + ("present" if present else "absent"))
            if not present:
                return True
        except Exception:
            if diagnostic is not None:
                diagnostic.append("post:" + outcome + "/search:failed")
        if attempt + 1 < attempts:
            time.sleep(2)
    return False


def cleanup_stale_proof_users(api, diagnostic):
    try:
        stale = proof_user_ids(api.get("/api/auth/user/search"))
    except Exception:
        diagnostic["stale cleanup detail"] = "search-failed"
        return False
    attempts = []
    outcomes = [delete_and_verify_user(api, user_uuid, diagnostic=attempts) for user_uuid in stale]
    result = all(outcomes)
    diagnostic["stale cleanup detail"] = "none" if not stale else "found:" + str(len(stale)) + ";" + ",".join(attempts)
    return result


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
            headers={"Authorization": basic(user, token)},
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
    """Yield labels, body and structured metadata without writing any of them."""
    for stream in streams:
        labels = stream.get("stream", {})
        for value in stream.get("values", []):
            if len(value) < 2:
                continue
            metadata = value[2] if len(value) > 2 and isinstance(value[2], dict) else {}
            yield labels, value[1], metadata


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
            return float(value) > 0
        except ValueError:
            return False
    return False


def read_local_metrics():
    try:
        with urllib.request.urlopen("http://127.0.0.1:8080/metrics", timeout=10) as response:
            return response.read().decode("utf-8", "replace")
    except urllib.error.URLError:
        return ""


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
    username = "deliveryproof" + secrets.token_hex(8)
    created_uuid = None
    process = None
    facts = {}
    diagnostics = {}
    query_start_ns = time.time_ns() - 5 * 60 * 1_000_000_000
    try:
        facts["stale_user_cleanup"] = cleanup_stale_proof_users(api, diagnostics)
        if not facts["stale_user_cleanup"]:
            raise RuntimeError("stale proof-user cleanup could not be verified")
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
        result = api.post("/api/auth/user/add", {"user": {"name": username, "disabled": "1", "scope": "user", "scrambled_password": "1", "descr": "temporary CI delivery proof"}})
        if result.get("result") != "saved" or not result.get("uuid"):
            raise RuntimeError("testbed refused temporary user creation")
        created_uuid = result["uuid"]
        dns_source, dns_destination = "192.0.2.10", "192.0.2.20"
        send_zenarmor_dns(dns_source, dns_destination)
        send_filterlog(dns_source, dns_destination)
        time.sleep(20)
        selector = 'service_name="opnsense2otel",service_instance_id="' + instance + '"'
        queries = {name: loki_query('{' + selector + ',opnsense_source="' + name + '"}', loki_user, cap_token, query_start_ns)
                   for name in ("configchange", "configstate", "exporter", "syslog")}
        broad = loki_query('{' + selector + '}', loki_user, cap_token, query_start_ns)
        diagnostics = {name: query_diagnostic(name, result, broad) for name, result in queries.items()}
        facts["configchange_arrived"] = bool(queries["configchange"]["streams"])
        configchange = list(records(queries["configchange"]["streams"]))
        facts["configchange_redacted"] = any("<password>[redacted]</password>" in body for _, body, _ in configchange)
        configstate = list(records(queries["configstate"]["streams"]))
        families = {metadata.get("snapshot_family", "") for _, _, metadata in configstate}
        facts["configstate_families_arrived"] = families == {"firewall", "device_inventory", "security_posture"}
        facts["configstate_sensitive_fields_absent"] = bodies_have_no_sensitive_keys(configstate)
        facts["exporter_arrived"] = bool(queries["exporter"]["streams"])
        syslog_records = list(records(queries["syslog"]["streams"]))
        facts["domain_structured_metadata"] = has_domain_metadata(syslog_records, "delivery-proof.example")
        observed_labels = {key for labels, _, _ in records(broad["streams"]) for key in labels}
        expected = {"opnsense_action", "opnsense_device_category", "opnsense_interface", "opnsense_source", "opnsense_subsystem", "service_instance_id", "service_name"}
        unexpected_labels = sorted(observed_labels - expected)
        diagnostics["unexpected promoted label keys"] = "none" if not unexpected_labels else ",".join(unexpected_labels)
        diagnostics["configstate families"] = "none" if not families else ",".join(sorted(families))
        facts["labels_outside_allowlist_absent"] = bool(broad["streams"]) and not unexpected_labels
        metrics = read_local_metrics()
        diagnostics["configchange poll errors"] = "yes" if poll_error_observed(metrics, "configchange") else "no"
        diagnostics["configstate poll errors"] = "yes" if poll_error_observed(metrics, "configstate") else "no"
    except Exception:
        # Do not render exception text: HTTP/library errors can include a response
        # body and that body is outside this proof's redaction boundary.
        facts["proof_completed"] = False
    finally:
        # Keep exporter teardown in a nested finally: a failed rollback must never
        # leave its credential-bearing process alive on the runner.
        try:
            if created_uuid:
                facts["rollback"] = delete_and_verify_user(api, created_uuid)
        finally:
            if process:
                stop_process_group(process)
    print("## Live delivery proof")
    print("- instance label: `" + instance + "`")
    for name in sorted(facts):
        print("- " + name.replace("_", " ") + ": " + ("yes" if facts[name] else "no"))
    for name in sorted(diagnostics):
        print("- " + name + " query result: " + diagnostics[name])
    # A configstate absence scan is useful live evidence, but is not a claim that
    # its redactor saw the temporary user's password field.
    print("- configstate redaction exercise: no (the temporary Auth user is outside its three source shapes)")
    required_facts = ("configchange_arrived", "configchange_redacted", "configstate_families_arrived",
                      "configstate_sensitive_fields_absent", "exporter_arrived", "domain_structured_metadata",
                      "labels_outside_allowlist_absent", "rollback", "stale_user_cleanup")
    return 0 if all(facts.get(name) for name in required_facts) else 1


if __name__ == "__main__":
    sys.exit(main())
