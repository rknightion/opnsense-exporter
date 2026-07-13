#!/usr/bin/env python3
"""
Single-source builder for OPNsense exporter alert + recording rules.

Rules are defined once (RULES / RECORDING below) and emitted as Grafana-managed manifests:

  * `grafana-managed/*.json`         — Grafana-managed `rules.alerting.grafana.app/v0alpha1`
                                       AlertRule / RecordingRule manifests (+ a folder),
                                       pushable with `gcx resources push`. Use `--stack` to add
                                       an IRM label contract (domain/page) for routed alerting.

Grafana-managed alerting is the only supported format: it carries `noDataState` (so the
exporter-down/NoData case actually fires) and Grafana templating (`$values`), neither of which
a portable Prometheus rule-group file can express. A previously-shipped portable
`opnsense.rules.yaml` was dropped for this reason.

Usage:
    python3 build_rules.py                       # generic labels
    python3 build_rules.py --stack               # add domain=infra (+page on critical)
    python3 build_rules.py --datasource <uid>    # datasource UID (default grafanacloud-prom)
    python3 build_rules.py --folder <name>       # grafana folder (default opnsense-alerts)

Alerts are defined as a value-producing query `A` plus a threshold condition, rendered to the
Grafana A→C query/threshold node pipeline.
"""
import argparse
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))

# Each alert: name(slug), title, A (value query), cond (op, params), for_min, severity,
# summary, description. op in {gt, lt, within_range, outside_range}.
RULES = [
    dict(name="opnsense-exporter-down", title="OPNsenseExporterDown",
         A="opnsense_up", op="lt", params=[1, 0], for_min=15, severity="critical",
         nodata="Alerting",
         summary="OPNsense exporter/box down ({{ $labels.opnsense_instance }})",
         description="opnsense_up has been 0 (the OPNsense API was unreachable / the scrape failed) "
                     "or the target produced NoData for 15m. opnsense_up reflects API reachability ONLY - "
                     "a reachable box reporting a degraded subsystem (e.g. a crash report) stays up=1 and is "
                     "covered by the lower-severity OPNsenseCrashReports / OPNsenseFirewallUnhealthy alerts, "
                     "so this critical/page fires on genuine unreachability only. The 15m window tolerates a "
                     "router reboot (typically <10m) without paging."),
    dict(name="opnsense-firewall-unhealthy", title="OPNsenseFirewallUnhealthy",
         A="opnsense_firewall_status", op="lt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense firewall health check failing ({{ $labels.opnsense_instance }})",
         description="opnsense_firewall_status has reported 0 (errors) for 10m."),
    dict(name="opnsense-crash-reports", title="OPNsenseCrashReports",
         A="opnsense_crash_reporter_status", op="lt", params=[1, 0], for_min=5, severity="warning",
         summary="OPNsense crash reports present ({{ $labels.opnsense_instance }})",
         description="opnsense_crash_reporter_status is 0 — one or more crash reports are present."),
    # #218: the root filesystem "diskspace" health-check subsystem, surfaced by the generic
    # opnsense_system_subsystem_status_code gauge (no dedicated gauge for this one). OPNsense
    # omits a healthy subsystem from the payload entirely, so the series is ABSENT (not 0/OK)
    # on a healthy box — noDataState is deliberately left at the default "Ok" (see nodata=
    # default below) rather than "Alerting", unlike opnsense-exporter-down.
    dict(name="opnsense-disk-space-low", title="OPNsenseDiskSpaceLow",
         A='opnsense_system_subsystem_status_code{subsystem="diskspace"}', op="lt", params=[2, 0],
         for_min=10, severity="warning",
         summary="OPNsense root filesystem disk space low ({{ $labels.opnsense_instance }})",
         description="opnsense_system_subsystem_status_code{subsystem=\"diskspace\"} has reported below OK "
                     "(2 = OK, 1 = NOTICE, 0 = WARNING nearly full, -1 = ERROR critically full) for 10m. "
                     "Absent means healthy — OPNsense omits an OK subsystem from the health-check payload."),
    # The alert-condition window MUST be short (2m) so the long for:15m actually measures how long
    # errors PERSIST. If the window equals for (both 15m), increase()>0 stays true for 15m after the
    # last error, so for:15m is satisfied by any burst spanning >1 eval interval and the alert fires
    # ~15m AFTER recovery (#94). With a 2m window, an 8m error burst keeps the condition true only
    # ~t=0..10m (<15m) → for:15m never elapses → no false page; genuinely sustained errors keep every
    # rolling 2m window non-empty, so the condition stays true past 15m and the alert fires.
    dict(name="opnsense-endpoint-errors", title="OPNsenseEndpointErrors",
         A="sum by (opnsense_instance, endpoint) (increase(opnsense_exporter_endpoint_errors_total[2m]))",
         op="gt", params=[0, 0], for_min=15, severity="warning",
         summary="OPNsense exporter endpoint errors ({{ $labels.endpoint }})",
         description="The {{ $labels.endpoint }} API endpoint has produced errors sustained for 15m "
                     "(at least one error in every rolling 2m window for the full 15m). A brief router "
                     "reboot / WAN blip empties the 2m window well before 15m elapses, so it does not fire. "
                     "One alert per endpoint."),
    # Split primary vs failover: the default (primary) WAN reconverges in <1m after a reboot, so it
    # keeps a tight for=5m + critical/page. A secondary/failover WAN can take ~7-10m to re-establish
    # (DHCP + dpinger convergence) after a reboot, so it gets for=15m + warning (no page) to avoid
    # false pages during reboots. Requires the default_gateway label (opnsense-exporter >=0.x).
    dict(name="opnsense-gateway-down", title="OPNsenseGatewayDown",
         A='opnsense_gateways_status{default_gateway="true"}', op="lt", params=[1, 0], for_min=5, severity="critical",
         summary="OPNsense PRIMARY gateway {{ $labels.name }} is offline",
         description="Primary WAN gateway {{ $labels.name }} ({{ $labels.address }}) offline (status 0) for 5m."),
    dict(name="opnsense-gw-down-failover", title="OPNsenseGatewayDownFailover",
         A='opnsense_gateways_status{default_gateway="false"}', op="lt", params=[1, 0], for_min=15, severity="warning",
         summary="OPNsense FAILOVER gateway {{ $labels.name }} is offline",
         description="Failover/secondary WAN gateway {{ $labels.name }} ({{ $labels.address }}) offline (status 0) for 15m. "
                     "Lower urgency — primary WAN unaffected. The 15m window tolerates a router reboot / slow secondary-WAN re-establish."),
    dict(name="opnsense-gateway-high-loss", title="OPNsenseGatewayHighLoss",
         A="opnsense_gateways_loss_percentage", op="gt", params=[20, 0], for_min=10, severity="warning",
         summary="OPNsense gateway {{ $labels.name }} high packet loss",
         description="Gateway {{ $labels.name }} packet loss > 20% for 10m (current {{ $values.A.Value | printf \"%.1f\" }}%)."),
    dict(name="opnsense-gateway-high-rtt", title="OPNsenseGatewayHighRTT",
         A="opnsense_gateways_rtt_milliseconds / (opnsense_gateways_rtt_high_milliseconds > 0)",
         op="gt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense gateway {{ $labels.name }} RTT over its high threshold",
         description="Gateway {{ $labels.name }} mean RTT has exceeded its configured high-latency threshold for 10m."),
    dict(name="opnsense-pf-states-near-limit", title="OPNsensePFStateTableNearLimit",
         A="opnsense_firewall_pf_states_current / (opnsense_firewall_pf_states_limit > 0)",
         op="gt", params=[0.9, 0], for_min=10, severity="warning",
         summary="OPNsense PF state table near its limit",
         description="PF state table is over 90% of its configured limit for 10m."),
    dict(name="opnsense-memory-high", title="OPNsenseMemoryHigh",
         A="opnsense_system_memory_used_bytes / (opnsense_system_memory_total_bytes > 0)",
         op="gt", params=[0.9, 0], for_min=15, severity="warning",
         summary="OPNsense memory usage high ({{ $labels.opnsense_instance }})",
         description="Physical memory usage has been above 90% for 15m."),
    dict(name="opnsense-disk-usage-high", title="OPNsenseDiskUsageHigh",
         A="opnsense_system_disk_usage_ratio", op="gt", params=[0.9, 0], for_min=15, severity="warning",
         summary="OPNsense disk {{ $labels.mountpoint }} almost full",
         description="Filesystem {{ $labels.mountpoint }} ({{ $labels.device }}) usage above 90% for 15m."),
    dict(name="opnsense-high-temperature", title="OPNsenseHighTemperature",
         A="opnsense_temperature_celsius", op="gt", params=[85, 0], for_min=10, severity="warning",
         summary="OPNsense sensor {{ $labels.device }} hot",
         description="Temperature sensor {{ $labels.device }} above 85°C for 10m."),
    dict(name="opnsense-smart-failed", title="OPNsenseSmartHealthFailed",
         A="opnsense_smart_device_health", op="lt", params=[1, 0], for_min=5, severity="critical",
         summary="OPNsense SMART health failed on {{ $labels.device }}",
         description="SMART overall-health for {{ $labels.device }} ({{ $labels.model }}) reports FAILED."),
    dict(name="opnsense-firmware-needs-reboot", title="OPNsenseFirmwareNeedsReboot",
         A="opnsense_firmware_needs_reboot", op="gt", params=[0, 0], for_min=30, severity="warning",
         summary="OPNsense needs a reboot ({{ $labels.opnsense_instance }})",
         description="A firmware update flagged that OPNsense needs a reboot."),
    dict(name="opnsense-cert-expiring", title="OPNsenseCertificateExpiringSoon",
         A="(opnsense_certificate_valid_to_seconds - time()) / 86400",
         op="within_range", params=[0, 14], for_min=0, severity="warning",
         summary="OPNsense certificate expiring soon: {{ $labels.commonname }}",
         description="Certificate {{ $labels.commonname }} ({{ $labels.description }}) expires within 14 days."),
    dict(name="opnsense-cert-expiring-critical", title="OPNsenseCertificateExpiringCritical",
         A="(opnsense_certificate_valid_to_seconds - time()) / 86400",
         op="within_range", params=[0, 3], for_min=0, severity="critical",
         summary="OPNsense certificate expiring imminently: {{ $labels.commonname }}",
         description="Certificate {{ $labels.commonname }} ({{ $labels.description }}) expires within 3 days."),
    # Exclude on-demand services that are expected to be stopped (e.g. iperf, which only runs during
    # an explicit performance test). Add other expected-down service names to the exclusion as needed.
    dict(name="opnsense-service-down", title="OPNsenseServiceDown",
         A='opnsense_services_status{name!="iperf"}', op="lt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense service {{ $labels.name }} stopped",
         description="Service {{ $labels.name }} ({{ $labels.description }}) has been stopped for 10m. "
                     "On-demand services (e.g. iperf) are excluded. One alert per service."),
    dict(name="opnsense-ntp-unsynced", title="OPNsenseNTPPeerUnreachable",
         A="opnsense_ntp_peer_reach", op="lt", params=[1, 0], for_min=15, severity="warning",
         summary="OPNsense NTP peer {{ $labels.server }} unreachable",
         description="NTP peer {{ $labels.server }} reachability register has been 0 for 15m."),
    # Unlike opnsense-endpoint-errors, this is a genuine count-in-window threshold (>5 bogus answers
    # per rolling 15m) with for:0 — it fires immediately when the count is exceeded, so there is no
    # for-duration whose meaning the 15m window could distort. The #94 defect (long for paired with an
    # equally-long increase window) does not apply here, so the 15m window is intentional and kept.
    dict(name="opnsense-unbound-dnssec-bogus", title="OPNsenseUnboundDNSSECBogus",
         A="sum by (opnsense_instance) (increase(opnsense_unbound_dns_answers_bogus_total[15m]))",
         op="gt", params=[5, 0], for_min=0, severity="info",
         summary="OPNsense Unbound DNSSEC bogus answers ({{ $labels.opnsense_instance }})",
         description="More than 5 DNSSEC-bogus answers in 15m — possible misconfiguration or tampering."),
]

# Recording rules: metric name (level:metric:operation) + value query.
RECORDING = [
    dict(metric="instance:opnsense_interface_rx_bits:rate5m",
         expr="sum by (opnsense_instance, interface) (rate(opnsense_interfaces_received_bytes_total[5m])) * 8"),
    dict(metric="instance:opnsense_interface_tx_bits:rate5m",
         expr="sum by (opnsense_instance, interface) (rate(opnsense_interfaces_transmitted_bytes_total[5m])) * 8"),
    dict(metric="instance:opnsense_firewall_block_packets:rate5m",
         expr="sum by (opnsense_instance, interface) ("
              "rate(opnsense_firewall_in_ipv4_block_packets[5m]) + rate(opnsense_firewall_out_ipv4_block_packets[5m]) + "
              "rate(opnsense_firewall_in_ipv6_block_packets[5m]) + rate(opnsense_firewall_out_ipv6_block_packets[5m]))"),
    dict(metric="instance:opnsense_pf_state:utilization",
         expr="opnsense_firewall_pf_states_current / (opnsense_firewall_pf_states_limit > 0)"),
    dict(metric="instance:opnsense_unbound_cache:hit_ratio",
         expr="rate(opnsense_unbound_dns_cache_hits_total[5m]) / "
              "(rate(opnsense_unbound_dns_cache_hits_total[5m]) + rate(opnsense_unbound_dns_cache_miss_total[5m]) > 0)"),
    dict(metric="instance:opnsense_unbound_queries:rate5m",
         expr="rate(opnsense_unbound_dns_queries_total[5m])"),
    dict(metric="instance:opnsense_gateway_loss:ratio",
         expr="opnsense_gateways_loss_percentage / 100"),
    dict(metric="instance:opnsense_system_mem:utilization",
         expr="opnsense_system_memory_used_bytes / (opnsense_system_memory_total_bytes > 0)"),
]

def grafana_for(for_min: int) -> str:
    return "0s" if not for_min else f"{for_min}m0s"


def emit_grafana_managed(ds: str, folder: str, stack: bool):
    outdir = os.path.join(HERE, "grafana-managed")
    os.makedirs(outdir, exist_ok=True)
    for stale in os.listdir(outdir):  # clear stale manifests so renames don't linger
        if stale.endswith(".json"):
            os.remove(os.path.join(outdir, stale))
    written = []
    # Folder manifest (named so its UID == folder); pushed first so the rules resolve.
    folder_manifest = {
        "apiVersion": "folder.grafana.app/v1beta1", "kind": "Folder",
        "metadata": {"name": folder},
        "spec": {"title": "OPNsense Exporter Alerts"},
    }
    fp = os.path.join(outdir, "_folder.json")
    with open(fp, "w") as f:
        json.dump(folder_manifest, f, indent=2)
        f.write("\n")
    written.append(fp)
    for r in RULES:
        labels = {"severity": r["severity"]}
        if stack:
            labels["domain"] = "infra"
            if r["severity"] == "critical":
                labels["page"] = "true"
        cond = {"evaluator": {"type": r["op"], "params": r["params"]},
                "operator": {"type": "and"}, "query": {"params": []},
                "reducer": {"type": "last", "params": []}, "type": "query"}
        manifest = {
            "apiVersion": "rules.alerting.grafana.app/v0alpha1", "kind": "AlertRule",
            "metadata": {"name": r["name"],
                         "annotations": {"grafana.app/folder": folder},
                         "labels": {"grafana.app/folder": folder}},
            "spec": {
                "title": r["title"], "noDataState": r.get("nodata", "Ok"),
                "execErrState": "Error", "for": grafana_for(r["for_min"]),
                "trigger": {"interval": "1m"}, "labels": labels,
                "annotations": {"summary": r["summary"], "description": r["description"],
                                "runbook_url": "https://github.com/rknightion/opnsense-exporter/blob/main/grafana/README.md#alerts"},
                "expressions": {
                    "A": {"datasourceUID": ds,
                          "relativeTimeRange": {"from": "15m0s", "to": "0s"},
                          "model": {"datasource": {"type": "prometheus", "uid": ds},
                                    "editorMode": "code", "expr": r["A"], "instant": True,
                                    "range": False, "intervalMs": 60000,
                                    "maxDataPoints": 43200, "refId": "A"}},
                    "C": {"model": {"datasource": {"type": "__expr__", "uid": "__expr__"},
                                    "expression": "A", "type": "threshold", "refId": "C",
                                    "intervalMs": 1000, "maxDataPoints": 43200,
                                    "conditions": [cond]},
                          "source": True},
                },
            },
        }
        p = os.path.join(outdir, f"{r['name']}.json")
        with open(p, "w") as f:
            json.dump(manifest, f, indent=2)
            f.write("\n")
        written.append(p)
    for r in RECORDING:
        labels = {"domain": "infra"} if stack else {}
        # Grafana rule UIDs are capped at 40 chars; keep the slug compact.
        short = (r["metric"].replace("instance:opnsense_", "").replace("opnsense_", "")
                 .replace(":", "-").replace("_", "-"))
        slug = "oxrec-" + short
        manifest = {
            "apiVersion": "rules.alerting.grafana.app/v0alpha1", "kind": "RecordingRule",
            "metadata": {"name": slug,
                         "annotations": {"grafana.app/folder": folder},
                         "labels": {"grafana.app/folder": folder}},
            "spec": {"title": r["metric"], "metric": r["metric"],
                     "targetDatasourceUID": "", "paused": False,
                     "trigger": {"interval": "1m"}, "labels": labels,
                     "expressions": {"A": {"datasourceUID": ds,
                                           "relativeTimeRange": {"from": "10m0s", "to": "0s"},
                                           "model": {"datasource": {"type": "prometheus", "uid": ds},
                                                     "editorMode": "code", "expr": r["expr"],
                                                     "instant": False, "range": True,
                                                     "intervalMs": 1000, "maxDataPoints": 43200,
                                                     "refId": "A"},
                                           "source": True}}},
        }
        p = os.path.join(outdir, f"{slug}.json")
        with open(p, "w") as f:
            json.dump(manifest, f, indent=2)
            f.write("\n")
        written.append(p)
    return outdir, written


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--datasource", default="grafanacloud-prom")
    ap.add_argument("--folder", default="opnsense-alerts")
    ap.add_argument("--stack", action="store_true",
                    help="add IRM label contract (domain=infra; page=true on critical)")
    args = ap.parse_args()

    outdir, written = emit_grafana_managed(args.datasource, args.folder, args.stack)
    print(f"wrote {len(written)} grafana-managed manifests to {outdir}")
    print(f"alerts: {len(RULES)}  recording rules: {len(RECORDING)}  stack-labels: {args.stack}")


if __name__ == "__main__":
    main()
