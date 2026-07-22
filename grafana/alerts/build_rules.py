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
    # The syslog/Zenarmor push-based log receiver (#248-#261) had no alert coverage yet — these four
    # close that gap for the log-shipping pipeline itself (sink health, backpressure, label loss,
    # source liveness).
    dict(name="opnsense-logship-sink-errors", title="OPNsenseLogShipSinkErrors",
         A="sum by (instance) (rate(opnsense_exporter_logs_ship_errors_total[5m]))",
         op="gt", params=[0, 0], for_min=10, severity="warning",
         summary="OPNsense log-shipping sink errors ({{ $labels.instance }})",
         description="The log-shipping sink (OTLP/Loki) has been failing Emit calls for 10m — shipped "
                     "records are being lost. Grouped by instance, not opnsense_instance: the "
                     "opnsense_exporter_logs_* family carries no opnsense_instance label."),
    dict(name="opnsense-logship-queue-near-capacity", title="OPNsenseLogShipQueueNearCapacity",
         A="opnsense_exporter_logs_queue_length / (opnsense_exporter_logs_queue_capacity > 0)",
         op="gt", params=[0.9, 0], for_min=5, severity="warning",
         summary="OPNsense log-shipping queue near capacity",
         description="The log-shipping backpressure queue has been over 90% full for 5m — overflow "
                     "drops are imminent."),
    dict(name="opnsense-logship-resource-capped", title="OPNsenseLogShipResourceCapped",
         A="sum by (instance) (increase(opnsense_exporter_logs_resource_capped_total[15m]))",
         op="gt", params=[0, 0], for_min=0, severity="warning",
         summary="OPNsense log-shipping records had labels dropped ({{ $labels.instance }})",
         description="Records were shipped with their opnsense.* resource labels dropped in the last "
                     "15m, so label-scoped queries against them silently under-report."),
    # Scoped to syslog|zenarmor: both are continuously-active push sources, so 15m of silence is a
    # genuine stall. A source that is legitimately quiet or not configured would false-fire if
    # included, so it is deliberately excluded rather than covered here.
    dict(name="opnsense-logship-cursor-stalled", title="OPNsenseLogShipCursorStalled",
         A='time() - max by (source) (opnsense_exporter_logs_last_event_timestamp_seconds{source=~"syslog|zenarmor"})',
         op="gt", params=[900, 0], for_min=0, severity="warning",
         summary="OPNsense log-shipping source {{ $labels.source }} stalled",
         description="Push source {{ $labels.source }} has shipped no events for 15m despite being "
                     "continuously active. Scoped to syslog|zenarmor only, so a quiet or unconfigured "
                     "source cannot false-fire."),
    dict(name="opnsense-ipsec-tunnel-down", title="OPNsenseIPsecTunnelDown",
         A="opnsense_ipsec_phase1_status", op="lt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense IPsec tunnel {{ $labels.name }} down",
         description="IPsec phase1 tunnel {{ $labels.name }} ({{ $labels.description }}) has reported "
                     "status 0 (down; connected=1) for 10m. Catches a tunnel dropping while the daemon "
                     "itself keeps running, which opnsense-service-down misses."),
    # Verified semantics: 1=up, 0=down, 2=unknown, 3=stale. lt 1 fires on 0 only — 2/3 are
    # deliberately NOT alerted, since unknown/stale is not the same claim as confirmed down.
    dict(name="opnsense-wireguard-peer-down", title="OPNsenseWireGuardPeerDown",
         A="opnsense_wireguard_peer_status", op="lt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense WireGuard peer {{ $labels.peer_name }} down",
         description="WireGuard peer {{ $labels.peer_name }} on {{ $labels.device_name }} has reported "
                     "status 0 (down) for 10m. Status values are 1=up, 0=down, 2=unknown, 3=stale — "
                     "this alert deliberately fires on 0 only, not on unknown/stale."),
    # remote_services_total>0 is load-bearing: reachable=0 also means "HA sync isn't configured at
    # all", so the guard restricts firing to boxes where HA sync is actually set up.
    dict(name="opnsense-hasync-unreachable", title="OPNsenseHASyncUnreachable",
         A="opnsense_hasync_remote_reachable == 0 and on(opnsense_instance) "
           "(opnsense_hasync_remote_services_total > 0)",
         op="lt", params=[1, 0], for_min=10, severity="warning",
         summary="OPNsense HA sync peer unreachable ({{ $labels.opnsense_instance }})",
         description="opnsense_hasync_remote_reachable has been 0 for 10m on a box where HA sync is "
                     "configured (remote_services_total > 0). The guard excludes boxes with HA sync "
                     "unconfigured, where reachable=0 is the normal, expected reading."),
    # carp_vip_status: 1=MASTER, 0=BACKUP (both normal — inside the [0,1] range), 2=INIT, -1=unknown
    # (faults — outside the range). The `unless` clause suppresses alerts during deliberate maintenance
    # mode.
    dict(name="opnsense-carp-vip-fault", title="OPNsenseCARPVIPFault",
         A="opnsense_carp_vip_status unless on(opnsense_instance) (opnsense_carp_maintenance_mode == 1)",
         op="outside_range", params=[0, 1], for_min=5, severity="warning",
         summary="OPNsense CARP VIP {{ $labels.vip }} fault on {{ $labels.interface }}",
         description="CARP VIP {{ $labels.vip }} on {{ $labels.interface }} has been outside the normal "
                     "MASTER(1)/BACKUP(0) range for 5m — status 2 (INIT) or -1 (unknown). BACKUP is a "
                     "normal, healthy state and does not fire; this only fires on INIT/unknown. "
                     "Suppressed while opnsense_carp_maintenance_mode is 1."),
    # Threshold and lookback are deployment-specific: tune --exporter.ids-alert-lookback and the 50
    # threshold per site, same tone as opnsense-unbound-dnssec-bogus above. Verified: action is only
    # ever allowed/blocked — no drop/reject values exist.
    dict(name="opnsense-ids-alert-spike", title="OPNsenseIDSAlertSpike",
         A='sum by (opnsense_instance) (opnsense_ids_recent_alerts{action="blocked"})',
         op="gt", params=[50, 0], for_min=5, severity="info",
         summary="OPNsense IDS blocked-alert spike ({{ $labels.opnsense_instance }})",
         description="More than 50 blocked IDS alerts held in the recent-alerts window for 5m. The "
                     "threshold and --exporter.ids-alert-lookback window are deployment-specific — tune "
                     "both per site. action is only ever allowed/blocked (no drop/reject)."),
    # No bytes are lost on eviction (the oldest is force-emitted, not dropped), so this is a warning,
    # not a page: the correlate window can no longer be held under current flow volume.
    dict(name="opnsense-flow-correlator-evicting", title="OPNsenseFlowCorrelatorEvicting",
         A="sum by (opnsense_instance) (rate(opnsense_flow_correlator_evicted_total[5m]))",
         op="gt", params=[0, 0], for_min=15, severity="warning",
         summary="OPNsense flow correlator evicting entries ({{ $labels.opnsense_instance }})",
         description="The flow correlator has force-emitted entries for 15m because "
                     "--flow.correlate.max-entries is binding under current flow volume. No bytes are "
                     "lost, but the cap should be raised so the accumulator can hold a full correlate "
                     "window; sustained eviction shortens the effective join window and lowers the "
                     "merged hit-rate."),
    # Metrics are never truncated, only per-flow logs, so this is a warning about log completeness and a
    # possible flood on the unauthenticated NetFlow ingress rather than a data-integrity page.
    dict(name="opnsense-flow-logs-truncated", title="OPNsenseFlowLogsTruncated",
         A="sum by (opnsense_instance) (rate(opnsense_flow_logs_truncated_total[5m]))",
         op="gt", params=[0, 0], for_min=10, severity="warning",
         summary="OPNsense flow logs truncated by budget ({{ $labels.opnsense_instance }})",
         description="Flow log records have been dropped by the --flow.max-logs-per-window budget for "
                     "10m. Metrics are unaffected, but per-flow logs are incomplete. Raise the budget if "
                     "this is expected volume, or restrict the unauthenticated NetFlow ingress with "
                     "--flow.netflow.allowed-peers if it is a flood."),
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
    dict(metric="instance:opnsense_zenarmor_block:ratio5m",
         expr='sum by (opnsense_instance) (rate(opnsense_log_events_zenarmor_total{action="block"}[5m])) / '
              '(sum by (opnsense_instance) (rate(opnsense_log_events_zenarmor_total[5m])) > 0)'),
    dict(metric="instance:opnsense_haproxy_5xx:ratio5m",
         expr='sum by (opnsense_instance, backend) (rate(opnsense_log_events_haproxy_total{status_class="5xx"}[5m])) / '
              '(sum by (opnsense_instance, backend) (rate(opnsense_log_events_haproxy_total[5m])) > 0)'),
    dict(metric="instance:opnsense_ipsec_tunnels_down:count",
         expr="sum by (opnsense_instance) (opnsense_ipsec_phase1_status == bool 0)"),
    dict(metric="instance:opnsense_wireguard_peers_down:count",
         expr="sum by (opnsense_instance) (opnsense_wireguard_peer_status == bool 0)"),
    dict(metric="instance:opnsense_ids_alerts:active",
         expr='sum by (opnsense_instance) (opnsense_ids_recent_alerts{action="blocked"})'),
    # Pins source="netflow" deliberately. The flow family carries TWO independent measurements of the
    # same traffic (Zenarmor and NetFlow) and #346 decision 3 forbids summing them; NetFlow post-repair
    # is authoritative for volume, so pinning it here gives a double-count-safe per-WAN byte rate that
    # dashboards and alerts can build on without every query having to remember the source filter.
    dict(metric="instance:opnsense_flow_bytes:rate5m",
         expr='sum by (opnsense_instance, interface, direction) '
              '(rate(opnsense_flow_bytes_total{source="netflow"}[5m]))'),
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
                     "targetDatasourceUID": ds, "paused": False,
                     "trigger": {"interval": "1m"}, "labels": labels,
                     "expressions": {"A": {"datasourceUID": ds,
                                           "relativeTimeRange": {"from": "10m0s", "to": "0s"},
                                           "model": {"datasource": {"type": "prometheus", "uid": ds},
                                                     "editorMode": "code", "expr": r["expr"],
                                                     "format": "table", "instant": True,
                                                     "range": False,
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
