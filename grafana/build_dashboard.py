#!/usr/bin/env python3
"""
Build the OPNsense Exporter Grafana v2 dynamic dashboard.

Usage:
    python3 build_dashboard.py            # write dashboard.json + run coverage gate
    python3 build_dashboard.py --check    # coverage gate only (non-zero exit if gaps)

The dashboard is a single `dashboard.grafana.app/v2` manifest using TabsLayout with
per-tab/row conditionalRendering driven by hidden sentinel variables, so tabs and rows
auto-hide when their metrics are absent. See grafana/README.md.
"""
import json
import os
import re
import sys

import sentinel_contract
import uids
from annotations import add_annotations
from builder import (INSTANCE_SEL, Builder, sel, grp, RATE, ENABLED, UPDOWN, OKERR,
                     YESNO, GW_STATUS)

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
METRICS_MD = os.path.join(REPO, "docs", "metrics", "metrics.md")
# The exporter's own self-metrics, source-scanned rather than registry-walked (#428).
SELF_METRICS_MD = os.path.join(REPO, "docs", "metrics", "self-metrics.md")
OUT = os.path.join(HERE, "dashboard.json")
# The self-observability companion (#431). A second file rather than a second layout
# inside the first: it has its own uid, its own tags and its own audience, and Grafana
# resolves a dashboard link by uid.
HEALTH_OUT = os.path.join(HERE, "dashboard-health.json")
STATS_PATH = os.path.join(REPO, "grafana", "dashboard-stats.json")
# The feature-sentinel documentation contract (#417): a machine-readable manifest
# plus the generated section of tabs/AUTHORING.md, both derived from the same
# Builder this file already produces. See sentinel_contract.py.
SENTINEL_CONTRACT_PATH = os.path.join(HERE, "sentinel-contract.json")
AUTHORING_PATH = os.path.join(HERE, "tabs", "AUTHORING.md")

# Metrics intentionally NOT charted on a panel (covered structurally / not useful as a
# series). Keep this list short and justified — the coverage gate flags everything else.
# Histogram base names cannot satisfy the word-boundary coverage substring gate: they
# are only ever queried via their _bucket/_sum/_count series (e.g.
# opnsense_exporter_api_request_duration_seconds_bucket), never the bare base name. The
# metric IS paneled (see build_diagnostics), so exempt only the base name from the
# substring check (#126).
COVERAGE_EXEMPT = {
    "opnsense_exporter_api_request_duration_seconds",
    # Same histogram case (#353): the flow source-byte-delta-ratio is charted via its
    # _bucket series (histogram_quantile on the Flow Volume tab), never the bare base.
    "opnsense_flow_source_byte_delta_ratio",
    # Same histogram case (#426): the /metrics handler's own request-duration histogram
    # is charted via its _bucket series in build_diagnostics, never the bare base.
    "opnsense_exporter_server_metrics_request_duration_seconds",
}

# The exporter's own go_*/process_* runtime metrics carry whatever `job` label the user's
# Prometheus scrape config sets. The docs use `job_name: opnsense` (getting-started,
# integration-dashboards, k8s static config) while deploy/k8s/scrape.yaml + the ScrapeConfig
# CRD use `job: opnsense-exporter`. Match both with a regex so the Exporter Runtime panels
# return data regardless of which documented setup the user followed (#113).
JOB = 'job=~"opnsense.*"'

SYSTEM_STATUS = {
    "-1": ("Error", "red"),
    "0": ("Warning", "orange"),
    "1": ("Notice", "yellow"),
    "2": ("OK", "green"),
}
CRASH_STATUS = {"0": ("Reports present", "red"), "1": ("Clear", "green")}

# Leaf modules keep their local `b.tab(...)` contract. Once every leaf exists,
# the orchestrator moves each one into exactly one compact top-level domain.
TAB_GROUPS = [
    # A `None` domain title means "these leaves sit at the top level, ungrouped".
    # Overview has always been top-level; expressing it as an entry here rather than
    # as a special case inside organize_tabs is what lets the health dashboard —
    # three tabs, no useful domain layer — reuse the same function and the same
    # strict leaf-assignment check (#431 step 3).
    (None, ("Overview",)),
    ("System", (
        "System & Resources", "Services, Cron & DynDNS", "Certificates", "UPS",
        "Monit", "HA Sync", "CARP / HA",
    )),
    ("Network", (
        "Interfaces", "Gateways & WAN", "DNS - Unbound", "DHCP",
        "Routing & Neighbors", "Protocol Stats", "NTP", "Chrony",
        "Traffic Shaper", "NetFlow", "FRR Routing", "Captive Portal",
    )),
    ("Security", (
        "Firewall & PF", "Aliases", "IDS/IPS", "CrowdSec", "ClamAV",
        "Q-Feeds", "Zenarmor",
    )),
    ("VPN & remote access", ("VPN", "Tailscale", "NetBird", "Tor")),
    ("Services", ("Syslog", "HAProxy", "Relayd", "Nginx", "Siproxd")),
    ("Observability", (
        "Log-derived Events", "Flow Volume", "Recording rules",
    )),
]

# The self-observability dashboard (#431). Deliberately flat: three tabs do not
# need a domain layer, and burying "Diagnostics" one click deeper on the dashboard
# an operator opens *because something is already wrong* would be a regression.
#
# "Recording rules" is NOT here, and that is a per-rule finding rather than a
# per-tab preference. The owner's rule is that a recording rule relating to
# self-observability may move while the rest stay on the main dashboard; all 14
# bundled rules derive from firewall metrics (`opnsense_*`), none from exporter
# self-metrics (`opnsense_exporter_*`), so the sort produces an empty set today.
# `tests/test_recording_rules.py` enforces the rule going forward rather than
# leaving it as a comment.
HEALTH_TAB_GROUPS = [
    (None, ("Diagnostics", "Log Shipping")),
]

# A tab containing only conditional rows is still rendered by Grafana unless the
# tab itself is conditional. Reuse each module's presence variables here; lists
# form an OR group for features with multiple implementations or datasources.
OPTIONAL_TAB_PRESENCE = {
    "Aliases": "has_alias",
    "DNS - Unbound": "has_unbound",
    "DHCP": ["has_dnsmasq", "has_kea", "has_dhcpv4_isc", "has_dhcpv6_isc"],
    "VPN": ["has_wireguard", "has_openvpn", "has_ipsec"],
    "Tailscale": "has_tailscale",
    "NetBird": "has_netbird",
    "NTP": "has_ntp",
    "ClamAV": "has_clamav",
    "Syslog": ["has_syslog", "has_syslog_logs"],
    "Q-Feeds": "has_qfeeds",
    "NetFlow": "has_netflow",
    "CARP / HA": "has_carp",
    "HAProxy": "has_haproxy",
    "Relayd": "has_relayd",
    "Nginx": "has_nginx",
    "FRR Routing": "has_frr",
    "Monit": "has_monit",
    "CrowdSec": "has_crowdsec",
    "IDS/IPS": "has_ids",
    "UPS": ["has_nut", "has_apcupsd"],
    "Captive Portal": "has_captiveportal",
    "Traffic Shaper": "has_trafficshaper",
    "HA Sync": "has_hasync",
    "Chrony": "has_chrony",
    "Tor": "has_tor",
    "Siproxd": "has_siproxd",
    "Log-derived Events": "has_log_events",
    "Flow Volume": "has_flow",
    "Zenarmor": ["has_zenarmor_metrics", "has_zenarmor_logs"],
    "Log Shipping": "has_logs",
    "Recording rules": "has_recording_rules",
}


# ---- $device sources -----------------------------------------------------
# $device enumerates the kernel DEVICE-name interface label (igb0, ixl0_vlan25,
# pppoe0) — a DISJOINT label space from $interface's configured descriptions (LAN,
# IOT). That contract is #98's and every one of the 14 consuming panels still
# depends on it: they all filter `interface=~"$device"`.
#
# It is sourced from ALL FIVE device-bearing collectors rather than one (#424).
# Collectors are independently disableable and firewall data is not a prerequisite
# for the interface/flow/vnStat views, so a single-metric source held the picker —
# and with it every consuming panel — hostage to one --exporter.disable-* flag.
#
# Three of the five publish the kernel device in an `interface` label and are
# normalised with label_join (the same normalisation the #368 dead-hook rule uses).
DEVICE_SOURCES_INTERFACE_LABEL = (
    "opnsense_firewall_in_ipv4_pass_packets_total",   # collector/firewall.go:77-80
    "opnsense_netflow_cache_packets_total",           # collector/netflow.go:86-89
    "opnsense_vnstat_bytes_total",                    # collector/vnstat.go:37,45-48
)
# The other two already carry a `device` label. Both are info metrics that publish
# an entry even when the device name is unknown — flow.go:779-784 does so
# deliberately, so an operator can SEE an unresolved ifIndex — hence device!="",
# or the picker grows a blank entry.
DEVICE_SOURCES_DEVICE_LABEL = (
    "opnsense_interfaces_info",                       # collector/interfaces.go:148-151
    "opnsense_flow_interface_info",                   # collector/flow.go:554,568
)
# query_result rows arrive as `{device="igb0",opnsense_instance="fw1"} 1 <ms>`, so
# the picker needs a capturing regex to pull the value back out. It must be a JS
# regex LITERAL: Grafana anchors a bare string as ^…$, which never matches inside a
# row. Requiring one or more characters is the second layer of the blank-entry guard.
DEVICE_VALUE_REGEX = r'/device="([^"]+)"/'


def device_variable_query() -> str:
    """Bounded union of every device-bearing source, one series per (appliance,
    device). `or` is a set union on full label sets, so a series is only ever
    dropped by an identically-labelled one — the device set can never shrink.
    Grouping on (opnsense_instance, device) keeps two appliances' identically
    named devices as separate series instead of merging them, and strips every
    other label so the result stays one valueless series per pair."""
    operands = [
        f'label_join({metric}{{{INSTANCE_SEL}}}, "device", "", "interface")'
        for metric in DEVICE_SOURCES_INTERFACE_LABEL
    ] + [
        f'{metric}{{{INSTANCE_SEL},device!=""}}'
        for metric in DEVICE_SOURCES_DEVICE_LABEL
    ]
    return ("query_result(group by (opnsense_instance, device) ("
            + " or ".join(operands) + "))")


def add_core_variables(b: Builder):
    b.variables.append({"kind": "DatasourceVariable", "spec": {
        "name": "datasource", "label": "Data source", "pluginId": "prometheus",
        "current": {"text": "grafanacloud-prom", "value": "grafanacloud-prom"},
        "options": [], "multi": False, "includeAll": False, "allowCustomValue": True,
        "hide": "dontHide", "refresh": "onDashboardLoad",
        "regex": "(?!grafanacloud-usage|grafanacloud-ml-metrics).+", "skipUrlSync": False}})
    # Loki datasource for the mixed-datasource log panels (Zenarmor/syslog raw streams,
    # top-talker tables). Defaults to grafanacloud-logs; log panels/rows auto-hide via
    # Loki presence sentinels when this resolves to a datasource with no matching streams.
    # The regex excludes the account's non-log loki datasources so the picker defaults sanely.
    b.variables.append({"kind": "DatasourceVariable", "spec": {
        "name": "loki_datasource", "label": "Loki data source", "pluginId": "loki",
        "current": {"text": "grafanacloud-logs", "value": "grafanacloud-logs"},
        "options": [], "multi": False, "includeAll": False, "allowCustomValue": True,
        "hide": "dontHide", "refresh": "onDashboardLoad",
        "regex": "(?!grafanacloud-usage-insights|grafanacloud-alert-state-history).+",
        "skipUrlSync": False}})
    b.variables.append({"kind": "QueryVariable", "spec": {
        "name": "opnsense_instance", "label": "OPNsense instance",
        "current": {"text": "All", "value": "$__all"}, "options": [],
        "query": {"kind": "DataQuery", "version": "v0", "group": "prometheus",
                  "datasource": {"name": "${datasource}"},
                  "spec": {"query": "label_values(opnsense_up, opnsense_instance)",
                           "refId": "opnsense_instance"}},
        "refresh": "onDashboardLoad", "regex": "", "sort": "alphabeticalAsc",
        "hide": "dontHide", "includeAll": True, "multi": True, "allValue": ".+",
        "allowCustomValue": True, "skipUrlSync": False}})
    # $interface enumerates the DESCRIPTION-space interface label (LAN, IOT, ...) from the
    # interfaces collector — use it for interface metrics and the description-based firewall
    # log-entries panel.
    b.variables.append({"kind": "QueryVariable", "spec": {
        "name": "interface", "label": "Interface",
        "current": {"text": "All", "value": "$__all"}, "options": [],
        "query": {"kind": "DataQuery", "version": "v0", "group": "prometheus",
                  "datasource": {"name": "${datasource}"},
                  "spec": {"query": 'label_values(opnsense_interfaces_link_state{opnsense_instance=~"$opnsense_instance"}, interface)',
                           "refId": "interface"}},
        "refresh": "onTimeRangeChanged", "regex": "", "sort": "alphabeticalAsc",
        "hide": "dontHide", "includeAll": True, "multi": True, "allValue": ".+",
        "allowCustomValue": True, "skipUrlSync": False}})
    # $device enumerates the kernel DEVICE-name interface label (igb0, ixl0_vlan25, pppoe0)
    # — a DISJOINT label space from $interface (#98) — from every device-bearing
    # collector, so no single --exporter.disable-* flag can empty the picker (#424).
    # See DEVICE_SOURCES_* above for the union and why each source is shaped as it is.
    b.variables.append({"kind": "QueryVariable", "spec": {
        "name": "device", "label": "Device (pf/netflow/interfaces)",
        "current": {"text": "All", "value": "$__all"}, "options": [],
        "query": {"kind": "DataQuery", "version": "v0", "group": "prometheus",
                  "datasource": {"name": "${datasource}"},
                  "spec": {"query": device_variable_query(),
                           "refId": "device"}},
        "refresh": "onTimeRangeChanged", "regex": DEVICE_VALUE_REGEX,
        "sort": "alphabeticalAsc",
        "hide": "dontHide", "includeAll": True, "multi": True, "allValue": ".+",
        "allowCustomValue": True, "skipUrlSync": False}})


# The other dashboard in the family, and the wording of the link to it. Keyed by the
# dashboard doing the linking, so each one advertises its counterpart exactly once and
# neither can link to itself (#431).
SIBLING_LINK = {
    uids.MAIN_UID: (uids.HEALTH_UID, "Exporter health",
                    "Is the exporter feeding this dashboard healthy? Scrape and poll "
                    "health, OTLP delivery, log shipping"),
    uids.HEALTH_UID: (uids.MAIN_UID, "Firewall dashboard",
                      "Back to the OPNsense operational dashboard, same instance and "
                      "time range"),
}


def add_navigation(b: Builder, *, self_uid: str = uids.MAIN_UID):
    """Dashboard-level links, from the frozen registry in uids.py (#419).

    `self_uid` picks the sibling link: each dashboard in the family links to the
    other, and both keep the documentation and runbook links. Passing the dashboard's
    own uid rather than the destination's means a spec cannot accidentally be given a
    link to itself.

    #419 reserved `uids.HEALTH_UID` with `exists=False` and `uids.dash_url()` refuses
    a reserved destination, so this call only started working when #431 generated the
    health dashboard and flipped that flag — a link that 404s could not have shipped
    in between.
    """
    sibling_uid, sibling_title, sibling_tip = SIBLING_LINK[self_uid]
    b.dashboard_links([
        uids.dashboard_link(sibling_title, uid=sibling_uid, tooltip=sibling_tip),
        uids.external_link(
            "Documentation", uids.DOCS_BASE,
            tooltip="Metric reference, collector reference and configuration"),
        uids.external_link(
            "Alert runbooks", uids.RUNBOOK_URL,
            tooltip="What each generated alert means and what to do about it"),
    ])


def build_overview(b: Builder):
    up = b.stat("Exporter scrape", sel("opnsense_up"), mappings=UPDOWN,
                color_mode="background",
                thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
                desc="Latest OPNsense API scrape: 1 is up, 0 is unreachable or failed.",
                legend="{{opnsense_instance}}", w=3, h=4)
    fw = b.stat("Firewall health", sel("opnsense_firewall_status"), mappings=OKERR,
                color_mode="background",
                thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
                desc="Aggregate OPNsense subsystem health: 1 is healthy, 0 has errors.",
                legend="{{opnsense_instance}}", w=3, h=4)
    crash = b.stat("Crash reports", sel("opnsense_crash_reporter_status"), mappings=CRASH_STATUS,
                   color_mode="background",
                   thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
                   desc="Reports present means OPNsense has an unacknowledged crash report.",
                   legend="{{opnsense_instance}}", w=3, h=4)
    reboot = b.stat("Reboot required", sel("opnsense_firmware_needs_reboot"), mappings=YESNO,
                    color_mode="background",
                    thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}],
                    desc="Whether installed firmware changes require a reboot.",
                    legend="{{opnsense_instance}}", w=3, h=4)
    syscode = b.stat("System health", sel("opnsense_system_status_code"), mappings=SYSTEM_STATUS,
                     color_mode="background",
                     thresholds=[{"color": "red", "value": None}, {"color": "orange", "value": 0},
                                 {"color": "yellow", "value": 1}, {"color": "green", "value": 2}],
                     desc="OPNsense health code: -1 error, 0 warning, 1 notice, 2 OK.",
                     legend="{{opnsense_instance}}", w=3, h=4)
    pkgs = b.stat("Package upgrades", sel("opnsense_firmware_upgrade_packages_count"),
                  thresholds=[{"color": "green", "value": None}, {"color": "yellow", "value": 1}],
                  color_mode="background", desc="Packages available from the configured firmware channel.",
                  legend="{{opnsense_instance}}", w=3, h=4)
    uptime = b.stat("Uptime", sel("opnsense_system_uptime_seconds"), unit="s", w=3, h=4,
                    graph="none", color="thresholds", legend="{{opnsense_instance}}",
                    desc="Time since the firewall last booted.")
    svc = b.stat("Stopped services", sel("opnsense_services_stopped_total"),
                 thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}],
                 color_mode="background", desc="Configured services currently not running.",
                 legend="{{opnsense_instance}}", w=3, h=4)

    pressure_thresholds = [{"color": "green", "value": None},
                           {"color": "yellow", "value": 70}, {"color": "red", "value": 90}]
    mem = b.stat("Memory used", f'100 * {sel("opnsense_system_memory_used_bytes")} / '
                 f'{sel("opnsense_system_memory_total_bytes")}', unit="percent", w=4, h=5,
                 graph="none", color_mode="background", thresholds=pressure_thresholds,
                 desc="Physical memory currently in use.")
    pf = b.stat("PF states", f'100 * {sel("opnsense_firewall_pf_states_current")} / '
                f'clamp_min({sel("opnsense_firewall_pf_states_limit")}, 1)',
                unit="percent", w=4, h=5, graph="none", color_mode="background",
                thresholds=pressure_thresholds, desc="Current PF state-table utilisation.")
    load = b.stat("Load (1m)", sel("opnsense_system_load_average", 'interval="1"'),
                  decimals=2, w=4, h=5, graph="none", desc="One-minute system load average.")
    # `max by (opnsense_instance)`, not a bare `max` (#468). "Highest" and "worst"
    # meant one box's filesystems when these were written; a bare max silently
    # redefines them as worst-across-the-selection without a word of the
    # description becoming false, so a second firewall's full disk can be
    # attributed to the first. The stat panel renders one tile per series, so a
    # single-instance selection looks exactly as it did.
    disk = b.stat("Highest disk use",
                  f'100 * max {grp()} ({sel("opnsense_system_disk_usage_ratio")})',
                  unit="percent", w=4, h=5, graph="none", color_mode="background",
                  legend="{{opnsense_instance}}",
                  thresholds=pressure_thresholds, desc="Highest current utilisation across mounted filesystems.")
    temp = b.stat("Max Temp", f'max {grp()} ({sel("opnsense_temperature_celsius")})', unit="celsius",
                  w=4, h=5, graph="none", thresholds=[{"color": "green", "value": None},
                                        {"color": "yellow", "value": 70}, {"color": "red", "value": 85}],
                  color="thresholds", color_mode="background", legend="{{opnsense_instance}}",
                  desc="Highest reported hardware temperature.")
    cpu = b.stat("CPU Busy %", f'100 - {sel("opnsense_activity_cpu_idle_percent")}',
                 unit="percent", w=4, h=5, graph="none", color_mode="background",
                 thresholds=pressure_thresholds, desc="Current non-idle CPU percentage.")

    gw_status = b.statetimeline("Gateway Status", [(sel("opnsense_gateways_status"),
                                "{{name}} ({{address}})")], GW_STATUS, w=12, h=7,
                                desc=(
                                     "Per-gateway state over time from OPNsense's own dpinger "
                                     "monitoring — up, down, or a loss/latency warning. A "
                                     "gateway with no monitoring IP configured reports no state "
                                     "and so has no row."
                                ))
    wan_rtt = b.ts("Gateway RTT", [(sel("opnsense_gateways_rtt_milliseconds"), "{{name}} rtt"),
                                   (sel("opnsense_gateways_rttd_milliseconds"), "{{name}} stddev")],
                   unit="ms", w=12, h=7)
    health_hist = b.statushistory("Health History",
                                  [(sel("opnsense_up"), "up"),
                                   (sel("opnsense_firewall_status"), "firewall"),
                                   (sel("opnsense_crash_reporter_status"), "crash-free")],
                                  OKERR, w=24, h=5,
                                  desc=(
                                       "Three independent signals over time: exporter "
                                       "reachability (opnsense_up), the firewall's own health "
                                       "status, and the crash reporter. As above, a gap means no "
                                       "scrape, which is a different fault from a red square."
                                  ))

    b.tab("Overview", [
        b.row("Health", [up, fw, crash, reboot, syscode, pkgs, uptime, svc]),
        b.row("Resource pressure", [mem, pf, load, disk, temp, cpu]),
        b.row("Connectivity & History", [gw_status, wan_rtt, health_hist]),
        b.row("Exporter Health", exporter_health_summary(b)),
    ])


def exporter_health_summary(b: Builder) -> list:
    """Three tiles answering "can I trust the rest of this dashboard?" (#431).

    The self-observability detail moved to its own dashboard, which creates a new
    way to be wrong: an operator reading a flat graph has no reason to suspect the
    exporter stopped collecting rather than the firewall going quiet. These stay
    behind as the tripwire, and every one of them links through to the detail.

    Deliberately three tiles and no graphs. Anything that needs a time axis to read
    belongs on the health dashboard; duplicating panels here would give two places
    to fix a description and one of them would rot.
    """
    detail = [uids.data_link("Open the exporter health dashboard",
                             uid=uids.HEALTH_UID, tab=("Diagnostics", ""))]
    failing = b.stat(
        "Failing Collectors",
        f'sum {grp()} ({sel("opnsense_exporter_scrape_collector_success")} == bool 0)',
        w=4, h=5, graph="none", color_mode="background",
        legend="{{opnsense_instance}}",
        thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}],
        desc="Sub-collectors whose most recent scheduled poll failed. Anything above "
             "zero means part of this dashboard is showing retained data rather than "
             "current data — which tab is affected is on the health dashboard.")
    stalest = b.stat(
        "Stalest Collector Data",
        f'max {grp()} (time() - {sel("opnsense_exporter_collector_last_success_timestamp_seconds")})',
        unit="s", w=4, h=5, graph="none", color_mode="background",
        legend="{{opnsense_instance}}",
        thresholds=[{"color": "green", "value": None}, {"color": "yellow", "value": 900},
                    {"color": "red", "value": 3600}],
        desc="Age of the oldest fully-clean collector poll. Compare against the poll "
             "tiers before alarming: the cold tier legitimately sits at 15 minutes, so "
             "a value under an hour is normal on a healthy exporter.")
    api_errs = b.stat(
        "OPNsense API Error Rate",
        f'sum {grp()} (rate({sel("opnsense_exporter_endpoint_errors_total")}[{RATE}]))',
        unit="errps", w=4, h=5, graph="none", color_mode="background",
        legend="{{opnsense_instance}}",
        thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 0.01}],
        desc="Errors per second calling the firewall's API. A plugin-gated endpoint "
             "returning 404 is not counted, so anything here is a real failure — auth, "
             "TLS, timeout or a 5xx.")
    for name in (failing, stalest, api_errs):
        b.panel_links(name, detail)
    return [failing, stalest, api_errs]


def build_diagnostics(b: Builder):
    # scope="target_join": go_*/process_* come from the Go client library and carry
    # no appliance label at all, so the only portable way to scope them is the
    # co-scrape identity — they are gathered from the SAME /metrics target as
    # opnsense_up (main.go hands selfMetricsRegistry to the same handler), so
    # joining on (job, instance) tells us whether the SELECTED box's exporter is
    # the one exposing them. The JOB matcher is kept as belt-and-braces: go_goroutines
    # is a near-universal series name and the join is the only thing narrowing it.
    b.sentinel("has_go_runtime", metric="go_goroutines", more=JOB,
               scope="target_join")
    up = b.statushistory("Scrape Success (opnsense_up)", [(sel("opnsense_up"), "{{opnsense_instance}}")],
                         UPDOWN, w=12, h=6,
                         desc=(
                              "1 = the exporter reached the firewall on its last poll. A GAP is "
                              "not a zero: zero means the exporter answered and reported the "
                              "firewall unreachable, while a gap means Prometheus got nothing "
                              "from the exporter at all."
                         ))
    # #439: this panel used to plot opnsense_exporter_scrapes_total against
    # opnsense_exporter_scrape_skips_total and diagnose "mutex pile-up in front of a
    # slow firewall". The skip counter had no increment site after #336 — serving is a
    # lock-free replay of the poll snapshot, so no scrape can queue behind collection —
    # and it was removed, taking the permanently-flat second series with it. The
    # replacement pairs serving rate against the rate of OPNsense API calls the poll
    # scheduler actually makes. Both move, and their independence IS the point: the
    # scrape rate is set by Prometheus, the API rate by the poll tiers, and neither
    # drives the other.
    scrapes = b.ts("Scrape Rate vs OPNsense API Rate",
                   [(f'rate({sel("opnsense_exporter_scrapes_total")}[{RATE}])',
                     "/metrics scrapes served {{opnsense_instance}}"),
                    (f'sum by (opnsense_instance) (rate({sel("opnsense_exporter_api_requests_total")}[{RATE}]))',
                     "OPNsense API calls (background poll) {{opnsense_instance}}")],
                   unit="reqps", w=12, h=6,
                   desc="How often Prometheus scrapes this exporter, against how often the exporter actually "
                        "calls the firewall. Since #336 the two are decoupled: a scrape replays an in-memory "
                        "snapshot and makes no API call, so scraping harder costs the firewall nothing and the "
                        "API line moves only when you change poll intervals, enable collectors, or the response "
                        "cache stops serving hits. API rate climbing on its own is worth a look; scrape rate "
                        "climbing on its own is not. Serving backpressure, if you are hunting it, shows up as "
                        "HTTP 503s from the exporter's in-flight cap, not on this panel.")
    errs_ts = b.ts("Endpoint Errors (rate)", [(f'rate({sel("opnsense_exporter_endpoint_errors_total")}[{RATE}])',
                   "{{endpoint}}")], unit="errps", w=12, h=7,
                   desc=(
                        "OPNsense API errors per second, per endpoint. A plugin-gated endpoint "
                        "that 404s is NOT counted here — the client treats that as "
                        "feature-absent — so anything on this panel is a real failure: auth, "
                        "TLS, timeout or a 5xx."
                   ))
    errs_tbl = b.table("Endpoint Errors (total)",
                       [f'sort_desc(sum {grp("endpoint")} ({sel("opnsense_exporter_endpoint_errors_total")}))'],
                       renames={"Value": "Errors", "endpoint": "Endpoint", "opnsense_instance": "Instance"},
                       w=12, h=7,
                       desc=(
                            "Cumulative API errors per endpoint since the exporter started. A "
                            "large total with a flat rate panel beside it is history, not a live "
                            "problem; the two are meant to be read together."
                       ))
    # #494: the soft series budget is REPORTED, never enforced — nothing is dropped
    # or refused when it is exceeded. This counts the COLLECTOR registry only, which
    # is what /metrics and the OTLP bridge serve; the exporter's own process_*/go_*
    # and otlp delivery-health families live on a separate self registry and are not
    # in this number, so it reads lower than what the tenant finally stores for this
    # job. Charted as a rate alongside the level because a budget breach is far less
    # interesting than the slope that got there.
    series_total = b.ts("Collector Series Total (soft budget)",
                        [(sel("opnsense_exporter_series_total"), "series {{opnsense_instance}}")],
                        w=12, h=6,
                        desc="Total series on the collector registry, the number --exporter.series-budget "
                             "is measured against. The budget is advisory: exceeding it logs a rate-limited "
                             "warning and flags the console's Cardinality tab, and changes nothing about what "
                             "is exported. Excludes the exporter's own process_*/go_* and OTLP delivery "
                             "families, which are on a separate registry, so expect this to read lower than "
                             "your tenant's series count for this job.")
    build = b.table("Build Info", [sel("opnsense_exporter_build_info")],
                    excludes=["Value", "__name__", "job", "instance"],
                    renames={"version": "Version", "goversion": "Go", "opnsense_instance": "Instance"},
                    w=12, h=6,
                    desc="Requires the exporter build that emits opnsense_exporter_build_info.")
    cov = b.statetimeline("Collector Enabled", [(sel("opnsense_exporter_collector_enabled"),
                          "{{collector}}")],
                          {"0": ("Disabled", "red"), "1": ("Enabled", "green")}, w=12, h=8,
                          desc="opnsense_exporter_collector_enabled: which collectors are on.")

    scrape_dur = b.ts("Collector Poll Duration",
                      [(sel("opnsense_exporter_scrape_collector_duration_seconds"), "{{collector}}")],
                      unit="s", w=12, h=8,
                      desc="Duration of the latest scheduled background poll. The metric keeps its "
                           "historical node_exporter-compatible name; /metrics only replays this value.")
    scrape_ok = b.statetimeline("Collector Poll Success",
                                [(sel("opnsense_exporter_scrape_collector_success"), "{{collector}}")],
                                OKERR, w=12, h=8,
                                desc="1 = the latest scheduled sub-collector poll completed cleanly; "
                                     "0 = error or panic. The metric name is retained for compatibility.")

    # Poll scheduler observability (#336): each collector polls the OPNsense API on its
    # own tier (fast/medium/slow/cold), decoupled from the Prometheus scrape. These
    # panels expose the configured interval, the age of the last poll ATTEMPT, and the
    # countdown to the next poll — the same data the operator console shows.
    poll_interval = b.table("Collector Poll Interval",
                            [sel("opnsense_exporter_collector_poll_interval_seconds")],
                            renames={"Value": "Interval", "collector": "Collector", "opnsense_instance": "Instance"},
                            unit_overrides={"Interval": "s"},
                            excludes=["__name__", "job", "instance"], w=8, h=8,
                            desc="Configured poll interval per collector (#336): fast 15s / medium 60s / "
                                 "slow 5m / cold 15m, overridable via --collector.poll-interval-override.")
    # #382: this panel used to be titled "Collector Poll Age (freshness)" and told the
    # operator that age past the interval meant polls were failing. That was backwards.
    # last_poll_timestamp advances on EVERY attempt including a failed one, so a
    # collector failing every single poll keeps this clock at sub-interval values
    # forever while the snapshot it replays ages indefinitely. It is scheduler
    # liveness only; data age lives on the two panels in the row below.
    poll_age = b.ts("Collector Last Attempt Age (scheduler liveness)",
                    [(f'time() - {sel("opnsense_exporter_collector_last_poll_timestamp_seconds")}', "{{collector}}")],
                    unit="s", w=8, h=8,
                    desc="Seconds since each collector's last poll ATTEMPT completed — successful or not. "
                         "This is SCHEDULER LIVENESS, NOT data freshness: a failed poll advances this clock "
                         "just like a successful one, so a collector that has been failing for six hours "
                         "still reads under one interval here while replaying six-hour-old retained data. "
                         "A value climbing past the collector's interval means the poller itself is stalled "
                         "or starved of a concurrency slot. For how old the served data actually is, read "
                         "'Collector Retained Data Age' below (#382).")
    next_poll = b.ts("Collector Next Poll (in)",
                     [(f'{sel("opnsense_exporter_collector_next_poll_timestamp_seconds")} - time()', "{{collector}}")],
                     unit="s", w=8, h=8,
                     desc="Seconds until each collector's next scheduled poll, read from the scheduler's "
                          "actual fixed-cadence deadline rather than derived from last poll + interval (#385).")

    # #382: the two honest data clocks. Error-aware retention (#336 D8) deliberately
    # keeps a collector's last-good metrics when a later poll fails with nothing to
    # show, so the exported domain metrics can be arbitrarily old. These two panels are
    # the only place that age is visible.
    snapshot_age = b.ts("Collector Retained Data Age (true data age)",
                        [(f'time() - {sel("opnsense_exporter_collector_snapshot_timestamp_seconds")}',
                          "{{collector}}")],
                        unit="s", w=12, h=8,
                        desc="Seconds since each collector's stored metric buffer was last REPLACED — the "
                             "true age of the data every scrape and every OTLP export replays. It advances "
                             "on a successful poll and on a partial-error poll that still emitted data, and "
                             "deliberately does NOT advance when a failed poll emitted nothing and the "
                             "last-good buffer was retained. This is the freshness number: a line climbing "
                             "past ~3x that collector's poll interval means it is serving stale retained "
                             "data, which is what OPNsenseCollectorDataStale alerts on. A collector that "
                             "has never stored data has no line at all (the gauge is absent rather than 0, "
                             "so it cannot render as a 1970 epoch) — OPNsenseCollectorNeverStoredData "
                             "covers that case.")
    success_age = b.ts("Collector Time Since Last Full Success",
                       [(f'time() - {sel("opnsense_exporter_collector_last_success_timestamp_seconds")}',
                         "{{collector}}")],
                       unit="s", w=12, h=8,
                       desc="Seconds since each collector's last FULLY CLEAN poll. Unlike retained data age "
                            "this does not advance on a partial-error poll, so the two together separate "
                            "'refreshed but degraded' from 'fully healthy': if this climbs while retained "
                            "data age stays low, the collector is still refreshing part of its data but one "
                            "of its endpoints has been erroring the whole time — see the Endpoint Errors "
                            "panels above for which one. OPNsenseCollectorDegraded alerts on this.")

    # OTLP delivery health (#388). The exporter connects lazily, so "otlp metrics export
    # enabled" is logged before any network I/O: a wrong endpoint or expired credential
    # delivers nothing indefinitely. KNOWN LIMITATION — these series cannot reach a
    # pure-OTLP backend while the OTLP path is down; read them at /metrics or on the
    # operator console during an outage, and as historical evidence after recovery.
    #
    # These four panels were structurally empty for every instance selection until
    # #466: `telemetry.Start` received the RAW self-metrics registry, so the otlp_*
    # family carried no opnsense_instance, while the panels filtered on it with `=~`
    # — and `=~` never matches an absent label. The fix gave the family identity
    # (main.go now passes logSelfMetricsRegisterer) rather than removing the filter,
    # because "which firewall's exporter failed to deliver" is the whole question
    # these panels answer. `main_test.go`'s
    # TestSelfMetricsRegistryIsNeverRegisteredOnBare fails if any future family is
    # registered bare the same way.
    #
    # scope="self_labeled", not "target_join": the family now carries
    # opnsense_instance for the same reason logship's does — it is registered through
    # the instance-stamping wrapper. `has_go_runtime` stays target_join because
    # go_*/process_* come from the client library and genuinely cannot carry an
    # appliance label.
    b.sentinel("has_otlp", metric="opnsense_exporter_otlp_enabled",
               scope="self_labeled")
    otlp_on = b.stat("OTLP Export Enabled", sel("opnsense_exporter_otlp_enabled"),
                     mappings=ENABLED, color_mode="background", graph="none", w=4, h=7,
                     thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
                     desc="1 = the OTLP metric push pipeline is RUNNING. It does NOT mean delivery is "
                          "working: the exporter connects lazily, so this reads 1 from startup even with a "
                          "wrong endpoint or an expired credential. Judge delivery by the two panels to the "
                          "right. Construction failure is fatal at startup, so there is no "
                          "configured-but-inactive state — the metric is either 1 or absent.")
    otlp_fails = b.stat("OTLP Consecutive Failures",
                        sel("opnsense_exporter_otlp_consecutive_failures"),
                        w=5, h=7, color_mode="background",
                        thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}],
                        desc="Exports that have failed back-to-back. Reset to 0 by the next success, so any "
                             "sustained non-zero value is an ongoing delivery outage rather than a blip. "
                             "OPNsenseOTLPDeliveryFailing alerts on this.")
    otlp_age = b.stat("Time Since Last Successful OTLP Export",
                      f'time() - ({sel("opnsense_exporter_otlp_last_success_timestamp_seconds")} > 0)',
                      unit="s", w=5, h=7, graph="none", color_mode="background",
                      thresholds=[{"color": "green", "value": None}, {"color": "yellow", "value": 300},
                                  {"color": "red", "value": 900}],
                      desc="Seconds since the last export the backend accepted. NO DATA here means no "
                           "export has EVER succeeded since this exporter started — the gauge is 0 in that "
                           "state and the `> 0` guard suppresses it deliberately, because subtracting 0 "
                           "from time() would render a 56-year age as though a real export had once "
                           "landed. No-data plus a rising consecutive-failure count is the "
                           "never-worked-since-boot case (wrong endpoint / bad credential).")
    otlp_rate = b.ts("OTLP Export Rate (by result)",
                     [(f'sum {grp("result")} (rate({sel("opnsense_exporter_otlp_exports_total")}[{RATE}]))',
                       "{{result}}")],
                     unit="reqps", w=10, h=7,
                     desc="Export calls per second by outcome, counted once per export call and never per "
                          "metric. Both result values are seeded to 0 at startup, so a healthy exporter "
                          "shows a flat zero error line rather than an absent series.")

    go_goro = b.ts("Exporter Goroutines", [(f"go_goroutines{{{JOB}}}", "goroutines")],
                   w=8, h=6,
                   desc=(
                        "Go runtime goroutines in the exporter process. NOTE: go_* metrics carry "
                        "no opnsense_instance label, so this panel is scoped by scrape job and "
                        "does NOT follow the $opnsense_instance picker — with two exporters "
                        "scraped it shows both."
                   ))
    go_mem = b.ts("Exporter Memory", [(f"process_resident_memory_bytes{{{JOB}}}", "RSS"),
                  (f"go_memstats_heap_inuse_bytes{{{JOB}}}", "heap inuse")],
                  unit="bytes", w=8, h=6,
                  desc=(
                       "Exporter process RSS and Go heap in use. Like the other two process "
                       "panels this is scoped by scrape job, not by $opnsense_instance, because "
                       "process_*/go_* metrics carry no appliance label. RSS above heap is "
                       "normal — it includes the Go runtime's arenas."
                  ))
    go_cpu = b.ts("Exporter CPU", [(f"rate(process_cpu_seconds_total{{{JOB}}}[{RATE}])",
                  "cpu")], unit="percentunit", w=8, h=6,
                  desc=(
                       "CPU seconds per second consumed by the exporter process: 1.0 means one "
                       "core saturated. Scoped by scrape job rather than by $opnsense_instance, "
                       "since process_* metrics carry no appliance label."
                  ))

    # Per-endpoint API request rate + p95 latency, sourced from the client choke-point
    # self-metrics (#126). api_requests_total gives the denominator for a per-endpoint
    # error rate; the duration histogram shows which endpoint regressed when a
    # collector's background poll duration spikes.
    api_rate = b.ts("API Request Rate (by endpoint)",
                    [(f'sum {grp("endpoint")} (rate({sel("opnsense_exporter_api_requests_total")}[{RATE}]))',
                      "{{endpoint}}")], unit="reqps", w=12, h=7)
    api_p95 = b.ts("API Request p95 Latency (by endpoint)",
                   [(f'histogram_quantile(0.95, sum {grp("le", "endpoint")} '
                     f'(rate(opnsense_exporter_api_request_duration_seconds_bucket'
                     f'{{opnsense_instance=~"$opnsense_instance"}}[{RATE}])))', "{{endpoint}}")],
                   unit="s", w=12, h=7,
                   desc="p95 of opnsense_exporter_api_request_duration_seconds by endpoint.")

    # Response cache (#196). A cache hit issues no API request, so it is invisible to
    # api_requests_total above — that absence is by design (it is what makes the request
    # rate drop when caching works), but it cannot be told apart from a disabled
    # collector. These panels make the cache observable directly.
    cache_hit_ratio = b.stat(
        "API Cache Hit Rate",
        # Per instance, NOT a blended fleet ratio (#468). A ratio is the one shape
        # where merging actively misleads rather than merely fusing: sum/sum weights
        # the answer by call volume, so one exporter with a broken cache drags the
        # figure down and a healthy one hides it — and neither box's real hit rate
        # appears anywhere on the panel.
        f'sum {grp()} (rate({sel("opnsense_exporter_api_cache_hits_total")}[{RATE}])) / '
        f'(sum {grp()} (rate({sel("opnsense_exporter_api_cache_hits_total")}[{RATE}])) + '
        f'sum {grp()} (rate({sel("opnsense_exporter_api_cache_misses_total")}[{RATE}])))',
        unit="percentunit", w=6, h=7, legend="{{opnsense_instance}}",
        desc="Share of calls to cacheable endpoints served from cache rather than the "
             "firewall. Endpoints with no TTL are not counted, so this describes the cache "
             "itself. Expect a high steady-state value: slow-moving endpoints are re-fetched "
             "only once per --exporter.cache-ttl / --exporter.firmware-cache-ttl.")
    cache_hits = b.ts(
        "API Cache Hits (by kind)",
        [(f'sum {grp("kind")} (rate({sel("opnsense_exporter_api_cache_hits_total")}[{RATE}]))', "{{kind}}")],
        unit="reqps", w=9, h=7,
        desc='kind="body": a replayed payload from a slow-moving endpoint (firmware status, '
             'certificate inventory, CPU/system identity). kind="absent": a replayed 404 from a '
             'plugin-gated endpoint — the plugin is not installed on this firewall, and the '
             'exporter is no longer re-asking on every scheduled poll.')
    cache_by_ep = b.table(
        "API Cache Hits (by endpoint)",
        [f'sort_desc(sum {grp("endpoint", "kind")} ({sel("opnsense_exporter_api_cache_hits_total")}))'],
        renames={"Value": "Hits", "endpoint": "Endpoint", "kind": "Kind", "opnsense_instance": "Instance"},
        w=9, h=7,
        desc="Which endpoints the cache is actually saving calls on. An endpoint with a "
             "configured TTL and no hits (see opnsense_exporter_api_cache_misses_total) has an "
             "ineffective TTL.")

    # ---- annotation writing (#428) ---------------------------------------
    # Opt-in (--annotations.enabled) and, once on, deliberately quiet: nothing is
    # written until a watched event occurs, which on a healthy firewall may be days.
    # That is exactly why these four series need to be visible — a successful start
    # proves nothing, so without them "correctly quiet" and "the Grafana token expired
    # three weeks ago" look identical. The family was registered through
    # logship.SelfMetricsRegisterer, so unlike otlp_* it DOES carry opnsense_instance
    # and the ordinary instance matcher scopes it (scope="self_labeled").
    b.sentinel("has_annotations", metric="opnsense_exporter_annotations_written_total",
               scope="self_labeled")
    ann_rate = b.ts("Annotation Writes (rate)",
                    [(f'rate({sel("opnsense_exporter_annotations_written_total")}[{RATE}])', "written"),
                     (f'rate({sel("opnsense_exporter_annotations_failed_total")}[{RATE}])', "failed"),
                     (f'rate({sel("opnsense_exporter_annotations_rate_limited_total")}[{RATE}])',
                      "rate limited"),
                     (f'rate({sel("opnsense_exporter_annotations_undeliverable_total")}[{RATE}])',
                      "undeliverable"),
                     (f'rate({sel("opnsense_exporter_annotations_skipped_total")}[{RATE}])', "skipped")],
                    unit="ops", w=12, h=7,
                    desc="Annotations written to Grafana per second, against those that failed or were "
                         "skipped. A failed write is RETRIED on the next detection pass — the event is "
                         "not marked seen — so a brief failure rate that stops without a matching drop "
                         "in writes cost nothing. rate limited and undeliverable are BREAKDOWNS of "
                         "failed, not additions to it, and they are the two shapes worth telling apart "
                         "(#519): rate limited is HTTP 429, after which the writer backs off and posts "
                         "nothing until the wait expires (honouring Retry-After when the server sends "
                         "one) — a Grafana org shares one annotation limit, so another writer can cause "
                         "it. undeliverable is a 4xx that can never succeed (malformed body, or a token "
                         "without the annotation write permission); those events are abandoned rather "
                         "than retried, so a sustained rate means annotations are being lost and the "
                         "exporter log names the status. Skips are lossier still: a detection pass hit "
                         "its --annotations.max-per-cycle cap and left the excess for the next pass, so "
                         "a sustained skip rate means the backlog is not draining and the cap needs "
                         "raising.")
    ann_age = b.stat("Time Since Last Annotation Written",
                     f'time() - ({sel("opnsense_exporter_annotations_last_success_timestamp_seconds")} > 0)',
                     unit="s", w=12, h=7, graph="none", color_mode="background",
                     thresholds=[{"color": "green", "value": None}],
                     desc="Seconds since the last annotation Grafana accepted. Deliberately has NO red "
                          "threshold: a long age is the normal state on a quiet firewall and says "
                          "nothing on its own. NO DATA means no annotation has EVER been written since "
                          "this exporter started. Read it beside the failure rate — a climbing age with "
                          "a non-zero failure rate is a broken token or URL, while a climbing age with "
                          "no failures at all is simply a firewall with nothing to report.")

    # ---- /metrics handler self-observability (#426) ----------------------
    # No presence sentinel: unlike annotations (opt-in) or OTLP (opt-in), the
    # handler serving THIS dashboard's own data source is by definition always
    # running whenever any of these panels can render at all — the same
    # reasoning "Scrape Health" above already relies on for opnsense_up. The
    # family registers through the SAME instance-stamping wrapper as the
    # annotation writer (main.go passes logSelfMetricsRegisterer, reused
    # rather than duplicated), so it carries opnsense_instance and is scoped
    # here with the ordinary sel() instance matcher (scope="self_labeled"), not
    # target_join. Registering bare and then filtering on opnsense_instance anyway
    # is the #466 mistake, and main_test.go now fails on it.
    server_inflight = b.stat(
        "Metrics Handler In-Flight Requests",
        sel("opnsense_exporter_server_metrics_requests_in_flight"),
        unit="short", w=6, h=6, graph="none", legend="{{opnsense_instance}}",
        desc="Requests currently admitted and being served by /metrics, bounded by the "
             "exporter's --collector.poll-interval-independent in-flight cap (40). "
             "Self-referential by construction: the very scrape that reads this gauge is "
             "itself one of the requests it counts, so it never reads 0 in its own response "
             "- read it as a trend, not a single-sample zero/nonzero check.")
    server_req_rate = b.ts(
        "Metrics Handler Requests (rate, by status)",
        [(f'rate({sel("opnsense_exporter_server_metrics_requests_total")}[{RATE}])',
          "{{status}} {{opnsense_instance}}")],
        unit="reqps", w=9, h=6,
        desc="Admitted /metrics requests completed per second, by outcome status: ok = "
             "served (however the underlying gather went - see Gather Errors below); "
             "bad_request = rejected collect[]/exclude[] parameters; internal_error = the "
             "scrape view itself failed to register. A request the admission cap rejected "
             "outright is never counted here - see the Rejections panel.")
    server_rejected = b.ts(
        "Metrics Handler Admission Rejections (rate)",
        [(f'rate({sel("opnsense_exporter_server_metrics_requests_rejected_total")}[{RATE}])',
          "{{reason}} {{opnsense_instance}}")],
        unit="reqps", w=9, h=6,
        desc="Requests refused before admission because 40 concurrent /metrics requests "
             "were already being served (reason=in_flight_limit). The exporter's listener "
             "has no authentication by default, so any reachable client can drive this; a "
             "sustained non-zero rate means either a slow-reading scraper backlog or more "
             "concurrent scrapers than the exporter is sized for.")
    server_gather_err = b.ts(
        "Metrics Handler Gather Errors / Partial Scrapes (rate)",
        [(f'rate({sel("opnsense_exporter_server_metrics_gather_errors_total")}[{RATE}])',
          "{{reason}} {{opnsense_instance}}")],
        unit="errps", w=6, h=6,
        desc="Gather() errors ContinueOnError caught and logged instead of blanking the "
             "whole response (#81) - most commonly a collector emitting a duplicate label "
             "tuple. The response still returned 200 with whatever WAS collected; this is "
             "the only queryable evidence that a scrape was partial rather than complete.")
    server_p95 = b.ts(
        "Metrics Handler Request p95 Latency (by status)",
        [(f'histogram_quantile(0.95, sum {grp("le", "status")} '
          f'(rate(opnsense_exporter_server_metrics_request_duration_seconds_bucket'
          f'{{opnsense_instance=~"$opnsense_instance"}}[{RATE}])))', "{{status}}")],
        unit="s", w=6, h=6,
        desc="p95 of opnsense_exporter_server_metrics_request_duration_seconds, timed from "
             "admission to response completion, by outcome status. Excludes requests the "
             "admission cap rejected outright (they never do enough work to be worth "
             "timing) - a rejection shows up on the Rejections panel instead.")

    b.tab("Diagnostics", [
        b.row("Scrape Health", [up, scrapes, errs_ts, errs_tbl]),
        b.row("Per-Collector Scrapes", [scrape_dur, scrape_ok]),
        b.row("Per-Collector Poll Schedule", [poll_interval, poll_age, next_poll]),
        b.row("Per-Collector Data Freshness", [snapshot_age, success_age]),
        b.row("OTLP Delivery Health", [otlp_on, otlp_fails, otlp_age, otlp_rate],
              present="has_otlp"),
        b.row("API Requests (per endpoint)", [api_rate, api_p95]),
        b.row("API Response Cache", [cache_hit_ratio, cache_hits, cache_by_ep]),
        b.row("Grafana Annotation Writing", [ann_rate, ann_age], present="has_annotations"),
        b.row("Metrics Handler Serving Path",
              [server_inflight, server_req_rate, server_rejected, server_gather_err, server_p95]),
        b.row("Exporter Build & Collectors", [build, cov, series_total]),
        b.row("Exporter Runtime (Go client metrics)", [go_goro, go_mem, go_cpu],
              present="has_go_runtime"),
    ])


# ---- coverage gate -------------------------------------------------------
def load_catalogue() -> list:
    """Every metric this exporter can emit: firewall metrics AND its own self-metrics.

    Two sources, because no single one sees everything (#428). METRICS_MD is generated
    by walking the COLLECTOR registry, so it covers firewall data and internal/collector's
    own meta family — and nothing else. Every metric registered outside that package was
    therefore invisible to this gate: the whole opnsense_exporter_logs_* family, the
    annotations writer, and the OTLP delivery series could ship with no panel and no
    complaint. SELF_METRICS_MD is generated by scanning the source for metric
    declarations (scripts/docgen/selfmetrics.go) and closes that hole.

    The two overlap on internal/collector's meta metrics, which is intended: they are
    reached by both mechanisms and the set union deduplicates them.
    """
    names = []
    for path in (METRICS_MD, SELF_METRICS_MD):
        with open(path) as f:
            for line in f:
                m = re.match(r"\|\s*(opnsense_[a-z0-9_]+)\s*\|", line)
                if m:
                    names.append(m.group(1))
    return sorted(set(names))


def coverage(*builders: Builder) -> list:
    """Catalogue metrics referenced by NO panel across the whole dashboard family.

    Variadic rather than single-Builder because the gate asks "is this metric
    visible to an operator anywhere", not "is it on this particular file" (#431).
    Scoping it to one Builder made splitting content structurally impossible: the
    moment a panel moved to a second dashboard its metric read as MISSING on the
    first, so the self-observability split could not land without either weakening
    the gate or exempting every metric it moved. Taking the union costs nothing
    while there is one dashboard and is the whole unblock once there are two.
    """
    blob = "\n".join(expr for b in builders for expr in b._exprs)
    missing = []
    for n in load_catalogue():
        if n in COVERAGE_EXEMPT:
            continue
        # Word-boundary match so e.g. opnsense_mbuf_total is not "covered" by
        # opnsense_mbuf_cluster_total. Right boundary = not followed by [a-z0-9_].
        if not re.search(re.escape(n) + r"(?![a-z0-9_])", blob):
            missing.append(n)
    return missing


def leaf_tab_titles(b: Builder) -> list[str]:
    """Return feature-tab titles beneath the top-level domains."""
    titles = []
    for tab in b.tabs:
        layout = tab["spec"]["layout"]
        if layout["kind"] == "TabsLayout":
            titles.extend(child["spec"]["title"] for child in layout["spec"]["tabs"])
        else:
            titles.append(tab["spec"]["title"])
    return titles


# ---- registry ------------------------------------------------------------
def build_all(tab_groups=TAB_GROUPS) -> Builder:
    """Build the MAIN (firewall-operational) dashboard's Builder. `tab_groups` is
    threaded through to `organize_tabs` rather than read from the module global, so
    this same function can serve as the `build_fn` for any `DashboardSpec` in
    `DASHBOARDS` (#431) — defaults to `TAB_GROUPS` for its own spec and for any
    pre-existing caller."""
    b = Builder()
    add_core_variables(b)
    add_navigation(b, self_uid=uids.MAIN_UID)   # dashboard-level links (#419)
    add_annotations(b)           # shared event timeline (#421)
    # Leaf order is local to each domain after organize_tabs().
    build_overview(b)
    register_subsystem_tabs(b, MAIN_TAB_MODULES)   # provided by tabs/ modules
    organize_tabs(b, tab_groups)
    return b


def build_health(tab_groups=HEALTH_TAB_GROUPS) -> Builder:
    """Build the SELF-OBSERVABILITY dashboard's Builder (#431).

    This is the exporter watching itself: scrape health, per-collector poll
    schedule and freshness, OTLP delivery, the API response cache, the Go runtime
    and the log-shipping pipeline. Deliberately NOT firewall domain health — the
    epic's own scope line — which is why the Recording Rules tab stays on the main
    dashboard even though it is "derived" data.

    It carries the same core variables and annotation layers as the main dashboard
    on purpose: the question an operator asks here is almost always "was the
    exporter unwell *when that firewall event happened*", and answering it needs
    the same instance picker and the same event timeline.

    There is deliberately no separate Overview tab. Diagnostics already opens on
    scrape health, and a summary tab in front of it would be a second place to
    state the same three facts — the summary that IS wanted lives on the main
    dashboard, where the reader has no other way to learn them.
    """
    b = Builder()
    add_core_variables(b)
    add_navigation(b, self_uid=uids.HEALTH_UID)
    add_annotations(b)
    register_subsystem_tabs(b, HEALTH_TAB_MODULES)
    build_diagnostics(b)
    organize_tabs(b, tab_groups)
    return b


def build_family() -> list:
    """Build every dashboard in the family, as `(spec, builder)` pairs in spec order.

    The primary dashboard is first: `dashboard-stats.json` and the docgen prose
    counts that read it describe the main dashboard specifically.
    """
    return [(spec, spec.build()) for spec in DASHBOARDS]


def organize_tabs(b: Builder, tab_groups=TAB_GROUPS):
    """Move every leaf tab into the layered top-level information architecture.

    Title matching is deliberate: it makes a renamed, duplicate, or unassigned
    leaf a build failure instead of silently dropping feature coverage.

    `tab_groups` is a parameter, not the module-level `TAB_GROUPS` global, because
    each dashboard in the family (`DASHBOARDS`, #431) organizes its OWN leaf set —
    reading the module global here would make a second dashboard's leaves fail this
    dashboard's assignment check. Defaults to `TAB_GROUPS` so today's single spec
    (and any caller that predates the family) is unaffected.
    """
    leaves = {}
    for tab in b.tabs:
        title = tab["spec"]["title"]
        if title in leaves:
            raise ValueError(f"duplicate dashboard leaf tab: {title}")
        leaves[title] = tab

    expected = set()
    for _, titles in tab_groups:
        expected.update(titles)
    actual = set(leaves)
    if actual != expected:
        missing = sorted(expected - actual)
        unassigned = sorted(actual - expected)
        raise ValueError(f"dashboard leaf assignment mismatch: missing={missing}, unassigned={unassigned}")

    # Restricted to leaves this dashboard actually has. OPTIONAL_TAB_PRESENCE is a
    # family-wide registry (one entry per optional feature, wherever it lives), so
    # indexing it unconditionally would KeyError on whichever dashboard does not
    # own that tab.
    for title, present in OPTIONAL_TAB_PRESENCE.items():
        if title in leaves:
            leaves[title]["spec"]["conditionalRendering"] = b._cond(present=present)

    b.tabs = []
    for group_title, leaf_titles in tab_groups:
        if group_title is None:
            b.tabs.extend(leaves.pop(title) for title in leaf_titles)
            continue
        # A parent containing only optional features must disappear with its
        # children. Otherwise Grafana leaves an empty top-level domain visible.
        # Domains with at least one core leaf stay unconditional.
        parent_presence = []
        if all(title in OPTIONAL_TAB_PRESENCE for title in leaf_titles):
            for title in leaf_titles:
                presence = OPTIONAL_TAB_PRESENCE[title]
                parent_presence.extend(
                    [presence] if isinstance(presence, str) else presence
                )
        b.tab_group(
            group_title,
            [leaves.pop(title) for title in leaf_titles],
            present=parent_presence or None,
        )
    if leaves:
        raise ValueError(f"unassigned dashboard leaf tabs: {sorted(leaves)}")


# Tab modules in display order, split by which dashboard owns them (#431). A module
# appears in exactly one list: building it onto both dashboards would produce two
# copies of the same tab that drift independently.
MAIN_TAB_MODULES = [
    "system", "interfaces", "firewall", "alias", "gateways", "dns_unbound", "dhcp",
    "vpn", "tailscale", "netbird", "routing", "protocols", "ntp", "certificates",
    "clamav", "services_cron", "syslog", "qfeeds", "netflow", "carp", "haproxy",
    "relayd", "nginx", "frr", "monit", "crowdsec", "ids", "ups",
    "captiveportal", "trafficshaper", "hasync", "chrony", "tor", "siproxd", "log_events",
    "flow", "zenarmor", "recording_rules",
]
HEALTH_TAB_MODULES = ["logs"]


def register_subsystem_tabs(b: Builder, order=None):
    """Import each listed tab module and call its build(b). Tab modules live in tabs/
    and are listed in display order. Missing modules are skipped (lets the dashboard
    build incrementally during development)."""
    order = MAIN_TAB_MODULES if order is None else order
    import importlib
    for mod in order:
        try:
            m = importlib.import_module(f"tabs.{mod}")
        except ModuleNotFoundError:
            print(f"  (tab module tabs/{mod}.py not present yet — skipping)", file=sys.stderr)
            continue
        m.build(b)


class DashboardSpec:
    """Describes one dashboard the family (`DASHBOARDS`) builds, so `main()` can
    iterate rather than assume there is exactly one (#431 step 2).

    `uid` doubles as the manifest's `metadata.name` — this repo's v2 dashboards have
    no separate uid field; `metadata.name` IS the uid Grafana resolves navigation
    links against (see `uids.py`). Kept as one field rather than two to avoid a
    seam that could silently drift apart.

    `build_fn` must accept this spec's `tab_groups` and return a fully-built
    `Builder` (variables, navigation, annotations, every tab, already organized via
    `organize_tabs`) — `build_all` is today's only implementation.
    """

    def __init__(self, *, uid: str, title: str, description: str, tags: list[str],
                 out_path: str, tab_groups: list, build_fn):
        self.uid = uid
        self.title = title
        self.description = description
        self.tags = tags
        self.out_path = out_path
        self.tab_groups = tab_groups
        self.build_fn = build_fn

    def build(self) -> Builder:
        return self.build_fn(self.tab_groups)


# The dashboard family. The MAIN spec must stay first: `dashboard-stats.json` and the
# docgen prose counts that read it describe the operational dashboard specifically.
#
# `DASH_NAME` overrides the main uid only. It exists so a fork can publish under its
# own uid; the health dashboard derives its uid from the registry either way, because
# `uids.dash_url()` resolves cross-links through `DESTINATIONS` and an unregistered
# uid would fail the build rather than silently emitting a link that 404s.
DASHBOARDS = [
    DashboardSpec(
        uid=os.environ.get("DASH_NAME", uids.MAIN_UID),
        title="OPNsense Exporter",
        description="Comprehensive single-pane OPNsense firewall dashboard. Tabs and "
                    "rows auto-hide when their metrics are absent. Exporter "
                    "self-observability lives on the companion OPNsense Exporter "
                    "Health dashboard. Built from grafana/build_dashboard.py.",
        tags=["opnsense", "firewall", "network", "exporter"],
        out_path=OUT,
        tab_groups=TAB_GROUPS,
        build_fn=build_all,
    ),
    DashboardSpec(
        uid=uids.HEALTH_UID,
        title="OPNsense Exporter Health",
        description="Self-observability for the OPNsense exporter itself: scrape and "
                    "poll health, per-collector freshness, OPNsense API errors and "
                    "response cache, OTLP delivery and the log-shipping pipeline. "
                    "Firewall data lives on the OPNsense Exporter dashboard. Built "
                    "from grafana/build_dashboard.py.",
        tags=["opnsense", "exporter", "self-observability"],
        out_path=HEALTH_OUT,
        tab_groups=HEALTH_TAB_GROUPS,
        build_fn=build_health,
    ),
]


def main():
    check_only = "--check" in sys.argv
    built = build_family()
    builders = [b for _, b in built]

    missing = coverage(*builders)
    total = len(load_catalogue())
    covered = total - len(missing)
    for spec, b in built:
        leaf_names = leaf_tab_titles(b)
        print(f"{spec.title}: {len(b.elements)} panels, {len(b.tabs)} domains, "
              f"{len(leaf_names)} feature tabs", file=sys.stderr)
    print(f"coverage: {covered}/{total} catalogue metrics referenced across the "
          f"dashboard family", file=sys.stderr)
    if missing:
        print(f"MISSING ({len(missing)}):", file=sys.stderr)
        for n in missing:
            print(f"  - {n}", file=sys.stderr)

    # Correctness gate: every dateTimeAsIso field must be fed epoch milliseconds
    # (epoch seconds render as ~1970 dates otherwise). Fails the build in both
    # modes — a stale dashboard.json can't ship without this being satisfied (#78).
    # Aggregated across the whole family: a violation on any dashboard's Builder is
    # still a violation, and today's single-spec case is unaffected (one Builder in
    # the list, same items as before).
    ts_violations = [v for b in builders for v in b._ts_violations]
    if ts_violations:
        print(f"dateTimeAsIso fields fed unscaled epoch seconds ({len(ts_violations)}):", file=sys.stderr)
        for v in ts_violations:
            print(f"  - {v}  (wrap the expr in epoch_ms())", file=sys.stderr)
        sys.exit(1)

    # A multi-expr table() renames/units its merged columns by "Value #A".."Value #N"; keying on a
    # metric name (or bare "Value") is a silent no-op that ships unlabeled, unit-less columns (#97).
    # The single-expr mirror image is #509: there the value column is bare "Value", so a "Value #A"
    # key matches nothing. The two spellings are correct in exactly opposite cases, which is why
    # panel-146 shipped a table with no value column at all and every gate stayed green.
    table_key_violations = [v for b in builders for v in b._table_key_violations]
    if table_key_violations:
        print(f"dead table rename/unit keys ({len(table_key_violations)}):", file=sys.stderr)
        for v in table_key_violations:
            print(f"  - {v}", file=sys.stderr)
        print('  (multi-expr: key on "Value #A".."Value #N" in expr order, never the metric name.'
              ' single-expr: key on bare "Value".)', file=sys.stderr)
        sys.exit(1)

    # A DHCP-backend row bundles a service-health stat with the lease/pool panels, so its
    # presence sentinel must gate on whether the backend EXISTS, not on its lease count. A
    # `> 0` count comparison hides a live-but-idle backend (leases_total=0), conflating
    # "absent" with "present but zero" and blanking the very health stat meant to answer
    # "is it up?" (#114). These must gate on existence via label_values(...)/service_running.
    # A table field listed in `excludes` is dropped, so renaming/unit-overriding that same field
    # is a dead no-op that silently hides the column (#112).
    table_exclude_conflicts = [v for b in builders for v in b._table_exclude_conflicts]
    if table_exclude_conflicts:
        print(f"table rename/unit keys that are also excluded ({len(table_exclude_conflicts)}):", file=sys.stderr)
        for v in table_exclude_conflicts:
            print(f"  - {v}", file=sys.stderr)
        sys.exit(1)

    dhcp_presence_sentinels = {"has_dnsmasq", "has_kea", "has_dhcpv4_isc", "has_dhcpv6_isc"}
    bad_sentinels = [v["spec"]["name"] for b in builders for v in b.variables
                     if v["spec"]["name"] in dhcp_presence_sentinels
                     and "> 0" in v["spec"]["query"]["spec"]["query"]]
    if bad_sentinels:
        print(f"count-gated DHCP presence sentinels ({len(bad_sentinels)}):", file=sys.stderr)
        for name in bad_sentinels:
            print(f"  - {name}  (gate on existence via label_values(...), not a `> 0` lease-count threshold)", file=sys.stderr)
        sys.exit(1)

    if not check_only:
        for spec, b in built:
            manifest = b.manifest(
                title=spec.title, description=spec.description, tags=spec.tags,
                name=spec.uid)
            with open(spec.out_path, "w") as f:
                json.dump(manifest, f, indent=2)
                f.write("\n")
            print(f"wrote {spec.out_path}", file=sys.stderr)

        # Both artifacts describe the FAMILY, not the primary dashboard (#431 step 3).
        #
        # `dashboard-stats.json` feeds prose in the README and docs site — "all N
        # metrics across M tabs". `metrics` was already family-wide (it is the
        # catalogue the union coverage gate ran against), so leaving `tabs` primary-
        # scoped would have paired a family number with a single-dashboard one in the
        # same sentence and made it quietly false. `top_level_tabs` stays primary: the
        # domain layer is a property of the operational dashboard's information
        # architecture and the companion deliberately has no domain layer at all. The
        # per-dashboard breakdown is carried alongside for anything that needs it.
        #
        # The sentinel contract is family-wide for a different reason: it documents
        # the rules a TAB MODULE author must follow, and tab modules now build onto
        # either dashboard, so scoping it to the primary would drop the health
        # dashboard's sentinels from the contract that is supposed to govern them.
        _, primary_b = built[0]
        leaf_names = [t for _, b in built for t in leaf_tab_titles(b)]
        top_level_tab_names = [t["spec"]["title"] for t in primary_b.tabs]
        with open(STATS_PATH, "w") as f:
            json.dump({"metrics": total,
                       "panels": sum(len(b.elements) for _, b in built),
                       "tabs": len(leaf_names),
                       "tab_names": leaf_names,
                       "top_level_tabs": len(primary_b.tabs),
                       "top_level_tab_names": top_level_tab_names,
                       "dashboards": [
                           {"uid": spec.uid, "title": spec.title,
                            "panels": len(b.elements),
                            "tabs": len(leaf_tab_titles(b)),
                            "tab_names": leaf_tab_titles(b)}
                           for spec, b in built]}, f, indent=2)
            f.write("\n")
        print(f"wrote {STATS_PATH}", file=sys.stderr)

        # Feature-sentinel documentation contract (#417): regenerate both the
        # machine-readable manifest and the generated section of AUTHORING.md from
        # THESE SAME Builders, so the two can never independently drift.
        contract = sentinel_contract.build_contract(
            [(spec.title, b) for spec, b in built])
        with open(SENTINEL_CONTRACT_PATH, "w") as f:
            f.write(sentinel_contract.contract_json(contract))
        print(f"wrote {SENTINEL_CONTRACT_PATH}", file=sys.stderr)
        with open(AUTHORING_PATH) as f:
            authoring_doc = f.read()
        authoring_doc = sentinel_contract.inject_authoring_section(
            authoring_doc, sentinel_contract.render_authoring_section(contract))
        with open(AUTHORING_PATH, "w") as f:
            f.write(authoring_doc)
        print(f"wrote {AUTHORING_PATH}", file=sys.stderr)

    # Coverage gate fails the build in BOTH modes: CLAUDE.md promises `make dashboard`
    # fails if any catalogue metric is left off the dashboard, and CI enforces the same
    # via `build_dashboard.py --check`. In write mode the (partial) dashboard.json is
    # still written first so a contributor can iterate, then the non-zero exit blocks
    # the commit/CI until a panel is added (#84).
    if missing:
        sys.exit(1)


if __name__ == "__main__":
    main()
