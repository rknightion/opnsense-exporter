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
from annotations import add_annotations
from builder import (INSTANCE_SEL, Builder, sel, grp, RATE, ENABLED, UPDOWN, OKERR,
                     YESNO, GW_STATUS)

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
METRICS_MD = os.path.join(REPO, "docs", "metrics", "metrics.md")
OUT = os.path.join(HERE, "dashboard.json")
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
        "Log-derived Events", "Flow Volume", "Log Shipping", "Recording rules", "Diagnostics",
    )),
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
    ])


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
                            renames={"Value": "Interval (s)", "collector": "Collector", "opnsense_instance": "Instance"},
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
    # ⚠ THE FOUR PANELS BELOW ARE CURRENTLY ALWAYS EMPTY — owned by #466, do not fix
    # here. The claim that used to sit in this comment was INVERTED: it said the
    # otlp_* family "uses sel_pipeline() (bare selector), never sel(), because sel()
    # would render every panel here permanently empty". sel_pipeline() is a pure ALIAS
    # of sel() (see builder.py) — it injects opnsense_instance just the same. So the
    # premise is right and the conclusion is backwards: the family really does carry
    # NO opnsense_instance (telemetry.Start receives the RAW selfMetricsRegistry at
    # main.go:1016, unlike logship which wraps its registerer at main.go:896), and
    # because sel_pipeline() filters on that absent label anyway, all four panels are
    # structurally empty. #466 carries both candidate fixes; #414 deliberately left
    # the panels untouched and only scoped the sentinel.
    #
    # scope="target_join" for the same reason as has_go_runtime: the otlp_* family is
    # on the RAW self-metrics registry, so it carries no opnsense_instance — but it
    # is served from the same target as opnsense_up, so (job, instance) scopes it.
    b.sentinel("has_otlp", metric="opnsense_exporter_otlp_enabled",
               scope="target_join")
    otlp_on = b.stat("OTLP Export Enabled", b.sel_pipeline("opnsense_exporter_otlp_enabled"),
                     mappings=ENABLED, color_mode="background", graph="none", w=4, h=7,
                     thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
                     desc="1 = the OTLP metric push pipeline is RUNNING. It does NOT mean delivery is "
                          "working: the exporter connects lazily, so this reads 1 from startup even with a "
                          "wrong endpoint or an expired credential. Judge delivery by the two panels to the "
                          "right. Construction failure is fatal at startup, so there is no "
                          "configured-but-inactive state — the metric is either 1 or absent.")
    otlp_fails = b.stat("OTLP Consecutive Failures",
                        b.sel_pipeline("opnsense_exporter_otlp_consecutive_failures"),
                        w=5, h=7, color_mode="background",
                        thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}],
                        desc="Exports that have failed back-to-back. Reset to 0 by the next success, so any "
                             "sustained non-zero value is an ongoing delivery outage rather than a blip. "
                             "OPNsenseOTLPDeliveryFailing alerts on this.")
    otlp_age = b.stat("Time Since Last Successful OTLP Export",
                      f'time() - ({b.sel_pipeline("opnsense_exporter_otlp_last_success_timestamp_seconds")} > 0)',
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
                     [(f'sum {grp("result")} (rate({b.sel_pipeline("opnsense_exporter_otlp_exports_total")}[{RATE}]))',
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

    b.tab("Diagnostics", [
        b.row("Scrape Health", [up, scrapes, errs_ts, errs_tbl]),
        b.row("Per-Collector Scrapes", [scrape_dur, scrape_ok]),
        b.row("Per-Collector Poll Schedule", [poll_interval, poll_age, next_poll]),
        b.row("Per-Collector Data Freshness", [snapshot_age, success_age]),
        b.row("OTLP Delivery Health", [otlp_on, otlp_fails, otlp_age, otlp_rate],
              present="has_otlp"),
        b.row("API Requests (per endpoint)", [api_rate, api_p95]),
        b.row("API Response Cache", [cache_hit_ratio, cache_hits, cache_by_ep]),
        b.row("Exporter Build & Collectors", [build, cov]),
        b.row("Exporter Runtime (Go client metrics)", [go_goro, go_mem, go_cpu],
              present="has_go_runtime"),
    ])


# ---- coverage gate -------------------------------------------------------
def load_catalogue() -> list:
    names = []
    with open(METRICS_MD) as f:
        for line in f:
            m = re.match(r"\|\s*(opnsense_[a-z0-9_]+)\s*\|", line)
            if m:
                names.append(m.group(1))
    return sorted(set(names))


def coverage(b: Builder) -> list:
    blob = "\n".join(b._exprs)
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
def build_all() -> Builder:
    b = Builder()
    add_core_variables(b)
    add_annotations(b)           # shared event timeline (#421)
    # Leaf order is local to each domain after organize_tabs().
    build_overview(b)
    register_subsystem_tabs(b)   # provided by tabs/ modules
    build_diagnostics(b)
    organize_tabs(b)
    return b


def organize_tabs(b: Builder):
    """Move every leaf tab into the layered top-level information architecture.

    Title matching is deliberate: it makes a renamed, duplicate, or unassigned
    leaf a build failure instead of silently dropping feature coverage.
    """
    leaves = {}
    for tab in b.tabs:
        title = tab["spec"]["title"]
        if title in leaves:
            raise ValueError(f"duplicate dashboard leaf tab: {title}")
        leaves[title] = tab

    expected = {"Overview"}
    for _, titles in TAB_GROUPS:
        expected.update(titles)
    actual = set(leaves)
    if actual != expected:
        missing = sorted(expected - actual)
        unassigned = sorted(actual - expected)
        raise ValueError(f"dashboard leaf assignment mismatch: missing={missing}, unassigned={unassigned}")

    for title, present in OPTIONAL_TAB_PRESENCE.items():
        leaves[title]["spec"]["conditionalRendering"] = b._cond(present=present)

    overview = leaves.pop("Overview")
    b.tabs = [overview]
    for group_title, leaf_titles in TAB_GROUPS:
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


def register_subsystem_tabs(b: Builder):
    """Import every tab module and call its build(b). Tab modules live in tabs/ and
    are listed here in display order. Missing modules are skipped (lets the dashboard
    build incrementally during development)."""
    order = [
        "system", "interfaces", "firewall", "alias", "gateways", "dns_unbound", "dhcp",
        "vpn", "tailscale", "netbird", "routing", "protocols", "ntp", "certificates",
        "clamav", "services_cron", "syslog", "qfeeds", "netflow", "carp", "haproxy",
        "relayd", "nginx", "frr", "monit", "crowdsec", "ids", "ups",
        "captiveportal", "trafficshaper", "hasync", "chrony", "tor", "siproxd", "log_events",
        "flow", "zenarmor", "logs", "recording_rules",
    ]
    import importlib
    for mod in order:
        try:
            m = importlib.import_module(f"tabs.{mod}")
        except ModuleNotFoundError:
            print(f"  (tab module tabs/{mod}.py not present yet — skipping)", file=sys.stderr)
            continue
        m.build(b)


def main():
    check_only = "--check" in sys.argv
    b = build_all()
    missing = coverage(b)
    total = len(load_catalogue())
    covered = total - len(missing)
    leaf_names = leaf_tab_titles(b)
    print(f"coverage: {covered}/{total} catalogue metrics referenced "
          f"({len(b.elements)} panels, {len(b.tabs)} domains, {len(leaf_names)} feature tabs)",
          file=sys.stderr)
    if missing:
        print(f"MISSING ({len(missing)}):", file=sys.stderr)
        for n in missing:
            print(f"  - {n}", file=sys.stderr)

    # Correctness gate: every dateTimeAsIso field must be fed epoch milliseconds
    # (epoch seconds render as ~1970 dates otherwise). Fails the build in both
    # modes — a stale dashboard.json can't ship without this being satisfied (#78).
    if b._ts_violations:
        print(f"dateTimeAsIso fields fed unscaled epoch seconds ({len(b._ts_violations)}):", file=sys.stderr)
        for v in b._ts_violations:
            print(f"  - {v}  (wrap the expr in epoch_ms())", file=sys.stderr)
        sys.exit(1)

    # A multi-expr table() renames/units its merged columns by "Value #A".."Value #N"; keying on a
    # metric name (or bare "Value") is a silent no-op that ships unlabeled, unit-less columns (#97).
    if b._table_key_violations:
        print(f"dead multi-expr table rename/unit keys ({len(b._table_key_violations)}):", file=sys.stderr)
        for v in b._table_key_violations:
            print(f"  - {v}  (key it on \"Value #A\"..\"Value #N\" in expr order, not the metric name)", file=sys.stderr)
        sys.exit(1)

    # A DHCP-backend row bundles a service-health stat with the lease/pool panels, so its
    # presence sentinel must gate on whether the backend EXISTS, not on its lease count. A
    # `> 0` count comparison hides a live-but-idle backend (leases_total=0), conflating
    # "absent" with "present but zero" and blanking the very health stat meant to answer
    # "is it up?" (#114). These must gate on existence via label_values(...)/service_running.
    # A table field listed in `excludes` is dropped, so renaming/unit-overriding that same field
    # is a dead no-op that silently hides the column (#112).
    if b._table_exclude_conflicts:
        print(f"table rename/unit keys that are also excluded ({len(b._table_exclude_conflicts)}):", file=sys.stderr)
        for v in b._table_exclude_conflicts:
            print(f"  - {v}", file=sys.stderr)
        sys.exit(1)

    dhcp_presence_sentinels = {"has_dnsmasq", "has_kea", "has_dhcpv4_isc", "has_dhcpv6_isc"}
    bad_sentinels = [v["spec"]["name"] for v in b.variables
                     if v["spec"]["name"] in dhcp_presence_sentinels
                     and "> 0" in v["spec"]["query"]["spec"]["query"]]
    if bad_sentinels:
        print(f"count-gated DHCP presence sentinels ({len(bad_sentinels)}):", file=sys.stderr)
        for name in bad_sentinels:
            print(f"  - {name}  (gate on existence via label_values(...), not a `> 0` lease-count threshold)", file=sys.stderr)
        sys.exit(1)

    if not check_only:
        manifest = b.manifest(
            title="OPNsense Exporter",
            description="Comprehensive single-pane OPNsense firewall dashboard. Tabs and "
                        "rows auto-hide when their metrics are absent. Built from "
                        "grafana/build_dashboard.py.",
            tags=["opnsense", "firewall", "network", "exporter"],
            name=os.environ.get("DASH_NAME", "opnsense-exporter"))
        with open(OUT, "w") as f:
            json.dump(manifest, f, indent=2)
            f.write("\n")
        print(f"wrote {OUT}", file=sys.stderr)
        top_level_tab_names = [t["spec"]["title"] for t in b.tabs]
        with open(STATS_PATH, "w") as f:
            json.dump({"metrics": total, "panels": len(b.elements), "tabs": len(leaf_names),
                       "tab_names": leaf_names, "top_level_tabs": len(b.tabs),
                       "top_level_tab_names": top_level_tab_names}, f, indent=2)
            f.write("\n")
        print(f"wrote {STATS_PATH}", file=sys.stderr)

        # Feature-sentinel documentation contract (#417): regenerate both the
        # machine-readable manifest and the generated section of AUTHORING.md from
        # THIS SAME Builder, so the two can never independently drift.
        contract = sentinel_contract.build_contract(b)
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
