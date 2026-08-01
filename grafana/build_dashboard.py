#!/usr/bin/env python3
"""
Build the opnsense2otel Grafana v2 dynamic dashboard.

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
from builder import (INSTANCE_LABEL, INSTANCE_SEL, Builder, sel, grp, RATE, ENABLED,
                     UPDOWN, OKERR, YESNO, GW_STATUS)

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
    # Same histogram case (#581): unbound's recursion-time histogram is charted as
    # p50/p90/p99 via histogram_quantile over its _bucket series on the DNS tab, never
    # the bare base name. Note this one is additionally absent entirely on a box
    # running extended-statistics: no (the 26.7 default), which is box state rather
    # than a gap — but the exemption is needed for the same reason as the three above,
    # not for that.
    "opnsense_unbound_dns_recursion_time_seconds",
}

# The REVERSE direction of COVERAGE_EXEMPT (#591): panel -> catalogue rather than
# catalogue -> panel. An `opnsense_`-prefixed name a panel queries which is not in
# the catalogue and is deliberately kept. Each entry needs a written reason, exactly
# as COVERAGE_EXEMPT's do — a bare name here silently re-opens the hole the gate
# exists to close.
#
# EMPTY BY DESIGN. Every legitimate shape the estate actually uses is handled
# structurally by `panel_metric_gaps()` (histogram child series, recording-rule
# output names, the `opnsense_instance` label token), so an entry here means a panel
# is querying something no build of this exporter can emit. If you are about to add
# one, first check it is not simply a typo — that is what item 1 of #591 turned out
# to be, and it survived from the first dashboard commit.
PANEL_METRIC_EXEMPT: dict[str, str] = {}

# ---- the runtime-metric ledger (#591 item 4) ----------------------------
# `coverage()` cannot see any of these. `load_catalogue()`'s row regex admits only
# `opnsense_`-prefixed names, and it could not do otherwise: the catalogue documents
# what THIS codebase emits, while `up`, `go_*` and `process_*` come from the
# Prometheus server and the client library. So the whole runtime namespace is
# structurally invisible to the gate that reports "1020/1020 metrics referenced" —
# blind spot 1 of #591.
#
# The answer is a written decision rather than a widened regex. Rob's call
# (2026-07-31) was selective coverage plus this ledger: panel the runtime metrics
# that answer a question nothing else answers, and record a REASON for each family
# left off, so "we decided not to chart that" stops being tribal knowledge that the
# next audit has to re-derive from scratch.
#
# Keys are exact metric names, or a `*` suffix for a family. Longest matching key
# wins, so a specific name overrides the family it sits in. Values are
# (verdict, reason); verdict is PANELLED or EXCLUDED.
#
# WHAT THE GATE ENFORCES, and what it cannot: `runtime_ledger_gaps()` checks both
# directions of the PANELLED half — a panel querying a runtime metric with no
# PANELLED entry fails, and a PANELLED entry no panel queries fails. The EXCLUDED
# half is a decision record and is NOT enforceable here, because nothing in this
# repo can enumerate what the client library will emit on the operator's platform
# and version without scraping a live process. Treat a missing EXCLUDED entry as a
# documentation gap, not as a passing check.
PANELLED = "panelled"
EXCLUDED = "excluded"
RUNTIME_METRIC_LEDGER: dict[str, tuple[str, str]] = {
    "up": (PANELLED, "Exporter Runtime / Liveness. The only signal that says the "
                     "exporter PROCESS is alive; opnsense_up says the firewall is "
                     "reachable, which is a different failure with a different fix, "
                     "and OPNsenseExporterDown alerts on the latter despite its name."),
    "go_goroutines": (PANELLED, "Exporter Goroutines. A goroutine count that climbs "
                                "and never falls is the leak signature for the "
                                "long-lived syslog/NetFlow/SSE listeners."),
    "go_memstats_heap_inuse_bytes": (PANELLED, "Exporter Memory, plotted against RSS "
                                               "so runtime arena overhead is visible "
                                               "as the gap between the two lines."),
    "go_gc_duration_seconds*": (PANELLED, "Exporter GC Pressure. The `*` covers the "
                                          "ConstSummary's quantile series plus its "
                                          "_sum and _count children, which are what "
                                          "give pause seconds/sec and cycles/sec."),
    "process_cpu_seconds_total": (PANELLED, "Exporter CPU. Rated to core-seconds per "
                                            "second, so 1.0 is one core saturated — "
                                            "the number that says whether the exporter "
                                            "itself is the bottleneck rather than the "
                                            "firewall it is waiting on."),
    "process_resident_memory_bytes": (PANELLED, "Exporter Memory, plotted with Go heap "
                                                "in use. RSS is the figure the host and "
                                                "any container limit actually enforce, "
                                                "and the gap to heap-in-use is runtime "
                                                "arena overhead rather than a leak."),
    "process_open_fds": (PANELLED, "FD Utilisation + Open vs Max File Descriptors. "
                                   "The shared failure surface of every listener and "
                                   "the API pool."),
    "process_max_fds": (PANELLED, "Denominator of FD Utilisation, and drawn on its "
                                  "own because a container or unit file can set it far "
                                  "lower than the operator assumes."),
    # --- deliberately not charted -----------------------------------------
    "go_info": (EXCLUDED, "A constant 1 labelled with the Go version. The build's Go "
                          "version is already a column of the Build Info table, from "
                          "opnsense_exporter_build_info, which is instance-labelled "
                          "and this is not."),
    "go_threads": (EXCLUDED, "OS threads, which for this workload track goroutines "
                             "and GOMAXPROCS and move for no reason an operator can "
                             "act on. Goroutines is the leak signal; a thread count "
                             "beside it adds a second line and no second question."),
    "go_memstats_*": (EXCLUDED, "~25 series describing heap internals (spans, mcache, "
                                "mspan, buckhash, next_gc, lookups). Diagnosing a Go "
                                "memory problem from these is a pprof job, not a "
                                "dashboard one; heap-in-use plus RSS plus GC pressure "
                                "is where a dashboard's usefulness ends. Overridden "
                                "above for heap_inuse_bytes only."),
    "go_sched_*": (EXCLUDED, "Not emitted. main.go:700 registers the base "
                             "`NewGoCollector()`; the runtime/metrics-derived "
                             "families need WithGoCollectorRuntimeMetrics, which is "
                             "not enabled. Listed so a future audit does not read "
                             "their absence as an oversight."),
    "go_cgo_*": (EXCLUDED, "Not emitted, and CGO_ENABLED=0 for every shipped build."),
    "process_start_time_seconds": (EXCLUDED, "Process start time. Restart detection is "
                                             "already an annotation layer, which puts "
                                             "it on every panel's time axis instead of "
                                             "on one tile nobody would open."),
    "process_virtual_memory_*": (EXCLUDED, "Virtual address space, which on a Go "
                                           "process is a large number bearing almost "
                                           "no relation to memory actually consumed. "
                                           "Charting it invites the wrong alarm; RSS "
                                           "is the honest figure and is charted."),
    "process_network_*": (EXCLUDED, "Linux-only, and it counts bytes on the EXPORTER "
                                    "host's interfaces. On a firewall dashboard that "
                                    "is a near-guaranteed misread — the interface "
                                    "traffic anyone wants is the FIREWALL's, and that "
                                    "is the whole Interfaces tab."),
    "promhttp_*": (EXCLUDED, "Not registered. internal/server/metrics.go:320 uses "
                             "promhttp.HandlerFor, never InstrumentMetricHandler, so "
                             "no promhttp_* series exists. The equivalent numbers are "
                             "hand-rolled and instance-labelled "
                             "(opnsense_exporter_server_metrics_*, charted on Metrics "
                             "& OTLP), which promhttp's could not have been."),
}

# The runtime namespaces the ledger governs. Deliberately a small closed list rather
# than "every identifier that is not opnsense_-prefixed": PromQL function names,
# keywords and label names are all bare identifiers too, so a broader scan would need
# a real parser to avoid reporting `rate`, `le` and `by` as unledgered metrics.
#
# `up` is an EXACT name, not a prefix. As a prefix it would also claim `upper`,
# `uptime` and any label value beginning "up" — and the whole point of the closed
# list is that a token it claims must really be a metric.
RUNTIME_METRIC_PREFIXES = ("go_", "process_", "promhttp_")
RUNTIME_METRIC_EXACT = ("up",)

# The exporter's own go_*/process_* runtime metrics carry whatever `job` label the user's
# Prometheus scrape config sets. The docs use `job_name: opnsense` (getting-started,
# integration-dashboards, k8s static config) while deploy/k8s/scrape.yaml + the ScrapeConfig
# CRD use `job: opnsense2otel`. Match both with a regex so the Exporter Runtime panels
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
        "System & Resources", "Kernel Memory", "Services, Cron & DynDNS", "Certificates",
        "UPS", "Monit", "HA Sync", "CARP / HA",
    )),
    ("Network", (
        "Interfaces", "Gateways & WAN", "DNS - Unbound", "DHCP",
        "Routing & Neighbors", "Protocol Stats", "NTP", "Chrony",
        "Traffic Shaper", "NetFlow", "Flow Volume", "FRR Routing", "Captive Portal",
    )),
    ("Security", (
        "Firewall & PF", "Authentication & Audit", "Aliases", "IDS/IPS", "CrowdSec",
        "ClamAV", "Q-Feeds", "Zenarmor",
    )),
    ("VPN & remote access", ("VPN", "Tailscale", "NetBird", "Tor")),
    ("Services", ("Syslog", "HAProxy", "Relayd", "Nginx", "Siproxd")),
]

# There is deliberately no "Observability" domain (#523). It held three leaves that
# were grouped by HOW their numbers were produced — derived from syslog, rolled up
# from flow records, precomputed by a recording rule — which is an implementation
# detail rather than a question anyone opens a dashboard to ask. Splitting them by
# WHO reads them put every firewall-operational panel on the domain tab that already
# owns its subsystem (filterlog events beside the pf counters, tunnel lifecycle
# beside tunnel state) and moved every exporter-pipeline counter to the health
# dashboard. Do not reintroduce the domain: a panel arriving here belongs to a
# subsystem, and if no subsystem claims it, that is the finding.

# The self-observability dashboard (#431), re-laid-out by #523.
#
# It launched deliberately flat — two tabs, one of them an eleven-row "Diagnostics",
# on the reasoning that an operator opening it because something is already wrong
# should not have to click into a domain first. That reasoning did not survive the
# tab count: eleven rows is not a fast read, and #523 moved three more subjects here
# (the flow pipeline, the derived-metric budget, recording rules). So it now carries
# the same shape as the main dashboard — an Overview of tiles that answer "is the
# exporter healthy" without scrolling, then domains for the detail behind each tile.
#
# The original concern is answered by the Overview rather than abandoned: every tile
# on it links to the tab holding its detail, so "something is wrong" is still one
# click from the panels that say what.
#
# "Recording rules" is top-level rather than inside a domain because it is the one
# tab here that is not about the exporter: it shows the bundled rules' OUTPUT, which
# is firewall data in precomputed form. It sits on this dashboard because every panel
# restates a raw System/Interfaces/Firewall panel, so on the operational dashboard it
# was duplication; here it answers "are my recording rules actually evaluating?".
# "Exporter Runtime" and "Recording rules" are top-level rather than each sitting in
# a domain of its own: a parent tab holding exactly one child is a click that shows
# the reader nothing they could not already see.
HEALTH_TAB_GROUPS = [
    (None, ("Overview",)),
    ("Collection", ("Scrape & Poll", "OPNsense API")),
    ("Delivery", ("Metrics & OTLP", "Log Shipping", "Flow Pipeline")),
    (None, ("Exporter Runtime", "Recording rules")),
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
    "Authentication & Audit": ["has_log_events_sshd", "has_log_events_audit",
                               "has_log_events_radius"],
    "Flow Volume": "has_flow_volume",
    "Flow Pipeline": "has_flow",
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
                  "spec": {"query": f'label_values({sel("opnsense_interfaces_link_state")}, interface)',
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
    # #591: this tile queried `100 - opnsense_activity_cpu_idle_percent` from the
    # first dashboard commit until now, and that metric has NEVER existed in any
    # release — zero hits in the Go source, absent from both generated catalogues.
    # `100 - <empty vector>` is an empty vector, so the most prominent tile on the
    # dashboard read "No data" for its entire life with every gate green. Nothing
    # checked panel -> catalogue; `panel_metric_gaps()` now does.
    #
    # The replacement is the cumulative counter reconstructed from the
    # api/diagnostics/cpu_usage SSE stream (#559). OPNsense reports CPU AGGREGATED
    # ACROSS CORES, so the family carries no `cpu` label and `sum by mode` of the
    # rate is 1, not the core count — which means `1 - rate(idle)` is already the
    # busy fraction of the whole machine and must NOT be divided by a core count.
    # Hoisted into a local because the mode matcher carries double quotes and
    # nesting `sel(..., 'mode="idle"')` inside the f-string below is a SyntaxError.
    #
    # NO presence gate, deliberately, and this is the considered answer rather than
    # an oversight. conditionalRendering lives on tabs and rows only (builder.py's
    # frozen contract — there is no per-panel form), and this tile shares the
    # "Resource pressure" row with memory, PF states, load, disk and temperature.
    # Gating the row on the CPU stream's health sentinel would therefore blank five
    # unrelated healthy panels every time one SSE connection stalled. Going no-data
    # during a stall is also the CORRECT reading rather than a regression: past the
    # grace window the collector WITHDRAWS cpu_seconds_total instead of freezing it,
    # because a frozen counter is indistinguishable from an idle CPU. Which of the
    # two it is gets answered by the three CPU-stream health stats on System &
    # Resources and by the OPNsenseCPUStreamStalled alert, so the information is not
    # lost — it is one click away, where it belongs.
    cpu_idle = sel("opnsense_cpu_seconds_total", 'mode="idle"')
    cpu = b.stat("CPU Busy %",
                 f'100 * (1 - sum {grp()} (rate({cpu_idle}[{RATE}])))',
                 unit="percent", w=4, h=5, graph="none", color_mode="background",
                 legend="{{opnsense_instance}}",
                 thresholds=pressure_thresholds,
                 desc="Non-idle CPU across all cores, as a rate over the cumulative "
                      "counters reconstructed from the api/diagnostics/cpu_usage SSE "
                      "stream. OPNsense reports CPU aggregated across cores, so 100% "
                      "means the whole machine is busy, not one core. Reads NO DATA "
                      "while the stream has been silent past its grace window: the "
                      "counters are deliberately withdrawn rather than frozen, since "
                      "a frozen counter looks exactly like a perfectly idle CPU. That "
                      "is the honest answer, not a broken panel — the CPU stream "
                      "health stats on System & Resources say which it is.")

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


def exporter_health_tiles(b: Builder) -> list:
    """The three tiles that answer "can I trust what I am reading?" — built ONCE and
    rendered on both dashboards (#431, shared by #523).

    They are the main dashboard's tripwire: the self-observability detail lives
    elsewhere, so an operator reading a flat graph has no reason to suspect the
    exporter stopped collecting rather than the firewall going quiet. They are also
    the first three tiles of the health dashboard's own Overview, because that
    dashboard has to answer the same question before anything else on it is worth
    reading.

    The shared builder is the point, not an economy. Both dashboards genuinely need
    these figures, and the earlier arrangement — three tiles here, no summary there —
    was what made "two copies drift apart" avoidable rather than solved. Rendering
    one definition twice means a fixed description is fixed in both places, and
    `tests/test_dashboard_family.py` asserts the specs are identical rather than
    asserting the titles differ.

    Tiles only, no time axis. Anything needing one belongs on the health tab that
    owns it — these say WHICH thing is unwell, those say since when and how badly.
    """
    failing = b.stat(
        "Failing Collectors",
        f'sum {grp()} ({sel("opnsense_exporter_scrape_collector_success")} == bool 0)',
        w=4, h=5, graph="none", color_mode="background",
        legend="{{opnsense_instance}}",
        thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}],
        desc="Sub-collectors whose most recent scheduled poll failed. Anything above "
             "zero means part of the operational dashboard is showing retained data "
             "rather than current data — which collector is affected is on the health "
             "dashboard's Scrape & Poll tab.")
    # #523 repointed this from last_success age to snapshot age. The two differ on a
    # collector that is refreshing part of its data while one endpoint errors: the old
    # query climbed there even though the served data was current, so the one tile an
    # operator uses to decide whether to trust the graphs cried wolf on a degraded but
    # usable collector. Snapshot age is the true age of what every scrape replays
    # (#382); "is this collector degraded" is answered by its own panel on Scrape & Poll.
    stalest = b.stat(
        "Stalest Collector Data",
        f'max {grp()} (time() - {sel("opnsense_exporter_collector_snapshot_timestamp_seconds")})',
        unit="s", w=4, h=5, graph="none", color_mode="background",
        legend="{{opnsense_instance}}",
        thresholds=[{"color": "green", "value": None}, {"color": "yellow", "value": 900},
                    {"color": "red", "value": 3600}],
        desc="Age of the oldest metric buffer any scrape or OTLP export would replay — "
             "the true age of the data, which does not advance on a failed poll that "
             "emitted nothing. Compare against the poll tiers before alarming: the cold "
             "tier legitimately sits at 15 minutes, so a value under an hour is normal.")
    api_errs = b.stat(
        "OPNsense API Error Rate",
        f'sum {grp()} (rate({sel("opnsense_exporter_endpoint_errors_total")}[{RATE}]))',
        unit="errps", w=4, h=5, graph="none", color_mode="background",
        legend="{{opnsense_instance}}",
        thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 0.01}],
        desc="Errors per second calling the firewall's API. A plugin-gated endpoint "
             "returning 404 is not counted, so anything here is a real failure — auth, "
             "TLS, timeout or a 5xx.")
    return [failing, stalest, api_errs]


def exporter_health_summary(b: Builder) -> list:
    """The main dashboard's rendering of the shared tiles, each linking through to
    the health dashboard."""
    tiles = exporter_health_tiles(b)
    detail = [uids.data_link("Open the exporter health dashboard",
                             uid=uids.HEALTH_UID, tab=("Overview", ""))]
    for name in tiles:
        b.panel_links(name, detail)
    return tiles


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

    # #517: autodiscovery for opt-in, plugin-gated collectors. The series only
    # exists while the probe last found the plugin answering (absent
    # otherwise, matching every other plugin-gated collector's own
    # convention), so this is an info-style table rather than a 0/1 gauge -
    # a row is precisely "available right now"; enabled says whether the
    # matching --exporter.enable-* switch is on. A row with enabled=false is
    # the "available but not enabled" case the one-shot startup log line also
    # reports; --exporter.enable-all-available turns all of these on at once.
    feature_available = b.table(
        "Plugin Availability (every plugin-gated collector)",
        [sel("opnsense_feature_available")],
        excludes=["__name__", "job", "instance"],
        renames={"feature": "Feature", "enabled": "Scraped", "Value": "Installed",
                 "opnsense_instance": "Instance"},
        w=12, h=8,
        desc="opnsense_feature_available: which plugin-gated features this firewall has, "
             "refreshed every 15 minutes independent of --exporter.cache-ttl (#517, widened "
             "in #525). Installed=1 means the plugin's API endpoint answered; Installed=0 "
             "means it returned 404 and the plugin is absent. NO ROW means availability has "
             "never been determined - an unreachable firewall keeps the previous verdict "
             "rather than reporting every plugin as gone. Installed=1 with Scraped=false is "
             "the actionable combination, and covers both an opt-in collector nobody turned "
             "on and a default-on one somebody disabled. An already-enabled collector is not "
             "re-probed: its own polling answers the same question.")

    # The one number worth alerting a human to. Counting the actionable combination
    # directly beats asking someone to read the table above and spot it.
    #
    # #597 triaged this tile: it is a DECLARED fleet total (see FLEET_TOTAL_PANELS in
    # tests/test_instance_identity.py), not a per-instance one. It matches that list's
    # stated shape exactly — a 4x4 inventory count whose only job is "is there anything
    # actionable", with the per-instance detail one panel away in the same row (the
    # Plugin Availability table above names the box and the feature). One tile per box
    # was considered and rejected for the same reason as the other sixteen: the tile is
    # read as a single number, and splitting it makes the healthy case N green cards.
    #
    # What #597 did fix is that it was fleet-wide by OMISSION: the bare selector had no
    # sel(), so it counted every instance in the datasource, including boxes
    # $opnsense_instance does not select. A declaration has to be true — the count now
    # spans exactly the selection, which is what the description claims.
    unscraped_sel = sel("opnsense_feature_available", 'enabled="false"')
    feature_unscraped = b.stat(
        "Plugins Installed But Not Scraped",
        f"count({unscraped_sel} == 1)",
        graph="none",
        thresholds=[(None, "green"), (1, "yellow")],
        desc="Features whose plugin IS installed but whose collector is switched off, so the "
             "box is serving data nothing is reading. Non-zero is not an error - an opt-in "
             "collector is off for a stated reason (per-poll API cost, cardinality, or "
             "exposing usernames) and a default-on one may have been disabled deliberately. "
             "The exporter also names each one in a startup log line with the flag that would "
             "turn it on. --exporter.enable-all-available turns on every one whose plugin the "
             "startup probe found present. Fleet total: this is a deliberate count across "
             "every instance $opnsense_instance selects (#597), so with two boxes picked a 3 "
             "may be three features on one box or two plus one across both - the Plugin "
             "Availability table above says which.")

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

    # ---- GC pressure (#591 item 4) ---------------------------------------
    # The panel that explains a rising /metrics or API p95 when no API call is
    # actually slow: stop-the-world pause time is charged to whatever goroutine was
    # running, so it inflates every latency histogram at once and shows up on none
    # of the per-endpoint panels.
    #
    # `go_gc_duration_seconds` is a client-library ConstSummary, NOT a histogram, so
    # there are no _bucket series and histogram_quantile does not apply. Its
    # quantiles are the runtime's own PauseQuantiles (0, 0.25, 0.5, 0.75, 1), _sum is
    # cumulative pause time and _count is NumGC (verified against
    # vendor/.../prometheus/go_collector.go:254-259). Three series, three questions:
    # how long is the worst pause, how often is it collecting, and how much of each
    # second is spent stopped.
    #
    # The third series is seconds-per-second, i.e. a unitless fraction, sharing a
    # seconds axis with the other two. That is a deliberate compromise rather than an
    # oversight — its magnitude is directly comparable to a pause duration, and it is
    # the number that answers "is GC the reason", so splitting it onto a second panel
    # would separate the answer from the evidence. Both derived series carry a field
    # override so the legend and tooltip state their real unit.
    gc = b.ts(
        "Exporter GC Pressure",
        [(f'go_gc_duration_seconds{{{JOB},quantile="1"}}', "worst pause"),
         (f'go_gc_duration_seconds{{{JOB},quantile="0.5"}}', "median pause"),
         (f"rate(go_gc_duration_seconds_sum{{{JOB}}}[{RATE}])", "pause seconds/sec"),
         (f"rate(go_gc_duration_seconds_count{{{JOB}}}[{RATE}])", "GC cycles/sec")],
        unit="s", w=8, h=6,
        overrides=[
            {"matcher": {"id": "byName", "options": "pause seconds/sec"},
             "properties": [{"id": "unit", "value": "percentunit"}]},
            {"matcher": {"id": "byName", "options": "GC cycles/sec"},
             "properties": [{"id": "unit", "value": "ops"}]},
        ],
        desc="Go garbage-collector pause behaviour in the exporter process. Read this "
             "when a latency panel elsewhere has climbed and no single endpoint or "
             "collector explains it: stop-the-world pauses are charged to whichever "
             "goroutine was running, so they inflate every latency figure at once and "
             "appear on none of the per-endpoint breakdowns. 'pause seconds/sec' is "
             "the share of wall-clock time spent stopped and is the number that "
             "actually decides whether GC is the cause — worst pause on its own can "
             "be alarming and harmless if it happens once an hour. Like the other "
             "runtime panels this is scoped by scrape job, NOT by $opnsense_instance: "
             "go_* metrics come from the client library and carry no appliance label.")

    # ---- file-descriptor headroom (#591 item 4) --------------------------
    # The exporter's failure surfaces share one budget: TCP and TLS syslog listener
    # slots, the NetFlow UDP socket, the OPNsense API connection pool and every
    # accepted /metrics request are all file descriptors out of the same rlimit.
    # Exhaustion presents as unrelated-looking symptoms in all of them at once —
    # syslog connections refused, API dials failing, scrapes 500ing — which is
    # precisely the kind of shared cause nobody finds by staring at the subsystem
    # panels.
    #
    # Its OWN sentinel rather than reusing has_go_runtime, because the two are not
    # co-present: go_goroutines comes from the Go collector and exists on every
    # platform, while process_open_fds/process_max_fds come from the process
    # collector, which emits nothing at all on wasip1/js/ios
    # (process_collector_not_supported.go) and reports an error instead of a value
    # when the Linux procfs probe or the darwin syscall fails. Sharing one sentinel
    # would light the row and render two permanently blank panels — the exact
    # "is it broken or is it absent?" ambiguity this dashboard exists to remove.
    #
    # scope="target_join" for the same reason has_go_runtime uses it: no appliance
    # label exists to scope on, so the co-scrape identity (job, instance) is joined
    # against opnsense_up instead.
    b.sentinel("has_process_fds", metric="process_open_fds", more=JOB,
               scope="target_join")
    fd_headroom = b.stat(
        "FD Utilisation",
        f"process_open_fds{{{JOB}}} / process_max_fds{{{JOB}}}",
        unit="percentunit", w=6, h=6, graph="none", color_mode="background",
        thresholds=[{"color": "green", "value": None}, {"color": "yellow", "value": 0.7},
                    {"color": "red", "value": 0.85}],
        desc="Open file descriptors as a share of the process rlimit. One shared "
             "budget covers the TCP and TLS syslog listeners, the NetFlow UDP socket, "
             "the OPNsense API connection pool and every in-flight /metrics request, "
             "so exhaustion presents as several unrelated-looking faults at once. The "
             "70%/85% boundaries are headroom warnings, not limits: nothing degrades "
             "at 70%, but a descriptor leak that reaches it will reach 100%. Scoped by "
             "scrape job, not by $opnsense_instance — process_* metrics carry no "
             "appliance label. Absent on platforms whose process collector cannot read "
             "descriptor counts, which is what the row's sentinel gates on.")
    fd_ts = b.ts(
        "Open vs Max File Descriptors",
        [(f"process_open_fds{{{JOB}}}", "open"),
         (f"process_max_fds{{{JOB}}}", "limit")],
        w=18, h=6,
        desc="Open descriptors against the rlimit over time. The tile beside this one "
             "cannot tell a leak from a burst and this panel can: a leak is a line "
             "that climbs and never returns, a burst is a spike that decays when the "
             "connections close. The limit is drawn because it is not a constant in "
             "practice — a container runtime or systemd unit can hand the process a "
             "far lower rlimit than the operator assumes, and a 'sudden' exhaustion "
             "is often the limit having always been small.")

    # ---- exporter alive vs firewall reachable (#591 item 4, #592 item 5) --
    # Two DIFFERENT failures that both get described as "the exporter is down", and
    # the pair exists so an incident does not start by confusing them:
    #
    #   up          — is the EXPORTER process alive and being scraped/pushing?
    #   opnsense_up — did the exporter reach the FIREWALL on its last poll?
    #
    # OPNsenseExporterDown alerts on opnsense_up, so despite its name it fires on
    # firewall unreachability. A dead exporter makes opnsense_up ABSENT rather than
    # 0, which is a different alert condition entirely.
    #
    # `up` has two provenances and they carry disjoint labels, which is why the
    # expression is an `or` of two matchers rather than one (verified against
    # internal/telemetry/synthetic.go): in PULL mode `up` is synthesized by the
    # Prometheus server per target and carries job/instance but no opnsense_instance;
    # in OTLP PUSH mode there is no scraper, so the exporter emits its own `up = 1`
    # with opnsense_instance as a const label and no job — and that gatherer is
    # deliberately never wired into /metrics, because a literal `up` there would
    # collide with the scrape target's own. Either matcher alone leaves this tile
    # permanently blank in one of the two supported delivery modes. A deployment
    # running both will legitimately show two series.
    #
    # Not covered by the reverse gate above and not coverable by it: `up` is not
    # `opnsense_`-prefixed, so no catalogue can contain it. RUNTIME_METRIC_LEDGER is
    # what records the decision instead.
    alive = b.stat(
        "Exporter Alive (up)",
        f'up{{{JOB}}} or {sel("up")}', mappings=UPDOWN,
        w=6, h=5, graph="none", color_mode="background",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        desc="Is the EXPORTER PROCESS alive — a different question from the tile "
             "beside it. In pull mode this is the `up` series Prometheus synthesizes "
             "for the scrape target; in OTLP push mode there is no scraper, so the "
             "exporter emits its own `up = 1` while it runs and the series simply "
             "stops when it dies. Both spellings are queried because they carry "
             "different labels and only one exists in each mode. NO DATA here means "
             "the exporter is gone or unreachable, and every other panel on both "
             "dashboards is showing history rather than the present.")
    fw_reachable = b.stat(
        "Firewall Reachable (opnsense_up)", sel("opnsense_up"), mappings=UPDOWN,
        w=6, h=5, graph="none", color_mode="background",
        legend="{{opnsense_instance}}",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        desc="Did the exporter reach the FIREWALL on its last poll. Read as a pair "
             "with 'Exporter Alive' to the left, which is what tells the two 'it is "
             "down' incidents apart: alive=1 with this at 0 is a firewall, network or "
             "credential fault and the exporter is working correctly; alive absent "
             "makes this absent too, and the fault is the exporter or its host. "
             "OPNsenseExporterDown alerts on THIS metric, so despite its name it "
             "fires on firewall unreachability, not on a dead exporter.")

    # Per-endpoint API request rate + p95 latency, sourced from the client choke-point
    # self-metrics (#126). api_requests_total gives the denominator for a per-endpoint
    # error rate; the duration histogram shows which endpoint regressed when a
    # collector's background poll duration spikes.
    api_rate = b.ts("API Request Rate (by endpoint)",
                    [(f'sum {grp("endpoint")} (rate({sel("opnsense_exporter_api_requests_total")}[{RATE}]))',
                      "{{endpoint}}")], unit="reqps", w=12, h=7)
    # #591 item 6b: the bucket selector is built with sel(), not hand-written. It
    # produced a byte-identical string before, which is exactly why it was worth
    # changing — a hand-written `{opnsense_instance=~"$opnsense_instance"}` is
    # correct until the day someone copies the line and drops the matcher, and
    # sel() is the chokepoint that makes that impossible to do by accident (the
    # same argument grp() makes for the by-clause). Two call sites had opted out;
    # this is one, `server_p95` below is the other.
    api_p95_buckets = sel("opnsense_exporter_api_request_duration_seconds_bucket")
    api_p95 = b.ts("API Request p95 Latency (by endpoint)",
                   [(f'histogram_quantile(0.95, sum {grp("le", "endpoint")} '
                     f'(rate({api_p95_buckets}[{RATE}])))', "{{endpoint}}")],
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
    # Through sel() rather than a hand-written matcher — see api_p95 above (#591 6b).
    server_p95_buckets = sel(
        "opnsense_exporter_server_metrics_request_duration_seconds_bucket")
    server_p95 = b.ts(
        "Metrics Handler Request p95 Latency (by status)",
        [(f'histogram_quantile(0.95, sum {grp("le", "status")} '
          f'(rate({server_p95_buckets}[{RATE}])))', "{{status}}")],
        unit="s", w=6, h=6,
        desc="p95 of opnsense_exporter_server_metrics_request_duration_seconds, timed from "
             "admission to response completion, by outcome status. Excludes requests the "
             "admission cap rejected outright (they never do enough work to be worth "
             "timing) - a rejection shows up on the Rejections panel instead.")

    # #523 split what was one eleven-row "Diagnostics" tab into four, along the
    # question each row answers. The panels are unchanged and still built together,
    # because several of them share a sentinel registration and all of them share the
    # module's scoping comments — splitting the FILE would separate a panel from the
    # paragraph explaining why it is scoped the way it is.
    b.tab("Scrape & Poll", [
        b.row("Scrape Health", [up, scrapes, errs_ts, errs_tbl]),
        b.row("Per-Collector Scrapes", [scrape_dur, scrape_ok]),
        b.row("Per-Collector Poll Schedule", [poll_interval, poll_age, next_poll]),
        b.row("Per-Collector Data Freshness", [snapshot_age, success_age]),
    ])
    b.tab("OPNsense API", [
        b.row("API Requests (per endpoint)", [api_rate, api_p95]),
        b.row("API Response Cache", [cache_hit_ratio, cache_hits, cache_by_ep]),
    ])
    b.tab("Metrics & OTLP", [
        b.row("OTLP Delivery Health", [otlp_on, otlp_fails, otlp_age, otlp_rate],
              present="has_otlp"),
        b.row("Metrics Handler Serving Path",
              [server_inflight, server_req_rate, server_rejected, server_gather_err, server_p95]),
        b.row("Grafana Annotation Writing", [ann_rate, ann_age], present="has_annotations"),
    ])
    b.tab("Exporter Runtime", [
        # First row on the tab, above the build/collector inventory: it answers
        # "which down is it?", which is the question that decides whether anything
        # below is worth reading (#591 item 4 / #592 item 5). Ungated — `up` and
        # `opnsense_up` are the two signals that must render when everything else
        # has stopped, so gating them on a presence sentinel would hide exactly the
        # panels an outage needs.
        b.row("Liveness (exporter vs firewall)", [alive, fw_reachable]),
        b.row("Exporter Build & Collectors", [build, cov, series_total]),
        b.row("Plugin Availability (autodiscovery, #517/#525)", [feature_available, feature_unscraped]),
        b.row("Go Runtime (client metrics)", [go_goro, go_mem, go_cpu, gc],
              present="has_go_runtime"),
        # Separate from the Go Runtime row on purpose: process_* descriptor counts
        # are not exported on every platform while go_* are, so they need their own
        # sentinel — see the has_process_fds registration above.
        b.row("File Descriptors (process collector)", [fd_headroom, fd_ts],
              present="has_process_fds"),
    ])


def build_health_overview(b: Builder):
    """The health dashboard's landing tab (#523): can I trust what the exporter is
    telling me, answered without scrolling and without a time axis.

    Every tile here restates a number whose detail lives on one of the tabs behind it,
    and every tile links to that tab. That is the deliberate trade the flat layout used
    to avoid: a tile is a second place a figure appears, but a reader arriving at an
    eleven-row tab has to know which row to read, and this dashboard's whole job is
    being read by somebody who does not yet know what is wrong.

    Tiles only. Anything needing a time axis to interpret belongs on the tab that owns
    it — the tiles say WHICH thing is unwell, the tabs say since when and how badly.
    """
    scrape_detail = [uids.data_link("Scrape and poll detail", uid=uids.HEALTH_UID,
                                    tab=("Collection", "Scrape & Poll"))]
    api_detail = [uids.data_link("API request and cache detail", uid=uids.HEALTH_UID,
                                 tab=("Collection", "OPNsense API"))]
    otlp_detail = [uids.data_link("Delivery detail", uid=uids.HEALTH_UID,
                                  tab=("Delivery", "Metrics & OTLP"))]
    logs_detail = [uids.data_link("Log shipping detail", uid=uids.HEALTH_UID,
                                  tab=("Delivery", "Log Shipping"))]

    # The same three tiles the main dashboard's summary row renders, from one
    # definition — see exporter_health_tiles().
    failing, stalest, api_errs = exporter_health_tiles(b)
    reachable = b.stat(
        "Firewall Reachable", sel("opnsense_up"), mappings=UPDOWN,
        w=4, h=5, graph="none", color_mode="background", legend="{{opnsense_instance}}",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        desc="1 = the exporter reached the firewall on its last poll. Absent — rather "
             "than 0 — means Prometheus is getting nothing from the exporter at all, "
             "which is a different fault with a different fix.")
    cache_ratio = b.stat(
        "API Cache Hit Rate",
        f'sum {grp()} (rate({sel("opnsense_exporter_api_cache_hits_total")}[{RATE}])) / '
        f'(sum {grp()} (rate({sel("opnsense_exporter_api_cache_hits_total")}[{RATE}])) + '
        f'sum {grp()} (rate({sel("opnsense_exporter_api_cache_misses_total")}[{RATE}])))',
        unit="percentunit", w=4, h=5, legend="{{opnsense_instance}}",
        desc="Share of calls to cacheable endpoints served from cache. Per instance, "
             "never blended across appliances — a sum/sum ratio lets one exporter's "
             "broken cache hide behind a healthy one. A collapse here shows up as a "
             "step in the API request rate on the OPNsense API tab.")
    series = b.stat(
        "Collector Series", sel("opnsense_exporter_series_total"),
        w=4, h=5, legend="{{opnsense_instance}}",
        desc="Series on the collector registry, the number --exporter.series-budget is "
             "measured against. The budget is advisory: exceeding it warns and changes "
             "nothing about what is exported. Excludes the exporter's own process_*/go_* "
             "and OTLP families, which live on a separate registry.")

    otlp_on = b.stat(
        "OTLP Export Enabled", sel("opnsense_exporter_otlp_enabled"), mappings=ENABLED,
        w=6, h=5, graph="none", color_mode="background",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        desc="1 = the OTLP metric push pipeline is RUNNING. It does NOT mean delivery "
             "is working — the exporter connects lazily, so this reads 1 from startup "
             "even with a wrong endpoint. Judge delivery by the two tiles beside it.")
    otlp_fail = b.stat(
        "OTLP Consecutive Failures", sel("opnsense_exporter_otlp_consecutive_failures"),
        w=6, h=5, graph="none", color_mode="background",
        thresholds=[{"color": "green", "value": None}, {"color": "red", "value": 1}],
        desc="Exports that have failed back-to-back, reset to 0 by the next success. "
             "Any sustained non-zero value is an ongoing delivery outage.")
    otlp_last = b.stat(
        "Since Last OTLP Export",
        f'time() - ({sel("opnsense_exporter_otlp_last_success_timestamp_seconds")} > 0)',
        unit="s", w=6, h=5, graph="none", color_mode="background",
        thresholds=[{"color": "green", "value": None}, {"color": "yellow", "value": 300},
                    {"color": "red", "value": 900}],
        desc="Seconds since the last export the backend accepted. NO DATA means no "
             "export has EVER succeeded since this exporter started — the `> 0` guard "
             "suppresses the zero deliberately, since time() minus 0 would render a "
             "56-year age as though an export had once landed.")
    # ---- syslog connection-slot headroom (#592 item 4) -------------------
    # Before these two gauges, pressure on the listener's connection budget was
    # observable only once `opnsense_exporter_logs_rejected_total{reason="conn_limit"}`
    # started climbing — a WALL-HIT counter, which tells an operator they have already
    # run out and never that they are about to. This is the headroom view.
    #
    # NOT summed across `transport`, and that is load-bearing rather than stylistic.
    # The budget is PER TRANSPORT by design (#328): plain TCP and TLS hold separate
    # budgets of the same size specifically so an unauthenticated plaintext flood
    # cannot starve the mTLS senders an operator trusts. A `sum` over the label would
    # average an exhausted TCP budget against an idle TLS one into a reassuring 50%,
    # which is the precise failure the split budget exists to prevent. Dividing two
    # identically-labelled vectors matches on the full label set, so this yields one
    # series — and, on a stat panel, one tile — per (instance, transport) with no
    # aggregation at all.
    #
    # An absent `transport="tls"` series is EXPECTED, not a gap: newSlotGauges seeds
    # only the transports actually listening, because a TLS budget pinned at zero on a
    # listener with no TLS socket would claim we are watching something that cannot
    # happen. A missing tile therefore means "not configured"; a tile at 100% means
    # "full". Those must not look alike, which is why this is one tile per transport
    # rather than a single blended number.
    #
    # Its own sentinel rather than the row's `has_logs`: has_logs probes
    # opnsense_exporter_logs_queue_capacity, i.e. the pipeline, which a box shipping
    # only Zenarmor or NetFlow records also has. Gating on that would render two
    # permanently blank tiles on every box with no syslog listener.
    b.sentinel("has_syslog_conn_slots",
               metric="opnsense_exporter_logs_syslog_conn_slots_limit",
               scope="self_labeled")
    slot_util = b.stat(
        "Syslog Connection Slots Used",
        f'{sel("opnsense_exporter_logs_syslog_conn_slots_in_use")} / '
        f'{sel("opnsense_exporter_logs_syslog_conn_slots_limit")}',
        unit="percentunit", w=6, h=5, graph="none", color_mode="background",
        legend="{{transport}} {{opnsense_instance}}",
        thresholds=[{"color": "green", "value": None}, {"color": "yellow", "value": 0.7},
                    {"color": "red", "value": 0.9}],
        desc="Syslog receiver connection slots held against the "
             "--logs.syslog.max-conns ceiling, ONE TILE PER TRANSPORT. The budget is "
             "per transport rather than a shared pool, so that an unauthenticated "
             "plaintext flood cannot starve the mTLS senders you trust — never read "
             "these as one number. A missing tile means that transport is not "
             "configured, which is a different state from a tile at 100%. Reaching "
             "the ceiling is the point at which new senders are refused and "
             "logs_rejected_total{reason=\"conn_limit\"} starts climbing, so this is "
             "the panel that gives you warning where that counter gives you the "
             "post-mortem. A TLS connection holds its slot from accept, BEFORE it has "
             "authenticated: rising TLS occupancy with no matching rise in records "
             "shipped is the slowloris signature, not busy senders.")
    ship_rate = b.stat(
        "Log Records Shipped",
        f'sum {grp()} (rate({sel("opnsense_exporter_logs_shipped_total")}[{RATE}]))',
        unit="ops", w=6, h=5, legend="{{opnsense_instance}}",
        desc="Records per second the log pipeline handed to its sink. Zero on a box "
             "that ships logs is the signal; absent means log shipping is off.")

    for panel in (reachable, failing, stalest):
        b.panel_links(panel, scrape_detail)
    for panel in (api_errs, cache_ratio):
        b.panel_links(panel, api_detail)
    for panel in (series, otlp_on, otlp_fail, otlp_last):
        b.panel_links(panel, otlp_detail)
    for panel in (ship_rate, slot_util):
        b.panel_links(panel, logs_detail)

    b.tab("Overview", [
        b.row("Collection", [reachable, failing, stalest, api_errs, cache_ratio, series]),
        # Two independently opt-in delivery paths, each gated on its own sentinel: a
        # box using neither would otherwise open on a row of permanent no-data tiles,
        # which is exactly the "is it broken or is it off?" ambiguity the rest of this
        # dashboard exists to remove.
        b.row("OTLP Delivery", [otlp_on, otlp_fail, otlp_last], present="has_otlp"),
        b.row("Log Shipping", [ship_rate], present="has_logs"),
        # A row of its own rather than a third tile on the row above: the two are
        # gated on different sentinels (see has_syslog_conn_slots), and a row can
        # carry only one presence condition. Merging them would mean choosing which
        # of the two panels is allowed to be honest about being absent.
        b.row("Syslog Listener Headroom", [slot_util],
              present="has_syslog_conn_slots"),
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

    ACCEPTED LIMITATION, recorded here so it is not re-derived (#591 blind spot 4):
    this is a SUBSTRING match over one flat blob of every expression, not a semantic
    one. It proves the metric name appears in some query. It does NOT prove an
    operator can ever see the result — a panel on a row whose presence sentinel is
    never satisfied, a hidden panel, or a series blanked by a `> 0` guard all count
    as coverage here. That is deliberate: the alternative is evaluating conditional
    rendering against a hypothetical firewall, which needs a fixture of what that
    firewall exports and would fail for every optional plugin nobody in the fixture
    runs. The gate's real claim is the narrower one — "no metric was forgotten
    entirely" — and it is worth having at that strength. Do NOT widen it by adding
    per-panel visibility heuristics; the honest fix is a live-box check, which is
    what `cmd/apidrift` is for.

    The complementary direction — a panel querying a metric that cannot exist — is
    `panel_metric_gaps()` below, not this function.
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


# A PromQL identifier, including the colons a recording-rule output name carries.
# Matching the colons is the point: `instance:opnsense_pf_state:utilization` must be
# seen as ONE token, or the bare `opnsense_pf_state` falls out of the middle of it
# and reads as a panel querying a metric that does not exist.
_PROM_IDENT = re.compile(r"[A-Za-z_:][A-Za-z0-9_:]*")
# The child series a histogram or summary exports. They are never in the catalogue —
# docgen lists the base name — so a panel legitimately querying `..._bucket` must
# resolve against the base.
_HIST_CHILD = re.compile(r"_(bucket|sum|count)$")


def panel_metric_gaps(*builders: Builder) -> dict:
    """Panel references to an `opnsense_*` name the exporter cannot emit (#591).

    The REVERSE of `coverage()`, and the gate that did not exist. `coverage()` asks
    "does every catalogue metric reach a panel"; nothing asked "does every panel
    reach a real metric", so a syntactically perfect selector for a metric that has
    never existed passed every gate in the repo — `tools/promqlcheck` parses syntax,
    and PromQL has no notion of an unknown metric name (an absent selector is an
    empty vector, not an error). `100 - <empty vector>` is an empty vector, so the
    Overview's headline "CPU Busy %" tile read "No data" from the first dashboard
    commit until #591 and every check stayed green.

    Returns {token: example expression}, so the failure message can name the panel
    query rather than just the token.

    Three things are NOT gaps, and each is skipped structurally rather than by
    allowlist, because each is a whole legitimate class rather than a case:

    * A token containing `:` is a RECORDING-RULE output name (`instance:x:rate5m`).
      Those are produced by `grafana/alerts/build_rules.py`, never by the exporter,
      so they are correctly absent from the catalogue. `test_recording_rules.py`
      owns checking that the rules generating them exist.
    * `_bucket` / `_sum` / `_count` are histogram and summary CHILD series. Tried as
      the literal token FIRST and only then stripped, so a metric genuinely named
      `..._count` (`opnsense_firmware_upgrade_packages_count`) is matched on its own
      name and never mangled into a nonexistent base.
    * `opnsense_instance` is a LABEL, and appears in every `by (...)` clause and
      every instance matcher in the estate.

    Non-`opnsense_`-prefixed runtime metrics (`up`, `go_*`, `process_*`) are out of
    scope here and covered by `RUNTIME_METRIC_LEDGER` instead — see its comment for
    why the catalogue cannot see them at all.
    """
    catalogue = set(load_catalogue())
    gaps = {}
    for b in builders:
        for expr in b._exprs:
            for token in _PROM_IDENT.findall(expr):
                if not token.startswith("opnsense_") or ":" in token:
                    continue
                if token == INSTANCE_LABEL or token in catalogue:
                    continue
                if _HIST_CHILD.sub("", token) in catalogue:
                    continue
                if token in PANEL_METRIC_EXEMPT:
                    continue
                gaps.setdefault(token, expr)
    return gaps


def _ledger_entry(token: str):
    """The RUNTIME_METRIC_LEDGER entry governing `token`, longest key first.

    Longest-match so a specific name can override the family it sits in —
    `go_memstats_heap_inuse_bytes` is panelled while the rest of `go_memstats_*`
    is not, and a shortest-match lookup would silently give the family's verdict
    to the one metric that has its own.
    """
    best = None
    for key, entry in RUNTIME_METRIC_LEDGER.items():
        name = key[:-1] if key.endswith("*") else key
        matched = token.startswith(name) if key.endswith("*") else token == key
        if matched and (best is None or len(name) > len(best[0])):
            best = (name, entry)
    return best[1] if best else None


def runtime_ledger_gaps(*builders: Builder) -> dict:
    """Disagreements between RUNTIME_METRIC_LEDGER and what panels actually query.

    The runtime namespace (`up`, `go_*`, `process_*`, `promhttp_*`) is structurally
    invisible to `coverage()`: `load_catalogue()` reads two generated documents whose
    row regex admits only `opnsense_`-prefixed names, and it cannot do otherwise —
    those documents describe what THIS codebase emits, and these metrics come from
    the Prometheus server and the client library. Widening the regex would not help;
    there is no row to match. So the decision is recorded instead, and this gate
    keeps the record honest in both directions:

      * a panel querying a runtime metric with no PANELLED entry  -> "unledgered"
      * a PANELLED entry no panel queries                         -> "stale"

    Returns {"unledgered": {token: expr}, "stale": [key, ...]}.

    The EXCLUDED half is deliberately NOT enforced, and pretending otherwise would
    be the worse mistake. Nothing in this repo can enumerate the metrics the client
    library will emit on the operator's platform and client_golang version without
    scraping a live process, so an "every excluded metric exists" check would be
    asserting against a hardcoded list — which is the drift this ledger exists to
    replace, reintroduced one layer down. The EXCLUDED entries are a decision record
    for the next auditor; the PANELLED entries are a gate.
    """
    blob = "\n".join(expr for b in builders for expr in b._exprs)
    unledgered = {}
    for b in builders:
        for expr in b._exprs:
            for token in _PROM_IDENT.findall(expr):
                if ":" in token:
                    continue
                if not (token.startswith(RUNTIME_METRIC_PREFIXES)
                        or token in RUNTIME_METRIC_EXACT):
                    continue
                entry = _ledger_entry(token)
                if entry is None or entry[0] != PANELLED:
                    unledgered.setdefault(token, expr)
    stale = []
    for key, (verdict, _) in RUNTIME_METRIC_LEDGER.items():
        if verdict != PANELLED:
            continue
        name = key[:-1] if key.endswith("*") else key
        # Right boundary only for an exact key: a `*` key is a prefix by definition,
        # so requiring "not followed by a name character" would reject the very
        # children (`_sum`, `_count`, `{quantile=...}`) it exists to cover.
        pattern = re.escape(name) + ("" if key.endswith("*") else r"(?![A-Za-z0-9_])")
        if not re.search(pattern, blob):
            stale.append(key)
    return {"unledgered": unledgered, "stale": sorted(stale)}


# ---- log-stream coverage gate (#591 item 5) -----------------------------
# The metric half of the project rule ("every emitted signal is consumed by at least
# one generated panel or rule") has been gate-enforced since #84. The LOG half was
# enforced by nothing at all — blind spot 2 of #591. `coverage()` blobs `_exprs`, and
# `builder.py` deliberately routes LogQL into a SEPARATE `_loki_exprs` list so LogQL
# can never reach the Prometheus gate; the only thing that had ever read that second
# list was the instance-scoping test. A whole registered source could therefore ship
# with no panel, and five of the seven did.
LOGSHIP_DIR = os.path.join(REPO, "internal", "logship")

# Source values that are registered but deliberately not required to appear in a
# panel. Same contract as COVERAGE_EXEMPT: a written reason each.
#
# THE FACTORY NAME IS NOT ALWAYS THE SOURCE VALUE, and this one entry is the whole
# difference between 6 registered factories and 7 shipped streams. It is expressed as
# a UNION (every Name() plus every static ExtraSourceNames() literal) minus this
# exemption, rather than as "drop any source that implements ExtraSourceNames and use
# its list instead". That second rule reads more elegant and is WRONG here: the
# syslog source implements ExtraSourceNames too (internal/logship/syslog/source.go:196
# — dynamically, reporting whatever a registered ProgramProcessor stamps), so the drop
# rule would delete `syslog` itself, the most-consumed stream on the estate, and no
# gate would notice because it would simply stop being required.
LOG_SOURCE_EXEMPT = {
    "flow": "The flowlog Bridge's LANE name, which is never stamped on a record. "
            "Every record it emits carries an explicit Record.Source override of "
            "`netflow` or `merged` (internal/logship/flowlog/flowlog.go:89-96,134 "
            "resolved through internal/flow/record.go:27-38), and both of those ARE "
            "required below. Requiring `flow` as well would demand a panel selecting "
            "a stream no record can ever carry.",
}

_GO_REGISTERS = re.compile(r"\bRegister(?:Push)?Source\(")
_GO_NAME_FN = re.compile(r"func\s*\([^)]*\)\s*Name\(\)\s*string\s*\{\s*return\s+([^\s}]+)\s*\}")
_GO_EXTRA_FN = re.compile(
    r"func\s*\([^)]*\)\s*ExtraSourceNames\(\)\s*\[\]string\s*\{\s*return\s+\[\]string\{([^}]*)\}")
_GO_STRING_LIT = re.compile(r'"([a-z0-9_]+)"')


def registered_log_sources() -> set:
    """Every `opnsense.source` value the Go pipeline can stamp, read from the source.

    DERIVED, not copied. A hardcoded Python list of source names is exactly the drift
    this epic keeps finding: the Go side would gain a source, the list would not, and
    the gate would go on reporting full coverage of a set that had quietly stopped
    being the real one. Nothing generated carries this set today (`self-metrics.md`
    documents metric names, not source values), so the Go source itself is the only
    non-drifting origin.

    The extraction is narrow on purpose — a source registers itself with
    `RegisterSource`/`RegisterPushSource` from an `init()` in its own file, and
    declares its name in the same file, either as a string literal in `Name()` or via
    a package const. Names reached only through a `Record.Source` override come from
    the `ExtraSourceNames()` declaration the pipeline already requires for its
    per-source metric pre-initialisation (internal/logship/source.go:69-75).

    It raises rather than returning a short set when the extraction stops working.
    That is the important property: a regex that silently matches nothing turns this
    gate into a check that every member of the empty set is panelled, which passes
    forever and looks identical to success.
    """
    names, registering = set(), []
    for root, _, files in os.walk(LOGSHIP_DIR):
        for fname in sorted(files):
            if not fname.endswith(".go") or fname.endswith("_test.go"):
                continue
            path = os.path.join(root, fname)
            with open(path) as f:
                text = f.read()
            if not _GO_REGISTERS.search(text):
                continue
            # source.go/push.go define the Register* functions themselves; they hold
            # no source of their own.
            consts = dict(re.findall(r'^const\s+(\w+)\s*=\s*"([a-z0-9_]+)"', text, re.M))
            found = set()
            for token in _GO_NAME_FN.findall(text):
                if token.startswith('"'):
                    found.add(token.strip('"'))
                elif token in consts:
                    found.add(consts[token])
            for literal_list in _GO_EXTRA_FN.findall(text):
                found |= set(_GO_STRING_LIT.findall(literal_list))
            if found:
                registering.append(path)
                names |= found
    if len(registering) < 5 or len(names) < 6:
        raise RuntimeError(
            "registered_log_sources() extracted "
            f"{sorted(names)} from {len(registering)} file(s) under {LOGSHIP_DIR}; "
            "that is fewer than the pipeline is known to have, so the Go-side shape "
            "the regexes match has changed. FIX THE EXTRACTION — do not lower this "
            "guard, or the log-coverage gate silently becomes a no-op.")
    return names


_LOKI_SOURCE_MATCHER = re.compile(r'opnsense_source\s*(?:=~|=)\s*"([^"]*)"')


def panelled_log_sources(*builders: Builder) -> set:
    """Source values selected by at least one generated LogQL expression.

    Reads the `opnsense_source` STREAM-SELECTOR matcher rather than searching for the
    bare word, because the bare word appears in body text, legends and unrelated
    matchers — "zenarmor" is in half the Zenarmor tab's line filters. A `=~` value is
    split on `|`, so `opnsense_source=~"netflow|merged"` covers both.

    Only the POSITIVE matchers `=` and `=~` count. `!=` / `!~` name a source in order
    to exclude it, which is the opposite of consuming it, and the regex is written so
    the `=` inside `!=` cannot match.
    """
    found = set()
    for b in builders:
        for expr in b._loki_exprs:
            for value in _LOKI_SOURCE_MATCHER.findall(expr):
                found |= {v.strip() for v in value.split("|") if v.strip()}
    return found


def log_stream_gaps(*builders: Builder) -> list:
    """Registered log sources that no generated panel selects (#591 item 5).

    The mirror of `coverage()` for the log half of the rule.

    SEMANTICS, decided in #591 and recorded here because the gate encodes it: the
    generic Log Explorer panel and the 31 derived `opnsense_log_events_*` metrics DO
    count as coverage for per-program SYSLOG FORMATS. A cron line, an radvd line and a
    miniupnpd failure variant are shapes WITHIN the `syslog` source, they are all
    reachable from the Log Explorer, and their volumes are already charted from the
    derived metrics — dedicated panels for each would be a tab of near-empty graphs.
    That reading does NOT extend to a whole SOURCE: `unbound`, `ids`, `crowdsec`,
    `netflow` and `merged` each carry attributes no metric summarises (which client
    hit which blocklist, which signature fired, which decision was taken, which
    conversation moved the bytes), so they are gaps under any reading of the rule and
    the gate requires an explicit selector for each.

    Hence the unit here is the SOURCE, not the program or the subsystem — a source is
    what the pipeline stamps and what Loki indexes, so it is the coarsest thing that
    can be selected and the finest thing that can be enforced without a fixture of
    real log lines. It also has to be the source rather than the subsystem for a
    blunter reason: `unbound`, `ids` and `crowdsec` never set `opnsense.subsystem` at
    all, so a subsystem-keyed gate could not see them.

    One name collision to keep straight, because collapsing it would hide a whole
    stream: `unbound` is BOTH a poll source (internal/logship/unbound.go, stamping
    `source="unbound"`) and a registered syslog PARSER
    (internal/logship/syslog/unbound.go:65, whose records stamp `source="syslog"`).
    They are different streams carrying different fields; a panel selecting the
    parser's output does not cover the poll source.
    """
    panelled = panelled_log_sources(*builders)
    return sorted(s for s in registered_log_sources()
                  if s not in panelled and s not in LOG_SOURCE_EXEMPT)


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
    # LAST, and it has to be: placement is derived from the finished layout, so it
    # must run after organize_tabs has built the domain level the 27 leaf-gates move
    # onto. Running it earlier would see leaves at the top level and place every one
    # of those at dashboard scope, silently achieving nothing (#619).
    b.place_variables()
    return b


def build_health(tab_groups=HEALTH_TAB_GROUPS) -> Builder:
    """Build the SELF-OBSERVABILITY dashboard's Builder (#431).

    This is the exporter watching itself: scrape health, per-collector poll
    schedule and freshness, OTLP delivery, the API response cache, the Go runtime,
    the log-shipping pipeline and the flow ingest path.

    It carries the same core variables and annotation layers as the main dashboard
    on purpose: the question an operator asks here is almost always "was the
    exporter unwell *when that firewall event happened*", and answering it needs
    the same instance picker and the same event timeline.

    Two things it now carries that are NOT exporter self-observability, both by
    owner decision in #523, and both for the same reason — they were duplication on
    the operational dashboard and are answers here. `Recording rules` shows the
    bundled rules' output, every panel of which restates a raw System/Interfaces/
    Firewall panel. The `Derived Metric Budget` row on Log Shipping counts the
    exporter's own bookkeeping about log-derived metrics, not the events themselves.

    The Overview tab is #523's reversal of this dashboard's original "deliberately
    flat, no summary" decision. See `HEALTH_TAB_GROUPS` for why that decision did
    not survive the tab count.
    """
    b = Builder()
    add_core_variables(b)
    add_navigation(b, self_uid=uids.HEALTH_UID)
    add_annotations(b)
    register_subsystem_tabs(b, HEALTH_TAB_MODULES)
    build_diagnostics(b)
    # Last: the Overview's rows are gated on sentinels the tab modules and
    # build_diagnostics register (has_logs, has_otlp), so it has to come after both.
    build_health_overview(b)
    organize_tabs(b, tab_groups)
    b.place_variables()   # last, for the same reason as build_all (#619)
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
    "system", "kernel_memory", "interfaces", "firewall", "auth_audit", "alias", "gateways",
    "dns_unbound", "dhcp", "vpn", "tailscale", "netbird", "routing", "protocols",
    "ntp", "certificates", "clamav", "services_cron", "syslog", "qfeeds", "netflow",
    "carp", "haproxy", "relayd", "nginx", "frr", "monit", "crowdsec", "ids", "ups",
    "captiveportal", "trafficshaper", "hasync", "chrony", "tor", "siproxd",
    "flow", "zenarmor",
]
# `log_events` is deliberately absent from BOTH lists: since #523 it builds no tab of
# its own, only rows that other modules place (see its docstring). Adding it back to a
# module list would call a `build()` it does not have.
HEALTH_TAB_MODULES = ["logs", "flow_pipeline", "recording_rules"]


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
        title="opnsense2otel",
        description="Comprehensive single-pane OPNsense firewall dashboard. Tabs and "
                    "rows auto-hide when their metrics are absent. Exporter "
                    "self-observability lives on the companion opnsense2otel "
                    "Health dashboard. Built from grafana/build_dashboard.py.",
        tags=["opnsense", "firewall", "network", "exporter"],
        out_path=OUT,
        tab_groups=TAB_GROUPS,
        build_fn=build_all,
    ),
    DashboardSpec(
        uid=uids.HEALTH_UID,
        title="opnsense2otel Health",
        description="Self-observability for the OPNsense exporter itself: scrape and "
                    "poll health, per-collector freshness, OPNsense API errors and "
                    "response cache, OTLP delivery and the log-shipping pipeline. "
                    "Firewall data lives on the opnsense2otel dashboard. Built "
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

    # ---- the three gates #591 added, all reported here and enforced at the
    # bottom of main() alongside `missing` --------------------------------------
    # They share the coverage gate's both-modes policy for the same reason it has
    # one: a stale dashboard.json must not be able to ship, and in write mode the
    # (partial) artifacts are still written first so a contributor can iterate
    # before the non-zero exit blocks the commit.

    # REVERSE coverage: a panel querying a metric no build can emit (#591 item 1/2).
    metric_gaps = panel_metric_gaps(*builders)
    if metric_gaps:
        print(f"panels referencing metrics outside the catalogue ({len(metric_gaps)}):",
              file=sys.stderr)
        for token, expr in sorted(metric_gaps.items()):
            print(f"  - {token}\n      in: {expr}", file=sys.stderr)
        print("  (fix the metric name, or add it to PANEL_METRIC_EXEMPT with a "
              "reason. `100 - <nonexistent metric>` is an empty vector, not an "
              "error — nothing else in CI can catch this.)", file=sys.stderr)

    # LOG-STREAM coverage: the mirror of `coverage()` for the log half of the rule.
    stream_gaps = log_stream_gaps(*builders)
    if stream_gaps:
        print(f"registered log sources no panel selects ({len(stream_gaps)}):",
              file=sys.stderr)
        for source in stream_gaps:
            print(f"  - {source}", file=sys.stderr)
        print("  (add a Loki panel selecting opnsense_source=\"<source>\" on the tab "
              "that owns it, or add it to LOG_SOURCE_EXEMPT with a reason.)",
              file=sys.stderr)
    else:
        print(f"log streams: {len(registered_log_sources()) - len(LOG_SOURCE_EXEMPT)}"
              f"/{len(registered_log_sources()) - len(LOG_SOURCE_EXEMPT)} registered "
              f"sources selected by a generated panel", file=sys.stderr)

    # RUNTIME LEDGER: the decision record for the metrics no catalogue can hold.
    ledger = runtime_ledger_gaps(*builders)
    if ledger["unledgered"]:
        print(f"runtime metrics on a panel with no ledger entry "
              f"({len(ledger['unledgered'])}):", file=sys.stderr)
        for token, expr in sorted(ledger["unledgered"].items()):
            print(f"  - {token}\n      in: {expr}", file=sys.stderr)
        print("  (add a PANELLED entry to RUNTIME_METRIC_LEDGER saying which panel "
              "and what question it answers.)", file=sys.stderr)
    if ledger["stale"]:
        print(f"RUNTIME_METRIC_LEDGER entries claiming a panel that no longer exists "
              f"({len(ledger['stale'])}):", file=sys.stderr)
        for key in ledger["stale"]:
            print(f"  - {key}", file=sys.stderr)
        print("  (the panel was removed or renamed: repoint the entry, or move it to "
              "EXCLUDED with the reason it is no longer charted.)", file=sys.stderr)

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
    #
    # #591 added three more failure conditions on the same terms — the reverse metric
    # gate, the log-stream gate and the runtime ledger. All four are collected into one
    # exit so a build reports EVERY problem it found rather than making a contributor
    # rediscover the next one on each rerun.
    if missing or metric_gaps or stream_gaps or ledger["unledgered"] or ledger["stale"]:
        sys.exit(1)


if __name__ == "__main__":
    main()
