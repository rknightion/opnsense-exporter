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

from builder import Builder, sel, RATE, UPDOWN, OKERR, YESNO, GW_STATUS

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
METRICS_MD = os.path.join(REPO, "docs", "metrics", "metrics.md")
OUT = os.path.join(HERE, "dashboard.json")
STATS_PATH = os.path.join(REPO, "grafana", "dashboard-stats.json")

# Metrics intentionally NOT charted on a panel (covered structurally / not useful as a
# series). Keep this list short and justified — the coverage gate flags everything else.
COVERAGE_EXEMPT = set()

# The exporter's own go_*/process_* runtime metrics carry whatever `job` label the user's
# Prometheus scrape config sets. The docs use `job_name: opnsense` (getting-started,
# integration-dashboards, k8s static config) while deploy/k8s/scrape.yaml + the ScrapeConfig
# CRD use `job: opnsense-exporter`. Match both with a regex so the Exporter Runtime panels
# return data regardless of which documented setup the user followed (#113).
JOB = 'job=~"opnsense.*"'


def add_core_variables(b: Builder):
    b.variables.append({"kind": "DatasourceVariable", "spec": {
        "name": "datasource", "label": "Data source", "pluginId": "prometheus",
        "current": {"text": "grafanacloud-prom", "value": "grafanacloud-prom"},
        "options": [], "multi": False, "includeAll": False, "allowCustomValue": True,
        "hide": "dontHide", "refresh": "onDashboardLoad",
        "regex": "(?!grafanacloud-usage|grafanacloud-ml-metrics).+", "skipUrlSync": False}})
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
    # from the pf-traffic / netflow collectors — a DISJOINT label space from $interface (#98).
    # Sourced from a firewall pf-traffic metric so it lists exactly the devices those panels plot.
    b.variables.append({"kind": "QueryVariable", "spec": {
        "name": "device", "label": "Device (pf/netflow)",
        "current": {"text": "All", "value": "$__all"}, "options": [],
        "query": {"kind": "DataQuery", "version": "v0", "group": "prometheus",
                  "datasource": {"name": "${datasource}"},
                  "spec": {"query": 'label_values(opnsense_firewall_in_ipv4_pass_packets{opnsense_instance=~"$opnsense_instance"}, interface)',
                           "refId": "device"}},
        "refresh": "onTimeRangeChanged", "regex": "", "sort": "alphabeticalAsc",
        "hide": "dontHide", "includeAll": True, "multi": True, "allValue": ".+",
        "allowCustomValue": True, "skipUrlSync": False}})


def build_overview(b: Builder):
    up = b.stat("Exporter / Box Up", sel("opnsense_up"), mappings=UPDOWN,
                color_mode="background",
                thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
                desc="opnsense_up: last scrape success (1=yes).", w=3, h=4)
    fw = b.stat("Firewall Health", sel("opnsense_firewall_status"), mappings=OKERR,
                color_mode="background",
                thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}], w=3, h=4)
    crash = b.stat("Crash Reporter", sel("opnsense_crash_reporter_status"), mappings=OKERR,
                   color_mode="background",
                   thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
                   desc="0 = crash reports present.", w=3, h=4)
    reboot = b.stat("Needs Reboot", sel("opnsense_firmware_needs_reboot"), mappings=YESNO,
                    color_mode="background",
                    thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}], w=3, h=4)
    syscode = b.stat("System Status Code", sel("opnsense_system_status_code"),
                     desc="2 = OK for OPNsense >= 25.1.", w=3, h=4)
    pkgs = b.stat("Pkg Upgrades", sel("opnsense_firmware_upgrade_packages_count"),
                  thresholds=[{"color": "green", "value": None}, {"color": "yellow", "value": 1}],
                  color_mode="background", w=3, h=4)
    uptime = b.stat("Uptime", sel("opnsense_system_uptime_seconds"), unit="s", w=3, h=4,
                    graph="none", color="thresholds")
    svc = b.stat("Services Stopped", sel("opnsense_services_stopped_total"),
                 thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}],
                 color_mode="background", w=3, h=4)

    mem = b.gauge("Memory Used %", f'100 * {sel("opnsense_system_memory_used_bytes")} / '
                  f'{sel("opnsense_system_memory_total_bytes")}', unit="percent", mx=100, w=4, h=6)
    pf = b.gauge("PF States %", f'100 * {sel("opnsense_firewall_pf_states_current")} / '
                 f'clamp_min({sel("opnsense_firewall_pf_states_limit")}, 1)',
                 unit="percent", mx=100, w=4, h=6)
    load = b.stat("Load (1m)", sel("opnsense_system_load_average", 'interval="1"'),
                  decimals=2, w=4, h=6, graph="area")
    disk = b.gauge("Worst Disk %", f'100 * max({sel("opnsense_system_disk_usage_ratio")})',
                   unit="percent", mx=100, w=4, h=6)
    temp = b.stat("Max Temp", f'max({sel("opnsense_temperature_celsius")})', unit="celsius",
                  w=4, h=6, thresholds=[{"color": "green", "value": None},
                                        {"color": "yellow", "value": 70}, {"color": "red", "value": 85}],
                  color="thresholds", color_mode="value")
    cpu = b.stat("CPU Busy %", f'100 - {sel("opnsense_activity_cpu_idle_percent")}',
                 unit="percent", w=4, h=6, graph="area")

    gw_status = b.statetimeline("Gateway Status", [(sel("opnsense_gateways_status"),
                                "{{name}} ({{address}})")], GW_STATUS, w=12, h=7)
    wan_rtt = b.ts("Gateway RTT", [(sel("opnsense_gateways_rtt_milliseconds"), "{{name}} rtt"),
                                   (sel("opnsense_gateways_rttd_milliseconds"), "{{name}} stddev")],
                   unit="ms", w=12, h=7)
    health_hist = b.statushistory("Health History",
                                  [(sel("opnsense_up"), "up"),
                                   (sel("opnsense_firewall_status"), "firewall"),
                                   (sel("opnsense_crash_reporter_status"), "crash-free")],
                                  OKERR, w=24, h=5)

    b.tab("Overview", [
        b.row("Health", [up, fw, crash, reboot, syscode, pkgs, uptime, svc]),
        b.row("Resource Pressure", [mem, pf, load, disk, temp, cpu]),
        b.row("Connectivity & History", [gw_status, wan_rtt, health_hist]),
    ])


def build_diagnostics(b: Builder):
    b.sentinel("has_go_runtime", f'label_values(go_goroutines{{{JOB}}}, __name__)')
    up = b.statushistory("Scrape Success (opnsense_up)", [(sel("opnsense_up"), "{{opnsense_instance}}")],
                         UPDOWN, w=12, h=6)
    scrapes = b.ts("Scrape Rate", [(f'rate({sel("opnsense_exporter_scrapes_total")}[{RATE}])',
                    "{{opnsense_instance}}")], unit="reqps", w=12, h=6)
    errs_ts = b.ts("Endpoint Errors (rate)", [(f'rate({sel("opnsense_exporter_endpoint_errors_total")}[{RATE}])',
                   "{{endpoint}}")], unit="errps", w=12, h=7)
    errs_tbl = b.table("Endpoint Errors (total)",
                       [f'sort_desc(sum by (endpoint) ({sel("opnsense_exporter_endpoint_errors_total")}))'],
                       renames={"Value": "Errors", "endpoint": "Endpoint"},
                       excludes=["opnsense_instance"], w=12, h=7)
    build = b.table("Build Info", [sel("opnsense_exporter_build_info")],
                    excludes=["Value", "__name__", "job", "instance"],
                    renames={"version": "Version", "goversion": "Go", "opnsense_instance": "Instance"},
                    w=12, h=6,
                    desc="Requires the exporter build that emits opnsense_exporter_build_info.")
    cov = b.statetimeline("Collector Enabled", [(sel("opnsense_exporter_collector_enabled"),
                          "{{collector}}")],
                          {"0": ("Disabled", "red"), "1": ("Enabled", "green")}, w=12, h=8,
                          desc="opnsense_exporter_collector_enabled: which collectors are on.")

    scrape_dur = b.ts("Collector Scrape Duration",
                      [(sel("opnsense_exporter_scrape_collector_duration_seconds"), "{{collector}}")],
                      unit="s", w=12, h=8)
    scrape_ok = b.statetimeline("Collector Scrape Success",
                                [(sel("opnsense_exporter_scrape_collector_success"), "{{collector}}")],
                                OKERR, w=12, h=8,
                                desc="1 = sub-collector scraped cleanly, 0 = error or panic.")

    go_goro = b.ts("Exporter Goroutines", [(f"go_goroutines{{{JOB}}}", "goroutines")],
                   w=8, h=6)
    go_mem = b.ts("Exporter Memory", [(f"process_resident_memory_bytes{{{JOB}}}", "RSS"),
                  (f"go_memstats_heap_inuse_bytes{{{JOB}}}", "heap inuse")],
                  unit="bytes", w=8, h=6)
    go_cpu = b.ts("Exporter CPU", [(f"rate(process_cpu_seconds_total{{{JOB}}}[{RATE}])",
                  "cpu")], unit="percentunit", w=8, h=6)

    b.tab("Diagnostics", [
        b.row("Scrape Health", [up, scrapes, errs_ts, errs_tbl]),
        b.row("Per-Collector Scrapes", [scrape_dur, scrape_ok]),
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


# ---- registry ------------------------------------------------------------
def build_all() -> Builder:
    b = Builder()
    add_core_variables(b)
    # Order matters: this is the tab order in the UI.
    build_overview(b)
    register_subsystem_tabs(b)   # provided by tabs/ modules
    build_diagnostics(b)
    return b


def register_subsystem_tabs(b: Builder):
    """Import every tab module and call its build(b). Tab modules live in tabs/ and
    are listed here in display order. Missing modules are skipped (lets the dashboard
    build incrementally during development)."""
    order = [
        "system", "interfaces", "firewall", "alias", "gateways", "dns_unbound",
        "dhcp", "vpn", "tailscale", "routing", "protocols", "ntp", "certificates",
        "services_cron", "syslog", "qfeeds", "netflow", "carp",
        "haproxy", "nginx", "frr", "monit",
        "crowdsec", "ups", "captiveportal",
        "trafficshaper", "hasync", "chrony",
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
    print(f"coverage: {covered}/{total} catalogue metrics referenced "
          f"({len(b.elements)} panels, {len(b.tabs)} tabs)", file=sys.stderr)
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
        with open(STATS_PATH, "w") as f:
            json.dump({"metrics": total, "panels": len(b.elements), "tabs": len(b.tabs)}, f, indent=2)
            f.write("\n")
        print(f"wrote {STATS_PATH}", file=sys.stderr)

    if check_only and missing:
        sys.exit(1)


if __name__ == "__main__":
    main()
