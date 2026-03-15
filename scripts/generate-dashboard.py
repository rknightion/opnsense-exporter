#!/usr/bin/env python3
"""Generate comprehensive Grafana v2beta1 dashboard for OPNsense Exporter.

Usage: python3 scripts/generate-dashboard.py
Output: deploy/grafana/dashboard.json
"""

import json
import re
from pathlib import Path

# Constants
VIZ_VER = "13.0.0-22600832492"
DS = {"name": "${datasource}"}
F = '{opnsense_instance="$opnsense_instance"}'
R = "$rate_interval"


class Dashboard:
    """Grafana v2beta1 dashboard builder."""

    def __init__(self):
        self._id = 0
        self.elements = {}
        self._metrics = set()

    # ── ID management ──

    def _nid(self):
        self._id += 1
        return self._id

    def _key(self):
        pid = self._nid()
        return f"panel-{pid}"

    # ── Metric tracking ──

    def _track(self, expr):
        for m in re.findall(r"opnsense_\w+", expr):
            self._metrics.add(m)

    # ── Query builders ──

    def _q(self, expr, legend="", ref="A", instant=False):
        self._track(expr)
        return {
            "kind": "PanelQuery",
            "spec": {
                "query": {
                    "kind": "DataQuery",
                    "group": "prometheus",
                    "version": "v0",
                    "datasource": DS,
                    "spec": {
                        "editorMode": "code",
                        "expr": expr,
                        "legendFormat": legend,
                        "range": not instant,
                        "instant": instant,
                    },
                },
                "refId": ref,
                "hidden": False,
            },
        }

    def _qg(self, queries, transforms=None):
        qs = []
        for i, item in enumerate(queries):
            if isinstance(item, tuple):
                expr, legend = item
                qs.append(self._q(expr, legend, ref=chr(65 + i)))
            elif isinstance(item, dict):
                qs.append(item)
            else:
                qs.append(self._q(item, ref=chr(65 + i)))
        return {
            "kind": "QueryGroup",
            "spec": {
                "queries": qs,
                "transformations": transforms or [],
                "queryOptions": {},
            },
        }

    # ── Panel builders ──

    def _panel(self, title, group, data, options, field_cfg, desc=""):
        key = self._key()
        self.elements[key] = {
            "kind": "Panel",
            "spec": {
                "id": self._id,
                "title": title,
                "description": desc,
                "links": [],
                "data": data,
                "vizConfig": {
                    "kind": "VizConfig",
                    "group": group,
                    "version": VIZ_VER,
                    "spec": {"options": options, "fieldConfig": field_cfg},
                },
            },
        }
        return key

    def stat(self, title, expr, unit="short", legend="", desc="",
             thresholds=None, color_mode="value", graph_mode="none",
             mappings=None, text_mode="auto", instant=True):
        if thresholds is None:
            thresholds = [{"value": 0, "color": "green"}]
        data = self._qg([self._q(expr, legend, instant=instant)])
        defaults = {
            "unit": unit,
            "thresholds": {"mode": "absolute", "steps": thresholds},
            "color": {"mode": "thresholds"},
        }
        if mappings:
            defaults["mappings"] = mappings
        return self._panel(title, "stat", data, {
            "colorMode": color_mode,
            "graphMode": graph_mode,
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "textMode": text_mode,
            "justifyMode": "auto",
            "orientation": "auto",
        }, {"defaults": defaults, "overrides": []}, desc)

    def ts(self, title, queries, unit="short", desc="", stack=False,
           fill=10, legend_mode="list", legend_place="bottom",
           min_val=None, max_val=None, decimals=None, line_width=1,
           thresholds=None):
        if isinstance(queries, str):
            queries = [(queries, "")]
        data = self._qg(queries)
        custom = {
            "drawStyle": "line",
            "lineInterpolation": "linear",
            "lineWidth": line_width,
            "fillOpacity": 80 if stack else fill,
            "gradientMode": "none",
            "spanNulls": False,
            "pointSize": 5,
            "showPoints": "auto",
            "stacking": {"mode": "normal" if stack else "none", "group": "A"},
            "axisPlacement": "auto",
            "axisBorderShow": False,
        }
        defaults = {
            "unit": unit,
            "color": {"mode": "palette-classic"},
            "custom": custom,
            "thresholds": {"mode": "absolute", "steps": thresholds or [
                {"value": 0, "color": "green"}, {"value": 80, "color": "red"},
            ]},
        }
        if min_val is not None:
            defaults["min"] = min_val
        if max_val is not None:
            defaults["max"] = max_val
        if decimals is not None:
            defaults["decimals"] = decimals
        return self._panel(title, "timeseries", data, {
            "legend": {"displayMode": legend_mode, "placement": legend_place, "showLegend": True},
            "tooltip": {"mode": "multi", "sort": "desc"},
        }, {"defaults": defaults, "overrides": []}, desc)

    def tbl(self, title, queries, desc="", instant=True, transforms=None):
        if isinstance(queries, str):
            queries = [queries]
        qs = []
        for i, item in enumerate(queries):
            if isinstance(item, tuple):
                qs.append(self._q(item[0], item[1], ref=chr(65 + i), instant=instant))
            elif isinstance(item, dict):
                qs.append(item)
            else:
                qs.append(self._q(item, ref=chr(65 + i), instant=instant))
        data = {
            "kind": "QueryGroup",
            "spec": {"queries": qs, "transformations": transforms or [], "queryOptions": {}},
        }
        return self._panel(title, "table", data, {
            "showTypeIcons": True,
            "cellHeight": "sm",
            "footer": {"show": False},
        }, {
            "defaults": {
                "color": {"mode": "thresholds"},
                "thresholds": {"mode": "absolute", "steps": [{"value": 0, "color": "green"}]},
                "custom": {"align": "auto", "filterable": True, "inspect": True},
            },
            "overrides": [],
        }, desc)

    def gauge(self, title, expr, unit="percentunit", legend="", desc="",
              min_val=0, max_val=1, thresholds=None):
        if thresholds is None:
            thresholds = [
                {"value": 0, "color": "green"},
                {"value": 0.8, "color": "orange"},
                {"value": 0.9, "color": "red"},
            ]
        data = self._qg([self._q(expr, legend, instant=True)])
        return self._panel(title, "gauge", data, {
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "showThresholdLabels": False,
            "showThresholdMarkers": True,
            "orientation": "auto",
        }, {
            "defaults": {
                "unit": unit,
                "min": min_val,
                "max": max_val,
                "thresholds": {"mode": "absolute", "steps": thresholds},
                "color": {"mode": "thresholds"},
            },
            "overrides": [],
        }, desc)

    def bg(self, title, expr, unit="short", legend="", desc="",
           thresholds=None, orientation="horizontal", min_val=None, max_val=None):
        if thresholds is None:
            thresholds = [{"value": 0, "color": "green"}, {"value": 80, "color": "red"}]
        data = self._qg([self._q(expr, legend, instant=True)])
        defaults = {
            "unit": unit,
            "thresholds": {"mode": "absolute", "steps": thresholds},
            "color": {"mode": "thresholds"},
        }
        if min_val is not None:
            defaults["min"] = min_val
        if max_val is not None:
            defaults["max"] = max_val
        return self._panel(title, "bargauge", data, {
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "orientation": orientation,
            "displayMode": "gradient",
            "showUnfilled": True,
            "valueMode": "color",
            "namePlacement": "auto",
        }, {"defaults": defaults, "overrides": []}, desc)

    def sh(self, title, expr, mappings, legend="", desc="", thresholds=None):
        data = self._qg([self._q(expr, legend)])
        return self._panel(title, "status-history", data, {
            "colWidth": 1,
            "rowHeight": 1,
            "showValue": "never",
            "legend": {"displayMode": "table", "placement": "right", "showLegend": True},
            "tooltip": {"mode": "single", "sort": "none", "hideZeros": False},
        }, {
            "defaults": {
                "unit": "none",
                "mappings": mappings,
                "thresholds": {"mode": "absolute", "steps": thresholds or [
                    {"value": 0, "color": "red"}, {"value": 1, "color": "green"},
                ]},
                "color": {"mode": "thresholds"},
                "min": 0,
            },
            "overrides": [],
        }, desc)

    def pie(self, title, queries, desc=""):
        if isinstance(queries, str):
            queries = [(queries, "")]
        data = self._qg(queries)
        return self._panel(title, "piechart", data, {
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "pieType": "pie",
            "legend": {"displayMode": "table", "placement": "right", "showLegend": True,
                        "values": ["value", "percent"]},
            "tooltip": {"mode": "multi", "sort": "desc"},
        }, {
            "defaults": {"color": {"mode": "palette-classic"}},
            "overrides": [],
        }, desc)

    # ── Layout builders ──

    def gi(self, key, x, y, w, h, repeat=None):
        spec = {
            "x": x, "y": y, "width": w, "height": h,
            "element": {"kind": "ElementReference", "name": key},
        }
        if repeat:
            spec["repeat"] = repeat
        return {"kind": "GridLayoutItem", "spec": spec}

    def agi(self, key, repeat=None):
        spec = {"element": {"kind": "ElementReference", "name": key}}
        if repeat:
            spec["repeat"] = repeat
        return {"kind": "AutoGridLayoutItem", "spec": spec}

    def row(self, title, items, collapsed=False, repeat=None,
            auto_grid=False, ag_spec=None):
        if auto_grid:
            ags = ag_spec or {}
            layout = {
                "kind": "AutoGridLayout",
                "spec": {
                    "maxColumnCount": ags.get("cols", 4),
                    "columnWidthMode": ags.get("colMode", "standard"),
                    "rowHeightMode": ags.get("rowMode", "standard"),
                    "fillScreen": ags.get("fill", False),
                    "items": items,
                },
            }
        else:
            layout = {"kind": "GridLayout", "spec": {"items": items}}
        spec = {"title": title, "collapse": collapsed, "layout": layout}
        if repeat:
            spec["repeat"] = repeat
        return {"kind": "RowsLayoutRow", "spec": spec}

    def tab(self, title, rows):
        return {
            "kind": "TabsLayoutTab",
            "spec": {
                "title": title,
                "layout": {"kind": "RowsLayout", "spec": {"rows": rows}},
            },
        }

    # ── Common mappings ──

    UP_DOWN_MAP = [{"type": "value", "options": {
        "0": {"text": "Down", "color": "red", "index": 0},
        "1": {"text": "Up", "color": "green", "index": 1},
    }}]

    ENABLED_MAP = [{"type": "value", "options": {
        "0": {"text": "Disabled", "color": "red", "index": 0},
        "1": {"text": "Enabled", "color": "green", "index": 1},
    }}]

    GW_STATUS_MAP = [{"type": "value", "options": {
        "0": {"text": "Offline", "color": "semi-dark-red", "index": 0},
        "1": {"text": "Online", "color": "semi-dark-green", "index": 1},
        "2": {"text": "Unknown", "color": "semi-dark-orange", "index": 2},
        "3": {"text": "Pending", "color": "semi-dark-yellow", "index": 3},
    }}]

    SERVICE_MAP = [{"type": "value", "options": {
        "0": {"text": "Stopped", "color": "red", "index": 0},
        "1": {"text": "Running", "color": "green", "index": 1},
    }}]

    CARP_VIP_MAP = [{"type": "value", "options": {
        "-1": {"text": "Unknown", "color": "gray", "index": 0},
        "0": {"text": "BACKUP", "color": "orange", "index": 1},
        "1": {"text": "MASTER", "color": "green", "index": 2},
        "2": {"text": "INIT", "color": "yellow", "index": 3},
    }}]

    # ── Threshold presets ──

    TH_UP = [{"value": 0, "color": "red"}, {"value": 1, "color": "green"}]
    TH_GREEN = [{"value": 0, "color": "green"}]
    TH_WARN = [{"value": 0, "color": "green"}, {"value": 80, "color": "orange"}, {"value": 90, "color": "red"}]
    TH_TEMP = [{"value": 0, "color": "blue"}, {"value": 50, "color": "green"}, {"value": 70, "color": "orange"}, {"value": 85, "color": "red"}]

    # ════════════════════════════════════════════════════════════════
    # TAB 1: OVERVIEW
    # ════════════════════════════════════════════════════════════════

    def _tab_overview(self):
        rows = []

        # Row 1.1: Health & Exporter
        p1 = self.stat("OPNsense Up", f"opnsense_up{F}", thresholds=self.TH_UP,
                        mappings=self.UP_DOWN_MAP, desc="1 = reachable, 0 = unreachable")
        p2 = self.stat("Firewall Status", f"opnsense_firewall_status{F}", thresholds=self.TH_UP,
                        mappings=self.ENABLED_MAP, desc="1 = OK, 0 = errors")
        p3 = self.stat("System Status Code", f"opnsense_system_status_code{F}",
                        thresholds=[{"value": 0, "color": "red"}, {"value": 2, "color": "green"}],
                        desc="2 = OK for OPNsense >= 25.1")
        p4 = self.stat("Total Scrapes", f"opnsense_exporter_scrapes_total{F}",
                        graph_mode="area", desc="Total exporter scrapes")
        p5 = self.ts("Endpoint Errors Rate", [
            (f'rate(opnsense_exporter_endpoint_errors_total{F}[{R}])', '{{{{endpoint}}}}'),
        ], desc="Errors by API endpoint")
        p6 = self.ts("OPNsense Up Over Time", [
            (f'opnsense_up{F}', 'up'),
        ], min_val=0, max_val=1, desc="Availability over time")
        rows.append(self.row("Health & Exporter", [
            self.gi(p1, 0, 0, 4, 5), self.gi(p2, 4, 0, 4, 5),
            self.gi(p3, 8, 0, 4, 5), self.gi(p4, 12, 0, 4, 5),
            self.gi(p5, 16, 0, 8, 5),
            self.gi(p6, 0, 5, 24, 6),
        ]))

        # Row 1.2: System Info
        p_info = self.tbl("System Information", f"opnsense_system_info{F}",
                          desc="System details from info metric labels")
        p_up = self.stat("Uptime", f"opnsense_system_uptime_seconds{F}", unit="dtdurations")
        p_mem_pct = self.gauge("Memory Usage",
            f'opnsense_system_memory_used_bytes{F} / opnsense_system_memory_total_bytes{F}',
            desc="Used / Total memory ratio")
        p_cfg = self.stat("Last Config Change", f"opnsense_system_config_last_change{F}",
                          unit="dateTimeFromNow", desc="Unix timestamp of last config change")
        p_fw = self.stat("Firmware Version", f"opnsense_firmware_info{F}",
                         text_mode="name", legend="{{product_version}}",
                         desc="OPNsense firmware version from labels")
        rows.append(self.row("System Info", [
            self.gi(p_info, 0, 0, 24, 4),
            self.gi(p_up, 0, 4, 6, 5), self.gi(p_mem_pct, 6, 4, 6, 5),
            self.gi(p_cfg, 12, 4, 6, 5), self.gi(p_fw, 18, 4, 6, 5),
        ]))

        # Row 1.3: CPU & Load
        p_cpu = self.ts("CPU Usage by Mode", [
            (f'opnsense_activity_cpu_user_percent{F}', 'User'),
            (f'opnsense_activity_cpu_nice_percent{F}', 'Nice'),
            (f'opnsense_activity_cpu_system_percent{F}', 'System'),
            (f'opnsense_activity_cpu_interrupt_percent{F}', 'Interrupt'),
            (f'opnsense_activity_cpu_idle_percent{F}', 'Idle'),
        ], unit="percent", stack=True, min_val=0, max_val=100)
        p_load = self.ts("System Load Average", [
            (f'opnsense_system_load_average{F}', '{{{{interval}}}}m'),
        ], desc="1, 5, 15 minute load averages")
        rows.append(self.row("CPU & Load", [
            self.gi(p_cpu, 0, 0, 12, 8), self.gi(p_load, 12, 0, 12, 8),
        ]))

        # Row 1.4: Memory & Swap
        p_mem = self.ts("Memory Usage", [
            (f'opnsense_system_memory_total_bytes{F}', 'Total'),
            (f'opnsense_system_memory_used_bytes{F}', 'Used'),
            (f'opnsense_system_memory_arc_bytes{F}', 'ZFS ARC'),
        ], unit="decbytes")
        p_swap = self.ts("Swap Usage", [
            (f'opnsense_system_swap_total_bytes{F}', '{{{{device}}}} Total'),
            (f'opnsense_system_swap_used_bytes{F}', '{{{{device}}}} Used'),
        ], unit="decbytes")
        rows.append(self.row("Memory & Swap", [
            self.gi(p_mem, 0, 0, 12, 8), self.gi(p_swap, 12, 0, 12, 8),
        ]))

        # Row 1.5: Disk & Temperature
        p_disk_ratio = self.bg("Disk Usage by Mountpoint",
            f'opnsense_system_disk_usage_ratio{F}', unit="percentunit",
            legend="{{mountpoint}}", min_val=0, max_val=1,
            thresholds=[{"value": 0, "color": "green"}, {"value": 0.8, "color": "orange"}, {"value": 0.9, "color": "red"}])
        p_disk_ts = self.ts("Disk Space", [
            (f'opnsense_system_disk_total_bytes{F}', '{{{{mountpoint}}}} Total'),
            (f'opnsense_system_disk_used_bytes{F}', '{{{{mountpoint}}}} Used'),
        ], unit="decbytes")
        p_temp = self.ts("Temperature Sensors", [
            (f'opnsense_temperature_celsius{F}', '{{{{device}}}} ({{{{type}}}})'),
        ], unit="celsius", thresholds=self.TH_TEMP)
        rows.append(self.row("Disk & Temperature", [
            self.gi(p_disk_ratio, 0, 0, 8, 8), self.gi(p_disk_ts, 8, 0, 8, 8),
            self.gi(p_temp, 16, 0, 8, 8),
        ]))

        # Row 1.6: Threads
        p_thr = self.stat("Total Threads", f"opnsense_activity_threads_total{F}")
        p_pie = self.pie("Threads by State", [
            (f'opnsense_activity_threads_running{F}', 'Running'),
            (f'opnsense_activity_threads_sleeping{F}', 'Sleeping'),
            (f'opnsense_activity_threads_waiting{F}', 'Waiting'),
        ])
        p_thr_ts = self.ts("Threads Over Time", [
            (f'opnsense_activity_threads_running{F}', 'Running'),
            (f'opnsense_activity_threads_sleeping{F}', 'Sleeping'),
            (f'opnsense_activity_threads_waiting{F}', 'Waiting'),
        ])
        rows.append(self.row("Threads", [
            self.gi(p_thr, 0, 0, 4, 8), self.gi(p_pie, 4, 0, 10, 8),
            self.gi(p_thr_ts, 14, 0, 10, 8),
        ]))

        # Row 1.7: Firmware & Services
        p_reboot = self.stat("Needs Reboot", f"opnsense_firmware_needs_reboot{F}",
                             thresholds=[{"value": 0, "color": "green"}, {"value": 1, "color": "orange"}],
                             mappings=[{"type": "value", "options": {"0": {"text": "No", "color": "green", "index": 0}, "1": {"text": "Yes", "color": "orange", "index": 1}}}])
        p_upg_reboot = self.stat("Upgrade Needs Reboot", f"opnsense_firmware_upgrade_needs_reboot{F}",
                             thresholds=[{"value": 0, "color": "green"}, {"value": 1, "color": "orange"}],
                             mappings=[{"type": "value", "options": {"0": {"text": "No", "color": "green", "index": 0}, "1": {"text": "Yes", "color": "orange", "index": 1}}}])
        p_new_pkg = self.stat("New Packages", f"opnsense_firmware_new_packages_count{F}",
                              thresholds=[{"value": 0, "color": "green"}, {"value": 1, "color": "blue"}])
        p_upg_pkg = self.stat("Upgrade Packages", f"opnsense_firmware_upgrade_packages_count{F}",
                              thresholds=[{"value": 0, "color": "green"}, {"value": 1, "color": "blue"}])
        p_last_check = self.stat("Last Firmware Check", f"opnsense_firmware_last_check_timestamp_seconds{F}",
                                 unit="dateTimeFromNow")
        p_svc_run = self.stat("Services Running", f"opnsense_services_running_total{F}",
                              thresholds=self.TH_GREEN, color_mode="background")
        p_svc_stop = self.stat("Services Stopped", f"opnsense_services_stopped_total{F}",
                               thresholds=[{"value": 0, "color": "green"}, {"value": 1, "color": "orange"}],
                               color_mode="background")
        p_svc_hist = self.sh("Services Status", f'opnsense_services_status{F}',
                             self.SERVICE_MAP, legend='{{name}}')
        p_cron = self.tbl("Cron Jobs", f'opnsense_cron_job_status{F}',
                          desc="Cron job configuration and status")
        rows.append(self.row("Firmware & Services", [
            self.gi(p_reboot, 0, 0, 4, 4), self.gi(p_upg_reboot, 4, 0, 4, 4),
            self.gi(p_new_pkg, 8, 0, 4, 4), self.gi(p_upg_pkg, 12, 0, 4, 4),
            self.gi(p_last_check, 16, 0, 4, 4),
            self.gi(p_svc_run, 20, 0, 2, 4), self.gi(p_svc_stop, 22, 0, 2, 4),
            self.gi(p_svc_hist, 0, 4, 24, 8),
            self.gi(p_cron, 0, 12, 24, 8),
        ]))

        return self.tab("Overview", rows)

    # ════════════════════════════════════════════════════════════════
    # TAB 2: FIREWALL
    # ════════════════════════════════════════════════════════════════

    def _tab_firewall(self):
        rows = []

        # Row 2.1: PF State
        p1 = self.stat("PF States Current", f"opnsense_firewall_pf_states_current{F}")
        p2 = self.stat("PF States Limit", f"opnsense_firewall_pf_states_limit{F}")
        p3 = self.gauge("PF States Usage",
            f'opnsense_firewall_pf_states_current{F} / opnsense_firewall_pf_states_limit{F}',
            desc="Current states as ratio of limit")
        p4 = self.stat("Firewall Rules Total", f"opnsense_firewall_rule_rules_total{F}")
        rows.append(self.row("PF State", [
            self.gi(p1, 0, 0, 6, 5), self.gi(p2, 6, 0, 6, 5),
            self.gi(p3, 12, 0, 6, 5), self.gi(p4, 18, 0, 6, 5),
        ]))

        # Row 2.2: IPv4 Traffic
        p_v4_in_pkt = self.ts("IPv4 Inbound Packets", [
            (f'opnsense_firewall_in_ipv4_pass_packets{F}', '{{{{interface}}}} Pass'),
            (f'opnsense_firewall_in_ipv4_block_packets{F}', '{{{{interface}}}} Block'),
        ], desc="Inbound IPv4 packets (pass vs block) per interface")
        p_v4_out_pkt = self.ts("IPv4 Outbound Packets", [
            (f'opnsense_firewall_out_ipv4_pass_packets{F}', '{{{{interface}}}} Pass'),
            (f'opnsense_firewall_out_ipv4_block_packets{F}', '{{{{interface}}}} Block'),
        ])
        p_v4_in_bytes = self.ts("IPv4 Inbound Bytes", [
            (f'opnsense_firewall_in_ipv4_pass_bytes_total{F}', '{{{{interface}}}} Pass'),
            (f'opnsense_firewall_in_ipv4_block_bytes_total{F}', '{{{{interface}}}} Block'),
        ], unit="decbytes")
        p_v4_out_bytes = self.ts("IPv4 Outbound Bytes", [
            (f'opnsense_firewall_out_ipv4_pass_bytes_total{F}', '{{{{interface}}}} Pass'),
            (f'opnsense_firewall_out_ipv4_block_bytes_total{F}', '{{{{interface}}}} Block'),
        ], unit="decbytes")
        rows.append(self.row("IPv4 Traffic", [
            self.gi(p_v4_in_pkt, 0, 0, 12, 8), self.gi(p_v4_out_pkt, 12, 0, 12, 8),
            self.gi(p_v4_in_bytes, 0, 8, 12, 8), self.gi(p_v4_out_bytes, 12, 8, 12, 8),
        ]))

        # Row 2.3: IPv6 Traffic
        p_v6_in_pkt = self.ts("IPv6 Inbound Packets", [
            (f'opnsense_firewall_in_ipv6_pass_packets{F}', '{{{{interface}}}} Pass'),
            (f'opnsense_firewall_in_ipv6_block_packets{F}', '{{{{interface}}}} Block'),
        ])
        p_v6_out_pkt = self.ts("IPv6 Outbound Packets", [
            (f'opnsense_firewall_out_ipv6_pass_packets{F}', '{{{{interface}}}} Pass'),
            (f'opnsense_firewall_out_ipv6_block_packets{F}', '{{{{interface}}}} Block'),
        ])
        p_v6_in_bytes = self.ts("IPv6 Inbound Bytes", [
            (f'opnsense_firewall_in_ipv6_pass_bytes_total{F}', '{{{{interface}}}} Pass'),
            (f'opnsense_firewall_in_ipv6_block_bytes_total{F}', '{{{{interface}}}} Block'),
        ], unit="decbytes")
        p_v6_out_bytes = self.ts("IPv6 Outbound Bytes", [
            (f'opnsense_firewall_out_ipv6_pass_bytes_total{F}', '{{{{interface}}}} Pass'),
            (f'opnsense_firewall_out_ipv6_block_bytes_total{F}', '{{{{interface}}}} Block'),
        ], unit="decbytes")
        rows.append(self.row("IPv6 Traffic", [
            self.gi(p_v6_in_pkt, 0, 0, 12, 8), self.gi(p_v6_out_pkt, 12, 0, 12, 8),
            self.gi(p_v6_in_bytes, 0, 8, 12, 8), self.gi(p_v6_out_bytes, 12, 8, 12, 8),
        ]))

        # Row 2.4: Interface Hits
        p_hits = self.ts("Firewall Interface Hits", [
            (f'rate(opnsense_firewall_interface_hits_total{F}[{R}])', '{{{{interface}}}}'),
        ], desc="Rate of firewall rule matches per interface")
        rows.append(self.row("Interface Hits", [
            self.gi(p_hits, 0, 0, 24, 8),
        ]))

        # Row 2.5: Firewall Rule Details (collapsed - opt-in)
        p_eval = self.ts("Rule Evaluations Rate", [
            (f'topk(10, rate(opnsense_firewall_rule_evaluations_total{F}[{R}]))', '{{{{description}}}}'),
        ], desc="Top 10 rules by evaluation rate. Requires --exporter.enable-firewall-rules-details")
        p_rpkt = self.ts("Rule Packets Rate", [
            (f'topk(10, rate(opnsense_firewall_rule_packets_total{F}[{R}]))', '{{{{description}}}}'),
        ])
        p_rbytes = self.ts("Rule Bytes Rate", [
            (f'topk(10, rate(opnsense_firewall_rule_bytes_total{F}[{R}]))', '{{{{description}}}} {{{{direction}}}}'),
        ], unit="decbytes")
        p_rstates = self.ts("Rule Active States", [
            (f'topk(10, opnsense_firewall_rule_states{F})', '{{{{description}}}}'),
        ])
        p_rpf = self.ts("PF Rules per Firewall Rule", [
            (f'opnsense_firewall_rule_pf_rules{F}', '{{{{description}}}}'),
        ])
        rows.append(self.row("Firewall Rule Details", [
            self.gi(p_eval, 0, 0, 12, 8), self.gi(p_rpkt, 12, 0, 12, 8),
            self.gi(p_rbytes, 0, 8, 12, 8), self.gi(p_rstates, 12, 8, 12, 8),
            self.gi(p_rpf, 0, 16, 24, 8),
        ], collapsed=True))

        # Row 2.6: PF Statistics
        p_st_ent = self.stat("State Table Entries", f"opnsense_pf_stats_state_table_entries{F}")
        p_src_trk = self.stat("Source Tracking Entries", f"opnsense_pf_stats_source_tracking_entries{F}")
        p_st_ops = self.ts("State Table Operations", [
            (f'rate(opnsense_pf_stats_state_table_searches_total{F}[{R}])', 'Searches'),
            (f'rate(opnsense_pf_stats_state_table_inserts_total{F}[{R}])', 'Inserts'),
            (f'rate(opnsense_pf_stats_state_table_removals_total{F}[{R}])', 'Removals'),
        ], desc="Rate of state table operations")
        p_pf_cnt = self.ts("PF Counters", [
            (f'rate(opnsense_pf_stats_counter_total{F}[{R}])', '{{{{counter}}}}'),
        ])
        p_pf_lim = self.ts("PF Limit Counters", [
            (f'rate(opnsense_pf_stats_limit_counter_total{F}[{R}])', '{{{{counter}}}}'),
        ])
        p_pf_mem = self.bg("PF Memory Limits", f'opnsense_pf_stats_memory_limit{F}',
                           unit="decbytes", legend="{{pool}}")
        p_pf_to = self.tbl("PF Timeouts", f'opnsense_pf_stats_timeout_seconds{F}',
                           desc="PF timeout values by name")
        rows.append(self.row("PF Statistics", [
            self.gi(p_st_ent, 0, 0, 6, 5), self.gi(p_src_trk, 6, 0, 6, 5),
            self.gi(p_st_ops, 12, 0, 12, 8),
            self.gi(p_pf_cnt, 0, 8, 12, 8), self.gi(p_pf_lim, 12, 8, 12, 8),
            self.gi(p_pf_mem, 0, 16, 12, 8), self.gi(p_pf_to, 12, 16, 12, 8),
        ]))

        return self.tab("Firewall", rows)

    # ════════════════════════════════════════════════════════════════
    # TAB 3: INTERFACES
    # ════════════════════════════════════════════════════════════════

    def _tab_interfaces(self):
        rows = []

        # Row 3.1: Interface Status (AutoGrid with repeat on interface)
        p_link = self.stat("Link State", f'opnsense_interfaces_link_state{F}',
                           mappings=self.UP_DOWN_MAP, thresholds=self.TH_UP,
                           legend='{{interface}}', text_mode="value_and_name")
        p_mtu = self.stat("MTU", f'opnsense_interfaces_mtu_bytes{F}',
                          unit="decbytes", legend='{{interface}}', text_mode="value_and_name")
        p_rate = self.stat("Line Rate", f'opnsense_interfaces_line_rate_bits{F}',
                           unit="bps", legend='{{interface}}', text_mode="value_and_name")
        p_sq = self.stat("Send Queue Length", f'opnsense_interfaces_send_queue_length{F}',
                         legend='{{interface}}', text_mode="value_and_name")
        p_sqm = self.stat("Send Queue Max", f'opnsense_interfaces_send_queue_max_length{F}',
                          legend='{{interface}}', text_mode="value_and_name")
        rows.append(self.row("Interface Status", [
            self.agi(p_link), self.agi(p_mtu), self.agi(p_rate),
            self.agi(p_sq), self.agi(p_sqm),
        ], auto_grid=True, ag_spec={"cols": 5, "colMode": "standard", "rowMode": "short"}))

        # Row 3.2: Throughput
        p_rx = self.ts("Received Bytes Rate", [
            (f'rate(opnsense_interfaces_received_bytes_total{F}[{R}])', '{{{{interface}}}}'),
        ], unit="Bps", desc="Bytes/sec received per interface")
        p_tx = self.ts("Transmitted Bytes Rate", [
            (f'rate(opnsense_interfaces_transmitted_bytes_total{F}[{R}])', '{{{{interface}}}}'),
        ], unit="Bps")
        rows.append(self.row("Throughput", [
            self.gi(p_rx, 0, 0, 12, 8), self.gi(p_tx, 12, 0, 12, 8),
        ]))

        # Row 3.3: Packets
        p_rxp = self.ts("Received Packets Rate", [
            (f'rate(opnsense_interfaces_received_packets_total{F}[{R}])', '{{{{interface}}}}'),
        ], desc="Packets/sec received per interface")
        p_txp = self.ts("Transmitted Packets Rate", [
            (f'rate(opnsense_interfaces_transmitted_packets_total{F}[{R}])', '{{{{interface}}}}'),
        ])
        p_mcrx = self.ts("Multicast Received Rate", [
            (f'rate(opnsense_interfaces_received_multicasts_total{F}[{R}])', '{{{{interface}}}}'),
        ])
        p_mctx = self.ts("Multicast Transmitted Rate", [
            (f'rate(opnsense_interfaces_transmitted_multicasts_total{F}[{R}])', '{{{{interface}}}}'),
        ])
        rows.append(self.row("Packets", [
            self.gi(p_rxp, 0, 0, 12, 8), self.gi(p_txp, 12, 0, 12, 8),
            self.gi(p_mcrx, 0, 8, 12, 8), self.gi(p_mctx, 12, 8, 12, 8),
        ]))

        # Row 3.4: Errors & Queues
        p_ierr = self.ts("Input Errors Rate", [
            (f'rate(opnsense_interfaces_input_errors_total{F}[{R}])', '{{{{interface}}}}'),
        ])
        p_oerr = self.ts("Output Errors Rate", [
            (f'rate(opnsense_interfaces_output_errors_total{F}[{R}])', '{{{{interface}}}}'),
        ])
        p_coll = self.ts("Collisions Rate", [
            (f'rate(opnsense_interfaces_collisions_total{F}[{R}])', '{{{{interface}}}}'),
        ])
        p_sqd = self.ts("Queue Drops Rate", [
            (f'rate(opnsense_interfaces_send_queue_drops_total{F}[{R}])', '{{{{interface}}}} Send'),
            (f'rate(opnsense_interfaces_input_queue_drops_total{F}[{R}])', '{{{{interface}}}} Input'),
        ])
        rows.append(self.row("Errors & Queues", [
            self.gi(p_ierr, 0, 0, 12, 8), self.gi(p_oerr, 12, 0, 12, 8),
            self.gi(p_coll, 0, 8, 12, 8), self.gi(p_sqd, 12, 8, 12, 8),
        ]))

        return self.tab("Interfaces", rows)

    # ════════════════════════════════════════════════════════════════
    # TAB 4: GATEWAYS
    # ════════════════════════════════════════════════════════════════

    def _tab_gateways(self):
        rows = []

        # Row 4.1: Status
        p_info = self.tbl("Gateway Information", f'opnsense_gateways_info{F}',
                          desc="Gateway config from labels")
        p_mon = self.tbl("Gateway Monitor Config", f'opnsense_gateways_monitor_info{F}',
                         desc="Gateway monitoring settings")
        p_status = self.sh("Gateway Status History", f'opnsense_gateways_status{F}',
                           self.GW_STATUS_MAP, legend='{{name}}',
                           thresholds=[{"value": 0, "color": "red"}, {"value": 1, "color": "green"},
                                       {"value": 2, "color": "orange"}, {"value": 3, "color": "yellow"}],
                           desc="0=Offline, 1=Online, 2=Unknown, 3=Pending")
        rows.append(self.row("Status", [
            self.gi(p_info, 0, 0, 12, 6), self.gi(p_mon, 12, 0, 12, 6),
            self.gi(p_status, 0, 6, 24, 10),
        ]))

        # Row 4.2: Latency
        p_rtt = self.ts("RTT", [
            (f'opnsense_gateways_rtt_milliseconds{F}', '{{{{name}}}}'),
        ], unit="ms", desc="Average round trip time")
        p_rttd = self.ts("RTT Deviation", [
            (f'opnsense_gateways_rttd_milliseconds{F}', '{{{{name}}}}'),
        ], unit="ms")
        p_rtt_th = self.ts("RTT Thresholds", [
            (f'opnsense_gateways_rtt_milliseconds{F}', '{{{{name}}}} Current'),
            (f'opnsense_gateways_rtt_low_milliseconds{F}', '{{{{name}}}} Low Threshold'),
            (f'opnsense_gateways_rtt_high_milliseconds{F}', '{{{{name}}}} High Threshold'),
        ], unit="ms", desc="Current RTT vs configured thresholds")
        rows.append(self.row("Latency", [
            self.gi(p_rtt, 0, 0, 8, 8), self.gi(p_rttd, 8, 0, 8, 8),
            self.gi(p_rtt_th, 16, 0, 8, 8),
        ]))

        # Row 4.3: Packet Loss
        p_loss = self.ts("Packet Loss", [
            (f'opnsense_gateways_loss_percentage{F}', '{{{{name}}}}'),
        ], unit="percent", desc="Current packet loss percentage")
        p_loss_th = self.ts("Loss Thresholds", [
            (f'opnsense_gateways_loss_percentage{F}', '{{{{name}}}} Current'),
            (f'opnsense_gateways_loss_low_percentage{F}', '{{{{name}}}} Low'),
            (f'opnsense_gateways_loss_high_percentage{F}', '{{{{name}}}} High'),
        ], unit="percent")
        rows.append(self.row("Packet Loss", [
            self.gi(p_loss, 0, 0, 12, 8), self.gi(p_loss_th, 12, 0, 12, 8),
        ]))

        # Row 4.4: Probe Config
        p_probe = self.ts("Probe Timings", [
            (f'opnsense_gateways_probe_interval_seconds{F}', '{{{{name}}}} Interval'),
            (f'opnsense_gateways_probe_period_seconds{F}', '{{{{name}}}} Period'),
            (f'opnsense_gateways_probe_timeout_seconds{F}', '{{{{name}}}} Timeout'),
        ], unit="s", desc="Gateway probe interval, period, and timeout")
        rows.append(self.row("Probe Configuration", [
            self.gi(p_probe, 0, 0, 24, 8),
        ]))

        return self.tab("Gateways", rows)

    # ════════════════════════════════════════════════════════════════
    # TAB 5: DNS (UNBOUND)
    # ════════════════════════════════════════════════════════════════

    def _tab_dns(self):
        rows = []
        uf = F  # unbound filter same as instance filter

        # Row 5.1: Service
        p_run = self.stat("Service Running", f"opnsense_unbound_dns_service_running{uf}",
                          thresholds=self.TH_UP, mappings=self.SERVICE_MAP)
        p_upt = self.stat("Uptime", f"opnsense_unbound_dns_uptime_seconds{uf}", unit="dtdurations")
        p_bl = self.stat("Blocklist Enabled", f"opnsense_unbound_dns_blocklist_enabled{uf}",
                         thresholds=self.TH_UP, mappings=self.ENABLED_MAP)
        p_ravg = self.stat("Recursion Time Avg", f"opnsense_unbound_dns_recursion_time_avg_seconds{uf}",
                           unit="s")
        p_rmed = self.stat("Recursion Time Median", f"opnsense_unbound_dns_recursion_time_median_seconds{uf}",
                           unit="s")
        rows.append(self.row("Service", [
            self.gi(p_run, 0, 0, 4, 5), self.gi(p_upt, 4, 0, 5, 5),
            self.gi(p_bl, 9, 0, 5, 5), self.gi(p_ravg, 14, 0, 5, 5),
            self.gi(p_rmed, 19, 0, 5, 5),
        ]))

        # Row 5.2: Query Performance
        p_qperf = self.ts("Query & Cache Performance", [
            (f'rate(opnsense_unbound_dns_queries_total{uf}[{R}])', 'Queries'),
            (f'rate(opnsense_unbound_dns_cache_hits_total{uf}[{R}])', 'Cache Hits'),
            (f'rate(opnsense_unbound_dns_cache_miss_total{uf}[{R}])', 'Cache Miss'),
            (f'rate(opnsense_unbound_dns_prefetch_total{uf}[{R}])', 'Prefetch'),
            (f'rate(opnsense_unbound_dns_expired_total{uf}[{R}])', 'Expired'),
        ])
        p_rcode = self.ts("Answers by Response Code", [
            (f'rate(opnsense_unbound_dns_answers_by_rcode_total{uf}[{R}])', '{{{{rcode}}}}'),
        ])
        p_qtype = self.ts("Queries by Type", [
            (f'rate(opnsense_unbound_dns_queries_by_type_total{uf}[{R}])', '{{{{type}}}}'),
        ])
        p_qproto = self.ts("Queries by Protocol", [
            (f'rate(opnsense_unbound_dns_queries_by_protocol_total{uf}[{R}])', '{{{{protocol}}}}'),
        ])
        rows.append(self.row("Query Performance", [
            self.gi(p_qperf, 0, 0, 12, 8), self.gi(p_rcode, 12, 0, 12, 8),
            self.gi(p_qtype, 0, 8, 12, 8), self.gi(p_qproto, 12, 8, 12, 8),
        ]))

        # Row 5.3: Security
        p_sec = self.ts("DNSSEC Answers", [
            (f'rate(opnsense_unbound_dns_answers_secure_total{uf}[{R}])', 'Secure'),
            (f'rate(opnsense_unbound_dns_answers_bogus_total{uf}[{R}])', 'Bogus'),
            (f'rate(opnsense_unbound_dns_rrset_bogus_total{uf}[{R}])', 'RRSet Bogus'),
        ])
        p_unw = self.ts("Unwanted Traffic", [
            (f'rate(opnsense_unbound_dns_unwanted_total{uf}[{R}])', '{{{{type}}}}'),
        ])
        rows.append(self.row("Security", [
            self.gi(p_sec, 0, 0, 12, 8), self.gi(p_unw, 12, 0, 12, 8),
        ]))

        # Row 5.4: Cache & Memory
        p_cache = self.ts("Cache Entry Count", [
            (f'opnsense_unbound_dns_cache_count{uf}', '{{{{cache}}}}'),
        ], desc="Entries in rrset, message, infra, key caches")
        p_mem = self.ts("Memory Usage", [
            (f'opnsense_unbound_dns_memory_bytes{uf}', '{{{{component}}}}'),
        ], unit="decbytes")
        rows.append(self.row("Cache & Memory", [
            self.gi(p_cache, 0, 0, 12, 8), self.gi(p_mem, 12, 0, 12, 8),
        ]))

        # Row 5.5: Request List & Advanced
        p_rlist = self.ts("Request List", [
            (f'opnsense_unbound_dns_request_list_avg{uf}', 'Average'),
            (f'opnsense_unbound_dns_request_list_max{uf}', 'Max'),
        ])
        p_rcur = self.ts("Request List Current", [
            (f'opnsense_unbound_dns_request_list_current{uf}', '{{{{scope}}}}'),
        ])
        p_rover = self.ts("Request List Overload", [
            (f'rate(opnsense_unbound_dns_request_list_overwritten_total{uf}[{R}])', 'Overwritten'),
            (f'rate(opnsense_unbound_dns_request_list_exceeded_total{uf}[{R}])', 'Exceeded'),
        ])
        p_tcp = self.gauge("TCP Usage Ratio", f'opnsense_unbound_dns_tcp_usage_ratio{uf}',
                           desc="TCP connection usage for DNS resolver")
        p_flags = self.ts("Query Flags", [
            (f'rate(opnsense_unbound_dns_query_flags_total{uf}[{R}])', '{{{{flag}}}}'),
        ])
        p_edns = self.ts("EDNS Queries", [
            (f'rate(opnsense_unbound_dns_edns_total{uf}[{R}])', '{{{{type}}}}'),
        ])
        p_timeout = self.ts("Timeouts & Rate Limiting", [
            (f'rate(opnsense_unbound_dns_queries_timed_out_total{uf}[{R}])', 'Timed Out'),
            (f'rate(opnsense_unbound_dns_queries_ip_ratelimited_total{uf}[{R}])', 'IP Rate Limited'),
        ])
        p_recur = self.ts("Recursive Replies", [
            (f'rate(opnsense_unbound_dns_recursive_replies_total{uf}[{R}])', 'Recursive Replies'),
        ])
        rows.append(self.row("Request List & Advanced", [
            self.gi(p_rlist, 0, 0, 8, 8), self.gi(p_rcur, 8, 0, 8, 8),
            self.gi(p_rover, 16, 0, 8, 8),
            self.gi(p_tcp, 0, 8, 6, 6), self.gi(p_flags, 6, 8, 9, 8),
            self.gi(p_edns, 15, 8, 9, 8),
            self.gi(p_timeout, 0, 16, 12, 8), self.gi(p_recur, 12, 16, 12, 8),
        ]))

        return self.tab("DNS", rows)

    # ════════════════════════════════════════════════════════════════
    # TAB 6: VPN
    # ════════════════════════════════════════════════════════════════

    def _tab_vpn(self):
        rows = []

        # Row 6.1: Service Status
        p_wg = self.stat("WireGuard Service", f"opnsense_wireguard_service_running{F}",
                         thresholds=self.TH_UP, mappings=self.SERVICE_MAP)
        p_ipsec = self.stat("IPsec Service", f"opnsense_ipsec_service_running{F}",
                            thresholds=self.TH_UP, mappings=self.SERVICE_MAP)
        p_ovpn = self.stat("OpenVPN Instances", f'count(opnsense_openvpn_instances{F})')
        rows.append(self.row("Service Status", [
            self.gi(p_wg, 0, 0, 8, 5), self.gi(p_ipsec, 8, 0, 8, 5),
            self.gi(p_ovpn, 16, 0, 8, 5),
        ]))

        # Row 6.2: WireGuard (collapsed)
        p_wg_if = self.sh("WireGuard Interface Status",
                          f'opnsense_wireguard_interfaces_status{F}',
                          self.UP_DOWN_MAP, legend='{{device_name}}')
        p_wg_peer = self.sh("WireGuard Peer Status",
                            f'opnsense_wireguard_peer_status{F}',
                            [{"type": "value", "options": {
                                "0": {"text": "Down", "color": "red", "index": 0},
                                "1": {"text": "Up", "color": "green", "index": 1},
                                "2": {"text": "Unknown", "color": "orange", "index": 2},
                            }}], legend='{{peer_name}}')
        p_wg_rx = self.ts("WireGuard Peer RX Rate", [
            (f'rate(opnsense_wireguard_peer_received_bytes_total{F}[{R}])', '{{{{peer_name}}}}'),
        ], unit="Bps")
        p_wg_tx = self.ts("WireGuard Peer TX Rate", [
            (f'rate(opnsense_wireguard_peer_transmitted_bytes_total{F}[{R}])', '{{{{peer_name}}}}'),
        ], unit="Bps")
        p_wg_hs = self.ts("WireGuard Last Handshake Age", [
            (f'time() - opnsense_wireguard_peer_last_handshake_seconds{F}', '{{{{peer_name}}}}'),
        ], unit="s", desc="Seconds since last handshake per peer")
        rows.append(self.row("WireGuard", [
            self.gi(p_wg_if, 0, 0, 24, 6),
            self.gi(p_wg_peer, 0, 6, 24, 6),
            self.gi(p_wg_rx, 0, 12, 12, 8), self.gi(p_wg_tx, 12, 12, 12, 8),
            self.gi(p_wg_hs, 0, 20, 24, 8),
        ], collapsed=True))

        # Row 6.3: IPsec Phase 1 (collapsed)
        p_ip1_st = self.sh("IPsec Phase 1 Status", f'opnsense_ipsec_phase1_status{F}',
                           self.UP_DOWN_MAP, legend='{{name}}')
        p_ip1_b = self.ts("Phase 1 Bytes", [
            (f'opnsense_ipsec_phase1_bytes_in{F}', '{{{{name}}}} In'),
            (f'opnsense_ipsec_phase1_bytes_out{F}', '{{{{name}}}} Out'),
        ], unit="decbytes")
        p_ip1_p = self.ts("Phase 1 Packets", [
            (f'opnsense_ipsec_phase1_packets_in{F}', '{{{{name}}}} In'),
            (f'opnsense_ipsec_phase1_packets_out{F}', '{{{{name}}}} Out'),
        ])
        p_ip1_t = self.ts("Phase 1 Install Time", [
            (f'opnsense_ipsec_phase1_install_time{F}', '{{{{name}}}}'),
        ], unit="s")
        rows.append(self.row("IPsec Phase 1", [
            self.gi(p_ip1_st, 0, 0, 24, 6),
            self.gi(p_ip1_b, 0, 6, 12, 8), self.gi(p_ip1_p, 12, 6, 12, 8),
            self.gi(p_ip1_t, 0, 14, 24, 8),
        ], collapsed=True))

        # Row 6.4: IPsec Phase 2 (collapsed)
        p_ip2_b = self.ts("Phase 2 Bytes", [
            (f'rate(opnsense_ipsec_phase2_bytes_in{F}[{R}])', '{{{{name}}}} In'),
            (f'rate(opnsense_ipsec_phase2_bytes_out{F}[{R}])', '{{{{name}}}} Out'),
        ], unit="Bps")
        p_ip2_p = self.ts("Phase 2 Packets", [
            (f'rate(opnsense_ipsec_phase2_packets_in{F}[{R}])', '{{{{name}}}} In'),
            (f'rate(opnsense_ipsec_phase2_packets_out{F}[{R}])', '{{{{name}}}} Out'),
        ])
        p_ip2_rk = self.ts("Phase 2 Rekey Time", [
            (f'opnsense_ipsec_phase2_rekey_time{F}', '{{{{name}}}}'),
        ], unit="s")
        p_ip2_lt = self.ts("Phase 2 Life Time", [
            (f'opnsense_ipsec_phase2_life_time{F}', '{{{{name}}}}'),
        ], unit="s")
        p_ip2_it = self.ts("Phase 2 Install Time", [
            (f'opnsense_ipsec_phase2_install_time{F}', '{{{{name}}}}'),
        ], unit="s")
        rows.append(self.row("IPsec Phase 2", [
            self.gi(p_ip2_b, 0, 0, 12, 8), self.gi(p_ip2_p, 12, 0, 12, 8),
            self.gi(p_ip2_rk, 0, 8, 8, 8), self.gi(p_ip2_lt, 8, 8, 8, 8),
            self.gi(p_ip2_it, 16, 8, 8, 8),
        ], collapsed=True))

        # Row 6.5: OpenVPN (collapsed)
        p_ov_inst = self.tbl("OpenVPN Instances", f'opnsense_openvpn_instances{F}',
                             desc="OpenVPN instances with role, description labels")
        p_ov_sess = self.sh("OpenVPN Sessions", f'opnsense_openvpn_sessions{F}',
                            [{"type": "value", "options": {
                                "0": {"text": "Not OK", "color": "red", "index": 0},
                                "1": {"text": "OK", "color": "green", "index": 1},
                            }}], legend='{{description}} ({{username}})')
        rows.append(self.row("OpenVPN", [
            self.gi(p_ov_inst, 0, 0, 24, 8),
            self.gi(p_ov_sess, 0, 8, 24, 8),
        ], collapsed=True))

        return self.tab("VPN", rows)

    # ════════════════════════════════════════════════════════════════
    # TAB 7: DHCP & NEIGHBORS
    # ════════════════════════════════════════════════════════════════

    def _tab_dhcp(self):
        rows = []

        # Row 7.1: Kea DHCPv4
        p_k4t = self.stat("Kea DHCPv4 Total", f"opnsense_kea_dhcp4_leases_total{F}")
        p_k4r = self.stat("DHCPv4 Reserved", f"opnsense_kea_dhcp4_leases_reserved_total{F}")
        p_k4d = self.stat("DHCPv4 Dynamic", f"opnsense_kea_dhcp4_leases_dynamic_total{F}")
        p_k4i = self.bg("DHCPv4 Leases by Interface",
                        f'opnsense_kea_dhcp4_leases_by_interface{F}', legend="{{interface}}")
        rows.append(self.row("Kea DHCPv4", [
            self.gi(p_k4t, 0, 0, 4, 5), self.gi(p_k4r, 4, 0, 4, 5),
            self.gi(p_k4d, 8, 0, 4, 5), self.gi(p_k4i, 12, 0, 12, 8),
        ]))

        # Row 7.2: Kea DHCPv6
        p_k6t = self.stat("Kea DHCPv6 Total", f"opnsense_kea_dhcp6_leases_total{F}")
        p_k6r = self.stat("DHCPv6 Reserved", f"opnsense_kea_dhcp6_leases_reserved_total{F}")
        p_k6d = self.stat("DHCPv6 Dynamic", f"opnsense_kea_dhcp6_leases_dynamic_total{F}")
        p_k6i = self.bg("DHCPv6 Leases by Interface",
                        f'opnsense_kea_dhcp6_leases_by_interface{F}', legend="{{interface}}")
        rows.append(self.row("Kea DHCPv6", [
            self.gi(p_k6t, 0, 0, 4, 5), self.gi(p_k6r, 4, 0, 4, 5),
            self.gi(p_k6d, 8, 0, 4, 5), self.gi(p_k6i, 12, 0, 12, 8),
        ]))

        # Row 7.3: Kea Lease Details (collapsed - opt-in high cardinality)
        p_k4l = self.tbl("Kea DHCPv4 Lease Details", f'opnsense_kea_dhcp4_lease_info{F}',
                         desc="Requires --exporter.enable-kea-details")
        p_k6l = self.tbl("Kea DHCPv6 Lease Details", f'opnsense_kea_dhcp6_lease_info{F}',
                         desc="Requires --exporter.enable-kea-details")
        rows.append(self.row("Kea Lease Details", [
            self.gi(p_k4l, 0, 0, 24, 10),
            self.gi(p_k6l, 0, 10, 24, 10),
        ], collapsed=True))

        # Row 7.4: Dnsmasq
        p_dm_run = self.stat("Dnsmasq Service", f"opnsense_dnsmasq_service_running{F}",
                             thresholds=self.TH_UP, mappings=self.SERVICE_MAP)
        p_dm_t = self.stat("Dnsmasq Total", f"opnsense_dnsmasq_leases_total{F}")
        p_dm_r = self.stat("Reserved", f"opnsense_dnsmasq_leases_reserved_total{F}")
        p_dm_d = self.stat("Dynamic", f"opnsense_dnsmasq_leases_dynamic_total{F}")
        p_dm_i = self.bg("Dnsmasq Leases by Interface",
                         f'opnsense_dnsmasq_leases_by_interface{F}', legend="{{interface}}")
        rows.append(self.row("Dnsmasq DHCP", [
            self.gi(p_dm_run, 0, 0, 4, 5), self.gi(p_dm_t, 4, 0, 4, 5),
            self.gi(p_dm_r, 8, 0, 4, 5), self.gi(p_dm_d, 12, 0, 4, 5),
            self.gi(p_dm_i, 16, 0, 8, 8),
        ]))

        # Row 7.5: Dnsmasq Lease Details (collapsed)
        p_dm_l = self.tbl("Dnsmasq Lease Details", f'opnsense_dnsmasq_lease_info{F}',
                          desc="Requires --exporter.enable-dnsmasq-details")
        rows.append(self.row("Dnsmasq Lease Details", [
            self.gi(p_dm_l, 0, 0, 24, 10),
        ], collapsed=True))

        # Row 7.6: ARP Table
        p_arp = self.tbl("ARP Table", f'opnsense_arp_table_entries{F}',
                         desc="ARP entries showing IP, MAC, hostname, interface")
        rows.append(self.row("ARP Table", [
            self.gi(p_arp, 0, 0, 24, 10),
        ]))

        # Row 7.7: NDP Table
        p_ndp = self.tbl("NDP Table (IPv6 Neighbors)", f'opnsense_ndp_entries{F}',
                         desc="NDP entries showing IP, MAC, interface")
        rows.append(self.row("NDP Table", [
            self.gi(p_ndp, 0, 0, 24, 10),
        ]))

        return self.tab("DHCP & Neighbors", rows)

    # ════════════════════════════════════════════════════════════════
    # TAB 8: NETWORK INTERNALS
    # ════════════════════════════════════════════════════════════════

    def _tab_internals(self):
        rows = []

        # Row 8.1: TCP
        p_tcp_state = self.ts("TCP Connections by State", [
            (f'opnsense_protocol_tcp_connection_count_by_state{F}', '{{{{state}}}}'),
        ], desc="Current TCP connection count by state")
        p_tcp_pkt = self.ts("TCP Packets Rate", [
            (f'rate(opnsense_protocol_tcp_sent_packets_total{F}[{R}])', 'Sent'),
            (f'rate(opnsense_protocol_tcp_received_packets_total{F}[{R}])', 'Received'),
        ])
        p_tcp_conn = self.ts("TCP Connection Lifecycle", [
            (f'rate(opnsense_protocol_tcp_connection_requests_total{F}[{R}])', 'Requests'),
            (f'rate(opnsense_protocol_tcp_connection_accepts_total{F}[{R}])', 'Accepts'),
            (f'rate(opnsense_protocol_tcp_connections_established_total{F}[{R}])', 'Established'),
            (f'rate(opnsense_protocol_tcp_connections_closed_total{F}[{R}])', 'Closed'),
            (f'rate(opnsense_protocol_tcp_connection_drops_total{F}[{R}])', 'Drops'),
        ])
        p_tcp_data = self.ts("TCP Data Throughput", [
            (f'rate(opnsense_protocol_tcp_sent_data_bytes_total{F}[{R}])', 'Sent'),
            (f'rate(opnsense_protocol_tcp_received_in_sequence_bytes_total{F}[{R}])', 'Received In Sequence'),
            (f'rate(opnsense_protocol_tcp_received_duplicate_bytes_total{F}[{R}])', 'Received Duplicate'),
        ], unit="Bps")
        p_tcp_retrans = self.ts("TCP Retransmissions", [
            (f'rate(opnsense_protocol_tcp_retransmit_timeouts_total{F}[{R}])', 'Timeouts'),
            (f'rate(opnsense_protocol_tcp_retransmitted_packets_total{F}[{R}])', 'Packets'),
            (f'rate(opnsense_protocol_tcp_retransmitted_bytes_total{F}[{R}])', 'Bytes'),
        ])
        p_tcp_misc = self.ts("TCP Keepalive & Errors", [
            (f'rate(opnsense_protocol_tcp_keepalive_timeouts_total{F}[{R}])', 'Keepalive Timeouts'),
            (f'rate(opnsense_protocol_tcp_keepalive_probes_total{F}[{R}])', 'Keepalive Probes'),
            (f'rate(opnsense_protocol_tcp_bad_connection_attempts_total{F}[{R}])', 'Bad Attempts'),
            (f'rate(opnsense_protocol_tcp_listen_queue_overflows_total{F}[{R}])', 'Listen Queue Overflows'),
        ])
        p_tcp_sync = self.ts("TCP SYN Cache & RTT", [
            (f'rate(opnsense_protocol_tcp_syncache_entries_total{F}[{R}])', 'SYN Cache Entries'),
            (f'rate(opnsense_protocol_tcp_syncache_dropped_total{F}[{R}])', 'SYN Cache Dropped'),
            (f'rate(opnsense_protocol_tcp_segments_updated_rtt_total{F}[{R}])', 'Segments Updated RTT'),
        ])
        rows.append(self.row("TCP", [
            self.gi(p_tcp_state, 0, 0, 12, 8), self.gi(p_tcp_pkt, 12, 0, 12, 8),
            self.gi(p_tcp_conn, 0, 8, 12, 8), self.gi(p_tcp_data, 12, 8, 12, 8),
            self.gi(p_tcp_retrans, 0, 16, 8, 8), self.gi(p_tcp_misc, 8, 16, 8, 8),
            self.gi(p_tcp_sync, 16, 16, 8, 8),
        ]))

        # Row 8.2: UDP
        p_udp = self.ts("UDP Traffic Rate", [
            (f'rate(opnsense_protocol_udp_delivered_packets_total{F}[{R}])', 'Delivered'),
            (f'rate(opnsense_protocol_udp_output_packets_total{F}[{R}])', 'Output'),
            (f'rate(opnsense_protocol_udp_received_datagrams_total{F}[{R}])', 'Received'),
        ])
        p_udp_drop = self.ts("UDP Dropped by Reason", [
            (f'rate(opnsense_protocol_udp_dropped_by_reason_total{F}[{R}])', '{{{{reason}}}}'),
        ])
        rows.append(self.row("UDP", [
            self.gi(p_udp, 0, 0, 12, 8), self.gi(p_udp_drop, 12, 0, 12, 8),
        ]))

        # Row 8.3: ICMP
        p_icmp = self.ts("ICMP Traffic Rate", [
            (f'rate(opnsense_protocol_icmp_calls_total{F}[{R}])', 'Calls'),
            (f'rate(opnsense_protocol_icmp_sent_packets_total{F}[{R}])', 'Sent'),
        ])
        p_icmp_drop = self.ts("ICMP Dropped by Reason", [
            (f'rate(opnsense_protocol_icmp_dropped_by_reason_total{F}[{R}])', '{{{{reason}}}}'),
        ])
        rows.append(self.row("ICMP", [
            self.gi(p_icmp, 0, 0, 12, 8), self.gi(p_icmp_drop, 12, 0, 12, 8),
        ]))

        # Row 8.4: ARP Protocol
        p_arp_rq = self.ts("ARP Requests Rate", [
            (f'rate(opnsense_protocol_arp_sent_requests_total{F}[{R}])', 'Sent Requests'),
            (f'rate(opnsense_protocol_arp_received_requests_total{F}[{R}])', 'Received Requests'),
            (f'rate(opnsense_protocol_arp_sent_replies_total{F}[{R}])', 'Sent Replies'),
            (f'rate(opnsense_protocol_arp_received_replies_total{F}[{R}])', 'Received Replies'),
        ])
        p_arp_err = self.ts("ARP Errors & Drops Rate", [
            (f'rate(opnsense_protocol_arp_sent_failures_total{F}[{R}])', 'Sent Failures'),
            (f'rate(opnsense_protocol_arp_received_packets_total{F}[{R}])', 'Received Packets'),
            (f'rate(opnsense_protocol_arp_dropped_no_entry_total{F}[{R}])', 'Dropped No Entry'),
            (f'rate(opnsense_protocol_arp_entries_timeout_total{F}[{R}])', 'Entries Timeout'),
            (f'rate(opnsense_protocol_arp_dropped_duplicate_address_total{F}[{R}])', 'Dropped Duplicate'),
        ])
        rows.append(self.row("ARP Protocol", [
            self.gi(p_arp_rq, 0, 0, 12, 8), self.gi(p_arp_err, 12, 0, 12, 8),
        ]))

        # Row 8.5: IP
        p_ip = self.ts("IP Packets Rate", [
            (f'rate(opnsense_protocol_ip_received_packets_total{F}[{R}])', 'Received'),
            (f'rate(opnsense_protocol_ip_forwarded_packets_total{F}[{R}])', 'Forwarded'),
            (f'rate(opnsense_protocol_ip_sent_packets_total{F}[{R}])', 'Sent'),
        ])
        p_ip_drop = self.ts("IP Dropped by Reason", [
            (f'rate(opnsense_protocol_ip_dropped_by_reason_total{F}[{R}])', '{{{{reason}}}}'),
        ])
        p_ip_frag = self.ts("IP Fragmentation", [
            (f'rate(opnsense_protocol_ip_fragments_received_total{F}[{R}])', 'Fragments Received'),
            (f'rate(opnsense_protocol_ip_reassembled_packets_total{F}[{R}])', 'Reassembled'),
            (f'rate(opnsense_protocol_ip_sent_fragments_total{F}[{R}])', 'Sent Fragments'),
        ])
        rows.append(self.row("IP", [
            self.gi(p_ip, 0, 0, 8, 8), self.gi(p_ip_drop, 8, 0, 8, 8),
            self.gi(p_ip_frag, 16, 0, 8, 8),
        ]))

        # Row 8.6: CARP & PFSync
        p_carp_dem = self.stat("CARP Demotion", f"opnsense_carp_demotion{F}")
        p_carp_al = self.stat("CARP Allow", f"opnsense_carp_allow{F}",
                              thresholds=self.TH_UP, mappings=self.ENABLED_MAP)
        p_carp_mm = self.stat("Maintenance Mode", f"opnsense_carp_maintenance_mode{F}",
                              thresholds=[{"value": 0, "color": "green"}, {"value": 1, "color": "orange"}],
                              mappings=self.ENABLED_MAP)
        p_carp_vt = self.stat("CARP VIPs Total", f"opnsense_carp_vips_total{F}")
        p_carp_vs = self.sh("CARP VIP Status", f'opnsense_carp_vip_status{F}',
                            self.CARP_VIP_MAP, legend='{{interface}} vhid:{{vhid}} {{vip}}',
                            thresholds=[{"value": -1, "color": "gray"}, {"value": 0, "color": "orange"},
                                        {"value": 1, "color": "green"}, {"value": 2, "color": "yellow"}])
        p_carp_cfg = self.tbl("CARP VIP Config",
                              f'opnsense_carp_vip_advbase_seconds{F}',
                              desc="CARP advertisement base and skew per VIP")
        # Also need advskew - add as second query
        p_carp_skew = self.ts("CARP VIP Advskew", [
            (f'opnsense_carp_vip_advskew{F}', '{{{{interface}}}} vhid:{{{{vhid}}}}'),
        ])
        p_carp_pkt = self.ts("CARP Packets Rate", [
            (f'rate(opnsense_protocol_carp_received_packets_total{F}[{R}])', '{{{{address_family}}}} RX'),
            (f'rate(opnsense_protocol_carp_sent_packets_total{F}[{R}])', '{{{{address_family}}}} TX'),
        ])
        p_carp_drop = self.ts("CARP Dropped by Reason", [
            (f'rate(opnsense_protocol_carp_dropped_by_reason_total{F}[{R}])', '{{{{reason}}}}'),
        ])
        p_pfsync_pkt = self.ts("PFSync Packets Rate", [
            (f'rate(opnsense_protocol_pfsync_received_packets_total{F}[{R}])', '{{{{address_family}}}} RX'),
            (f'rate(opnsense_protocol_pfsync_sent_packets_total{F}[{R}])', '{{{{address_family}}}} TX'),
        ])
        p_pfsync_err = self.ts("PFSync Errors & Drops", [
            (f'rate(opnsense_protocol_pfsync_dropped_by_reason_total{F}[{R}])', '{{{{reason}}}} Dropped'),
            (f'rate(opnsense_protocol_pfsync_send_errors_total{F}[{R}])', 'Send Errors'),
        ])
        rows.append(self.row("CARP & PFSync", [
            self.gi(p_carp_dem, 0, 0, 4, 4), self.gi(p_carp_al, 4, 0, 4, 4),
            self.gi(p_carp_mm, 8, 0, 4, 4), self.gi(p_carp_vt, 12, 0, 4, 4),
            self.gi(p_carp_vs, 0, 4, 24, 8),
            self.gi(p_carp_cfg, 0, 12, 12, 8), self.gi(p_carp_skew, 12, 12, 12, 8),
            self.gi(p_carp_pkt, 0, 20, 12, 8), self.gi(p_carp_drop, 12, 20, 12, 8),
            self.gi(p_pfsync_pkt, 0, 28, 12, 8), self.gi(p_pfsync_err, 12, 28, 12, 8),
        ]))

        # Row 8.7: Mbuf
        p_mbuf = self.ts("Mbuf Usage", [
            (f'opnsense_mbuf_current{F}', 'Current'),
            (f'opnsense_mbuf_cache{F}', 'Cache'),
            (f'opnsense_mbuf_total{F}', 'Total'),
        ])
        p_mbuf_cl = self.ts("Mbuf Cluster Usage", [
            (f'opnsense_mbuf_cluster_current{F}', 'Current'),
            (f'opnsense_mbuf_cluster_cache{F}', 'Cache'),
            (f'opnsense_mbuf_cluster_total{F}', 'Total'),
            (f'opnsense_mbuf_cluster_max{F}', 'Max'),
        ])
        p_mbuf_mem = self.ts("Mbuf Memory", [
            (f'opnsense_mbuf_bytes_in_use{F}', 'In Use'),
            (f'opnsense_mbuf_bytes_total{F}', 'Total'),
        ], unit="decbytes")
        p_mbuf_fail = self.ts("Mbuf Failures", [
            (f'rate(opnsense_mbuf_failures_total{F}[{R}])', '{{{{type}}}} Failures'),
            (f'rate(opnsense_mbuf_sleeps_total{F}[{R}])', '{{{{type}}}} Sleeps'),
        ])
        p_mbuf_sf = self.ts("Sendfile Stats", [
            (f'rate(opnsense_mbuf_sendfile_syscalls_total{F}[{R}])', 'Syscalls'),
            (f'rate(opnsense_mbuf_sendfile_io_total{F}[{R}])', 'I/O Ops'),
            (f'rate(opnsense_mbuf_sendfile_pages_sent_total{F}[{R}])', 'Pages Sent'),
        ])
        rows.append(self.row("Mbuf", [
            self.gi(p_mbuf, 0, 0, 8, 8), self.gi(p_mbuf_cl, 8, 0, 8, 8),
            self.gi(p_mbuf_mem, 16, 0, 8, 8),
            self.gi(p_mbuf_fail, 0, 8, 12, 8), self.gi(p_mbuf_sf, 12, 8, 12, 8),
        ]))

        # Row 8.8: Network Diagnostics (collapsed - opt-in)
        p_nd_disp = self.ts("Netisr Dispatched", [
            (f'rate(opnsense_network_diag_netisr_dispatched_total{F}[{R}])', '{{{{protocol}}}}'),
        ])
        p_nd_hyb = self.ts("Netisr Hybrid Dispatched", [
            (f'rate(opnsense_network_diag_netisr_hybrid_dispatched_total{F}[{R}])', '{{{{protocol}}}}'),
        ])
        p_nd_q = self.ts("Netisr Queued & Handled", [
            (f'rate(opnsense_network_diag_netisr_queued_total{F}[{R}])', '{{{{protocol}}}} Queued'),
            (f'rate(opnsense_network_diag_netisr_handled_total{F}[{R}])', '{{{{protocol}}}} Handled'),
        ])
        p_nd_drop = self.ts("Netisr Queue Drops", [
            (f'rate(opnsense_network_diag_netisr_queue_drops_total{F}[{R}])', '{{{{protocol}}}}'),
        ])
        p_nd_ql = self.ts("Netisr Queue Stats", [
            (f'opnsense_network_diag_netisr_queue_length{F}', '{{{{protocol}}}} Length'),
            (f'opnsense_network_diag_netisr_queue_watermark{F}', '{{{{protocol}}}} Watermark'),
            (f'opnsense_network_diag_netisr_queue_limit{F}', '{{{{protocol}}}} Limit'),
        ])
        p_nd_sock = self.bg("Active Sockets by Type",
                            f'opnsense_network_diag_sockets_active{F}', legend="{{type}}")
        p_nd_unix = self.stat("Unix Sockets", f"opnsense_network_diag_sockets_unix_total{F}")
        p_nd_rt = self.bg("Routes by Protocol",
                          f'opnsense_network_diag_routes_total{F}', legend="{{proto}}")
        p_nd_pfs = self.stat("PFSync Nodes", f"opnsense_network_diag_pfsync_nodes_total{F}")
        p_nd_pfi = self.tbl("PFSync Node Info", f'opnsense_network_diag_pfsync_node_info{F}',
                            desc="PFSync node details")
        rows.append(self.row("Network Diagnostics", [
            self.gi(p_nd_disp, 0, 0, 12, 8), self.gi(p_nd_hyb, 12, 0, 12, 8),
            self.gi(p_nd_q, 0, 8, 12, 8), self.gi(p_nd_drop, 12, 8, 12, 8),
            self.gi(p_nd_ql, 0, 16, 24, 8),
            self.gi(p_nd_sock, 0, 24, 8, 8), self.gi(p_nd_unix, 8, 24, 4, 5),
            self.gi(p_nd_rt, 12, 24, 8, 8), self.gi(p_nd_pfs, 20, 24, 4, 5),
            self.gi(p_nd_pfi, 0, 32, 24, 8),
        ], collapsed=True))

        # Row 8.9: Netflow (collapsed - opt-in)
        p_nf_en = self.stat("Netflow Enabled", f"opnsense_netflow_enabled{F}",
                            thresholds=self.TH_UP, mappings=self.ENABLED_MAP)
        p_nf_lc = self.stat("Local Collection", f"opnsense_netflow_local_collection_enabled{F}",
                            thresholds=self.TH_UP, mappings=self.ENABLED_MAP)
        p_nf_ac = self.stat("Netflow Active", f"opnsense_netflow_active{F}",
                            thresholds=self.TH_UP, mappings=self.ENABLED_MAP)
        p_nf_cc = self.stat("Collectors Count", f"opnsense_netflow_collectors_count{F}")
        p_nf_pkt = self.ts("Netflow Cache Packets", [
            (f'rate(opnsense_netflow_cache_packets_total{F}[{R}])', '{{{{interface}}}}'),
        ])
        p_nf_src = self.ts("Unique Source IPs", [
            (f'opnsense_netflow_cache_source_ip_addresses{F}', '{{{{interface}}}}'),
        ])
        p_nf_dst = self.ts("Unique Destination IPs", [
            (f'opnsense_netflow_cache_destination_ip_addresses{F}', '{{{{interface}}}}'),
        ])
        rows.append(self.row("Netflow", [
            self.gi(p_nf_en, 0, 0, 6, 5), self.gi(p_nf_lc, 6, 0, 6, 5),
            self.gi(p_nf_ac, 12, 0, 6, 5), self.gi(p_nf_cc, 18, 0, 6, 5),
            self.gi(p_nf_pkt, 0, 5, 24, 8),
            self.gi(p_nf_src, 0, 13, 12, 8), self.gi(p_nf_dst, 12, 13, 12, 8),
        ], collapsed=True))

        # Row 8.10: NTP
        p_ntp_tot = self.stat("NTP Peers Total", f"opnsense_ntp_peers_total{F}")
        p_ntp_info = self.tbl("NTP Peer Info", f'opnsense_ntp_peer_info{F}',
                              desc="NTP peer details: server, refid, type, status")
        p_ntp_lat = self.ts("NTP Peer Timing", [
            (f'opnsense_ntp_peer_delay_milliseconds{F}', '{{{{server}}}} Delay'),
            (f'opnsense_ntp_peer_offset_milliseconds{F}', '{{{{server}}}} Offset'),
            (f'opnsense_ntp_peer_jitter_milliseconds{F}', '{{{{server}}}} Jitter'),
        ], unit="ms")
        p_ntp_str = self.ts("NTP Stratum", [
            (f'opnsense_ntp_peer_stratum{F}', '{{{{server}}}}'),
        ])
        p_ntp_reach = self.ts("NTP Reach", [
            (f'opnsense_ntp_peer_reach{F}', '{{{{server}}}}'),
        ], desc="Reachability register (octal decoded)")
        p_ntp_poll = self.ts("NTP Poll & When", [
            (f'opnsense_ntp_peer_poll_seconds{F}', '{{{{server}}}} Poll'),
            (f'opnsense_ntp_peer_when_seconds{F}', '{{{{server}}}} When'),
        ], unit="s")
        rows.append(self.row("NTP", [
            self.gi(p_ntp_tot, 0, 0, 4, 5), self.gi(p_ntp_info, 4, 0, 20, 8),
            self.gi(p_ntp_lat, 0, 8, 12, 8), self.gi(p_ntp_str, 12, 8, 12, 8),
            self.gi(p_ntp_reach, 0, 16, 12, 8), self.gi(p_ntp_poll, 12, 16, 12, 8),
        ]))

        # Row 8.11: Certificates
        p_cert_tot = self.stat("Certificates Total", f"opnsense_certificate_total{F}")
        p_cert_exp = self.bg("Days Until Certificate Expiry",
            f'(opnsense_certificate_valid_to_seconds{F} - time()) / 86400',
            unit="short", legend="{{commonname}}",
            thresholds=[{"value": 0, "color": "red"}, {"value": 14, "color": "orange"},
                        {"value": 30, "color": "yellow"}, {"value": 90, "color": "green"}],
            desc="Days remaining until certificate expiry")
        p_cert_info = self.tbl("Certificate Inventory", f'opnsense_certificate_info{F}',
                               desc="All certificates with description, CN, type, in_use")
        p_cert_from = self.ts("Certificate Valid From", [
            (f'opnsense_certificate_valid_from_seconds{F}', '{{{{commonname}}}}'),
        ], unit="dateTimeAsIso", desc="Certificate valid-from timestamps")
        p_cert_to = self.ts("Certificate Valid To", [
            (f'opnsense_certificate_valid_to_seconds{F}', '{{{{commonname}}}}'),
        ], unit="dateTimeAsIso", desc="Certificate expiry timestamps")
        rows.append(self.row("Certificates", [
            self.gi(p_cert_tot, 0, 0, 4, 5), self.gi(p_cert_exp, 4, 0, 20, 8),
            self.gi(p_cert_info, 0, 8, 24, 8),
            self.gi(p_cert_from, 0, 16, 12, 8), self.gi(p_cert_to, 12, 16, 12, 8),
        ]))

        return self.tab("Network Internals", rows)

    # ════════════════════════════════════════════════════════════════
    # VARIABLES
    # ════════════════════════════════════════════════════════════════

    def _variables(self):
        return [
            {
                "kind": "DatasourceVariable",
                "spec": {
                    "name": "datasource",
                    "pluginId": "prometheus",
                    "refresh": "onDashboardLoad",
                    "regex": "",
                    "current": {"text": "", "value": ""},
                    "options": [],
                    "multi": False,
                    "includeAll": False,
                    "label": "Data Source",
                    "hide": "dontHide",
                    "skipUrlSync": False,
                    "allowCustomValue": True,
                },
            },
            {
                "kind": "QueryVariable",
                "spec": {
                    "name": "opnsense_instance",
                    "current": {"text": "", "value": ""},
                    "label": "OPNSense Instance",
                    "hide": "dontHide",
                    "refresh": "onDashboardLoad",
                    "skipUrlSync": False,
                    "query": {
                        "kind": "DataQuery",
                        "group": "prometheus",
                        "version": "v0",
                        "spec": {
                            "qryType": 1,
                            "query": "label_values(opnsense_up,opnsense_instance)",
                            "refId": "PrometheusVariableQueryEditor-VariableQuery",
                        },
                    },
                    "regex": "",
                    "sort": "alphabeticalAsc",
                    "definition": "label_values(opnsense_up,opnsense_instance)",
                    "options": [],
                    "multi": False,
                    "includeAll": False,
                    "allowCustomValue": True,
                },
            },
            {
                "kind": "QueryVariable",
                "spec": {
                    "name": "interface",
                    "current": {"text": "All", "value": "$__all"},
                    "label": "Interface",
                    "hide": "dontHide",
                    "refresh": "onDashboardLoad",
                    "skipUrlSync": False,
                    "query": {
                        "kind": "DataQuery",
                        "group": "prometheus",
                        "version": "v0",
                        "spec": {
                            "qryType": 1,
                            "query": f"label_values(opnsense_interfaces_link_state{F},interface)",
                            "refId": "PrometheusVariableQueryEditor-VariableQuery",
                        },
                    },
                    "regex": "",
                    "sort": "alphabeticalAsc",
                    "definition": f"label_values(opnsense_interfaces_link_state{F},interface)",
                    "options": [],
                    "multi": True,
                    "includeAll": True,
                    "allowCustomValue": True,
                },
            },
            {
                "kind": "IntervalVariable",
                "spec": {
                    "name": "rate_interval",
                    "label": "Rate Interval",
                    "hide": "dontHide",
                    "current": {"text": "5m", "value": "5m"},
                    "query": "1m,5m,15m,30m,1h",
                    "options": [],
                    "auto": False,
                    "skipUrlSync": False,
                },
            },
        ]

    # ════════════════════════════════════════════════════════════════
    # ASSEMBLY
    # ════════════════════════════════════════════════════════════════

    def build(self):
        tabs = [
            self._tab_overview(),
            self._tab_firewall(),
            self._tab_interfaces(),
            self._tab_gateways(),
            self._tab_dns(),
            self._tab_vpn(),
            self._tab_dhcp(),
            self._tab_internals(),
        ]
        return {
            "apiVersion": "dashboard.grafana.app/v2beta1",
            "kind": "Dashboard",
            "metadata": {
                "name": "opnsense-exporter-comprehensive",
                "generation": 1,
                "creationTimestamp": "2025-05-05T14:55:04Z",
                "labels": {},
                "annotations": {},
            },
            "spec": {
                "annotations": [{
                    "kind": "AnnotationQuery",
                    "spec": {
                        "query": {
                            "kind": "DataQuery",
                            "group": "grafana",
                            "version": "v0",
                            "spec": {"limit": 100, "matchAny": False, "tags": [], "type": "dashboard"},
                        },
                        "enable": True,
                        "hide": True,
                        "iconColor": "rgba(0, 211, 255, 1)",
                        "name": "Annotations & Alerts",
                        "builtIn": True,
                    },
                }],
                "cursorSync": "Off",
                "description": "Comprehensive dashboard for the OPNsense Prometheus Exporter covering all 300+ metrics.\n\nhttps://github.com/rknightion/opnsense-exporter",
                "editable": True,
                "elements": self.elements,
                "layout": {
                    "kind": "TabsLayout",
                    "spec": {"tabs": tabs},
                },
                "links": [{
                    "title": "OPNsense Exporter",
                    "type": "link",
                    "icon": "external link",
                    "tooltip": "GitHub Repository",
                    "url": "https://github.com/rknightion/opnsense-exporter",
                    "tags": [],
                    "asDropdown": False,
                    "targetBlank": True,
                    "includeVars": False,
                    "keepTime": False,
                }],
                "liveNow": True,
                "preload": False,
                "tags": ["opnsense", "firewall", "networking", "prometheus-exporter"],
                "timeSettings": {
                    "timezone": "browser",
                    "from": "now-15m",
                    "to": "now",
                    "autoRefresh": "1m",
                    "autoRefreshIntervals": [
                        "5s", "10s", "30s", "1m", "5m", "15m", "30m", "1h", "2h", "1d",
                    ],
                    "hideTimepicker": False,
                    "fiscalYearStartMonth": 0,
                },
                "title": "OPNSense Exporter",
                "variables": self._variables(),
            },
        }


def main():
    d = Dashboard()
    dashboard = d.build()

    out_path = Path(__file__).resolve().parent.parent / "deploy" / "grafana" / "dashboard.json"
    out_path.parent.mkdir(parents=True, exist_ok=True)

    with open(out_path, "w") as f:
        json.dump(dashboard, f, indent=2)
        f.write("\n")

    print(f"Dashboard generated: {out_path}")
    print(f"  Panels: {d._id}")
    print(f"  Unique metrics referenced: {len(d._metrics)}")
    print(f"  File size: {out_path.stat().st_size:,} bytes")

    # Print metrics coverage
    print(f"\nMetrics referenced ({len(d._metrics)}):")
    for m in sorted(d._metrics):
        print(f"  {m}")


if __name__ == "__main__":
    main()
