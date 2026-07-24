import sys
import unittest
from pathlib import Path


GRAFANA_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GRAFANA_DIR))

import build_dashboard  # noqa: E402
from builder import Builder  # noqa: E402


TOP_LEVEL_TITLES = [
    "Overview",
    "System",
    "Network",
    "Security",
    "VPN & remote access",
    "Services",
    "Observability",
]

LEAF_TITLES = {
    "Overview",
    "System & Resources",
    "Interfaces",
    "Firewall & PF",
    "Aliases",
    "Gateways & WAN",
    "DNS - Unbound",
    "DHCP",
    "VPN",
    "Tailscale",
    "NetBird",
    "Routing & Neighbors",
    "Protocol Stats",
    "NTP",
    "Certificates",
    "ClamAV",
    "Services, Cron & DynDNS",
    "Syslog",
    "Q-Feeds",
    "NetFlow",
    "CARP / HA",
    "HAProxy",
    "Relayd",
    "Nginx",
    "FRR Routing",
    "Monit",
    "CrowdSec",
    "IDS/IPS",
    "UPS",
    "Captive Portal",
    "Traffic Shaper",
    "HA Sync",
    "Chrony",
    "Tor",
    "Siproxd",
    "Log-derived Events",
    "Zenarmor",
    "Log Shipping",
    "Diagnostics",
    "Recording rules",
}

OPTIONAL_LEAVES = {
    "Aliases",
    "DNS - Unbound",
    "DHCP",
    "VPN",
    "Tailscale",
    "NetBird",
    "NTP",
    "ClamAV",
    "Syslog",
    "Q-Feeds",
    "NetFlow",
    "CARP / HA",
    "HAProxy",
    "Relayd",
    "Nginx",
    "FRR Routing",
    "Monit",
    "CrowdSec",
    "IDS/IPS",
    "UPS",
    "Captive Portal",
    "Traffic Shaper",
    "HA Sync",
    "Chrony",
    "Tor",
    "Siproxd",
    "Log-derived Events",
    "Zenarmor",
    "Log Shipping",
    "Recording rules",
}


def leaf_tabs(builder):
    leaves = []
    for tab in builder.tabs:
        layout = tab["spec"]["layout"]
        if layout["kind"] == "TabsLayout":
            leaves.extend(layout["spec"]["tabs"])
        else:
            leaves.append(tab)
    return leaves


def panel_for_metric(builder, metric):
    for panel in builder.elements.values():
        for query in panel["spec"]["data"]["spec"]["queries"]:
            if metric in query["spec"]["query"]["spec"]["expr"]:
                return panel
    raise AssertionError(f"no panel queries {metric}")


class DashboardHierarchyTest(unittest.TestCase):
    def test_all_leaf_tabs_are_grouped_exactly_once(self):
        builder = build_dashboard.build_all()

        self.assertEqual([tab["spec"]["title"] for tab in builder.tabs], TOP_LEVEL_TITLES)
        leaves = leaf_tabs(builder)
        titles = [tab["spec"]["title"] for tab in leaves]
        self.assertEqual(len(titles), len(set(titles)))
        self.assertEqual(set(titles), LEAF_TITLES)

    def test_optional_leaf_tabs_have_conditional_rendering(self):
        builder = build_dashboard.build_all()
        by_title = {tab["spec"]["title"]: tab for tab in leaf_tabs(builder)}

        for title in OPTIONAL_LEAVES:
            with self.subTest(title=title):
                self.assertIn("conditionalRendering", by_title[title]["spec"])

    def test_fully_optional_domains_are_presence_gated(self):
        builder = build_dashboard.build_all()
        by_title = {tab["spec"]["title"]: tab for tab in builder.tabs}

        expected = {
            "VPN & remote access": [
                "has_wireguard",
                "has_openvpn",
                "has_ipsec",
                "has_tailscale",
                "has_netbird",
                "has_tor",
            ],
            "Services": [
                "has_syslog",
                "has_syslog_logs",
                "has_haproxy",
                "has_relayd",
                "has_nginx",
                "has_siproxd",
            ],
        }
        for title, variables in expected.items():
            with self.subTest(title=title):
                condition = by_title[title]["spec"]["conditionalRendering"]["spec"]
                self.assertEqual(condition["condition"], "or")
                self.assertEqual(
                    [item["spec"]["variable"] for item in condition["items"]],
                    variables,
                )


class OverviewSemanticsTest(unittest.TestCase):
    def test_system_status_code_has_complete_health_mapping(self):
        builder = Builder()
        build_dashboard.build_overview(builder)
        panel = panel_for_metric(builder, "opnsense_system_status_code")
        mappings = panel["spec"]["vizConfig"]["spec"]["fieldConfig"]["defaults"]["mappings"]
        options = mappings[0]["options"]

        self.assertEqual(options["-1"]["text"], "Error")
        self.assertEqual(options["0"]["text"], "Warning")
        self.assertEqual(options["1"]["text"], "Notice")
        self.assertEqual(options["2"]["text"], "OK")


if __name__ == "__main__":
    unittest.main()
