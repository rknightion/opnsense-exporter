import sys
import unittest
from pathlib import Path


GRAFANA_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GRAFANA_DIR))

import build_dashboard  # noqa: E402
import uids  # noqa: E402
from builder import Builder  # noqa: E402


TOP_LEVEL_TITLES = [
    "Overview",
    "System",
    "Network",
    "Security",
    "VPN & remote access",
    "Services",
]

LEAF_TITLES = {
    "Overview",
    "System & Resources",
    "Kernel Memory",
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
    "Authentication & Audit",
    "Flow Volume",
    "Zenarmor",
}

# The self-observability dashboard's leaves (#431). A separate inventory rather than
# a union: these two tabs moving to a dashboard of their own is the whole point of
# the split, so a change that put either back on the main dashboard should fail
# BOTH lists rather than pass a combined one.
HEALTH_LEAF_TITLES = {
    "Overview",
    "Scrape & Poll",
    "OPNsense API",
    "Metrics & OTLP",
    "Log Shipping",
    "Flow Pipeline",
    "Exporter Runtime",
    "Recording rules",
}

LEAF_TITLES_BY_UID = {
    uids.MAIN_UID: LEAF_TITLES,
    uids.HEALTH_UID: HEALTH_LEAF_TITLES,
}

# Derived, not duplicated. This was a hand-maintained copy of
# build_dashboard.OPTIONAL_TAB_PRESENCE and drifted from it silently — the copy
# asserts nothing the source does not already state, so the only thing a second
# list could ever catch is itself being out of date. LEAF_TITLES above stays
# explicit on purpose: it is an inventory, and a tab quietly disappearing from
# the dashboard is exactly what it exists to fail on.
OPTIONAL_LEAVES = set(build_dashboard.OPTIONAL_TAB_PRESENCE)


def leaf_tabs(builder):
    leaves = []
    for tab in builder.tabs:
        layout = tab["spec"]["layout"]
        if layout["kind"] == "TabsLayout":
            leaves.extend(layout["spec"]["tabs"])
        else:
            leaves.append(tab)
    return leaves


def merged_family_builder():
    """A stand-in Builder whose `elements` are every panel in the family (#431).

    Only `elements` is merged, which is all `panel_for_metric` reads. Layout is
    deliberately NOT merged: two dashboards' tab trees do not compose, and a test
    that needs layout should ask a real Builder for it.
    """
    merged = Builder()
    for _, b in build_dashboard.build_family():
        merged.elements.update(b.elements)
    return merged


def panel_for_metric(builder, metric):
    for panel in builder.elements.values():
        for query in panel["spec"]["data"]["spec"]["queries"]:
            if metric in query["spec"]["query"]["spec"]["expr"]:
                return panel
    raise AssertionError(f"no panel queries {metric}")


def panel_for_title(builder, title):
    for panel in builder.elements.values():
        if panel["spec"]["title"] == title:
            return panel
    raise AssertionError(f"no panel titled {title}")


class DashboardHierarchyTest(unittest.TestCase):
    def test_all_leaf_tabs_are_grouped_exactly_once(self):
        builder = build_dashboard.build_all()

        self.assertEqual([tab["spec"]["title"] for tab in builder.tabs], TOP_LEVEL_TITLES)
        leaves = leaf_tabs(builder)
        titles = [tab["spec"]["title"] for tab in leaves]
        self.assertEqual(len(titles), len(set(titles)))
        self.assertEqual(set(titles), LEAF_TITLES)

    def test_every_dashboard_in_the_family_has_its_expected_leaves(self):
        for spec, b in build_dashboard.build_family():
            with self.subTest(uid=spec.uid):
                titles = [t["spec"]["title"] for t in leaf_tabs(b)]
                self.assertEqual(len(titles), len(set(titles)))
                self.assertEqual(set(titles), LEAF_TITLES_BY_UID[spec.uid])

    def test_optional_leaf_tabs_have_conditional_rendering(self):
        # Family-wide: OPTIONAL_TAB_PRESENCE is one registry covering both
        # dashboards, and "Log Shipping" is now gated on the health dashboard.
        by_title = {tab["spec"]["title"]: tab
                    for _, b in build_dashboard.build_family()
                    for tab in leaf_tabs(b)}

        for title in OPTIONAL_LEAVES:
            with self.subTest(title=title):
                self.assertIn(title, by_title,
                              f"{title} is in OPTIONAL_TAB_PRESENCE but no dashboard "
                              "in the family builds a leaf tab with that title")
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


class LogShippingSemanticsTest(unittest.TestCase):
    def test_queue_and_delivery_panels_follow_the_bounded_acknowledged_pipeline_contract(self):
        # This contract spans BOTH dashboards since #431: the queue/delivery panels
        # moved to the health dashboard while the log-derived event counters stayed
        # on the main one, and the invariant is precisely that they agree. A
        # merged view keeps the check on the pipeline rather than on one file.
        builder = merged_family_builder()

        queue_count = panel_for_metric(builder, "opnsense_exporter_logs_queue_length")
        count_exprs = [
            query["spec"]["query"]["spec"]["expr"]
            for query in queue_count["spec"]["data"]["spec"]["queries"]
        ]
        self.assertTrue(any("opnsense_exporter_logs_queue_length" in expr for expr in count_exprs))
        self.assertTrue(any("opnsense_exporter_logs_queue_capacity" in expr for expr in count_exprs))

        queue_bytes = panel_for_metric(builder, "opnsense_exporter_logs_queue_bytes")
        byte_exprs = [
            query["spec"]["query"]["spec"]["expr"]
            for query in queue_bytes["spec"]["data"]["spec"]["queries"]
        ]
        self.assertTrue(any("opnsense_exporter_logs_queue_bytes" in expr for expr in byte_exprs))
        self.assertTrue(any("opnsense_exporter_logs_queue_max_bytes" in expr for expr in byte_exprs))

        ship_errors = panel_for_metric(builder, "opnsense_exporter_logs_ship_errors_total")
        description = ship_errors["spec"]["description"]
        self.assertIn("retry", description.lower())
        self.assertNotIn("dropped", description.lower())

        received = panel_for_metric(builder, "opnsense_exporter_logs_last_received_timestamp_seconds")
        exported = panel_for_metric(builder, "opnsense_exporter_logs_last_exported_timestamp_seconds")
        self.assertIn("admitted", received["spec"]["description"].lower())
        self.assertIn("acknowledged", exported["spec"]["description"].lower())

        observation_dropped = panel_for_metric(
            builder, "opnsense_log_events_observation_dropped_total"
        )
        self.assertIn("handoff_full", observation_dropped["spec"]["description"])


class CARPOperationalEventSemanticsTest(unittest.TestCase):
    """#405 requires Grafana to show present CARP state BESIDE the event rate and the
    cause. The panel therefore belongs on the CARP / HA tab next to the VIP state
    timeline, not off on a separate log-derived events tab: the whole point is reading the
    transitions that produced the state you are looking at."""

    def test_carp_transition_rate_is_shown_on_the_carp_tab(self):
        builder = build_dashboard.build_all()

        state = panel_for_metric(builder, "opnsense_carp_vip_status")
        events = panel_for_metric(builder, "opnsense_log_events_carp_total")

        self.assertEqual(state["spec"]["title"], "CARP VIP Status")
        self.assertEqual(events["spec"]["title"], "CARP Transition Events")
        self.assertIn(
            'sum by (opnsense_instance, event, from, to, interface, vhid) '
            '(rate(opnsense_log_events_carp_total{'
            'opnsense_instance=~"$opnsense_instance"}[$__rate_interval]))',
            builder._exprs,
        )

    def test_carp_panel_names_the_closed_vocabulary_and_where_the_cause_lives(self):
        builder = build_dashboard.build_all()
        description = panel_for_metric(builder, "opnsense_log_events_carp_total")["spec"]["description"]

        for value in ("state_changed", "demoted", "promoted"):
            self.assertIn(value, description)
        # The operator has to be told where the cause went, or the panel looks like it
        # lost data the issue explicitly asked to keep.
        self.assertIn("carp.reason", description)

    def test_carp_event_panel_has_its_own_presence_sentinel(self):
        """The counter only exists once syslog shipping has actually seen a kernel CARP
        line, which is rarer than CARP itself being configured — so the row must not be
        gated on has_carp alone or it renders permanently empty on a working HA pair."""
        builder = build_dashboard.build_all()
        names = [v["spec"]["name"] for v in builder.all_variables()]
        self.assertIn("has_log_events_carp", names)


class GatewayOperationalEventSemanticsTest(unittest.TestCase):
    def test_gateway_alarm_event_rate_is_shown_next_to_current_gateway_state(self):
        builder = build_dashboard.build_all()

        state = panel_for_metric(builder, "opnsense_gateways_status")
        alarms = panel_for_metric(builder, "opnsense_log_events_gateway_total")

        self.assertEqual(state["spec"]["title"], "Gateway Status")
        self.assertEqual(alarms["spec"]["title"], "Gateway Alarm Events")
        self.assertIn(
            'sum by (opnsense_instance, gateway, event) '
            '(rate(opnsense_log_events_gateway_total{'
            'opnsense_instance=~"$opnsense_instance",'
            'event=~"alarm_started|alarm_cleared"}[$__rate_interval]))',
            builder._exprs,
        )
        self.assertIn("dpinger", alarms["spec"]["description"])
        self.assertIn("alarm_started", alarms["spec"]["description"])
        self.assertIn("alarm_cleared", alarms["spec"]["description"])


class RadiusOperationalEventSemanticsTest(unittest.TestCase):
    def test_radius_access_rate_uses_only_the_closed_non_pii_dimensions(self):
        builder = build_dashboard.build_all()

        panel = panel_for_metric(builder, "opnsense_log_events_radius_total")
        self.assertEqual(panel["spec"]["title"], "RADIUS Access Events by Result (rate)")
        self.assertIn(
            'sum by (opnsense_instance, event, result, client_scope) '
            '(rate(opnsense_log_events_radius_total{'
            'opnsense_instance=~"$opnsense_instance"}[$__rate_interval]))',
            builder._exprs,
        )
        self.assertIn("event=access", panel["spec"]["description"])
        self.assertIn("accepted", panel["spec"]["description"])
        self.assertIn("rejected", panel["spec"]["description"])
        self.assertIn("client_scope=configured", panel["spec"]["description"])
        self.assertIn("Accounting", panel["spec"]["description"])
        self.assertIn("not supported", panel["spec"]["description"])
        expressions = [
            query["spec"]["query"]["spec"]["expr"]
            for query in panel["spec"]["data"]["spec"]["queries"]
        ]
        self.assertFalse(any("username" in expression.lower() for expression in expressions))


class ZenarmorQuerySemanticsTest(unittest.TestCase):
    def test_block_category_rate_uses_one_selector_with_both_matchers(self):
        builder = build_dashboard.build_all()
        panel = panel_for_title(builder, "Zenarmor Blocks by Category (rate)")
        queries = panel["spec"]["data"]["spec"]["queries"]
        expression = next(
            query["spec"]["query"]["spec"]["expr"]
            for query in queries
            if query["spec"]["refId"] == "A"
        )

        self.assertIn(
            'opnsense_log_events_zenarmor_total{'
            'opnsense_instance=~"$opnsense_instance",'
            'action="block"}[$__rate_interval]',
            expression,
        )


class VPNLifecycleEventSemanticsTest(unittest.TestCase):
    def test_vpn_lifecycle_rate_uses_only_the_closed_non_pii_dimensions(self):
        builder = build_dashboard.build_all()

        panel = panel_for_metric(builder, "opnsense_log_events_vpn_total")
        self.assertEqual(panel["spec"]["title"], "VPN Lifecycle Events by Backend & Event (rate)")
        self.assertIn(
            'sum by (opnsense_instance, backend, event, result) '
            '(rate(opnsense_log_events_vpn_total{'
            'opnsense_instance=~"$opnsense_instance"}[$__rate_interval]))',
            builder._exprs,
        )
        for token in (
            "backend=ipsec",
            "openvpn",
            "established",
            "terminated",
            "authentication_failed",
            "liveness_failed",
            "certificate_failed",
        ):
            self.assertIn(token, panel["spec"]["description"])

    def test_vpn_failure_panel_breaks_down_by_configured_connection_only(self):
        builder = build_dashboard.build_all()

        panel = panel_for_title(builder, "VPN Lifecycle Failures by Connection (rate)")
        self.assertIn(
            'topk by (opnsense_instance) (20, sum by (opnsense_instance, backend, event, connection) '
            '(rate(opnsense_log_events_vpn_total{'
            'opnsense_instance=~"$opnsense_instance",'
            'result="failure"}[$__rate_interval])))',
            builder._exprs,
        )
        self.assertIn("configured", panel["spec"]["description"])
        self.assertIn("empty", panel["spec"]["description"].lower())

    # The dashboard is the other place a forbidden dimension could reappear: a
    # `sum by (...)` naming a label the exporter never emits is silently harmless
    # today and silently wrong the day someone adds it.
    def test_no_vpn_panel_query_can_reference_an_identity_dimension(self):
        builder = build_dashboard.build_all()

        forbidden = ("username", "user_name", "common_name", "serial", "identity",
                     "peer_address", "spi", "connection_id", "instance_id")
        for expression in builder._exprs:
            if "opnsense_log_events_vpn_total" not in expression:
                continue
            for token in forbidden:
                self.assertNotIn(token, expression.lower(), expression)


def panel_unit(panel):
    return panel["spec"]["vizConfig"]["spec"]["fieldConfig"]["defaults"]["unit"]


def panel_exprs(panel):
    return [
        query["spec"]["query"]["spec"]["expr"]
        for query in panel["spec"]["data"]["spec"]["queries"]
    ]


class IngestPanelUnitSplitTest(unittest.TestCase):
    """#416: three generated panels put a byte-rate series on the same field
    unit as an event/request/datagram-rate series ("short"), so the byte
    series' magnitude flattened the lower-volume rate series it was meant to
    be compared against. Each mixed panel is split into a dedicated byte-rate
    panel (unit="Bps") and a dedicated event/request-rate panel, with every
    original query expression preserved verbatim (checked against
    `builder._exprs`, the pre-`stable()` raw strings passed to `b.ts()`)."""

    @classmethod
    def setUpClass(cls):
        cls.builder = build_dashboard.build_all()
        # The NetFlow receiver panels moved to the health dashboard's Flow Pipeline
        # tab (#523). The unit split they are checked for is a property of the panels,
        # not of the dashboard they render on, so the check follows them.
        cls.health = build_dashboard.build_health()

    def test_syslog_dropped_truncated_rates_split_into_message_and_byte_panels(self):
        builder = self.builder

        messages = panel_for_title(builder, "Dropped / Truncated Message Rate (msgs/sec)")
        # #514 gave it a real per-second unit; what #416 asserts is that it is NOT the
        # byte panel's Bps, which is what flattened the message series.
        self.assertEqual(panel_unit(messages), "ops")
        message_exprs = panel_exprs(messages)
        self.assertFalse(any("truncated_bytes" in e for e in message_exprs))
        desc = messages["spec"]["description"].lower()
        self.assertIn("messages/sec", desc)
        self.assertIn("not bytes", desc)

        byte_rate = panel_for_title(builder, "Truncated Bytes Rate (bytes/sec)")
        self.assertEqual(panel_unit(byte_rate), "Bps")
        byte_exprs = panel_exprs(byte_rate)
        self.assertTrue(any("opnsense_syslog_truncated_bytes_total" in e for e in byte_exprs))
        self.assertFalse(any("dropped_total" in e or "truncated_messages" in e for e in byte_exprs))
        desc = byte_rate["spec"]["description"].lower()
        self.assertIn("bytes/sec", desc)
        self.assertIn("not a message count", desc)

        for raw in (
            'rate(opnsense_syslog_dropped_total{opnsense_instance=~"$opnsense_instance"}'
            '[$__rate_interval])',
            'rate(opnsense_syslog_truncated_messages_total{opnsense_instance=~"$opnsense_instance"}'
            '[$__rate_interval])',
            'rate(opnsense_syslog_truncated_bytes_total{opnsense_instance=~"$opnsense_instance"}'
            '[$__rate_interval])',
        ):
            self.assertIn(raw, builder._exprs)

    def test_netflow_ingest_rate_splits_into_datagram_and_byte_panels(self):
        builder = self.health

        datagrams = panel_for_title(builder, "NetFlow Ingest (datagrams/sec)")
        # Datagrams are packet-valued, so #514 units this pps — still not the byte
        # panel's Bps, which is the split #416 exists to protect.
        self.assertEqual(panel_unit(datagrams), "pps")
        datagram_exprs = panel_exprs(datagrams)
        self.assertFalse(any("bytes_received" in e for e in datagram_exprs))
        desc = datagrams["spec"]["description"].lower()
        self.assertIn("datagrams/sec", desc)
        self.assertIn("not bytes", desc)

        byte_rate = panel_for_title(builder, "NetFlow Ingest Bytes (bytes/sec)")
        self.assertEqual(panel_unit(byte_rate), "Bps")
        byte_exprs = panel_exprs(byte_rate)
        self.assertTrue(
            any("opnsense_flow_netflow_bytes_received_total" in e for e in byte_exprs)
        )
        self.assertFalse(any("datagrams_total" in e for e in byte_exprs))
        desc = byte_rate["spec"]["description"].lower()
        self.assertIn("bytes/sec", desc)
        self.assertIn("not a datagram count", desc)

        for raw in (
            'sum by (opnsense_instance, result) (rate(opnsense_flow_netflow_datagrams_total'
            '{opnsense_instance=~"$opnsense_instance"}[$__rate_interval]))',
            'rate(opnsense_flow_netflow_bytes_received_total{opnsense_instance=~"$opnsense_instance"}'
            '[$__rate_interval])',
        ):
            self.assertIn(raw, builder._exprs)

    def test_zenarmor_bulk_ingest_rate_splits_into_request_and_byte_panels(self):
        builder = self.builder

        requests = panel_for_title(builder, "Zenarmor Bulk Ingest Requests (requests/sec)")
        self.assertEqual(panel_unit(requests), "reqps")
        request_exprs = panel_exprs(requests)
        self.assertFalse(any("bulk_bytes" in e for e in request_exprs))
        desc = requests["spec"]["description"].lower()
        self.assertIn("requests/sec", desc)
        self.assertIn("not bytes", desc)

        byte_rate = panel_for_title(builder, "Zenarmor Bulk Ingest Bytes (bytes/sec)")
        self.assertEqual(panel_unit(byte_rate), "Bps")
        byte_exprs = panel_exprs(byte_rate)
        self.assertTrue(
            any("opnsense_exporter_logs_zenarmor_bulk_bytes_total" in e for e in byte_exprs)
        )
        self.assertFalse(any("bulk_requests" in e for e in byte_exprs))
        desc = byte_rate["spec"]["description"].lower()
        self.assertIn("bytes/sec", desc)
        self.assertIn("not a request count", desc)

        for raw in (
            'rate(opnsense_exporter_logs_zenarmor_bulk_requests_total'
            '{opnsense_instance=~"$opnsense_instance"}[$__rate_interval])',
            'rate(opnsense_exporter_logs_zenarmor_bulk_bytes_total'
            '{opnsense_instance=~"$opnsense_instance"}[$__rate_interval])',
        ):
            self.assertIn(raw, builder._exprs)


if __name__ == "__main__":
    unittest.main()
