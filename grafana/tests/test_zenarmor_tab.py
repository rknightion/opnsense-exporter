"""Guard: the retired companion's unique content survives on the Zenarmor tab (#435).

The live `opnsense-zenarmor` companion dashboard was retired, not merely superseded, so
whatever it could answer and this tab cannot is simply lost — silently, because a
question nobody can ask leaves no empty panel behind. Nine panels carried content the
canonical tab did not have: DNS query names, response codes and domain categories; HTTP
hosts, URIs, user agents and status codes; application names; and the all-verdict
counterparts to the blocked-only SNI and country tables.

They are pinned by title here, with the field each one exists to expose, so a future edit
has to decide rather than delete. The companion UID is also asserted retired, in both
directions: it must be in the never-reuse list, and it must not be linkable.

The other half of the contract is COST. This is a 2.5-3.3M records/day stream and #422
established that cold-load cost is round-trip count, so the merged rows are collapsed:
they issue nothing until an operator opens them. A future edit that expands them would
add nine range queries to every load of this tab.
"""

import sys
import unittest
from pathlib import Path

GRAFANA_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GRAFANA_DIR))

import build_dashboard  # noqa: E402
import uids  # noqa: E402
from tabs import zenarmor  # noqa: E402


# panel title -> the structured-metadata field it is the only home for.
MERGED_FROM_COMPANION = {
    "Top DNS Queries": "query",
    "DNS Response Codes": "rcode",
    "Top DNS Domain Categories": "domain_category",
    "Top HTTP Hosts": "host",
    "Top URIs": "uri",
    "Top User Agents": "user_agent",
    "HTTP Status Codes": "http_status_code",
    "Top Applications": "app_name",
    "Top TLS Server Names (SNI)": "server_name",
    "Destination Countries": "dst_geoip_country_name",
}

# Rows that must stay collapsed, and the reason: each holds range queries over the
# Zenarmor stream, and a collapsed row costs nothing until opened (#422).
COLLAPSED_ROWS = {"DNS Detail", "Web / HTTP Detail", "Applications & Destinations"}


def zenarmor_tab(spec):
    def leaves(tabs):
        for tab in tabs:
            layout = tab["spec"]["layout"]
            if layout["kind"] == "TabsLayout":
                yield from leaves(layout["spec"]["tabs"])
            else:
                yield tab
    for tab in leaves(spec["layout"]["spec"]["tabs"]):
        if tab["spec"]["title"] == "Zenarmor":
            return tab
    raise AssertionError("no Zenarmor leaf tab")


class ZenarmorMergeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.spec = build_dashboard.build_all().manifest("t", "d", [])["spec"]
        cls.tab = zenarmor_tab(cls.spec)
        cls.panels = {}
        for row in cls.tab["spec"]["layout"]["spec"]["rows"]:
            for item in row["spec"]["layout"]["spec"]["items"]:
                panel = cls.spec["elements"][item["spec"]["element"]["name"]]["spec"]
                cls.panels[panel["title"]] = (row["spec"], panel)

    def test_every_merged_panel_exists_and_queries_its_field(self):
        for title, field in MERGED_FROM_COMPANION.items():
            with self.subTest(title=title):
                self.assertIn(title, self.panels,
                              f"{title!r} came from the retired companion and is the only "
                              f"place {field!r} is visible — do not delete it silently")
                _, panel = self.panels[title]
                exprs = " ".join(q["spec"]["query"]["spec"].get("expr", "")
                                 for q in panel["data"]["spec"]["queries"])
                self.assertIn(field, exprs)

    def test_merged_panels_are_instance_scoped_and_rank_per_instance(self):
        """The companion had neither, and both matter here: an unscoped topk over a
        shared Loki tenant ranks another firewall's clients and DROPS this one's rows
        rather than merging them (#413/#468)."""
        for title in MERGED_FROM_COMPANION:
            _, panel = self.panels[title]
            for query in panel["data"]["spec"]["queries"]:
                expr = query["spec"]["query"]["spec"]["expr"]
                with self.subTest(title=title):
                    self.assertIn('service_instance_id=~"$opnsense_instance"', expr)
                    if "topk" in expr:
                        self.assertIn("topk by (service_instance_id)", expr)

    def test_the_web_panels_exclude_the_exporters_own_ingest_traffic(self):
        """Zenarmor POSTs its records to the exporter over HTTP, so without this filter
        the exporter's own endpoint is the top host, the top URI, and a large share of
        the status codes — the panel would mostly describe this dashboard's own plumbing."""
        for title in ("Top HTTP Hosts", "Top URIs", "Top User Agents", "HTTP Status Codes"):
            _, panel = self.panels[title]
            for query in panel["data"]["spec"]["queries"]:
                with self.subTest(title=title):
                    self.assertIn(zenarmor.NOT_SELF.strip("| "),
                                  query["spec"]["query"]["spec"]["expr"])

    def test_merged_rows_are_collapsed_and_sentinel_gated(self):
        rows = {r["spec"]["title"]: r["spec"]
                for r in self.tab["spec"]["layout"]["spec"]["rows"]}
        for title in COLLAPSED_ROWS:
            with self.subTest(row=title):
                self.assertIn(title, rows)
                self.assertTrue(rows[title]["collapse"],
                                f"row {title!r} must stay collapsed: it holds range queries "
                                "over a 2.5-3.3M records/day stream (#422)")
                self.assertTrue(rows[title].get("conditionalRendering"),
                                f"row {title!r} must hide when Zenarmor logs are absent")

    def test_the_client_filter_is_a_textbox_because_the_field_cannot_be_enumerated(self):
        """`device_name` is Loki structured metadata, not an indexed label, so
        `label_values()` returns null for it (verified live 2026-07-27). The companion
        shipped a query variable over a bare stream selector, which cannot have populated
        anything. A textbox is the honest form — and it costs no cold-load query."""
        by_name = {v["spec"]["name"]: v for v in self.spec["variables"]}
        self.assertIn(zenarmor.CLIENT_VAR, by_name)
        self.assertEqual(by_name[zenarmor.CLIENT_VAR]["kind"], "TextVariable")
        self.assertEqual(by_name[zenarmor.CLIENT_VAR]["spec"]["query"], ".*",
                         "an untouched dashboard must filter nothing")
        for title in MERGED_FROM_COMPANION:
            _, panel = self.panels[title]
            for query in panel["data"]["spec"]["queries"]:
                with self.subTest(title=title):
                    self.assertIn(f'device_name=~"${zenarmor.CLIENT_VAR}"',
                                  query["spec"]["query"]["spec"]["expr"])

    def test_the_companion_uid_is_retired_and_unlinkable(self):
        self.assertIn("opnsense-zenarmor", uids.RETIRED_UIDS)
        self.assertNotIn("opnsense-zenarmor", uids.DESTINATIONS)
        with self.assertRaises(ValueError):
            uids.dash_url(uid="opnsense-zenarmor")


if __name__ == "__main__":
    unittest.main()
