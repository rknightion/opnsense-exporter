"""Guard: a panel ships with a description, or is explicitly recorded as not needing one (#423).

#303 added descriptions broadly and left 62 panels empty. #423's brief was the
opposite of a blanket fill: describe only the panels whose diagnosis question or
caveat cannot be read off the title, and leave the self-evident ones alone — filler
text on an obvious panel costs tooltip space and trains operators to ignore
descriptions on the panels that do carry a warning.

That makes "empty" a DECISION, and this file is where the decision lives. A new
panel with no description fails here until its title is either described or added
to NO_DESCRIPTION_NEEDED with a reason — which is the same allowlist shape as the
sentinel, threshold and instance-identity guards.
"""

import sys
import unittest
from pathlib import Path


GRAFANA_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GRAFANA_DIR))

import build_dashboard  # noqa: E402


# Panel titles that legitimately carry no description. Grouped by why, because the
# reason is the reviewable part — "it's obvious" is not a reason on its own.
NO_DESCRIPTION_NEEDED = {
    # A named percentage gauge on a UPS. Title + unit is the whole story, and the
    # threshold colours already encode the interpretation.
    "NUT Battery Charge", "NUT Load", "APC Battery Charge", "APC Load",
    "Shared Memory Utilization",
    # Plain inventory counts: the title names the thing and the value is how many.
    "Alias Tables", "Configured Feeds", "Total Entries", "Addresses Blocked",
    "Peers Known", "Relays Known",
    # Binary service-state stats with value mappings already showing Running/Stopped.
    "Service Running", "Plugin Service", "Backend (tailscaled)",
    # Info tables: every column is a self-labelling string from the API.
    "Node Info", "License",
    # Direct read-outs of one metric whose title states the metric and whose unit
    # states the scale. Nothing about them is derived, aggregated or conditional.
    "Gateway RTT", "Per-Peer Latency", "Memory Usage", "Message Size",
    "Feed Entries / Addresses Blocked", "Configured Rules (enabled vs disabled)",
    # Requests/sec per endpoint. The row it sits in ("API Requests (per endpoint)")
    # and the latency panel beside it carry the context.
    "API Request Rate (by endpoint)",
}


def panels(builder):
    return [e["spec"] for e in builder.elements.values() if e["kind"] == "Panel"]


class PanelDescriptionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Across the whole family (#431). Every panel this project ships has to be
        # described; scoping this to the main dashboard would have quietly stopped
        # checking the ~49 that moved to the health dashboard.
        cls.builders = [b for _, b in build_dashboard.build_family()]
        cls.panels = [p for b in cls.builders for p in panels(b)]

    def test_every_panel_is_described_or_recorded_as_not_needing_one(self):
        undecided = sorted({
            p["title"] for p in self.panels
            if not (p.get("description") or "").strip()
            and p["title"] not in NO_DESCRIPTION_NEEDED
        })
        self.assertEqual(undecided, [])

    def test_the_no_description_list_is_not_stale(self):
        """An entry left behind after a panel gains a description (or is deleted)
        silently exempts a title that no longer needs exempting."""
        empty = {p["title"] for p in self.panels
                 if not (p.get("description") or "").strip()}
        self.assertEqual(sorted(NO_DESCRIPTION_NEEDED - empty), [])

    def test_described_panels_are_a_large_majority(self):
        """Pins the shape of the result so a future change cannot quietly move the
        dashboard back towards mass-empty by growing the allowlist instead."""
        empty = [p for p in self.panels if not (p.get("description") or "").strip()]
        self.assertLessEqual(len(empty), 30)
        self.assertGreater(len(self.panels) - len(empty), 700)

    def test_the_named_caveats_are_present_and_specific(self):
        """The point of #423 was the caveat, not the sentence. Each assertion below
        is a claim an operator would otherwise have to get from the PromQL."""
        by_title = {}
        for panel in self.panels:
            by_title.setdefault(panel["title"], (panel.get("description") or ""))
        cases = {
            # top-N panels: a missing series is absent, not zero
            "Largest Tables": "ABSENT rather than zero",
            "Packet Rate by Table": "top 20 per firewall",
            "Processed Rate by Destination": "syslog-ng",
            # byte counters rendered as bits
            "Throughput by Table": "multiplied by 8",
            "Blocked Byte Rate": "multiplied by 8",
            "Per-Peer Traffic": "×8",
            # epoch-seconds timestamps scaled for Grafana's dateTime formats
            "Last Handshake": "1970",
            "Feed Update Schedule": "milliseconds",
            # Loki: no series is not zero
            "Raw syslog stream": "NO SERIES rather than zero",
            # the three process panels do not follow the instance picker
            "Exporter CPU": "no appliance label",
            "Exporter Memory": "not by $opnsense_instance",
            "Exporter Goroutines": "does NOT follow",
            # a gap is not a zero
            "Scrape Success (opnsense_up)": "GAP is not a zero",
            # opposite polarity on two adjacent gauges
            "NVMe Available Spare": "LOW IS BAD",
            "NVMe Life Used": "HIGH IS BAD",
            # a derived countdown that goes negative
            "License Days Left": "NEGATIVE",
            # a global pf limit, not a per-table one
            "Table Entries Limit": "Not a per-table cap",
        }
        for title, phrase in cases.items():
            with self.subTest(title=title):
                self.assertIn(title, by_title, "panel is gone; update this test")
                self.assertIn(phrase, by_title[title])


if __name__ == "__main__":
    unittest.main()
