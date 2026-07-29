"""The self-observability split (#431 step 3): two dashboards, one gate.

Steps 1 and 2 built the seam — `coverage()` unions across builders, `DASHBOARDS`
is a list of specs — and deliberately produced byte-identical output so that
"the machinery changed" was separable from "the content moved". This file pins
the move itself.

What is worth testing here is not "there are two files". It is the three things
that can be *confidently wrong* after a split:

* a metric charted only on the second dashboard must still count as covered, or
  the gate has been quietly weakened to make the split fit;
* the main dashboard's link to the health dashboard must resolve, which means
  `uids.HEALTH_UID` must have flipped `exists=True` in this same commit — #419
  reserved it precisely so a 404 could not ship;
* nothing may be lost in transit. Every leaf tab and every panel that existed
  before must exist on exactly one of the two dashboards.
"""
import sys
import unittest
from pathlib import Path

GRAFANA_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GRAFANA_DIR))

import build_dashboard  # noqa: E402
import uids  # noqa: E402


def leaf_titles(builder):
    return build_dashboard.leaf_tab_titles(builder)


class FamilyShapeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.built = build_dashboard.build_family()
        cls.by_uid = {spec.uid: (spec, b) for spec, b in cls.built}

    def test_the_family_is_exactly_two_dashboards(self):
        self.assertEqual(sorted(self.by_uid), sorted([uids.MAIN_UID, uids.HEALTH_UID]))

    def test_the_main_dashboard_is_first(self):
        """`build_family()[0]` is the primary; docs and stats key off it."""
        self.assertEqual(self.built[0][0].uid, uids.MAIN_UID)

    def test_self_observability_tabs_live_on_the_health_dashboard(self):
        _, health = self.by_uid[uids.HEALTH_UID]
        self.assertEqual(set(leaf_titles(health)), {
            "Overview", "Scrape & Poll", "OPNsense API", "Metrics & OTLP",
            "Log Shipping", "Flow Pipeline", "Exporter Runtime", "Recording rules"})

    def test_they_are_gone_from_the_main_dashboard(self):
        _, main = self.by_uid[uids.MAIN_UID]
        moved = {"Scrape & Poll", "OPNsense API", "Metrics & OTLP", "Log Shipping",
                 "Flow Pipeline", "Exporter Runtime", "Recording rules"}
        self.assertEqual(moved & set(leaf_titles(main)), set(),
                         "a moved tab is still on the main dashboard; it would be "
                         "built twice and the two copies would drift")

    # "Overview" is the one title both dashboards carry, and it is deliberate: each
    # answers "what should I look at first" for its own reader. Every other leaf title
    # is unique across the family, which is what stops a tab being built twice.
    SHARED_LEAF_TITLES = {"Overview"}

    def test_no_leaf_tab_appears_on_both_dashboards(self):
        seen = {}
        for spec, b in self.built:
            for title in leaf_titles(b):
                if title in self.SHARED_LEAF_TITLES:
                    continue
                self.assertNotIn(title, seen,
                                 f"leaf tab {title!r} is on both {seen.get(title)} "
                                 f"and {spec.uid}")
                seen[title] = spec.uid

    def test_a_summary_tile_shared_with_the_health_dashboard_is_the_same_panel(self):
        """#523 inverted this check, and the inversion is the fix.

        It used to require that no summary tile shared a title with any health-
        dashboard panel, on the reasoning that two copies of one panel drift apart.
        That was the right worry and the wrong remedy: both dashboards genuinely need
        these three figures, so forbidding the shared title only forced the second
        copy to be spelled differently. `exporter_health_tiles()` now builds them once
        and both dashboards render that definition, so a shared title is EXPECTED and
        what must hold is that the two renderings are byte-identical.
        """
        _, main = self.by_uid[uids.MAIN_UID]
        _, health = self.by_uid[uids.HEALTH_UID]
        overview = [t for t in main.tabs if t["spec"]["title"] == "Overview"][0]
        row = [r for r in overview["spec"]["layout"]["spec"]["rows"]
               if r["spec"]["title"] == "Exporter Health"][0]
        summary = {item["spec"]["element"]["name"]
                   for item in row["spec"]["layout"]["spec"]["items"]}
        health_by_title = {p["spec"]["title"]: p for p in health.elements.values()}
        shared = 0
        for name in summary:
            panel = main.elements[name]
            twin = health_by_title.get(panel["spec"]["title"])
            if twin is None:
                continue
            shared += 1
            self.assertEqual(panel["spec"]["data"], twin["spec"]["data"],
                             f"{panel['spec']['title']!r} queries different data on the "
                             "two dashboards; it is meant to be one definition rendered "
                             "twice")
            self.assertEqual(panel["spec"]["description"], twin["spec"]["description"],
                             f"{panel['spec']['title']!r} has drifted in description "
                             "between the two dashboards")
        self.assertEqual(shared, 3,
                         "expected the three exporter_health_tiles() panels to appear "
                         f"on both dashboards, found {shared}")


class CoverageSurvivesTheSplitTest(unittest.TestCase):
    """The gate must span the family, not the primary dashboard."""

    def test_the_family_covers_the_catalogue(self):
        builders = [b for _, b in build_dashboard.build_family()]
        self.assertEqual(build_dashboard.coverage(*builders), [])

    def test_the_main_dashboard_alone_does_not(self):
        """The control. If this passed, nothing had actually moved."""
        main = build_dashboard.build_family()[0][1]
        self.assertNotEqual(build_dashboard.coverage(main), [],
                            "the main dashboard alone still covers the whole "
                            "catalogue, so no self-metric panel moved")


class HealthLinkTest(unittest.TestCase):
    """#419's reserved contract, discharged."""

    def test_the_health_destination_now_exists(self):
        self.assertTrue(uids.DESTINATIONS[uids.HEALTH_UID].exists,
                        "the health dashboard is generated but its registry entry "
                        "still says exists=False, so no link to it may be emitted")

    def test_main_links_to_health_and_health_links_back(self):
        by_uid = {spec.uid: b for spec, b in build_dashboard.build_family()}
        for source, target in ((uids.MAIN_UID, uids.HEALTH_UID),
                               (uids.HEALTH_UID, uids.MAIN_UID)):
            with self.subTest(source=source):
                urls = [link["url"] for link in by_uid[source].links]
                self.assertTrue(any(u.startswith(f"/d/{target}?") for u in urls),
                                f"{source} has no dashboard link to {target}: {urls}")

    def test_the_cross_links_carry_context(self):
        """A link that drops the instance lands on another firewall's data (#419)."""
        by_uid = {spec.uid: b for spec, b in build_dashboard.build_family()}
        for uid in (uids.MAIN_UID, uids.HEALTH_UID):
            for link in by_uid[uid].links:
                if not link["url"].startswith("/d/"):
                    continue
                with self.subTest(uid=uid, url=link["url"]):
                    self.assertIn(uids.INSTANCE_PARAM, link["url"])
                    self.assertIn(uids.URL_TIME_RANGE, link["url"])


class MainKeepsAHealthSummaryTest(unittest.TestCase):
    """The epic's scope line: main keeps a compact exporter-health summary.

    Without it the split trades one problem for another — an operator on the
    firewall dashboard would have no signal that the exporter feeding it is
    unwell, and no reason to click through.
    """

    @classmethod
    def setUpClass(cls):
        cls.main = build_dashboard.build_family()[0][1]

    def test_the_overview_tab_has_an_exporter_health_row(self):
        overview = [t for t in self.main.tabs
                    if t["spec"]["title"] == "Overview"]
        self.assertTrue(overview, "the main dashboard lost its Overview tab")
        rows = overview[0]["spec"]["layout"]["spec"]["rows"]
        titles = [r["spec"]["title"] for r in rows]
        self.assertIn("Exporter Health", titles,
                      f"no exporter-health summary row on the main Overview: {titles}")

    def test_the_summary_row_is_small(self):
        """A summary, not a second Diagnostics tab."""
        overview = [t for t in self.main.tabs if t["spec"]["title"] == "Overview"][0]
        row = [r for r in overview["spec"]["layout"]["spec"]["rows"]
               if r["spec"]["title"] == "Exporter Health"][0]
        n = len(row["spec"]["layout"]["spec"]["items"])
        self.assertLessEqual(n, 4, f"the summary row has {n} panels; it is meant to "
                                   "point at the health dashboard, not replace it")


if __name__ == "__main__":
    unittest.main()
