"""#530: every alert notification links to the panel that explains it.

An alert says WHAT crossed a threshold; the paired `__dashboardUid__`/`__panelId__`
annotations say WHERE to look, so Grafana's "View panel" lands the responder on the
canonical graph instead of a dashboard they then have to search.

The properties worth gating, and why each one can break silently:

  * **Completeness.** Every alert appears in `PANEL_LINKS` or in `PANEL_LINK_EXEMPT`
    with a reason. Without this a new alert ships unlinked and nobody notices, because
    an unlinked alert looks identical in every other respect.
  * **`__panelId__` is a STRING.** Annotation values are typed as strings, so an int is
    dropped silently — the rule then looks linked and is not.
  * **Resolution is by title, and titles are checked against the GENERATED dashboards.**
    Panel ids come from a counter in the dashboard builder and renumber whenever a panel
    is inserted, so a literal id would rot into a link to whatever panel inherited the
    number. A retitled panel must fail here rather than deep-link into nothing.
  * **Ambiguity is an error.** A title used twice (an Overview tile plus the domain-tab
    panel) must be qualified with a tab, because linking the first match sends an
    on-call engineer to the wrong tab.
  * **The link points at a real panel on the named dashboard**, verified by looking the
    emitted id up in that dashboard's own elements.
"""
import json
import sys
import unittest
from pathlib import Path

GRAFANA_DIR = Path(__file__).resolve().parents[1]
ALERTS_DIR = GRAFANA_DIR / "alerts"

sys.path.insert(0, str(GRAFANA_DIR))
sys.path.insert(0, str(ALERTS_DIR))

import build_rules  # noqa: E402

OPS_FOLDER = "opnsense2otel-alerts"
HEALTH_FOLDER = "opnsense2otel-health-alerts"


def _dashboard_panels():
    """dashboard uid -> {panel id: title} straight from the generated documents."""
    out = {}
    for path in build_rules.DASHBOARD_DOCS:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        out[doc["metadata"]["name"]] = {
            e["spec"]["id"]: e["spec"]["title"]
            for e in doc["spec"]["elements"].values() if e.get("kind") == "Panel"
        }
    return out


def _is_health(rule):
    return build_rules.rule_folder(rule, OPS_FOLDER, HEALTH_FOLDER) == HEALTH_FOLDER


class PanelLinkTest(unittest.TestCase):
    def test_every_alert_declares_a_panel_or_is_exempt(self):
        titles = {r["title"] for r in build_rules.RULES}
        declared = set(build_rules.PANEL_LINKS) | set(build_rules.PANEL_LINK_EXEMPT)
        missing = sorted(titles - declared)
        self.assertEqual(missing, [], "alerts with no panel-link decision — add them to "
                                     "PANEL_LINKS, or to PANEL_LINK_EXEMPT with a reason: "
                                     f"{missing}")

    def test_no_stale_panel_link_entries(self):
        titles = {r["title"] for r in build_rules.RULES}
        stale = sorted((set(build_rules.PANEL_LINKS) | set(build_rules.PANEL_LINK_EXEMPT))
                       - titles)
        self.assertEqual(stale, [], f"PANEL_LINKS/PANEL_LINK_EXEMPT name alerts that no "
                                    f"longer exist: {stale}")

    def test_exemptions_carry_a_reason(self):
        for title, reason in build_rules.PANEL_LINK_EXEMPT.items():
            with self.subTest(alert=title):
                self.assertTrue(isinstance(reason, str) and reason.strip(),
                                f"{title} is exempt from panel linking with no reason")

    def test_every_declared_link_resolves(self):
        by_title = {r["title"]: r for r in build_rules.RULES}
        for title, link in build_rules.PANEL_LINKS.items():
            with self.subTest(alert=title):
                rule = by_title[title]
                panel, tab = link if isinstance(link, tuple) else (link, None)
                # Raises on an unknown title, an unknown tab, or an unqualified
                # duplicate — all three are the failure this test exists to catch.
                build_rules.panel_ref(panel, _is_health(rule), tab)

    def test_emitted_annotations_are_string_ids_pointing_at_real_panels(self):
        panels = _dashboard_panels()
        for rule in build_rules.RULES:
            with self.subTest(alert=rule["title"]):
                ann = build_rules.panel_annotations(rule, _is_health(rule))
                if rule["title"] in build_rules.PANEL_LINK_EXEMPT:
                    self.assertEqual(ann, {})
                    continue
                self.assertEqual(set(ann), {"__dashboardUid__", "__panelId__"})
                uid, pid = ann["__dashboardUid__"], ann["__panelId__"]
                self.assertIsInstance(pid, str, "__panelId__ must be a string — an int is "
                                                "dropped silently by the annotations map")
                self.assertIn(uid, panels, f"{uid} is not one of the generated dashboards")
                self.assertIn(int(pid), panels[uid],
                              f"{rule['title']} links to panel {pid} which does not exist "
                              f"on {uid}")

    def test_link_title_matches_the_panel_it_resolves_to(self):
        """Guards against a tab qualifier silently selecting a differently-titled panel."""
        panels = _dashboard_panels()
        by_title = {r["title"]: r for r in build_rules.RULES}
        for title, link in build_rules.PANEL_LINKS.items():
            with self.subTest(alert=title):
                panel, tab = link if isinstance(link, tuple) else (link, None)
                uid, pid = build_rules.panel_ref(panel, _is_health(by_title[title]), tab)
                self.assertEqual(panels[uid][pid], panel)

    def test_ambiguous_title_without_a_tab_is_an_error(self):
        """The mechanism's own safety property, asserted rather than assumed.

        Picking the first match would send a responder to the Overview tile when they
        wanted the domain tab, so an unqualified duplicate must raise.
        """
        ambiguous = None
        for _uid, titles in build_rules._panel_index():
            for panel_title, found in titles.items():
                if len(found) > 1:
                    ambiguous = panel_title
                    break
            if ambiguous:
                break
        self.assertIsNotNone(ambiguous, "no duplicate panel title on either dashboard — "
                                        "this test needs one to be meaningful")
        with self.assertRaises(ValueError):
            build_rules.panel_ref(ambiguous, False)

    def test_unknown_panel_title_is_an_error(self):
        with self.assertRaises(ValueError):
            build_rules.panel_ref("a panel that does not exist", False)


if __name__ == "__main__":
    unittest.main()
