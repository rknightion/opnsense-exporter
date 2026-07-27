"""Guard: bar gauges do not inherit a synthetic 70/90 severity boundary (#415).

`Builder.bargauge()` used to inject the same green/yellow(70)/red(90) thresholds
into every panel whose caller omitted `thresholds=`. That default is defensible
for a 0-100 utilization panel, but most bar gauges are counts, bytes, rates,
versions, or categorical values with no such boundary — spending red/yellow on a
version number or an arbitrary count manufactures false incidents.

The fix is structural, not per-panel: an omitted `thresholds=` now renders
neutrally (a single no-boundary step), so a NEW bar-gauge caller that forgets to
think about thresholds stays neutral by construction instead of silently
inheriting a fabricated severity boundary. A caller that legitimately owns a
boundary (a normalized percentage/ratio) still passes `thresholds=` explicitly,
and must be added to EXPLICIT_THRESHOLD_TITLES below as a conscious, reviewed
decision — this file's structural guard fails otherwise, catching any future
accidental reintroduction of severity coloring on an undocumented panel.
"""

import sys
import unittest
from pathlib import Path


GRAFANA_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GRAFANA_DIR))

import build_dashboard  # noqa: E402
from builder import Builder  # noqa: E402


# The ONLY bar-gauge panels allowed to carry a caller-supplied severity boundary
# (more than one threshold step). Each entry is a deliberate decision that the
# panel's unit/scale has a real, defensible boundary:
EXPLICIT_THRESHOLD_TITLES = {
    # percent utilization, mx=100 — the sole defensible omitted-percentage case
    # per the 2026-07-26 issue-#415 live reconciliation; now passes an explicit
    # 70/90 contract instead of inheriting the builder default.
    "Disk Usage % by Mountpoint",
    # percentunit ratio, pre-existing explicit thresholds (0.05 / 0.2) — unchanged.
    "Gateway Packet Loss",
    # percentunit ratio, pre-existing explicit thresholds (0.01 / 0.05) — unchanged.
    "HAProxy 5xx Ratio",
}


def _steps(panel):
    return panel["spec"]["vizConfig"]["spec"]["fieldConfig"]["defaults"]["thresholds"]["steps"]


def _is_neutral(steps):
    """A neutral threshold carries exactly one step with no boundary value, so no
    severity color is reachable no matter what the series value is."""
    return len(steps) == 1 and steps[0].get("value") is None


def _bargauge_panels(builder):
    return [p for p in builder.elements.values()
            if p["spec"]["vizConfig"]["group"] == "bargauge"]


class BuilderBarGaugeThresholdTest(unittest.TestCase):
    """Unit-level: Builder.bargauge() itself must never fabricate a boundary."""

    def test_omitted_thresholds_render_neutrally_regardless_of_inputs(self):
        builder = Builder()
        cases = [
            ("Version Numbers", "opnsense_some_version_metric", "short"),
            ("Log File Sizes", "opnsense_some_bytes_metric", "bytes"),
            ("Arbitrary Counts", "opnsense_some_count_metric", "short"),
            ("A Rate", "opnsense_some_rate_metric", "reqps"),
        ]
        for title, metric, unit in cases:
            with self.subTest(title=title):
                name = builder.bargauge(title, [(metric, "{{x}}")], unit=unit)
                panel = builder.elements[name]
                steps = _steps(panel)
                self.assertTrue(
                    _is_neutral(steps),
                    f"{title!r} (unit={unit}) got a severity boundary it never "
                    f"asked for: {steps}",
                )

    def test_explicit_thresholds_pass_through_unmodified(self):
        builder = Builder()
        explicit = [
            {"color": "green", "value": None},
            {"color": "yellow", "value": 70},
            {"color": "red", "value": 90},
        ]
        name = builder.bargauge("Explicit", [("m", "{{x}}")], thresholds=explicit)
        self.assertEqual(_steps(builder.elements[name]), explicit)


class GeneratedDashboardBarGaugeTest(unittest.TestCase):
    """Integration-level: the real, built dashboard reflects the same contract."""

    @classmethod
    def setUpClass(cls):
        cls.builder = build_dashboard.build_all()

    def _panel(self, title):
        for panel in _bargauge_panels(self.builder):
            if panel["spec"]["title"] == title:
                return panel
        raise AssertionError(f"no bar-gauge panel titled {title!r}")

    def test_true_bargauge_panel_count(self):
        """Pins the real count so a stale '39' in old planning docs/issues cannot
        silently drift further from what the builder actually produces."""
        self.assertEqual(len(_bargauge_panels(self.builder)), 38)

    def test_neutral_bytes_panel_has_no_severity_boundary(self):
        panel = self._panel("eve Log File Sizes")
        defaults = panel["spec"]["vizConfig"]["spec"]["fieldConfig"]["defaults"]
        self.assertEqual(defaults["unit"], "bytes")
        self.assertTrue(_is_neutral(_steps(panel)), f"got {_steps(panel)}")

    def test_neutral_version_panel_has_no_severity_boundary(self):
        panel = self._panel("Signature Database Versions")
        defaults = panel["spec"]["vizConfig"]["spec"]["fieldConfig"]["defaults"]
        self.assertEqual(defaults["unit"], "short")
        self.assertTrue(_is_neutral(_steps(panel)), f"got {_steps(panel)}")

    def test_disk_usage_percent_panel_keeps_an_explicit_boundary(self):
        panel = self._panel("Disk Usage % by Mountpoint")
        defaults = panel["spec"]["vizConfig"]["spec"]["fieldConfig"]["defaults"]
        self.assertEqual(defaults["unit"], "percent")
        steps = _steps(panel)
        self.assertGreaterEqual(len(steps), 2, "expected an explicit multi-step boundary")
        values = {s["value"] for s in steps if s.get("value") is not None}
        self.assertEqual(values, {70, 90})

    def test_no_undocumented_bargauge_carries_a_severity_boundary(self):
        """The structural guard: any bar-gauge panel with more than one threshold
        step MUST be named in EXPLICIT_THRESHOLD_TITLES. A future caller that
        passes a real `thresholds=` list without adding itself here fails this
        test instead of shipping an unreviewed severity boundary."""
        offenders = {
            panel["spec"]["title"]: _steps(panel)
            for panel in _bargauge_panels(self.builder)
            if not _is_neutral(_steps(panel))
            and panel["spec"]["title"] not in EXPLICIT_THRESHOLD_TITLES
        }
        self.assertEqual(offenders, {})

    def test_explicit_threshold_titles_are_exactly_the_known_set(self):
        """Pins the known-explicit set from the other direction: every allow-listed
        title must actually still carry a real boundary. Catches the opposite
        mistake — a panel drops its explicit thresholds but the allowlist entry
        is left behind, silently blinding this guard."""
        actual = {
            panel["spec"]["title"]
            for panel in _bargauge_panels(self.builder)
            if not _is_neutral(_steps(panel))
        }
        self.assertEqual(actual, EXPLICIT_THRESHOLD_TITLES)


if __name__ == "__main__":
    unittest.main()
