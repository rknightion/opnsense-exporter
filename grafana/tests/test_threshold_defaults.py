"""Guard: no viz helper injects a severity boundary its caller never asked for.

`Builder.bargauge()` used to inject the same green/yellow(70)/red(90) thresholds
into every panel whose caller omitted `thresholds=` (#415), and `Builder.gauge()`
carried the identical default until #467. That default is defensible for a 0-100
utilization panel, but most bar gauges are counts, bytes, rates, versions, or
categorical values with no such boundary — spending red/yellow on a version
number or an arbitrary count manufactures false incidents.

The fix is structural, not per-panel: an omitted `thresholds=` now renders
neutrally (a single no-boundary step) in BOTH helpers, so a new caller that
forgets to think about thresholds stays neutral by construction instead of
silently inheriting a fabricated severity boundary. A caller that legitimately
owns a boundary (a normalized percentage/ratio, a documented absolute limit)
still passes `thresholds=` explicitly, and must be added to the allowlist for
its viz type below as a conscious, reviewed decision — this file's structural
guard fails otherwise, catching any future accidental reintroduction of severity
coloring on an undocumented panel.

Why gauges and bar gauges are held to ONE rule in ONE file rather than two: the
whole reason #467 existed is that #415's guard covered only `vizConfig.group ==
"bargauge"`, so the identical defect survived in the sibling helper for the
length of an epic. A parallel file would have been free to drift the same way.

Scope note — the other threshold-injecting helpers have a recorded verdict:

* `statetimeline()` / `statushistory()` default to `red@None / green@1`. That is
  a two-state MAPPING (down/up), not a severity boundary on a continuous scale:
  the colors exist to paint the two states. Correct as-is, asserted by
  `test_state_viz_defaults_are_a_binary_state_mapping_not_a_boundary`.

  The clause "every caller passes `mappings=` for a binary metric" was WRONG, and
  #510 is what it cost. `panel-323` plots a TCP connection-state CENSUS and passes
  `mappings={}`, so it inherited the binary default and painted every state that
  happened to sit at zero solid red — a healthy firewall rendered two-thirds
  alarm-coloured, which is worse than useless because it teaches the reader to
  ignore the panel. The default is unchanged (it is right for the binary case);
  what changed is that an unmapped timeline must now pass explicit thresholds, and
  `statetimeline()` fails the build otherwise.
* `stat()`, `loki_stat()` and `table()` already fall back to a single neutral
  blue step, i.e. they were never affected. Asserted below so a future edit
  cannot quietly give them a default boundary.
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
EXPLICIT_BARGAUGE_TITLES = {
    # percent utilization, mx=100 — the sole defensible omitted-percentage case
    # per the 2026-07-26 issue-#415 live reconciliation; now passes an explicit
    # 70/90 contract instead of inheriting the builder default.
    "Disk Usage % by Mountpoint",
    # percentunit ratio, pre-existing explicit thresholds (0.05 / 0.2) — unchanged.
    "Gateway Packet Loss",
    # percentunit ratio, pre-existing explicit thresholds (0.01 / 0.05) — unchanged.
    "HAProxy 5xx Ratio",
    # percent of the jumbo pool's own configured ceiling (#579), explicit 80/90. The
    # headroom panel the issue exists for: mbuf_failures_total{type="jumbo9"} reports
    # exhaustion only AFTER it has dropped packets. Guarded `> 0` against the
    # limit-0-means-no-ceiling trap, same as kernel_memory.py's Zone Saturation.
    "Jumbo Pool Utilization %",
}

# The same allowlist for radial gauges (#467). Every entry here is on a
# normalized or otherwise bounded scale where the boundary means something; the
# unit is named so a reviewer can check the claim without opening the tab module.
# A gauge on `short`, `bytes` or a categorical value has no business in this set.
EXPLICIT_GAUGE_TITLES = {
    "Memory Used %",                # percent, mx=100 — was INHERITING 70/90 before #467
    "PF States Used %",             # percent, mx=100 — already explicit 70/90
    "NVMe Available Spare",         # percent, low-is-bad: red -> yellow@10 -> green@50
    "NVMe Life Used",               # percent, wear indicator: yellow@80 -> red@100
    # The SATA twins of the two NVMe entries above (#577), on exactly the same
    # bounded scales and with matching boundaries. smartctl derives both with its
    # own vendor-attribute matching, which is why they are separate fields rather
    # than reconstructible from the generic attribute dump.
    "SATA SSD Spare Available",     # percent, low-is-bad: red -> yellow@10 -> green@50
    "SATA SSD Endurance Used",      # percent, wear indicator: yellow@80 -> red@100
    "Table Utilization",            # percent of the configured alias table limit
    "Cache Hit Ratio",              # percent, low-is-bad: red -> yellow@50 -> green@75
    "TCP Usage Ratio",              # percentunit of the configured TCP limit
    "Shared Memory Utilization",     # percent of the nginx SHM zone
    "NUT Battery Charge",           # percent, low-is-bad
    "NUT Load",                     # percent of UPS rated load
    "APC Battery Charge",           # percent, low-is-bad
    "APC Load",                     # percent of UPS rated load
    "Memory Utilization",           # percentunit, recording-rule view of Memory Used %
    "PF State Utilization",         # percentunit, recording-rule view of PF States Used %
    "Unbound Cache Hit Ratio",      # percentunit, low-is-bad
    # `Peer Reachability Register` is the one non-percentage entry, and it is
    # deliberate: NTP's 8-bit reachability register is a bounded 0-255 scale where
    # 255 (all eight polls answered) is the only healthy value, so red/yellow@127/
    # green@255 is a real boundary on a real scale rather than a fabricated one.
    "Peer Reachability Register",
}


def _steps(panel):
    return panel["spec"]["vizConfig"]["spec"]["fieldConfig"]["defaults"]["thresholds"]["steps"]


def _is_neutral(steps):
    """A neutral threshold carries exactly one step with no boundary value, so no
    severity color is reachable no matter what the series value is."""
    return len(steps) == 1 and steps[0].get("value") is None


def _panels_of(builders, group):
    """Panels of one viz group across the WHOLE dashboard family.

    Family-wide rather than per-dashboard since #523: a gauge is a gauge wherever it
    is rendered, and the recording-rule gauges moved to the health dashboard. Reading
    one builder would have let the pinned counts fall by four without anything being
    deleted, which is the opposite of what these pins are for.
    """
    if not isinstance(builders, (list, tuple)):
        builders = [builders]
    return [p for b in builders for p in b.elements.values()
            if p["spec"]["vizConfig"]["group"] == group]


def _bargauge_panels(builder):
    return _panels_of(builder, "bargauge")


def _gauge_panels(builder):
    return _panels_of(builder, "gauge")


class BuilderThresholdDefaultTest(unittest.TestCase):
    """Unit-level: neither helper may fabricate a boundary of its own accord."""

    # (helper name, how to invoke it with one series) — kept as a table so a new
    # value-with-thresholds helper is one line to bring under the same rule.
    HELPERS = (
        ("bargauge", lambda b, title, unit, th: b.bargauge(
            title, [("m", "{{x}}")], unit=unit, thresholds=th)),
        ("gauge", lambda b, title, unit, th: b.gauge(
            title, "m", unit=unit, thresholds=th)),
    )

    def test_omitted_thresholds_render_neutrally_regardless_of_inputs(self):
        cases = [
            ("Version Numbers", "short"),
            ("Log File Sizes", "bytes"),
            ("Arbitrary Counts", "short"),
            ("A Rate", "reqps"),
            # percent is included on purpose: even where 70/90 would be
            # defensible, the helper must not supply it — the point is that the
            # boundary is STATED by the caller, not inherited from the unit.
            ("A Percentage", "percent"),
        ]
        for helper, call in self.HELPERS:
            for title, unit in cases:
                with self.subTest(helper=helper, title=title, unit=unit):
                    builder = Builder()
                    name = call(builder, title, unit, None)
                    steps = _steps(builder.elements[name])
                    self.assertTrue(
                        _is_neutral(steps),
                        f"{helper}({title!r}, unit={unit}) got a severity "
                        f"boundary it never asked for: {steps}",
                    )

    def test_explicit_thresholds_pass_through_unmodified(self):
        explicit = [
            {"color": "green", "value": None},
            {"color": "yellow", "value": 70},
            {"color": "red", "value": 90},
        ]
        for helper, call in self.HELPERS:
            with self.subTest(helper=helper):
                builder = Builder()
                name = call(builder, "Explicit", "percent", explicit)
                self.assertEqual(_steps(builder.elements[name]), explicit)

    def test_neutral_default_helpers_stay_neutral(self):
        """`stat()`, `loki_stat()` and `table()` were never affected by #415/#467.
        Pinned so a future edit cannot quietly give them a default boundary."""
        builder = Builder()
        for name in (builder.stat("A Stat", "m"),
                     builder.loki_stat("A Loki Stat", '{a="b"} | json')):
            with self.subTest(panel=name):
                self.assertTrue(_is_neutral(_steps(builder.elements[name])))

    def test_state_viz_defaults_are_a_binary_state_mapping_not_a_boundary(self):
        """#467's recorded verdict on the remaining injecting helpers.

        `statetimeline()`/`statushistory()` inject `red@None / green@1`, which
        LOOKS like a boundary and is not: it colors the two values of a binary
        up/down metric, which is why every caller also passes `mappings=`. Left
        as-is deliberately. This test states the shape so the distinction is
        recorded in code rather than only in the issue.
        """
        builder = Builder()
        mappings = {"0": ("Down", "red"), "1": ("Up", "green")}
        for name in (builder.statetimeline("A Timeline", [("m", "{{x}}")], mappings),
                     builder.statushistory("A History", [("m", "{{x}}")], mappings)):
            with self.subTest(panel=name):
                steps = _steps(builder.elements[name])
                self.assertEqual(steps, [{"color": "red", "value": None},
                                         {"color": "green", "value": 1}])
                # The tell that it is a state mapping and not a severity scale:
                # the panel also carries value mappings for the same two values.
                defaults = builder.elements[name]["spec"]["vizConfig"]["spec"][
                    "fieldConfig"]["defaults"]
                self.assertIn("mappings", defaults)


class GeneratedDashboardThresholdTest(unittest.TestCase):
    """Integration-level: the real, built dashboard reflects the same contract."""

    @classmethod
    def setUpClass(cls):
        cls.builder = [b for _, b in build_dashboard.build_family()]

    def _panel(self, title, group="bargauge"):
        for panel in _panels_of(self.builder, group):
            if panel["spec"]["title"] == title:
                return panel
        raise AssertionError(f"no {group} panel titled {title!r}")

    def test_true_bargauge_panel_count(self):
        """Pins the real count so a stale '39' in old planning docs/issues cannot
        silently drift further from what the builder actually produces. 40 -> 41 when
        #557 added the Kea server-reported lease pool accounting bargauge; 41 -> 43
        when #587 added the top-resolved and top-blocked domain leaderboards; 43 -> 44
        when #579 added the jumbo mbuf pool utilization bargauge."""
        self.assertEqual(len(_bargauge_panels(self.builder)), 44)

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

    def test_gauge_panel_count(self):
        """Pins the gauge count for the same reason as the bar-gauge one: #467's
        measurement (17 gauges, 2 carrying the synthetic triple) has to stay
        checkable against what the builder actually produces. 17 -> 19 when #577
        added the SATA SSD spare/endurance pair alongside the NVMe ones."""
        self.assertEqual(len(_gauge_panels(self.builder)), 19)

    def test_memory_used_percent_keeps_its_boundary_now_stated_explicitly(self):
        """#467's no-visual-change criterion for the one panel that INHERITED the
        70/90 triple. The values and colors must be byte-identical to what the
        builder used to inject; only their origin changes."""
        panel = self._panel("Memory Used %", group="gauge")
        defaults = panel["spec"]["vizConfig"]["spec"]["fieldConfig"]["defaults"]
        self.assertEqual(defaults["unit"], "percent")
        self.assertEqual(defaults["max"], 100)
        self.assertEqual(_steps(panel), [
            {"color": "green", "value": None},
            {"color": "yellow", "value": 70},
            {"color": "red", "value": 90},
        ])

    def test_pf_states_used_percent_boundary_unchanged(self):
        """The second panel #467 named. Unlike Memory Used %, this one was ALREADY
        passing the triple explicitly — it merely matched the injected default by
        value — so nothing about it changes. Pinned so that is not re-litigated."""
        panel = self._panel("PF States Used %", group="gauge")
        defaults = panel["spec"]["vizConfig"]["spec"]["fieldConfig"]["defaults"]
        self.assertEqual(defaults["unit"], "percent")
        self.assertEqual(_steps(panel), [
            {"color": "green", "value": None},
            {"color": "yellow", "value": 70},
            {"color": "red", "value": 90},
        ])

    def test_no_undocumented_panel_carries_a_severity_boundary(self):
        """The structural guard: any gauge OR bar-gauge panel with more than one
        threshold step MUST be named in the allowlist for its viz type. A future
        caller that passes a real `thresholds=` list without adding itself there
        fails this test instead of shipping an unreviewed severity boundary."""
        for group, allowed in (("bargauge", EXPLICIT_BARGAUGE_TITLES),
                               ("gauge", EXPLICIT_GAUGE_TITLES)):
            with self.subTest(group=group):
                offenders = {
                    panel["spec"]["title"]: _steps(panel)
                    for panel in _panels_of(self.builder, group)
                    if not _is_neutral(_steps(panel))
                    and panel["spec"]["title"] not in allowed
                }
                self.assertEqual(offenders, {})

    def test_explicit_threshold_titles_are_exactly_the_known_set(self):
        """Pins both allowlists from the other direction: every allow-listed title
        must actually still carry a real boundary. Catches the opposite mistake —
        a panel drops its explicit thresholds but the allowlist entry is left
        behind, silently blinding this guard."""
        for group, allowed in (("bargauge", EXPLICIT_BARGAUGE_TITLES),
                               ("gauge", EXPLICIT_GAUGE_TITLES)):
            with self.subTest(group=group):
                actual = {
                    panel["spec"]["title"]
                    for panel in _panels_of(self.builder, group)
                    if not _is_neutral(_steps(panel))
                }
                self.assertEqual(actual, allowed)


if __name__ == "__main__":
    unittest.main()
