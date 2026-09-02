"""Gate: every registered log source is selected by a generated panel (#591 item 5).

The project rule is "every emitted metric AND every stable log stream is consumed by
at least one generated panel or rule". The metric half has been gate-enforced since
#84 and reports itself loudly on every build. The log half was enforced by nothing at
all — blind spot 2 of #591 — and the reason is structural rather than an oversight:
`builder.py` deliberately routes LogQL into a SEPARATE `_loki_exprs` list so a log
query can never reach the Prometheus coverage gate, and until now the only consumer
of that second list was the instance-scoping test. Five of the seven registered
sources shipped with no panel.

## Why the expected set is derived from Go rather than listed here

A hardcoded Python list of source names is precisely the drift this epic keeps
finding: Go gains a source, the list does not, and the gate goes on reporting full
coverage of a set that quietly stopped being the real one. Nothing generated carries
the set (`self-metrics.md` documents metric names, not `opnsense.source` values), so
the Go source is the only non-drifting origin and `registered_log_sources()` reads it.

The expected membership IS pinned below, but as a DRIFT ALARM rather than as the
gate's input: when Go changes, the pin fails and a human decides whether the new
source needs a panel. That is the opposite of a hardcoded gate, which would simply
never notice.

## The trap the derivation exists to avoid

The factory name is not always the source value. `internal/logship/flowlog` registers
ONE push source whose `Name()` is `"flow"`, and no record it ships ever carries that
value — every one gets an explicit `Record.Source` override of `netflow` or `merged`
(flowlog.go:96,134 resolved through internal/flow/record.go:27-38). The registered
factories can produce more shipped streams than factory names, so a gate keyed on `Name()` alone would be
wrong twice at once: demanding a panel for a stream that cannot exist, and letting
the two that do exist go unpanelled without complaint.
"""
import sys
import unittest
from pathlib import Path

GRAFANA_DIR = Path(__file__).resolve().parents[1]
REPO = GRAFANA_DIR.parent
sys.path.insert(0, str(GRAFANA_DIR))

import build_dashboard  # noqa: E402
from builder import Builder  # noqa: E402

LOG_SHIPPING_DOC = REPO / "docs" / "log-shipping.md"

# The `opnsense.source` values the pipeline can stamp, as of #591. A DRIFT ALARM, not
# the gate's input — see the module docstring. When this fails, read the diff and
# decide whether the new stream needs a panel; do not simply update the set.
EXPECTED_SOURCES = {
    "syslog", "unbound", "ids", "crowdsec", "zenarmor", "netflow", "merged",
    "configchange", "configstate",
}


class LogStreamCoverageTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builders = [b for _, b in build_dashboard.build_family()]

    def test_every_registered_source_is_selected_by_a_panel(self):
        gaps = build_dashboard.log_stream_gaps(*self.builders)
        self.assertEqual(
            [], gaps,
            "registered log source(s) that no generated LogQL panel selects. Each "
            "carries per-event detail no metric summarises, so a counter saying HOW "
            "MANY is not coverage for WHICH. Add a Loki panel selecting "
            'opnsense_source="<source>" on the tab that owns it, or add it to '
            f"LOG_SOURCE_EXEMPT with a written reason: {gaps}")

    def test_the_required_source_set_has_not_drifted(self):
        """Fails when Go gains or loses a source. That is the point: the gate above
        derives its set, so without this pin a newly registered source would silently
        become required and a removed one silently stop being checked, with the build
        reporting full coverage in both cases."""
        required = (build_dashboard.registered_log_sources()
                    - set(build_dashboard.LOG_SOURCE_EXEMPT))
        self.assertEqual(
            EXPECTED_SOURCES, required,
            "the set of log sources requiring a panel changed. If Go gained a source, "
            "decide whether it needs a panel and update EXPECTED_SOURCES with that "
            "decision; if the extraction broke, fix the extraction rather than this "
            "set — see registered_log_sources() in build_dashboard.py")

    def test_the_lane_name_flow_is_exempt_and_the_override_values_are_not(self):
        """The specific shape a `Name()`-only derivation gets wrong. Pinned in both
        directions so a future simplification that drops `ExtraSourceNames()` fails
        here rather than silently stopping enforcement on the two flow streams."""
        derived = build_dashboard.registered_log_sources()
        self.assertIn("flow", derived,
                      "the flowlog lane name is no longer derived, so the exemption "
                      "below is dead and the extraction has changed shape")
        self.assertIn("flow", build_dashboard.LOG_SOURCE_EXEMPT)
        self.assertTrue(build_dashboard.LOG_SOURCE_EXEMPT["flow"].strip(),
                        "the exemption must carry a written reason")
        for name in ("netflow", "merged"):
            self.assertIn(name, derived,
                          f"{name} is stamped only via ExtraSourceNames(); losing it "
                          "means the flow log streams stopped being required")
            self.assertNotIn(name, build_dashboard.LOG_SOURCE_EXEMPT)

    def test_the_syslog_source_survives_the_derivation(self):
        """The syslog source implements `ExtraSourceNames()` too — dynamically,
        reporting whatever a registered ProgramProcessor stamps
        (internal/logship/syslog/source.go:196). A derivation shaped as "drop any
        source implementing ExtraSourceNames and use its list instead" would therefore
        delete `syslog` itself, the most-consumed stream on the estate, and nothing
        would report it as missing because it would simply stop being required."""
        self.assertIn("syslog", build_dashboard.registered_log_sources())

    def test_an_unpanelled_source_is_caught(self):
        """The gate has teeth. Proven by running it against a Builder with no Loki
        expressions at all, which must report every required source rather than
        finding nothing to check."""
        gaps = build_dashboard.log_stream_gaps(Builder())
        self.assertEqual(sorted(EXPECTED_SOURCES), gaps)

    def test_a_regex_alternation_covers_every_alternative(self):
        """`opnsense_source=~"netflow|merged"` is one matcher covering two streams,
        which is how the flow drilldown is written. Reading it as the single literal
        `netflow|merged` would leave both permanently reported as gaps."""
        b = Builder()
        b.record_loki_expr('{service_name="opnsense2otel",opnsense_source=~"netflow|merged"} | json')
        self.assertEqual({"netflow", "merged"},
                         build_dashboard.panelled_log_sources(b))

    def test_coverage_is_read_from_the_stream_selector_not_the_body(self):
        """The word "zenarmor" appears in line filters, legends and panel text all
        over the Zenarmor tab. Counting a bare word match would score a stream as
        covered because some unrelated panel mentions it in a `|=` filter."""
        b = Builder()
        b.record_loki_expr('{service_name="opnsense2otel"} |= "zenarmor"')
        self.assertEqual(set(), build_dashboard.panelled_log_sources(b))

    def test_the_documented_source_table_agrees_with_the_source(self):
        """A second, independent origin for the same set. docs/log-shipping.md lists
        the `opnsense.source` values for operators writing their own queries; it was
        missing `netflow` and `merged` until #591. Checked as substring presence
        rather than by parsing the table, so it survives reformatting and still
        catches a source that reached Go but never reached the docs."""
        doc = LOG_SHIPPING_DOC.read_text()
        missing = sorted(s for s in EXPECTED_SOURCES if f"`{s}`" not in doc)
        self.assertEqual(
            [], missing,
            "log source(s) the pipeline can stamp are absent from "
            f"docs/log-shipping.md's source table: {missing}")


if __name__ == "__main__":
    unittest.main()
