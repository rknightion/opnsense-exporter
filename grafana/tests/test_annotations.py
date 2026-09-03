"""Guard: the dashboard's event-annotation layer is a generated contract (#421).

Annotations are the only part of the dashboard whose *absence* is invisible: a
missing panel is a hole on screen, a missing annotation is just a timeline with
nothing on it. So the contract is enforced from three directions here.

1. **Nothing is silently dropped on publication.** The deployed dashboard carried a
   built-in-store annotation layer the generator did not know about, so copying
   generated output over it would have deleted it. It is now generated, and
   `test_the_deployment_local_overlay_is_generator_owned` pins the exact tags the
   live query uses.

2. **Nothing is silently NOT annotated.** Every epoch-timestamp metric in the
   catalogue is either an annotation source or carries a written reason why it is
   not. A new `*_timestamp_seconds` metric fails this file until someone decides.

3. **An annotation cannot leak or mislead.** Each query is instance-scoped, each
   value-as-time query is bounded to the visible window and scaled to
   milliseconds, and no tag key may carry an address, hostname or raw log body.

4. **The two halves of the feature agree.** The exporter can also PUSH these events
   into Grafana's annotation store (`--annotations.enabled`, `internal/annotations`).
   The Go emitter's watched-metric set and its tag constant are read out of the Go
   source and compared with this side, because a divergence has no symptom: the
   exporter writes annotations nobody queries while the dashboard queries a tag
   nobody writes, and each half looks healthy on its own.
"""

import re
import sys
import unittest
from pathlib import Path


GRAFANA_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GRAFANA_DIR))

import annotations as ann  # noqa: E402
import uids  # noqa: E402
import build_dashboard  # noqa: E402
from builder import INSTANCE_SEL, LOKI_INSTANCE_SEL  # noqa: E402


# Structured-metadata / label keys that must never become annotation tags. Tags are
# indexed and queryable across dashboards, so a tag is a far wider exposure than
# the annotation text an operator has to hover to read (#421: "do not expose raw
# addresses, hostnames, or free-form log bodies as annotation tags").
FORBIDDEN_TAG_KEYS = {
    "host", "hostname", "config_user", "user_name", "audit_user", "peer",
    "real_address", "virtual_address", "src", "dst", "src_ip", "dst_ip",
    "source_address", "server_name", "ja3", "device_name", "username",
    "config_revision", "observed_timestamp", "pid",
}

# A metric is annotation-shaped if its value IS an instant. Anything matching this
# must appear in the annotation catalogue or in its exclusion ledger.
EPOCH_METRIC = re.compile(r"(_timestamp_seconds|_last_change)$")


def go_base_tag() -> str:
    """The tag constant from internal/annotations/catalog.go.

    Read out of the Go source rather than duplicated, because a silent divergence
    here has no symptom: the exporter writes annotations nobody queries and the
    dashboard queries a tag nobody writes, and both halves look healthy.
    """
    source = (GRAFANA_DIR.parent / "internal" / "annotations" / "catalog.go").read_text()
    match = re.search(r'BaseTag\s*=\s*"([^"]+)"', source)
    assert match, "BaseTag not found in internal/annotations/catalog.go"
    return match.group(1)


def go_watched_metrics() -> set:
    """The metric names in the Go emitter's catalogue.

    Every `opnsense_*` string literal in that file is a metric name — the tag
    constant is `opnsense2otel`, hyphenated, so it cannot be confused for one.
    Deliberately NOT filtered by EPOCH_METRIC: the interface marker is named
    `..._uptime_seconds` because it is an uptime reading until the boot epoch is
    added to it, and filtering on the suffix would quietly exempt it from parity.
    """
    source = (GRAFANA_DIR.parent / "internal" / "annotations" / "catalog.go").read_text()
    return set(re.findall(r'"(opnsense_[a-z0-9_]+)"', source))


def go_watch_defaults() -> dict:
    """`metric -> pushed by default?` from the Go emitter's catalogue.

    Parsed out of the source for the same reason as the tag constant: the two sides
    are one contract with no runtime that checks it. The `DefaultOff` field is the
    Go side of the per-kind push set, and a watch without it is pushed.
    """
    source = (GRAFANA_DIR.parent / "internal" / "annotations" / "catalog.go").read_text()
    block = source.split("var Watches = []Watch{", 1)
    assert len(block) == 2, "Watches catalogue not found in internal/annotations/catalog.go"
    out = {}
    for literal in re.findall(r"\n\t\{(.*?)\n\t\},", block[1], re.S):
        metric = re.search(r'Metric:\s*"(opnsense_[a-z0-9_]+)"', literal)
        # The reboot watch names its metric through the BootMetric constant.
        name = metric.group(1) if metric else (
            "opnsense_system_boot_timestamp_seconds"
            if re.search(r"Metric:\s*BootMetric", literal) else None)
        assert name, f"cannot read the metric out of watch literal: {literal[:80]}"
        out[name] = not re.search(r"DefaultOff:\s*true", literal)
    return out


def epoch_metrics():
    return [n for n in build_dashboard.load_catalogue() if EPOCH_METRIC.search(n)]


def go_link_constants() -> dict:
    """The dashboard UID and instance parameter the Go annotation writer links to.

    Read out of `internal/annotations/links.go` for the same reason as the tag
    constant above, and for a worse failure mode: a pushed annotation's link is
    clicked by an operator during an incident, weeks after the divergence, and a UID
    that no longer matches simply 404s. Nothing tests it on the Go side either — the
    UID is only meaningful relative to the dashboard this repository generates.
    """
    source = (GRAFANA_DIR.parent / "internal" / "annotations" / "links.go").read_text()
    out = {}
    for const in ("DashboardUID", "InstanceVar"):
        match = re.search(const + r'\s*=\s*"([^"]+)"', source)
        assert match, f"{const} not found in internal/annotations/links.go"
        out[const] = match.group(1)
    return out


class AnnotationLinkContractTest(unittest.TestCase):
    """The exporter's pushed annotations link back to THIS dashboard (#419/#421)."""

    def test_go_writer_links_to_the_registered_main_dashboard(self):
        self.assertEqual(go_link_constants()["DashboardUID"], uids.MAIN_UID)

    def test_go_writer_uses_the_dashboards_own_instance_variable(self):
        instance_vars = [v["spec"]["name"] for v in build_dashboard.build_all().variables
                         if v["spec"]["name"] == "opnsense_instance"]
        self.assertEqual(instance_vars, ["opnsense_instance"])
        self.assertEqual(go_link_constants()["InstanceVar"], "var-opnsense_instance")


class AnnotationEnvelopeTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.builder = build_dashboard.build_all()
        cls.annotations = cls.builder.manifest("t", "d", [])["spec"]["annotations"]

    def specs(self):
        return [a["spec"] for a in self.annotations]

    def by_group(self, group):
        return [s for s in self.specs() if s["query"]["group"] == group]

    def grafana_layer(self, name):
        for spec in self.by_group("grafana"):
            if spec["name"] == name:
                return spec
        self.fail(f"no built-in-store annotation layer named {name!r}")

    def test_the_dashboard_ships_annotations_at_all(self):
        self.assertGreater(len(self.annotations), 0,
                           "spec.annotations is empty; the event timeline is the point of #421")

    def test_every_envelope_matches_the_live_verified_v2_shape(self):
        """The v2 AnnotationQuery envelope was taken from Grafana's own converted
        node_exporter dashboard on the live stack, not from documentation: the real
        query lives under `legacyOptions`, while `query.spec` stays empty."""
        for spec in self.specs():
            with self.subTest(name=spec["name"]):
                self.assertIn("name", spec)
                self.assertIsInstance(spec["enable"], bool)
                self.assertIsInstance(spec["hide"], bool)
                self.assertTrue(spec["iconColor"])
                query = spec["query"]
                self.assertEqual(query["kind"], "DataQuery")
                self.assertEqual(query["version"], "v0")
                self.assertIn(query["group"], ("prometheus", "loki", "grafana"))
                if query["group"] == "prometheus":
                    self.assertEqual(query["datasource"], {"name": "${datasource}"})
                elif query["group"] == "loki":
                    self.assertEqual(query["datasource"], {"name": "${loki_datasource}"})
                if query["group"] != "grafana":
                    # A datasource annotation's real query lives in legacyOptions and
                    # query.spec stays empty. The built-in annotation store is the one
                    # exception: its tag query IS query.spec, as the live artifact shows.
                    self.assertEqual(query["spec"], {})

    def test_annotation_names_are_unique(self):
        names = [s["name"] for s in self.specs()]
        self.assertEqual(sorted(names), sorted(set(names)))

    def test_the_pushed_event_layer_queries_the_exporters_own_tag(self):
        """The exporter can WRITE these events into Grafana's annotation store
        (`--annotations.enabled`), which makes them visible to every other dashboard
        rather than only to the one that derives them. That only works if the tag the
        Go writer stamps and the tag this layer queries are the same string, so the
        two are asserted against each other here rather than trusted to match."""
        spec = self.grafana_layer("Exporter-pushed events")
        self.assertEqual(spec["query"]["datasource"], {"name": "-- Grafana --"})
        self.assertEqual(spec["query"]["spec"]["type"], "tags")
        self.assertEqual(spec["query"]["spec"]["tags"], [ann.EXPORTER_TAG])
        self.assertFalse(spec["query"]["spec"]["matchAny"])
        self.assertEqual(ann.EXPORTER_TAG, go_base_tag(),
                         "internal/annotations BaseTag and EXPORTER_TAG must be identical, "
                         "or pushed annotations land where the dashboard never looks")

    def test_the_deployment_local_overlay_is_generator_owned(self):
        """The publication-safety gate. The live dashboard has carried a
        built-in-store layer for automation outside this repository since before the
        generator existed, so copying generated output over it would have deleted it.
        Both tags are pinned: the second scopes the query to this dashboard, without
        which every change event in the estate lands on it."""
        spec = self.grafana_layer("External change events")
        self.assertEqual(spec["query"]["spec"]["type"], "tags")
        self.assertEqual(sorted(spec["query"]["spec"]["tags"]),
                         sorted(ann.EXTERNAL_CHANGE_TAGS))

    def test_every_prometheus_annotation_is_instance_scoped(self):
        proms = self.by_group("prometheus")
        self.assertGreater(len(proms), 0)
        for spec in proms:
            with self.subTest(name=spec["name"]):
                self.assertIn(INSTANCE_SEL, spec["legacyOptions"]["expr"])

    def test_every_loki_annotation_is_instance_scoped_in_the_stream_selector(self):
        """Position matters, exactly as in test_loki_scoping: a filter appended
        after the `|` would already have admitted every appliance's lines."""
        lokis = self.by_group("loki")
        self.assertGreater(len(lokis), 0)
        for spec in lokis:
            with self.subTest(name=spec["name"]):
                expr = spec["legacyOptions"]["expr"]
                selector = expr.split("}")[0] + "}"
                self.assertIn(LOKI_INSTANCE_SEL, selector)

    def test_new_device_annotation_reads_the_nested_snapshot_entity(self):
        entry = next(spec for spec in self.by_group("loki")
                     if spec["name"] == "New device observed")
        expr = entry["legacyOptions"]["expr"]
        self.assertIn('snapshot_family="device_inventory"', expr)
        self.assertIn('| json | entity_new_device="true"', expr)
        self.assertNotIn("hostname", entry["legacyOptions"].get("tagKeys", ""))

    def test_value_as_time_queries_are_scaled_and_window_bounded(self):
        """`useValueForTime` places the marker at the sample's VALUE, so the value
        must be epoch milliseconds (epoch seconds land in 1970), and the query must
        be bounded to the visible window or Grafana renders every historical event
        for a metric that has existed for months."""
        found = 0
        for spec in self.by_group("prometheus"):
            opts = spec["legacyOptions"]
            if opts.get("useValueForTime") != "on":
                continue
            found += 1
            with self.subTest(name=spec["name"]):
                self.assertIn("* 1000", opts["expr"])
                self.assertIn("> $__from < $__to", opts["expr"])
        self.assertGreater(found, 0, "no value-as-time annotations; timestamps would be approximate")

    def test_prometheus_annotations_do_not_use_value_as_time_without_saying_so(self):
        """A timestamp-valued metric queried WITHOUT useValueForTime annotates the
        scrape that observed the change, which can be a whole poll interval late —
        15 minutes on the cold tier. Any such annotation must be deliberate."""
        for spec in self.by_group("prometheus"):
            opts = spec["legacyOptions"]
            if opts.get("useValueForTime") == "on":
                continue
            with self.subTest(name=spec["name"]):
                self.assertTrue(
                    ann.observation_time_is_deliberate(spec["name"]),
                    "an observation-time annotation must be listed in "
                    "annotations.OBSERVATION_TIME_ANNOTATIONS with a reason")

    def test_every_annotation_carries_a_title(self):
        for spec in self.specs():
            if spec["query"]["group"] == "grafana":
                continue
            with self.subTest(name=spec["name"]):
                self.assertTrue(spec["legacyOptions"].get("titleFormat"))

    def test_no_tag_key_carries_an_address_hostname_or_body(self):
        for spec in self.specs():
            keys = [k.strip() for k in spec.get("legacyOptions", {}).get("tagKeys", "").split(",")]
            for key in filter(None, keys):
                with self.subTest(name=spec["name"], key=key):
                    self.assertNotIn(key, FORBIDDEN_TAG_KEYS)

    def test_every_annotation_records_why_it_exists(self):
        """The catalogue is a series of judgement calls about what is worth
        interrupting a graph for. Each one states its reason next to it, so the set
        can be reviewed without reverse-engineering the PromQL."""
        for entry in ann.ANNOTATIONS:
            with self.subTest(name=entry.name):
                self.assertTrue(entry.why and len(entry.why) > 20)


class AnnotationLedgerTest(unittest.TestCase):
    """Coverage of the annotation-shaped part of the metric catalogue."""

    def test_every_epoch_metric_is_annotated_or_excluded_with_a_reason(self):
        annotated = set()
        for entry in ann.ANNOTATIONS:
            annotated.update(entry.metrics)
        undecided = sorted(
            n for n in epoch_metrics()
            if n not in annotated and n not in ann.NOT_ANNOTATED
        )
        self.assertEqual(undecided, [],
                         "each of these is an instant-valued metric: annotate it, or "
                         "add it to annotations.NOT_ANNOTATED with the reason")

    def test_the_exclusion_ledger_is_not_stale(self):
        catalogue = set(build_dashboard.load_catalogue())
        gone = sorted(n for n in ann.NOT_ANNOTATED if n not in catalogue)
        self.assertEqual(gone, [], "these metrics no longer exist; drop the ledger entries")

    def test_every_exclusion_states_a_reason(self):
        for metric, reason in ann.NOT_ANNOTATED.items():
            with self.subTest(metric=metric):
                self.assertTrue(reason and len(reason) > 20)

    def test_the_non_instant_ledger_is_real_current_and_reasoned(self):
        """The second ledger (#592 item 2), kept apart from NOT_ANNOTATED on purpose.

        NOT_ANNOTATED answers "this metric's value IS an instant, and here is why we
        still do not mark it". A metric that was ASKED to become a marker and cannot,
        because its value is not an instant at all, fails no gate and would therefore
        leave no trace — the request simply gets re-raised. Folding it into
        NOT_ANNOTATED instead would contradict that ledger's own header and quietly
        widen what the annotation gate is understood to cover.

        Same three properties as the other ledger: the metric exists, the reason is
        written down, and the two ledgers stay disjoint.
        """
        catalogue = set(build_dashboard.load_catalogue())
        for metric, reason in ann.NOT_INSTANT_VALUED.items():
            with self.subTest(metric=metric):
                self.assertIn(metric, catalogue,
                              "this metric no longer exists; drop the ledger entry")
                self.assertFalse(EPOCH_METRIC.search(metric),
                                 "this metric IS instant-shaped — it belongs in "
                                 "NOT_ANNOTATED, which the annotation gate reads")
                self.assertTrue(reason and len(reason) > 20)
                self.assertNotIn(metric, ann.NOT_ANNOTATED)

    def test_the_go_emitter_watches_exactly_what_the_dashboard_derives(self):
        """The push and derive paths must describe the same events. A metric the Go
        side pushes but this side does not derive means an annotation appears with no
        matching layer to explain it; the reverse means an event the dashboard shows
        is invisible to every other dashboard in the org."""
        derived = set()
        for entry in ann.ANNOTATIONS:
            derived.update(entry.metrics)
        self.assertEqual(sorted(go_watched_metrics()), sorted(derived))

    def test_the_push_default_matches_the_dashboards_own_default(self):
        """The bug this guards (#540): the dashboard's per-kind toggle governs only
        the DERIVED layer. The pushed copy of the same event reaches the dashboard
        through `Exporter-pushed events`, a catch-all on the base tag, so a kind that
        is default-off here but pushed by default renders anyway and the toggle looks
        broken. Q-Feeds was exactly that — off on the dashboard, written to Grafana's
        store every twenty minutes. The two defaults are therefore one decision, and
        a new default-off layer needs `DefaultOff: true` on its Go watch."""
        derived = {}
        for entry in ann.ANNOTATIONS:
            for metric in entry.metrics:
                derived[metric] = derived.get(metric, False) or entry.enable
        for metric, pushed in go_watch_defaults().items():
            with self.subTest(metric=metric):
                self.assertIn(metric, derived)
                self.assertEqual(
                    pushed, derived[metric],
                    f"{metric} is {'pushed' if pushed else 'not pushed'} by default but its "
                    f"dashboard layer is {'on' if derived[metric] else 'off'} — set "
                    "DefaultOff on the Go watch, or enable the layer")

    def test_annotation_metrics_exist_in_the_catalogue(self):
        catalogue = set(build_dashboard.load_catalogue())
        for entry in ann.ANNOTATIONS:
            for metric in entry.metrics:
                with self.subTest(name=entry.name, metric=metric):
                    self.assertIn(metric, catalogue)


if __name__ == "__main__":
    unittest.main()


class AnnotationPlacementTest(unittest.TestCase):
    """Where each layer's toggle lives is a decision, not a default (#470).

    Sixteen layers plus two dashboard links pushed the controls area to three rows on
    every tab, which rendered validation caught and reasoning had not. Schema v2 has
    `placement: "inControlsMenu"` for exactly this, and Grafana 13 / v2 is the only
    supported target, so it is used unconditionally.

    The toolbar is for the layers an operator toggles WHILE reading a graph. Everything
    else — including every default-off layer — goes in the menu, and a new layer must
    say which it is.
    """

    @classmethod
    def setUpClass(cls):
        cls.specs = [a["spec"] for a in
                     build_dashboard.build_all().manifest("t", "d", [])["spec"]["annotations"]]

    def test_every_layer_declares_a_placement(self):
        for entry in ann.ANNOTATIONS:
            with self.subTest(name=entry.name):
                self.assertIsInstance(entry.on_toolbar, bool)

    def test_the_toolbar_set_is_small_and_is_the_declared_one(self):
        toolbar = {s["name"] for s in self.specs if "placement" not in s}
        self.assertEqual(toolbar, ann.TOOLBAR_LAYERS)
        self.assertLessEqual(
            len(toolbar), 4,
            "the toolbar set is growing again; a layer belongs there only if an "
            "operator toggles it while reading a graph")

    def test_everything_else_is_in_the_controls_menu(self):
        for spec in self.specs:
            if spec["name"] in ann.TOOLBAR_LAYERS:
                continue
            with self.subTest(name=spec["name"]):
                self.assertEqual(spec["placement"], "inControlsMenu")

    def test_no_default_off_layer_sits_on_the_toolbar(self):
        """A layer nobody has enabled is the last thing worth toolbar space."""
        for entry in ann.ANNOTATIONS:
            if not entry.enable:
                with self.subTest(name=entry.name):
                    self.assertFalse(entry.on_toolbar)

    def test_toolbar_layers_are_the_discontinuity_explainers(self):
        """Named rather than counted: these three are why the feature exists — a
        rate panel stepping because the box rebooted, because the config changed, or
        because one interface's counters reset."""
        self.assertEqual(
            ann.TOOLBAR_LAYERS,
            {"Reboot", "Config change", "Interface counter reset"})
        for entry in ann.ANNOTATIONS:
            if entry.on_toolbar:
                self.assertTrue(entry.enable, f"{entry.name} is on the toolbar but off")
