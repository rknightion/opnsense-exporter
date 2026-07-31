"""Every fieldConfig.overrides entry must match Grafana's v2 Dashboard schema.

WHY THIS EXISTS (#616). One call site passed the shorthand 3-tuple form of an override
and the builder emitted it verbatim. JSON has no tuple, so it serialised as a list of
lists, and Grafana's GitSync rejected the ENTIRE dashboard on unmarshal:

    Dashboard in version "v2" cannot be handled as a Dashboard: json: cannot unmarshal
    array into Go struct field
    DashboardSpec.spec.elements.spec.vizConfig.spec.fieldConfig.overrides
    of type v2.DashboardV2FieldConfigSourceOverrides

The failure was invisible from this repository: `make dashboard`, `make grafana-check`
and CI all passed, because the JSON is perfectly well-formed — it is only wrong against
a schema none of those check. The live dashboard silently stopped updating and drifted
12 panels behind over two days.

Builder._overrides now normalises and rejects at construction time. This test is the
backstop for the other route in: a panel helper that builds its fieldConfig by hand and
never goes through it. It walks the SHIPPED artifacts, so it holds no matter which code
path produced them.
"""
import json
import os
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

DASHBOARDS = ("dashboard.json", "dashboard-health.json")


def iter_overrides(node, path=""):
    """Yield (path, value) for every "overrides" key anywhere in the document."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "overrides":
                yield f"{path}/{key}", value
            yield from iter_overrides(value, f"{path}/{key}")
    elif isinstance(node, list):
        for i, value in enumerate(node):
            yield from iter_overrides(value, f"{path}[{i}]")


class TestFieldOverrides(unittest.TestCase):
    def test_every_override_is_a_matcher_properties_object(self):
        checked = 0
        for name in DASHBOARDS:
            with open(os.path.join(ROOT, name), encoding="utf-8") as fh:
                doc = json.load(fh)
            for path, overrides in iter_overrides(doc):
                self.assertIsInstance(
                    overrides, list,
                    f"{name}{path}: overrides must be a list, got {type(overrides).__name__}")
                for i, ov in enumerate(overrides):
                    where = f"{name}{path}[{i}]"
                    # The exact failure mode: a list/tuple where an object belongs.
                    self.assertIsInstance(
                        ov, dict,
                        f"{where}: each override must be an object with 'matcher' and "
                        f"'properties'; got {type(ov).__name__} {ov!r}. A 3-tuple "
                        f"(regex, property_id, value) is accepted by Builder._overrides "
                        f"and expanded — pass it through there rather than building "
                        f"fieldConfig by hand.")
                    self.assertIn("matcher", ov, f"{where}: missing 'matcher'")
                    self.assertIn("properties", ov, f"{where}: missing 'properties'")
                    self.assertIsInstance(ov["matcher"], dict, f"{where}: matcher must be an object")
                    self.assertIn("id", ov["matcher"], f"{where}: matcher missing 'id'")
                    self.assertIsInstance(
                        ov["properties"], list, f"{where}: properties must be a list")
                    for prop in ov["properties"]:
                        self.assertIsInstance(prop, dict, f"{where}: each property must be an object")
                        self.assertIn("id", prop, f"{where}: property missing 'id'")
                    checked += 1
        self.assertGreater(checked, 0, "walked the dashboards and found no overrides at all")


class TestBuilderOverrideNormalisation(unittest.TestCase):
    def setUp(self):
        import sys
        if ROOT not in sys.path:
            sys.path.insert(0, ROOT)
        from builder import Builder  # noqa: PLC0415
        self.norm = Builder._overrides

    def test_tuple_shorthand_expands_to_byregexp(self):
        self.assertEqual(
            self.norm([("downloads/day .*", "unit", "short")]),
            [{"matcher": {"id": "byRegexp", "options": "downloads/day .*"},
              "properties": [{"id": "unit", "value": "short"}]}])

    def test_full_form_passes_through(self):
        full = [{"matcher": {"id": "byName", "options": "CPU"},
                 "properties": [{"id": "unit", "value": "percent"}]}]
        self.assertEqual(self.norm(full), full)

    def test_none_and_empty(self):
        self.assertEqual(self.norm(None), [])
        self.assertEqual(self.norm([]), [])

    def test_malformed_raises(self):
        for bad in ([("only", "two")], [{"matcher": {"id": "byName"}}], ["nope"], [42]):
            with self.assertRaises(ValueError):
                self.norm(bad)


if __name__ == "__main__":
    unittest.main()
