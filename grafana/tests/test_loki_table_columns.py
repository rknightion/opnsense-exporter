"""Guard: a `loki_table()` renders named columns, not a serialised label set (#471).

A LogQL metric query returns one frame per output series, and the series' labels
live on the value FIELD, not in the rows. `reduce{mode:seriesToRows}` therefore
names each row after the frame's display name, which for a Loki metric frame is
the whole label set — the live dashboard rendered `Top Applications` as

    Field                                                        Total
    {app_name="STUN", service_instance_id="opnsense"}            57495

The value and the ordering were right; the key column was a truncated label dump
with the instance repeated inside every row. The fix is a `labelsToFields` split
(labels become real columns) then an `organize` that titles and orders the three
columns. #479 later made these queries INSTANT and removed the `groupBy` that sat
between the two: it aggregated a range query's many points per series, which an
instant query does not have, and it silently dropped the value column.

What this file pins, in contract terms rather than by importing the builder's
constants:

* the ranked label reaches the table as its OWN column, titled from the call site;
* the appliance identity reaches it as its own DISTINCT column, not concatenated
  into the key (that is the readable half of #468 — `test_instance_identity.py`
  only proves identity survives the query, not that a human can see it);
* no column is named after a raw Loki label or a label set;
* `reduce`/`seriesToRows` is gone from every Loki table, because leaving it in
  alongside the new chain would silently restore the old shape.
"""

import re
import sys
import unittest
from pathlib import Path


GRAFANA_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GRAFANA_DIR))

import build_dashboard  # noqa: E402
from builder import Builder  # noqa: E402


# Spelled out, not imported: this is the contract the dashboard owes Grafana, and
# a test that reads the constant it is meant to pin cannot fail when it changes.
INSTANCE_LABEL = "service_instance_id"
INSTANCE_COLUMN = "Instance"
VALUE_COLUMN = "Total"

# A column title a human wrote, e.g. "Application", "DNS Query", "TLS Server Name".
# Deliberately excludes `_` and `=` and `{`, which is what a raw Loki label or a
# serialised label set would bring.
HUMAN_TITLE = re.compile(r"[A-Z][A-Za-z0-9 ()/-]*$")


def transformations(panel):
    return panel["spec"]["data"]["spec"].get("transformations", [])


def transform(panel, group):
    """The single transformation of this kind on the panel, or None."""
    found = [t for t in transformations(panel) if t.get("group") == group]
    if not found:
        return None
    assert len(found) == 1, f"expected one {group} transform, got {len(found)}"
    return found[0]["spec"]["options"]


def rendered_columns(panel):
    """The column names the table panel will show, in display order.

    Derived the way Grafana derives them. `labelsToFields` (columns mode) turns
    each frame's labels into fields and merges the frames, so the field set is
    the ranked label, the instance label, and the datasource's own `Value` —
    plus `Time`, which organize drops. organize then renames and orders.

    There is deliberately no aggregation step to model (#479): an instant query
    returns one point per series, so nothing needs summing.
    """
    organize = transform(panel, "organize")
    assert transform(panel, "labelsToFields") is not None, "no labelsToFields transform"
    assert organize is not None, "no organize transform"

    index = organize.get("indexByName", {})
    excluded = organize.get("excludeByName", {})
    # Only one of the two value spellings is ever a real field: `merge` emits
    # "Value #A". Both are configured so neither can regress, so the unrendered
    # one is dropped here rather than counted as a fourth column.
    fields = [f for f in index if not excluded.get(f) and f != "Value"]
    fields.sort(key=lambda f: index.get(f, len(index)))
    return [organize.get("renameByName", {}).get(f, f) for f in fields]


def loki_table_panels(builder):
    """[(title, panel)] for every table panel fed by a Loki query."""
    out = []
    for element in builder.elements.values():
        if element["kind"] != "Panel":
            continue
        spec = element["spec"]
        if spec["vizConfig"]["group"] != "table":
            continue
        queries = spec["data"]["spec"]["queries"]
        if any(q["spec"]["datasource"].get("type") == "loki" for q in queries):
            out.append((spec["title"], element))
    return out


class LokiTableHelperTest(unittest.TestCase):
    """Unit-level: one synthetic call, checked end to end."""

    def _panel(self, **kwargs):
        builder = Builder()
        expr = ('topk by (service_instance_id) (25, sum by (service_instance_id, app_name) '
                '(count_over_time({service_instance_id=~"$opnsense_instance"} '
                '| app_name!="" [$__auto])))')
        name = builder.loki_table("Top Applications", [expr],
                                  field_title="Application", **kwargs)
        return builder.elements[name]

    def test_the_ranked_label_becomes_its_own_titled_column(self):
        self.assertIn("Application", rendered_columns(self._panel()))

    def test_the_instance_is_a_distinct_column_not_part_of_the_key(self):
        columns = rendered_columns(self._panel())
        self.assertIn(INSTANCE_COLUMN, columns)
        self.assertNotIn(INSTANCE_LABEL, columns)

    def test_the_table_renders_exactly_label_instance_value(self):
        self.assertEqual(rendered_columns(self._panel()),
                         ["Application", INSTANCE_COLUMN, VALUE_COLUMN])

    def test_the_label_set_reduce_is_gone(self):
        panel = self._panel()
        self.assertIsNone(transform(panel, "reduce"))
        self.assertNotIn("seriesToRows", str(transformations(panel)))

    def test_labels_are_split_into_fields_before_organizing(self):
        panel = self._panel()
        groups = [t["group"] for t in transformations(panel)]
        self.assertIn("labelsToFields", groups)
        self.assertLess(groups.index("labelsToFields"), groups.index("organize"))

    def test_no_aggregation_step_survives(self):
        """#479: `groupBy` here looked its target field up by DISPLAY name, and the
        Loki datasource stamps displayNameFromDS with the serialised label set, so
        it never found "Value" and silently dropped the value column — the table
        rendered its key and instance columns with no number at all. An instant
        query returns one point per series, so there is nothing to aggregate."""
        panel = self._panel()
        self.assertIsNone(transform(panel, "groupBy"))
        self.assertIsNone(transform(panel, "reduce"))

    def test_the_value_column_is_renamed_under_its_merged_field_name(self):
        """`merge` suffixes the value field with its refId, so the field reaching
        organize is "Value #A". Renaming only "Value" leaves the column titled
        "Value #A" AND silently breaks the sort, which resolves "Total" by display
        name and falls back to alphabetical order when it does not match — the
        table then looks fine while no longer being ranked at all."""
        organize = transform(self._panel(), "organize")
        self.assertEqual(organize["renameByName"]["Value #A"], VALUE_COLUMN)
        self.assertEqual(organize["renameByName"]["Value"], VALUE_COLUMN)

    def test_the_time_column_is_dropped(self):
        """One point per series, all stamped identically — a wasted column."""
        organize = transform(self._panel(), "organize")
        self.assertTrue(organize["excludeByName"]["Time"])

    def test_the_default_sort_column_exists(self):
        panel = self._panel()
        sort_by = panel["spec"]["vizConfig"]["spec"]["options"]["sortBy"][0]["displayName"]
        self.assertIn(sort_by, rendered_columns(panel))

    def test_an_ambiguous_ranked_label_is_refused_rather_than_guessed(self):
        """The helper derives the ranked label from the query's own group-by so it
        cannot drift from what is ranked. Two candidate labels have no single key
        column, and silently picking one would mislabel every row."""
        builder = Builder()
        expr = ('topk by (service_instance_id) (25, sum by (service_instance_id, app_name, host) '
                '(count_over_time({service_instance_id=~"$opnsense_instance"} [$__auto])))')
        with self.assertRaises(ValueError):
            builder.loki_table("Ambiguous", [expr], field_title="Application")


class BuiltDashboardLokiTablesTest(unittest.TestCase):
    """Every shipped Loki table, on the real manifest."""

    @classmethod
    def setUpClass(cls):
        cls.builder = build_dashboard.build_all()
        cls.panels = loki_table_panels(cls.builder)

    def test_the_scan_sees_every_loki_table(self):
        """Guards the guard: a structural change that stopped matching panels would
        make every assertion below vacuously pass on an empty scan."""
        self.assertGreaterEqual(len(self.panels), 12)

    def test_no_loki_table_still_reduces_a_label_set_into_its_key_column(self):
        offenders = [t for t, p in self.panels
                     if "seriesToRows" in str(transformations(p))]
        self.assertEqual(offenders, [])

    def test_every_loki_table_shows_a_titled_key_an_instance_and_a_value(self):
        for title, panel in self.panels:
            with self.subTest(panel=title):
                columns = rendered_columns(panel)
                self.assertEqual(len(columns), 3, columns)
                key, instance, value = columns
                self.assertEqual(instance, INSTANCE_COLUMN)
                self.assertEqual(value, VALUE_COLUMN)
                self.assertRegex(key, HUMAN_TITLE)

    def test_no_column_is_named_after_a_raw_label_or_a_label_set(self):
        for title, panel in self.panels:
            with self.subTest(panel=title):
                for column in rendered_columns(panel):
                    self.assertNotIn("{", column)
                    self.assertNotIn("=", column)
                    self.assertNotIn("_", column)

    def test_the_instance_column_is_never_hidden(self):
        for title, panel in self.panels:
            with self.subTest(panel=title):
                organize = transform(panel, "organize")
                self.assertFalse(organize.get("excludeByName", {}).get(INSTANCE_LABEL))

    def test_every_loki_table_sorts_by_a_column_it_renders(self):
        for title, panel in self.panels:
            with self.subTest(panel=title):
                sort_by = panel["spec"]["vizConfig"]["spec"]["options"]["sortBy"]
                self.assertIn(sort_by[0]["displayName"], rendered_columns(panel))


if __name__ == "__main__":
    unittest.main()


class LokiTableIsAnInstantQueryTest(unittest.TestCase):
    """#479: a top-N table must be an INSTANT query, not a range query.

    Loki's `max_query_series` (default 500) is enforced on the number of distinct
    series a query RETURNS. For a range query that is the UNION across every step,
    so `topk(25, ...)` over 6h at 5m steps returns every name that entered the top
    25 in ANY step — measured at 82 distinct over 1h for DNS names, and past 500
    over 6h. Three panels therefore returned no data at all, with a query error.

    `topk` cannot save a range query, because the union is taken after `topk` runs
    per step. An instant query returns exactly N series regardless of the window,
    which is also what a top-N table actually wants: one aggregate over the
    selected range, not a time series. Verified live: instant `topk(200)` over 6h,
    24h and 7d all return exactly 200 series, while the range form fails at 6h.
    """

    @classmethod
    def setUpClass(cls):
        cls.panels = loki_table_panels(build_dashboard.build_all())

    def test_every_loki_table_is_an_instant_query(self):
        for title, panel in self.panels:
            with self.subTest(panel=title):
                for query in panel["spec"]["data"]["spec"]["queries"]:
                    spec = query["spec"]["query"]["spec"]
                    self.assertTrue(spec["instant"], f"{title} is still a range query")
                    self.assertFalse(spec["range"])
                    self.assertEqual(spec["queryType"], "instant")

    def test_no_loki_table_uses_the_step_derived_auto_interval(self):
        # $__auto is derived from the query STEP, which an instant query does not
        # have. The window must be the dashboard's selected range instead, or the
        # table silently aggregates over an interval nobody chose.
        for title, panel in self.panels:
            with self.subTest(panel=title):
                for query in panel["spec"]["data"]["spec"]["queries"]:
                    expr = query["spec"]["query"]["spec"]["expr"]
                    self.assertNotIn("$__auto", expr, f"{title} still uses $__auto")
                    self.assertIn("[$__range]", expr)

    def test_every_topk_stays_under_lokis_series_ceiling(self):
        # 500 is the wall, not the target: instant topk(500) FAILS live, and
        # topk(450) returned 465 series, so N is not an exact bound on the result.
        # Anything at or near 500 has no headroom on a busier window.
        for title, panel in self.panels:
            with self.subTest(panel=title):
                for query in panel["spec"]["data"]["spec"]["queries"]:
                    expr = query["spec"]["query"]["spec"]["expr"]
                    # The rendered form is `topk by (service_instance_id) (N, ...)`,
                    # so the optional by-clause must be skipped explicitly. A pattern
                    # of `topk[^(]*\(` matches only as far as `topk by (` and then
                    # finds no digits — it silently matches nothing and the assertion
                    # passes on every input. Caught by mutation-testing this check.
                    for n in re.findall(r"topk(?:\s+by\s*\([^)]*\))?\s*\((\d+),", expr):
                        self.assertLessEqual(int(n), 250, f"{title} ranks {n}")


class UnboundedLabelTablesPinTheirOwnWindowTest(unittest.TestCase):
    """#479: the WINDOW is the cardinality lever, not `topk`.

    Loki's max_query_series (500) is enforced on an intermediate of the query,
    and `topk` prunes only the result — so the rank depth has no bearing on
    whether the query fails. Measured through Grafana's own query path against
    the live tenant, on the DNS-name table: N=25 and N=200 both return data at
    1h and both fail at 3h and 6h. Only the range moves it.

    A table ranking an unbounded label must therefore pin its own window, or it
    breaks the moment the dashboard is set wider than the cliff — silently, as
    "No data" with a query error rather than as a partial result.
    """

    UNBOUNDED = {
        "Top DNS Queries",            # DNS names
        "Top TLS Server Names (SNI)",  # SNI values
        "Top JA3 Fingerprints",       # JA3 hashes
        "Top URIs",                   # request paths
        # #591 item 5 / #592 item 1 — the same two shapes on the new log-stream
        # tables. Query names are the Unbound lane's own copy of the DNS-name
        # cardinality already pinned above, and endpoint ADDRESSES are worse: the
        # flow lane emits one record per connection-window, so a busy WAN mints
        # distinct dst_ip values continuously.
        "Top Blocked Query Names",           # DNS names, unbound per-query lane
        "Top Flow Destinations by Bytes",    # remote addresses, flow-log lane
    }

    @classmethod
    def setUpClass(cls):
        cls.panels = loki_table_panels(build_dashboard.build_all())

    def test_every_unbounded_label_table_pins_a_window(self):
        seen = set()
        for title, panel in self.panels:
            if title not in self.UNBOUNDED:
                continue
            seen.add(title)
            with self.subTest(panel=title):
                qopts = panel["spec"]["data"]["spec"]["queryOptions"]
                self.assertIn("timeFrom", qopts,
                              f"{title} ranks an unbounded label but follows the "
                              "dashboard picker, so it breaks past the cliff")
        self.assertEqual(seen, self.UNBOUNDED,
                         "a pinned table was renamed — update UNBOUNDED, do not "
                         "let this guard silently check nothing")

    def test_bounded_label_tables_are_left_on_the_dashboard_picker(self):
        """The pin is a cost, not a default: it decouples the panel from the time
        picker, which is only worth paying where the query would otherwise fail."""
        for title, panel in self.panels:
            if title in self.UNBOUNDED:
                continue
            with self.subTest(panel=title):
                self.assertNotIn("timeFrom", panel["spec"]["data"]["spec"]["queryOptions"])
