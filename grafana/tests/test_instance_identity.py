"""Guard: no panel aggregation or table transform destroys instance identity (#468).

#413/#414 scoped what data ENTERS a panel — the stream selector and the presence
sentinels. This is the other half: what the panel does to that data once it has
it. `sum by (protocol) (...)` admits both selected firewalls' series correctly and
then adds them together, and the panel says nothing: the legend still reads "tcp",
the unit is still right, and the number is the sum of two unrelated appliances.

#425's audit classified all 119 offenders. Three distinct failure shapes, because
a fix that treats them as one shape looks right and is not:

* **Merging** — `sum`/`count`/`max` with a group-by that omits the instance, or a
  `without` clause that names it. Two boxes' rows are added or maxed together.
* **Dropping** — `topk` with no clause. If one firewall's series dominate, the
  other firewall's rows are not merged into the result, they are ABSENT from it,
  with nothing on screen suggesting a second box exists. Worse than merging, and
  invisible. Where `topk` wraps an inner aggregation, the inner clause has to
  carry the label too: the fusion has already happened before `topk` runs.
* **Hiding** — a table whose query returns per-instance rows and whose `organize`
  transform then excludes the `opnsense_instance` column, leaving duplicate rows
  distinguishable by nothing at all.

The fix is structural: `grp()` / `topk_by()` (and `loki_grp()` / `loki_topk_by()`)
build the clause so the label cannot be forgotten, and this file fails on any
built query where one is missing. Both allowlists ship SMALL and each entry
carries its reason.

Scanned across the WHOLE dashboard family since #597, not just the main dashboard —
see `setUpClass`. Panel titles in failure messages carry their dashboard uid, because
the two files have different readers and one shared title ("Overview").

Deliberately behavioural as well as structural: `test_two_instance_fixture_*`
evaluates every real aggregation clause against a two-instance fixture whose
interface names, mountpoints and service names deliberately COLLIDE (`LAN`,
`WAN`, `/`, `192.168.1.10` on both boxes), which is the case that makes merging
indistinguishable from a legitimate single row.
"""

import re
import sys
import unittest
from pathlib import Path


GRAFANA_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GRAFANA_DIR))

import build_dashboard  # noqa: E402
from builder import TRANSPORT_LABELS  # noqa: E402


# Spelled out rather than imported: this is the contract, and a test that imports
# the constant it checks cannot fail when that constant changes.
PROM_LABEL = "opnsense_instance"
LOKI_LABEL = "service_instance_id"

# Every PromQL/LogQL aggregation operator that takes an optional by/without clause.
# `sort` / `sort_desc` are deliberately ABSENT: they are ordering functions, not
# aggregations — they return every input series with every label intact, so they
# can no more destroy identity than `rate()` can. Including them flagged the seven
# `sort_desc(sum by (reason) (...))` drop tables whose inner `sum` was already
# correct, which is a false positive that would have been "fixed" by wrapping a
# clause round a function that does not take one.
AGG_OPS = ("sum", "min", "max", "avg", "group", "stddev", "stdvar", "count",
           "count_values", "bottomk", "topk", "quantile", "limitk", "limit_ratio")
_AGG_RE = re.compile(r"\b(" + "|".join(AGG_OPS) + r")\b\s*(?:(by|without)\s*\(([^)]*)\))?\s*\(")

# `Builder._query()` wraps EVERY Prometheus target in
# `max without (job, service_instance_id, service_name, service_version) (...)`.
# That wrapper is instance-PRESERVING by construction — opnsense_instance is not in
# the list — so it must be recognised and skipped. A scan that counted it as a
# merge would flag all ~970 targets and prove nothing, which is the single trap
# #425 called out in its method note.
WRAPPER = ("max", "without", frozenset(TRANSPORT_LABELS))

# Panels whose aggregation is a DELIBERATE fleet total. Each is a single-value
# inventory count that composes into a coherent number across boxes ("how many
# monit checks are failing anywhere"), and each says so in its description —
# `test_declared_fleet_totals_say_so_on_the_panel` enforces that half, so an entry
# here cannot silently become an unlabelled merge (#425 criterion 3).
#
# The alternative — one tile per instance — was considered and rejected for these:
# they are 4x4 stat cards read as a single number, and the per-instance view is
# already one click away on the detail panels in the same row. Anything that is a
# DIAGNOSTIC rather than an inventory count (a ratio, a "worst peer", a top-N, any
# breakdown by an operator-configurable name) does NOT belong here.
FLEET_TOTAL_PANELS = {
    "Expired Vouchers": "captive-portal voucher inventory",
    "Unused Vouchers": "captive-portal voucher inventory",
    "Valid (Active) Vouchers": "captive-portal voucher inventory",
    "Outdated Hub Items": "CrowdSec hub inventory",
    "Tainted Hub Items": "CrowdSec hub inventory",
    "Checks Monitored": "monit check inventory",
    "Checks OK": "monit check inventory",
    "Hosts Configured": "relayd host inventory",
    "Hosts Up": "relayd host inventory",
    "Tables Active": "relayd table inventory",
    "Virtual Servers Active": "relayd virtual-server inventory",
    "Built Circuits": "Tor circuit inventory",
    "Total Circuits": "Tor circuit inventory",
    "Total Streams": "Tor stream inventory",
    "OpenVPN Instances Enabled": "OpenVPN instance inventory",
    "Unhealthy Subsystems": "count of unhealthy subsystems anywhere in the selection",
    # The only panel the #597 widening surfaced on the health dashboard, and the sole
    # reason this list grew: plugin-availability inventory, "is there anything actionable
    # anywhere in the selection". Kept fleet-wide rather than split per box because the
    # per-instance answer is the Plugin Availability table immediately above it, which
    # already carries an Instance column. Its query gained `sel()` in the same commit —
    # it was previously counting instances the variable does not even select, which is
    # fleet-wide by omission, not the declaration this entry makes.
    "Plugins Installed But Not Scraped": "plugin-availability inventory; the per-instance "
                                        "breakdown is the table in the same row",
}

# The phrase every fleet-total panel must carry, so the label is greppable and
# uniform rather than 16 different hand-written hints.
FLEET_TOTAL_PHRASE = "Fleet total"

# Tables allowed to hide the instance column. Empty by design: the project's own
# convention (the Build Info and NTP peer tables) is to RENAME it to "Instance",
# and a hidden column on a per-instance query produces indistinguishable duplicate
# rows the moment two boxes share a mountpoint, an ARP entry or an LLDP neighbour.
TABLE_HIDE_EXCEPTIONS: dict[str, str] = {}


def aggregations(expr: str):
    """Yield (op, kind, frozenset(labels)) for each aggregation in expr.

    Handles PromQL/LogQL's postfix form (`sum(x) by (y)`) as well as the prefix
    form, because accepting only the prefix form would silently pass a postfix
    merge.
    """
    for match in _AGG_RE.finditer(expr):
        op, kind, labels = match.group(1), match.group(2), match.group(3)
        if kind is None:
            kind, labels = _postfix_clause(expr, match.end() - 1)
        parsed = frozenset(x.strip() for x in labels.split(",")) if labels else frozenset()
        yield op, kind, parsed


def _postfix_clause(expr: str, open_paren: int):
    depth = 0
    for i in range(open_paren, len(expr)):
        if expr[i] == "(":
            depth += 1
        elif expr[i] == ")":
            depth -= 1
            if depth == 0:
                tail = re.match(r"\s*(by|without)\s*\(([^)]*)\)", expr[i + 1:])
                return (tail.group(1), tail.group(2)) if tail else (None, None)
    return None, None


def destroys_identity(op, kind, labels, label) -> bool:
    """Whether this aggregation removes `label` from the output series."""
    if (op, kind, labels) == WRAPPER:
        return False
    if kind == "by":
        return label not in labels
    if kind == "without":
        return label in labels
    # No clause at all: every label is dropped, including the instance. For topk
    # the consequence is different (rows vanish rather than fuse) but the test is
    # the same one.
    return True


def panel_targets(builder):
    """[(title, is_loki, expr)] for every panel target the builder emitted."""
    out = []
    for element in builder.elements.values():
        if element["kind"] != "Panel":
            continue
        title = element["spec"]["title"]
        for query in element["spec"]["data"]["spec"]["queries"]:
            spec = query["spec"]
            is_loki = spec["datasource"].get("type") == "loki"
            out.append((title, is_loki, spec["query"]["spec"]["expr"]))
    return out


def hidden_instance_tables(builder):
    """Titles of panels whose organize transform excludes the instance column."""
    out = []
    for element in builder.elements.values():
        if element["kind"] != "Panel":
            continue
        for transform in element["spec"]["data"]["spec"].get("transformations", []):
            options = transform.get("spec", {}).get("options", {})
            if options.get("excludeByName", {}).get(PROM_LABEL):
                out.append(element["spec"]["title"])
    return out


# ---- the two-instance fixture -------------------------------------------
# Names collide on purpose. Two independent OPNsense boxes really do both call an
# interface "LAN", both mount "/", both NAT 192.168.1.0/24 and both run a service
# called "unbound" — which is exactly why a merged row is indistinguishable from a
# legitimate single row, and why classification by eye cannot find this bug.
#
# One fixture per label space, NOT one carrying both identity labels: a Prometheus
# series really does carry `service_instance_id` (the query wrapper exists to strip
# it), so a shared fixture would keep two boxes apart via the OTHER label space's
# identity and pass a genuinely merging `without (opnsense_instance)` clause.
def _fixture(label):
    shared = {"interface": "LAN", "interface_description": "LAN", "mountpoint": "/",
              "host": "192.168.1.10", "protocol": "tcp", "source": "netflow",
              "counter": "state-mismatch"}
    return [{label: "fw-a", **shared}, {label: "fw-b", **shared}]


PROM_FIXTURE = _fixture(PROM_LABEL)
LOKI_FIXTURE = _fixture(LOKI_LABEL)


def output_series(samples, kind, labels):
    """The distinct output series an aggregation with this clause would produce."""
    keys = set()
    for sample in samples:
        if kind == "by":
            keys.add(tuple(sorted((k, sample[k]) for k in labels if k in sample)))
        elif kind == "without":
            keys.add(tuple(sorted((k, v) for k, v in sample.items() if k not in labels)))
        else:
            keys.add(())
    return keys


class InstanceIdentityTest(unittest.TestCase):
    # The WHOLE dashboard family, not `build_all()` (#597). `build_all()` returns the
    # MAIN dashboard's Builder alone, so no panel on `dashboard-health.json` — where 79
    # metrics live exclusively — was checked for instance identity at all, and the one
    # live offender behind that blind spot ("Plugins Installed But Not Scraped", a bare
    # `count()`) sat there passing every gate in the repo.
    #
    # Iterating `build_family()` rather than adding a second hardcoded builder is the
    # same shape of fix `coverage()` took in #431: the scan follows `DASHBOARDS`, so a
    # third dashboard is covered the day it is registered rather than the day someone
    # remembers this file exists. `test_the_scan_covers_every_dashboard_the_family_builds`
    # fails if that stops being true.
    @classmethod
    def setUpClass(cls):
        cls.built = build_dashboard.build_family()
        cls.builders = [b for _, b in cls.built]
        cls.targets_by_uid = {spec.uid: panel_targets(b) for spec, b in cls.built}
        # Flat, but carrying the uid: a failure message has to name the dashboard, or
        # the reader greps a title that exists on the other file.
        cls.targets = [(uid, title, is_loki, expr)
                       for uid, targets in cls.targets_by_uid.items()
                       for title, is_loki, expr in targets]

    def panels(self):
        """Every panel element across the family, as (uid, element)."""
        return [(spec.uid, element)
                for spec, b in self.built
                for element in b.elements.values()
                if element["kind"] == "Panel"]

    def _offenders(self, is_loki: bool):
        label = LOKI_LABEL if is_loki else PROM_LABEL
        found = {}
        for uid, title, loki, expr in self.targets:
            if loki is not is_loki or title in FLEET_TOTAL_PANELS:
                continue
            for op, kind, labels in aggregations(expr):
                if destroys_identity(op, kind, labels, label):
                    clause = f"{op} {kind or 'no-clause'}({','.join(sorted(labels))})"
                    found.setdefault(f"{title} [{uid}]", set()).add(clause)
        return {k: sorted(v) for k, v in found.items()}

    def test_the_scan_sees_a_realistic_number_of_targets(self):
        """Guards the guard. A structural change to the panel dict would otherwise
        make every assertion below vacuously pass on an empty scan."""
        self.assertGreater(len(self.targets), 900)
        self.assertTrue(any(loki for _, _, loki, _ in self.targets))
        self.assertTrue(any(tuple(aggregations(expr))
                            for _, _, _, expr in self.targets))

    def test_the_scan_covers_every_dashboard_the_family_builds(self):
        """The guard for the #597 bug itself: a fixture that silently sees less than
        the family builds.

        The floor above is family-WIDE, so it stayed comfortably true while an entire
        dashboard went unscanned — 1078 main-dashboard targets drown out 144 health
        ones. This is per dashboard and derived from `DASHBOARDS`, so narrowing the
        fixture back to one builder, or registering a third dashboard whose panels this
        scan cannot read, fails here instead of quietly halving the guard's reach.

        It also catches two specs sharing a uid, which would collapse `targets_by_uid`
        and hide one dashboard's panels behind the other's key — the same silent
        narrowing by a different route.
        """
        self.assertEqual(
            sorted(self.targets_by_uid),
            sorted(spec.uid for spec in build_dashboard.DASHBOARDS),
            "the instance-identity scan no longer covers every dashboard the family "
            "builds — every assertion in this file is blind to the missing one",
        )
        for uid, targets in self.targets_by_uid.items():
            with self.subTest(dashboard=uid):
                self.assertTrue(targets, f"{uid}: no panel targets scanned")
                self.assertTrue(
                    any(tuple(aggregations(expr)) for _, _, expr in targets),
                    f"{uid}: not one aggregation clause scanned, so every offender "
                    "assertion below is vacuous for this dashboard",
                )

    def test_the_query_wrapper_is_not_mistaken_for_a_merge(self):
        """The trap #425 named: every target is wrapped in `max without (job, ...)`,
        which PRESERVES the instance. If WRAPPER ever stops matching, this file
        would flag all ~970 targets and be switched off rather than fixed."""
        wrapped = [expr for _, _, loki, expr in self.targets if not loki]
        self.assertTrue(wrapped)
        for expr in wrapped[:50]:
            self.assertFalse(
                any(destroys_identity(op, kind, labels, PROM_LABEL)
                    for op, kind, labels in aggregations(expr)
                    if (op, kind, labels) == WRAPPER),
                f"wrapper treated as a merge in {expr}",
            )

    def test_no_prometheus_panel_aggregation_drops_instance_identity(self):
        self.assertEqual(self._offenders(is_loki=False), {})

    def test_no_logql_panel_aggregation_drops_instance_identity(self):
        self.assertEqual(self._offenders(is_loki=True), {})

    def _hidden(self):
        return {t for b in self.builders for t in hidden_instance_tables(b)}

    def test_no_table_hides_the_instance_column(self):
        hidden = sorted(t for t in self._hidden() if t not in TABLE_HIDE_EXCEPTIONS)
        self.assertEqual(hidden, [])

    def test_table_hide_exceptions_are_not_stale(self):
        """An exception left behind after a table is fixed blinds the check for a
        title that no longer offends — the same stale-allowlist mistake the
        bar-gauge and sentinel guards protect against."""
        self.assertEqual(set(TABLE_HIDE_EXCEPTIONS) - self._hidden(), set())

    def test_declared_fleet_totals_say_so_on_the_panel(self):
        """#425 criterion 3. Zero panels were labelled as fleet totals when the
        audit ran; a deliberate merge is only acceptable if the panel admits it."""
        missing = []
        for uid, element in self.panels():
            title = element["spec"]["title"]
            if title not in FLEET_TOTAL_PANELS:
                continue
            text = element["spec"].get("description", "") or ""
            if FLEET_TOTAL_PHRASE.lower() not in text.lower():
                missing.append(f"{title} [{uid}]")
        self.assertEqual(sorted(missing), [])

    def test_fleet_total_allowlist_is_not_stale(self):
        """Every allow-listed title must still exist AND still aggregate. A panel
        that gained a per-instance clause should leave the list, or the next reader
        believes a merge is happening that no longer is."""
        titles = {e["spec"]["title"] for _, e in self.panels()}
        self.assertEqual(set(FLEET_TOTAL_PANELS) - titles, set(),
                         "allowlisted panel titles that no longer exist")
        for title in FLEET_TOTAL_PANELS:
            exprs = [e for _, t, loki, e in self.targets if t == title and not loki]
            with self.subTest(title=title):
                self.assertTrue(
                    any(destroys_identity(op, kind, labels, PROM_LABEL)
                        for expr in exprs for op, kind, labels in aggregations(expr)),
                    "allowlisted as a fleet total but no longer aggregates away "
                    "the instance — remove the entry",
                )

    def test_no_alert_or_recording_rule_drops_instance_identity(self):
        """The rules were ALREADY correct when #468 landed — all 27 group-by clauses
        in `alerts/build_rules.py` name `opnsense_instance` and none aggregates
        bare. This pins that, because a rule is worse than a panel to get wrong: an
        alert that merges two firewalls fires with no way to tell which box is
        broken, and a recording rule bakes the merge into stored data.
        """
        sys.path.insert(0, str(GRAFANA_DIR / "alerts"))
        from alerts.build_rules import RECORDING, RULES  # noqa: PLC0415

        # An alert rule's PromQL lives under "A" (its Grafana query refId), NOT
        # "expr" — a first cut of this test looked for "expr" on both and silently
        # checked only the 14 recording rules while claiming to cover all 55.
        exprs = [(r["metric"], r["expr"]) for r in RECORDING]
        exprs += [(r["name"], r["A"]) for r in RULES]
        # Derived, not a hand-bumped literal (#597). This used to read
        # `assertEqual(len(exprs), 78)` with five lines of changelog, and every rule that
        # landed anywhere in the repo failed this file until someone edited a number they
        # had no reason to read. What the literal was actually protecting is narrow and
        # says so in its own comment: an emptied or half-read RULES/RECORDING would make
        # the offender scan below pass by having nothing to scan. Three assertions cover
        # that without a number that moves:
        #
        # * the sum proves BOTH lists were read — the shape bug the docstring records (a
        #   first cut looked for "expr" on both and silently checked only the 14 recording
        #   rules while claiming all 55) fails here, because 14 != 14 + 64;
        # * the floors break the circularity, so two empty lists cannot satisfy the sum.
        #   They are floors, not equalities, so a rule landing never touches this file.
        #
        # The EXACT counts are pinned deliberately in tests/test_runbooks.py
        # (test_exact_alert_count_is_64 / test_exact_recording_count_is_14), which owns
        # that number and carries its changelog, and test_build_rules.py checks the
        # emitted manifests against the same lists. A second copy here only ever meant
        # two files to bump for one change.
        self.assertEqual(len(exprs), len(RECORDING) + len(RULES))
        self.assertGreater(len(RULES), 50, "RULES looks emptied or truncated; the "
                                          "offender scan below would pass vacuously")
        self.assertGreater(len(RECORDING), 10, "RECORDING looks emptied or truncated; the "
                                              "offender scan below would pass vacuously")
        offenders = {
            name: f"{op} {kind or 'no-clause'}({','.join(sorted(labels))})"
            for name, expr in exprs
            for op, kind, labels in aggregations(expr)
            if destroys_identity(op, kind, labels, PROM_LABEL)
        }
        self.assertEqual(offenders, {})

    def test_two_instance_fixture_keeps_the_boxes_apart_in_every_clause(self):
        """The behavioural half of the guard, on names that COLLIDE across boxes.

        Every real aggregation clause in the built dashboard is applied to two
        appliances that share every other label value. A clause that retains
        identity yields two output series; a merging one yields a single fused
        series that looks exactly like one healthy box.
        """
        for uid, title, is_loki, expr in self.targets:
            if title in FLEET_TOTAL_PANELS:
                continue
            label = LOKI_LABEL if is_loki else PROM_LABEL
            fixture = LOKI_FIXTURE if is_loki else PROM_FIXTURE
            for op, kind, labels in aggregations(expr):
                if (op, kind, labels) == WRAPPER or kind is None:
                    continue
                with self.subTest(dashboard=uid, panel=title, clause=f"{op} {kind}"):
                    series = output_series(fixture, kind, labels)
                    self.assertEqual(
                        len(series), 2,
                        f"{title!r}: `{op} {kind} ({','.join(sorted(labels))})` fuses "
                        f"two appliances into one series; group by {label} as well",
                    )

    def test_the_fixture_would_catch_a_merge(self):
        """Negative control. If `output_series` returned two series for a clause
        that genuinely merges, the test above would pass on a broken dashboard."""
        self.assertEqual(len(output_series(PROM_FIXTURE, "by", {"interface"})), 1)
        self.assertEqual(len(output_series(PROM_FIXTURE, "by", {PROM_LABEL, "interface"})), 2)
        self.assertEqual(len(output_series(PROM_FIXTURE, "without", {PROM_LABEL})), 1)
        self.assertEqual(len(output_series(PROM_FIXTURE, None, ())), 1)
        self.assertEqual(len(output_series(LOKI_FIXTURE, "by", {"interface"})), 1)
        self.assertEqual(len(output_series(LOKI_FIXTURE, "by", {LOKI_LABEL})), 2)


if __name__ == "__main__":
    unittest.main()
