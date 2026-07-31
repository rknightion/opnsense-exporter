"""Guard: every PromQL series selector is scoped to an identity (#600).

`test_instance_identity.py` guards the AGGREGATION half — a `sum`/`count`/`max`
whose by/without clause drops the instance label. This is the SELECTOR half: an
expression with no instance matcher at all is not a merge, so the aggregation
scan cannot see it, and until #600 nothing else looked.

`test_loki_scoping.py`'s docstring asserts the premise this file enforces:

    The Prometheus side has one chokepoint (`sel()`), so a panel cannot forget
    the instance matcher. LogQL had none [...]

True by convention, unenforced in fact. A hand-written f-string matcher is
indistinguishable from a `sel()` call in review, which is exactly how the #597
finding got in.

#597 found it by LUCK OF ITS SHAPE, which is the argument for this file. The
"Plugins Installed But Not Scraped" tile was a bare `count(...)` with no by
clause, so the merge scan caught it. Written `count by (opnsense_instance)
(opnsense_feature_available{enabled="false"})` it would have had a
correct-looking aggregation over an unscoped selector, passed every check in the
repo, and still counted boxes `$opnsense_instance` does not select.

## Two legitimate scoping regimes, not one

The naive rule — "every selector carries `opnsense_instance`" — is WRONG, and
enforcing it would reintroduce #591's headline bug (a perfect query against data
that does not exist). Measured against the built family:

* **1208 selectors on `opnsense_*` / `instance:opnsense*`** (the exporter's own
  metrics and the recording rules derived from them). These carry
  `opnsense_instance`, so they MUST match the variable or the panel shows boxes
  the operator did not pick.
* **14 selectors on `go_*`, `process_*` and `up`.** These come from Prometheus's
  standard Go and process collectors, not from this exporter's instrumentation,
  so the series **do not carry `opnsense_instance` at all** and a matcher on it
  would select nothing. They are scoped `job=~"opnsense.*"` instead.

Identity still survives for the second group, which is why `job` scoping is
sufficient rather than merely tolerated: `WRAPPER` is `max without (job,
service_instance_id, service_name, service_version)` (`builder.py:167`), and
`instance` is NOT in that list — so two exporter processes stay two series,
keyed by the scrape target address.

The accepted limitation, stated rather than hidden: the second group cannot be
filtered by `$opnsense_instance`, because the label does not exist on those
series. Selecting one firewall still shows every exporter's runtime metrics.
That is a property of the upstream collectors, not a bug this gate can fix, and
it is the same boundary `RUNTIME_METRIC_LEDGER` records in `build_dashboard.py`.

So the rule this file enforces is: **an `opnsense`-namespace selector carries the
`opnsense_instance` matcher; anything else carries a `job` matcher.** A firewall
metric scoped by `job` alone is a real bug (it ignores the picker), which is why
the two regimes are keyed on the metric name and not merged into "either will
do".
"""

import re
import sys
import unittest
from pathlib import Path


GRAFANA_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GRAFANA_DIR))

import build_dashboard  # noqa: E402


# Spelled out rather than imported from builder: this is the contract the
# dashboards owe the datasource, and a test that imports the constant it checks
# cannot fail when that constant changes. Same reasoning as test_loki_scoping.
INSTANCE_MATCHER = re.compile(r'opnsense_instance\s*=~?')
JOB_MATCHER = re.compile(r'\bjob\s*=~?')

# Selectors deliberately left unscoped, each with its reason. EMPTY BY DESIGN:
# every selector in the family is scoped through `sel()` or a job matcher today,
# so there is no structural reason for an exception. An entry here means a panel
# knowingly reads series it cannot attribute to an appliance — say why.
#
# Keyed "<panel title>::<metric name>" so an exception cannot silently widen to
# every selector in a panel, or to every panel using a metric.
PROM_SCOPE_EXCEPTIONS: dict[str, str] = {}


def selectors(expr: str) -> list[tuple[str, str]]:
    """[(metric_name, selector_text)] for every `{...}` in a PromQL expression.

    Brace-matching rather than a regex because a label value can legally contain
    a brace (`opnsense_x{re=~".*\\{.*"}`), and quote-aware because it can contain
    an escaped quote. Returns the metric name preceding each selector, which is
    what decides WHICH scoping rule applies — the whole point of the check.
    """
    out: list[tuple[str, str]] = []
    i = 0
    while True:
        start = expr.find("{", i)
        if start == -1:
            return out
        depth = 0
        quoted = False
        for j in range(start, len(expr)):
            char = expr[j]
            if char == '"' and expr[j - 1] != "\\":
                quoted = not quoted
            if quoted:
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    name = re.search(r"([A-Za-z_:][A-Za-z0-9_:]*)$", expr[:start])
                    out.append((name.group(1) if name else "", expr[start:j + 1]))
                    i = j + 1
                    break
        else:
            # Unbalanced braces: return what was parsed. The vacuity guard below
            # is what catches a parser that silently stops seeing selectors.
            return out


def unscoped(metric: str, selector: str) -> str:
    """"" if the selector is correctly scoped, else why it is not.

    The two regimes are ASYMMETRIC, and the asymmetry is the whole rule:

    * An `opnsense`-namespace metric must carry `opnsense_instance` specifically.
      A `job` matcher is NOT sufficient there — it returns data and keeps the
      label, so nothing looks merged, while silently ignoring the
      `$opnsense_instance` picker. That is the #597 bug.
    * Anything else may carry EITHER. `job` is the normal answer for `go_*` and
      `process_*`, which cannot carry `opnsense_instance` at all. But `up` is a
      genuine mixed case: it is emitted over OTLP with instance as a CONST label,
      so `up{opnsense_instance=~"..."}` is correctly scoped too, and the shipped
      panel is an `or` of one selector per regime. An earlier version of this
      rule demanded `job` for every non-namespace metric and rejected that half —
      the negative control below is what caught it.
    """
    if "opnsense" in metric:
        if not INSTANCE_MATCHER.search(selector):
            return f"{metric}: no opnsense_instance matcher (bypassed sel()?)"
        return ""
    if not (JOB_MATCHER.search(selector) or INSTANCE_MATCHER.search(selector)):
        return f"{metric}: no job or opnsense_instance matcher"
    return ""


class PromScoping(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.built = build_dashboard.build_family()
        cls.targets = [
            (spec.uid, element["spec"]["title"], query["spec"]["query"]["spec"]["expr"])
            for spec, builder in cls.built
            for element in builder.elements.values()
            if element["kind"] == "Panel"
            for query in element["spec"]["data"]["spec"]["queries"]
            if query["spec"]["datasource"].get("type") != "loki"
        ]

    def test_every_prometheus_selector_is_scoped(self):
        """The gate. An `opnsense`-namespace selector carries the instance matcher;
        anything else carries a job matcher.

        Landed with an EMPTY exception ledger — this is a regression fence, not a
        cleanup. Every offender it would have reported was fixed before it existed
        (#597's `feature_unscraped` was the last one).
        """
        offenders = {}
        for uid, title, expr in self.targets:
            for metric, selector in selectors(expr):
                if PROM_SCOPE_EXCEPTIONS.get(f"{title}::{metric}"):
                    continue
                why = unscoped(metric, selector)
                if why:
                    offenders.setdefault(f"{uid} / {title}", []).append(why)
        self.assertEqual(offenders, {})

    def test_the_check_catches_an_unscoped_firewall_metric(self):
        """Negative control: the gate above passing must mean something.

        A firewall metric scoped by `job` alone is the subtle case — it returns
        data, keeps `opnsense_instance` as a label so nothing looks merged, and
        silently ignores the `$opnsense_instance` picker. If this stops failing,
        the rule has collapsed into "any matcher will do" and the gate is decoration.
        """
        self.assertTrue(unscoped("opnsense_feature_available", '{enabled="false"}'))
        self.assertTrue(unscoped("opnsense_feature_available", '{job=~"opnsense.*"}'))
        self.assertFalse(
            unscoped("opnsense_feature_available",
                     '{opnsense_instance=~"$opnsense_instance",enabled="false"}'))

    def test_the_check_catches_an_unscoped_runtime_metric(self):
        """Negative control for the other regime, and for its boundary.

        `go_goroutines` cannot carry `opnsense_instance`, so requiring it there
        would be #591's bug. Requiring NOTHING there would let a genuinely
        fleet-wide runtime selector through. The rule is `job`, and this pins it.
        """
        self.assertTrue(unscoped("go_goroutines", "{}"))
        self.assertFalse(unscoped("go_goroutines", '{job=~"opnsense.*"}'))
        # `up` is the mixed case: one selector per regime, joined by `or`. Each
        # side is checked independently, so neither can carry the other.
        self.assertFalse(unscoped("up", '{job=~"opnsense.*"}'))
        self.assertFalse(unscoped("up", '{opnsense_instance=~"$opnsense_instance"}'))

    def test_the_selector_parser_still_sees_selectors(self):
        """Vacuity guard: every assertion here is over `selectors()` output, so a
        parser that quietly stops matching turns the gate green while checking
        nothing. That failure mode IS #597, one layer down.

        Floors, not equalities, so a landing panel never edits this file. The
        runtime floor is what stops the `go_*`/`process_*`/`up` regime from
        vanishing unnoticed and taking its half of the rule with it.
        """
        found = [(m, s) for _, _, expr in self.targets for m, s in selectors(expr)]
        self.assertGreater(len(self.targets), 900, "prom targets not scanned")
        self.assertGreater(len(found), 900, "no selectors parsed out of the family")
        self.assertGreater(
            sum(1 for m, _ in found if "opnsense" in m), 900,
            "the opnsense-namespace regime has no selectors to check")
        self.assertGreater(
            sum(1 for m, _ in found if "opnsense" not in m), 5,
            "the runtime regime has no selectors to check")
        self.assertFalse([m for m, _ in found if not m],
                         "a selector with no leading metric name cannot be routed "
                         "to either regime — decide which rule applies")

    def test_the_parser_survives_a_brace_in_a_label_value(self):
        """Why brace-matching rather than a regex. A greedy or non-greedy regex
        both mis-split this, and a mis-split selector loses its matcher and reads
        as an offender — a FALSE positive would get this gate weakened.
        """
        expr = 'opnsense_x{opnsense_instance=~"$opnsense_instance",re=~".*\\{.*"} + 1'
        self.assertEqual(len(selectors(expr)), 1)
        self.assertEqual(unscoped(*selectors(expr)[0]), "")


if __name__ == "__main__":
    unittest.main()
