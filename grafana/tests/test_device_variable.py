"""Guard: the `$device` picker stays populated on a reduced-collector box (#424).

`$device` enumerates the kernel DEVICE-name label space (`igb0`, `ixl0_vlan25`,
`pppoe0`), which #98 established is DISJOINT from `$interface`'s description space
(`LAN`, `IOT`). #98 sourced it from a single pf-traffic counter, which is correct
about the label space and wrong about availability: every collector is
independently disableable, so a box running interface/flow/vnStat metrics with the
firewall collector off got an EMPTY device picker while device-bearing data sat
right there in the datasource. An empty picker is worse than a wrong one — 14
panels across three tabs filter on `interface=~"$device"`.

The replacement unions all five device-bearing sources, normalising the three that
label the device as `interface` into a `device` label, and groups by
`(opnsense_instance, device)` so no single collector is load-bearing and no two
appliances' device identities merge.

Two layers are tested:

* SHAPE — deterministic assertions on the shipped query string and variable spec.
* SEMANTICS — a Python mirror of the query's PromQL, *parsed out of the shipped
  query* rather than restated, evaluated against fixture series. Parsing it back
  is what stops the mirror from passing vacuously when the query changes: drop a
  source from the union and the fixture that only that source covers goes empty.
  No Prometheus engine is available to this suite (same constraint as the
  dead-hook mirror in test_build_rules.py).
"""

import re
import sys
import unittest
from pathlib import Path


GRAFANA_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GRAFANA_DIR))

import build_dashboard  # noqa: E402
from builder import INSTANCE_SEL  # noqa: E402


# The five device-bearing sources, split by the label each one ACTUALLY carries,
# verified against the collectors:
#   opnsense_firewall_in_ipv4_pass_packets_total  interface  collector/firewall.go:77-80
#   opnsense_netflow_cache_packets_total          interface  collector/netflow.go:86-89
#   opnsense_vnstat_bytes_total                   interface  collector/vnstat.go:37,45-48
#   opnsense_interfaces_info                      device     collector/interfaces.go:148-151
#   opnsense_flow_interface_info                  device     collector/flow.go:554,568
# Hardcoded on purpose. This is an INVENTORY: a source quietly dropping out of the
# union is exactly what it exists to fail on, so importing the list from
# build_dashboard would restate the source and assert nothing about it.
INTERFACE_LABELLED_SOURCES = (
    "opnsense_firewall_in_ipv4_pass_packets_total",
    "opnsense_netflow_cache_packets_total",
    "opnsense_vnstat_bytes_total",
)
DEVICE_LABELLED_SOURCES = (
    "opnsense_interfaces_info",
    "opnsense_flow_interface_info",
)
ALL_SOURCES = INTERFACE_LABELLED_SOURCES + DEVICE_LABELLED_SOURCES

GROUP_KEYS = ("opnsense_instance", "device")


def device_variable() -> dict:
    builder = build_dashboard.build_all()
    for variable in builder.variables:
        if variable["spec"]["name"] == "device":
            return variable["spec"]
    raise AssertionError("no $device variable in the built dashboard")


def device_query() -> str:
    return device_variable()["query"]["spec"]["query"]


# ---- Python mirror of the shipped query ----------------------------------

QUERY_RESULT_RE = re.compile(r"^query_result\((?P<inner>.+)\)$", re.DOTALL)
GROUP_BY_RE = re.compile(r"^group by \((?P<labels>[^()]*)\)\s*\((?P<inner>.+)\)$", re.DOTALL)
LABEL_JOIN_RE = re.compile(
    r'^label_join\((?P<inner>.+),\s*"(?P<dst>[^"]*)",\s*"(?P<sep>[^"]*)",\s*"(?P<src>[^"]*)"\)$',
    re.DOTALL,
)
SELECTOR_RE = re.compile(
    r"^(?P<metric>[a-zA-Z_:][a-zA-Z0-9_:]*)\{(?P<matchers>.*)\}$", re.DOTALL
)
MATCHER_RE = re.compile(
    r'^(?P<label>[a-zA-Z_][a-zA-Z0-9_]*)(?P<op>=~|!~|!=|=)"(?P<value>.*)"$', re.DOTALL
)


def _split_top_level(text: str, separator: str) -> list[str]:
    """Split on `separator` at bracket depth 0 and outside double quotes."""
    parts: list[str] = []
    depth = quoted = 0
    start = index = 0
    while index < len(text):
        char = text[index]
        if quoted:
            if char == '"':
                quoted = 0
            index += 1
            continue
        if char == '"':
            quoted = 1
        elif char in "({[":
            depth += 1
        elif char in ")}]":
            depth -= 1
        elif depth == 0 and text.startswith(separator, index):
            parts.append(text[start:index])
            index += len(separator)
            start = index
            continue
        index += 1
    parts.append(text[start:])
    return parts


def _parse_matchers(text: str) -> list[tuple[str, str, str]]:
    matchers = []
    for raw in _split_top_level(text, ","):
        raw = raw.strip()
        if not raw:
            continue
        match = MATCHER_RE.match(raw)
        if not match:
            raise AssertionError(f"unparseable label matcher {raw!r}")
        matchers.append((match.group("label"), match.group("op"), match.group("value")))
    return matchers


def _parse_operand(text: str) -> dict:
    join = None
    match = LABEL_JOIN_RE.match(text)
    if match:
        join = (match.group("dst"), match.group("sep"), match.group("src"))
        text = match.group("inner").strip()
    selector = SELECTOR_RE.match(text)
    if not selector:
        raise AssertionError(f"union operand {text!r} is not a plain metric selector")
    return {
        "metric": selector.group("metric"),
        "matchers": _parse_matchers(selector.group("matchers")),
        "join": join,
    }


def parse_device_query(query: str) -> tuple[tuple[str, ...], list[dict]]:
    """Shipped query -> (group-by labels, union operands).

    Raises AssertionError with the offending query when the shipped variable is
    not the bounded `query_result(group by (...) (... or ...))` union form — which
    is the pre-#424 single-metric `label_values(...)` failure, stated in full
    rather than surfacing as an opaque None.
    """
    outer = QUERY_RESULT_RE.match(query.strip())
    if not outer:
        raise AssertionError(
            "$device is not a bounded query_result(...) union; a single-source "
            f"variable cannot survive a disabled collector (#424): {query!r}"
        )
    grouped = GROUP_BY_RE.match(outer.group("inner").strip())
    if not grouped:
        raise AssertionError(
            "$device query_result(...) is not grouped by (opnsense_instance, device); "
            f"two appliances' device identities would merge (#424): {query!r}"
        )
    labels = tuple(part.strip() for part in grouped.group("labels").split(","))
    operands = [
        _parse_operand(part.strip())
        for part in _split_top_level(grouped.group("inner").strip(), " or ")
    ]
    return labels, operands


def _instance_regex(selected) -> str:
    """Grafana's regex-context interpolation of $opnsense_instance: the All value
    `.+` when nothing is narrowed, `(a|b)` for a multi-select, bare for one."""
    if selected is None:
        return ".+"
    if len(selected) == 1:
        return selected[0]
    return "(" + "|".join(selected) + ")"


def _matches(labels: dict, matchers, selected) -> bool:
    for label, operator, value in matchers:
        value = value.replace("$opnsense_instance", _instance_regex(selected))
        actual = labels.get(label, "")
        if operator == "=":
            ok = actual == value
        elif operator == "!=":
            ok = actual != value
        elif operator == "=~":
            ok = re.fullmatch(value, actual) is not None
        else:
            ok = re.fullmatch(value, actual) is None
        if not ok:
            return False
    return True


def grouped_rows(query: str, series, selected=None) -> list[dict]:
    """Evaluate the shipped query over `series` at one instant.

    `series` is [(metric_name, labels), ...]. Mirrors, in order: per-operand
    selector matching, label_join, the `or` set union (a right-hand series is
    dropped only when a left-hand one carries an IDENTICAL label set sans
    __name__, so the union can never lose a device), and `group by`, which drops
    every other label and dedupes.
    """
    group_labels, operands = parse_device_query(query)
    seen_signatures = set()
    joined: list[dict] = []
    for operand in operands:
        for metric, labels in series:
            if metric != operand["metric"]:
                continue
            if not _matches(labels, operand["matchers"], selected):
                continue
            out = dict(labels)
            if operand["join"]:
                destination, separator, source = operand["join"]
                out[destination] = separator.join([labels.get(source, "")])
            signature = frozenset(out.items())
            if signature in seen_signatures:
                continue
            seen_signatures.add(signature)
            joined.append(out)

    rows: list[dict] = []
    for labels in joined:
        # An empty label value is indistinguishable from an absent one in
        # Prometheus, so `group by` yields a row without that label.
        row = {key: labels[key] for key in group_labels if labels.get(key, "") != ""}
        if row not in rows:
            rows.append(row)
    return rows


def _js_regex_body(variable_regex: str) -> str:
    """Grafana's stringToJsRegex: a `/…/flags` literal is used as written, a bare
    string is anchored `^…$` (which would never match inside a series string)."""
    if not variable_regex.startswith("/"):
        return "^" + variable_regex + "$"
    match = re.match(r"^/(?P<body>.*)/(?P<flags>[gimsy]*)$", variable_regex, re.DOTALL)
    if not match:
        raise AssertionError(f"{variable_regex!r} is not a valid JS regex literal")
    return match.group("body")


def picker_options(query: str, variable_regex: str, series, selected=None) -> list[str]:
    """Full mirror through to the option list an operator sees: `query_result`
    row formatting, the variable regex capture, uniq-by-value, alphabeticalAsc."""
    pattern = re.compile(_js_regex_body(variable_regex))
    values: list[str] = []
    for row in grouped_rows(query, series, selected):
        text = "{" + ",".join(f'{k}="{v}"' for k, v in row.items()) + "} 1 1753600000000"
        match = pattern.search(text)
        if not match:
            continue
        value = match.group(1) if match.groups() else match.group(0)
        if value not in values:
            values.append(value)
    return sorted(values)


# ---- fixtures ------------------------------------------------------------

JOB = "integrations/opnsense"
TARGET = "10.0.0.1:8080"


def series_for(instance, *, pf=(), netflow=(), vnstat=(), overview=(), ifmap=()):
    """Fixture series for one exporter instance.

    `overview` and `ifmap` are (description, device) / (description, device,
    ifindex): both carry the description in `interface` and the kernel name in
    `device`, which is the whole reason they can back the picker at all.
    """
    out = []
    base = {"opnsense_instance": instance, "job": JOB, "instance": TARGET}
    for device in pf:
        out.append(("opnsense_firewall_in_ipv4_pass_packets_total",
                    {**base, "interface": device}))
    for device in netflow:
        out.append(("opnsense_netflow_cache_packets_total", {**base, "interface": device}))
    for device in vnstat:
        for direction in ("rx", "tx"):
            out.append(("opnsense_vnstat_bytes_total",
                        {**base, "interface": device, "direction": direction}))
    for description, device in overview:
        out.append(("opnsense_interfaces_info",
                    {**base, "interface": description, "device": device,
                     "identifier": description.lower(), "media": "1000baseT <full-duplex>",
                     "link_type": "ethernet", "vlan_tag": "", "vlan_parent": "",
                     "physical": "true"}))
    for description, device, ifindex in ifmap:
        out.append(("opnsense_flow_interface_info",
                    {**base, "interface": description, "device": device,
                     "ifindex": ifindex}))
    return out


# A box with every collector on. pf covers all three devices, so this is exactly
# the set the pre-#424 pf-only variable produced — the no-regression baseline.
FULL_COLLECTOR = series_for(
    "fw1",
    pf=("igb0", "igb1", "pppoe0"),
    netflow=("igb0", "pppoe0"),
    vnstat=("igb0", "igb1", "pppoe0"),
    overview=(("LAN", "igb0"), ("IOT", "igb1"), ("AAISP", "pppoe0")),
    ifmap=(("LAN", "igb0", "1"), ("AAISP", "pppoe0", "7")),
)
FULL_COLLECTOR_DEVICES = ["igb0", "igb1", "pppoe0"]

# The supported configuration #424 is about: --exporter.disable-firewall (and no
# NetFlow plugin), interface/flow/vnStat data present.
FIREWALL_DISABLED = series_for(
    "fw1",
    vnstat=("igb0", "igb1", "pppoe0"),
    overview=(("LAN", "igb0"), ("IOT", "igb1"), ("AAISP", "pppoe0")),
    ifmap=(("LAN", "igb0", "1"), ("AAISP", "pppoe0", "7")),
)


class DeviceVariableShapeTest(unittest.TestCase):
    def setUp(self):
        self.spec = device_variable()
        self.query = self.spec["query"]["spec"]["query"]

    def test_every_device_bearing_source_is_in_the_union(self):
        _, operands = parse_device_query(self.query)
        self.assertEqual(sorted(o["metric"] for o in operands), sorted(ALL_SOURCES))

    def test_every_source_metric_still_exists(self):
        """A union is exactly as fault-tolerant as it is silent: an operand naming
        a metric that no longer exists matches nothing, the other four still
        answer, and the picker looks fine while one collector has quietly stopped
        contributing. That is #424's own failure mode wearing a different hat.

        #464 renamed opnsense_vnstat_total_bytes -> opnsense_vnstat_bytes_total
        mid-flight and every other test in this file stayed green, which is what
        motivated this one. The catalogue (docs/metrics/metrics.md) is generated
        from the registered descriptors, so it is the authority on what exists."""
        catalogue = set(build_dashboard.load_catalogue())
        self.assertTrue(catalogue, "metric catalogue is empty - extractor is broken")
        missing = sorted(metric for metric in ALL_SOURCES if metric not in catalogue)
        self.assertEqual(
            [], missing,
            f"$device union names {len(missing)} metric(s) the exporter does not "
            f"export: {missing}. A renamed or removed source is a SILENT operand.",
        )
        # And the shipped query must name the same set the inventory does, so a
        # rename applied to only one of the two still fails.
        _, operands = parse_device_query(self.query)
        self.assertEqual(sorted(o["metric"] for o in operands), sorted(ALL_SOURCES))

    def test_the_interface_labelled_sources_are_normalised_to_device(self):
        _, operands = parse_device_query(self.query)
        by_metric = {o["metric"]: o for o in operands}
        for metric in INTERFACE_LABELLED_SOURCES:
            with self.subTest(metric=metric):
                self.assertEqual(by_metric[metric]["join"], ("device", "", "interface"))

    def test_the_device_labelled_sources_are_taken_as_they_are(self):
        _, operands = parse_device_query(self.query)
        by_metric = {o["metric"]: o for o in operands}
        for metric in DEVICE_LABELLED_SOURCES:
            with self.subTest(metric=metric):
                self.assertIsNone(by_metric[metric]["join"])

    def test_the_device_labelled_sources_exclude_an_empty_device(self):
        # opnsense_flow_interface_info deliberately publishes ifmap entries whose
        # device is unknown (collector/flow.go:780-784) so an operator can SEE
        # them. They must not become a blank picker entry.
        _, operands = parse_device_query(self.query)
        by_metric = {o["metric"]: o for o in operands}
        for metric in DEVICE_LABELLED_SOURCES:
            with self.subTest(metric=metric):
                self.assertIn(("device", "!=", ""), by_metric[metric]["matchers"])

    def test_grouping_keeps_the_appliance_alongside_the_device(self):
        group_labels, _ = parse_device_query(self.query)
        self.assertEqual(group_labels, GROUP_KEYS)

    def test_every_union_operand_is_scoped_to_the_selected_instance(self):
        # The instance-scoping contract from #413/#414: the variable's own query
        # is scoped, and every operand of a union counts.
        _, operands = parse_device_query(self.query)
        for operand in operands:
            with self.subTest(metric=operand["metric"]):
                self.assertIn(
                    ("opnsense_instance", "=~", "$opnsense_instance"),
                    operand["matchers"],
                )
        self.assertEqual(self.query.count(INSTANCE_SEL), len(ALL_SOURCES))

    def test_the_query_is_bounded(self):
        # No range selector, no regex metric matcher (which would scan the whole
        # datasource), and a two-label grouping - so the result is one series per
        # (appliance, device) at one instant. Forbidding "[" also rules out
        # Grafana's legacy [[variable]] syntax, which templateSrv would expand
        # inside the expression.
        group_labels, operands = parse_device_query(self.query)
        self.assertEqual(len(group_labels), 2)
        self.assertNotIn("[", self.query)
        for operand in operands:
            with self.subTest(metric=operand["metric"]):
                self.assertNotIn("__name__", [m[0] for m in operand["matchers"]])

    def test_the_regex_captures_exactly_the_device_label_value(self):
        # query_result rows arrive as `{device="igb0",...} 1 <ms>`, so the
        # variable needs a capturing regex literal; a bare string would be
        # anchored ^…$ by Grafana and match nothing.
        regex = self.spec["regex"]
        self.assertTrue(regex.startswith("/"), regex)
        pattern = re.compile(_js_regex_body(regex))
        self.assertEqual(pattern.groups, 1)
        self.assertEqual(
            pattern.search('{device="igb0",opnsense_instance="fw1"} 1 1753600000000').group(1),
            "igb0",
        )
        self.assertIsNone(pattern.search('{opnsense_instance="fw1"} 1 1753600000000'))

    def test_multi_select_and_all_regex_behaviour_is_unchanged(self):
        self.assertTrue(self.spec["multi"])
        self.assertTrue(self.spec["includeAll"])
        self.assertEqual(self.spec["allValue"], ".+")
        self.assertEqual(self.spec["sort"], "alphabeticalAsc")
        self.assertEqual(self.spec["hide"], "dontHide")
        self.assertEqual(self.spec["current"], {"text": "All", "value": "$__all"})


class DeviceVariableSemanticsTest(unittest.TestCase):
    def setUp(self):
        self.spec = device_variable()
        self.query = self.spec["query"]["spec"]["query"]
        self.regex = self.spec["regex"]

    def options(self, series, selected=None):
        return picker_options(self.query, self.regex, series, selected)

    def test_firewall_disabled_still_populates_the_picker(self):
        # THE #424 regression. Pre-fix this variable was
        # label_values(opnsense_firewall_in_ipv4_pass_packets_total{...}, interface)
        # and this fixture produced an empty picker, blanking 14 panels.
        self.assertEqual(self.options(FIREWALL_DISABLED), FULL_COLLECTOR_DEVICES)

    def test_interfaces_collector_alone_populates_the_picker(self):
        interfaces_only = series_for(
            "fw1", overview=(("LAN", "igb0"), ("IOT", "igb1"), ("AAISP", "pppoe0")))
        self.assertEqual(self.options(interfaces_only), FULL_COLLECTOR_DEVICES)

    def test_full_collector_values_are_exactly_what_the_pf_only_source_gave(self):
        self.assertEqual(self.options(FULL_COLLECTOR), FULL_COLLECTOR_DEVICES)

    def test_a_consistent_box_gains_no_extra_or_duplicated_value(self):
        # Five sources agreeing on the device set must still yield each device
        # once: `or` unions on full label sets and `group by` collapses the rest,
        # so the same device arriving from five collectors is one option.
        options = self.options(FULL_COLLECTOR)
        self.assertEqual(len(options), len(set(options)))
        pf_only = sorted({
            labels["interface"] for metric, labels in FULL_COLLECTOR
            if metric == "opnsense_firewall_in_ipv4_pass_packets_total"
        })
        self.assertEqual(options, pf_only)
        # The description space never leaks in - the whole point of #98.
        for description in ("LAN", "IOT", "AAISP"):
            self.assertNotIn(description, options)

    def test_a_device_only_the_overview_knows_about_is_deliberately_listed(self):
        # The union is a SUPERSET by construction, and this is the intended
        # behaviour rather than a leak: an interface the box knows about but which
        # passes no traffic (admin-down, no pf counters) is now selectable, where
        # the pf-only source hid it. Its pf panels then read No data for that
        # selection - the same deal $interface has always offered, since
        # opnsense_interfaces_link_state covers every interface regardless of
        # traffic. Recorded as a test so it is a decision, not a surprise.
        with_idle = FULL_COLLECTOR + series_for("fw1", overview=(("SPARE", "igb2"),))
        self.assertEqual(self.options(with_idle), sorted(FULL_COLLECTOR_DEVICES + ["igb2"]))

    def test_no_single_source_is_load_bearing(self):
        for dropped in ALL_SOURCES:
            with self.subTest(without=dropped):
                reduced = [(m, l) for m, l in FULL_COLLECTOR if m != dropped]
                self.assertEqual(self.options(reduced), FULL_COLLECTOR_DEVICES)

    def test_an_unknown_device_never_becomes_a_blank_option(self):
        with_unmapped = FULL_COLLECTOR + series_for("fw1", ifmap=(("", "", "9"),))
        self.assertEqual(self.options(with_unmapped), FULL_COLLECTOR_DEVICES)

    def test_two_appliances_sharing_a_device_name_stay_distinct(self):
        fleet = series_for("fw1", pf=("igb0",), overview=(("LAN", "igb0"),)) + \
            series_for("fw2", pf=("igb0", "ix0"),
                       overview=(("LAN", "igb0"), ("WAN", "ix0")))
        rows = grouped_rows(self.query, fleet)
        self.assertEqual(
            sorted((row["opnsense_instance"], row["device"]) for row in rows),
            [("fw1", "igb0"), ("fw2", "igb0"), ("fw2", "ix0")],
        )
        # The picker itself is a flat list of device names, exactly as the
        # pre-#424 label_values() was, so a shared name shows once.
        self.assertEqual(self.options(fleet), ["igb0", "ix0"])

    def test_selecting_one_appliance_excludes_the_others_devices(self):
        fleet = series_for("fw1", pf=("igb0",), overview=(("LAN", "igb0"),)) + \
            series_for("fw2", pf=("igb0", "ix0"),
                       overview=(("LAN", "igb0"), ("WAN", "ix0")))
        self.assertEqual(self.options(fleet, selected=["fw1"]), ["igb0"])
        self.assertEqual(self.options(fleet, selected=["fw2"]), ["igb0", "ix0"])
        self.assertEqual(self.options(fleet, selected=["fw1", "fw2"]), ["igb0", "ix0"])

    def test_a_box_with_no_device_bearing_data_yields_an_empty_picker(self):
        # Guards the guard: the mirror must be capable of returning nothing, or
        # every assertion above passes for the wrong reason.
        self.assertEqual(self.options(series_for("fw1")), [])


class DeviceConsumerContractTest(unittest.TestCase):
    """Every panel that filters on `$device` must do so through the `interface`
    label - `$device` holds kernel device names, and the two label spaces never
    overlap (#98). The variable now READS a `device` label from two sources, which
    is exactly the confusion that could push a panel onto the wrong one."""

    def test_every_device_consumer_filters_the_interface_label(self):
        builder = build_dashboard.build_all()
        consumers = [expr for expr in builder._exprs if "$device" in expr]
        self.assertGreaterEqual(len(consumers), 14)
        for expr in consumers:
            with self.subTest(expr=expr[:80]):
                self.assertIn('interface=~"$device"', expr)
                self.assertNotIn('device=~"$device"', expr)


if __name__ == "__main__":
    unittest.main()
