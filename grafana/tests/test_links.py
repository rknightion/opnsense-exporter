"""Guard: dashboard and panel navigation is generated from one frozen registry (#419).

A link is the one dashboard element that can be *confidently wrong*. A panel with no
data reads "No data" and an operator distrusts it; a link that resolves to a 404, or
to the right dashboard with the wrong instance selected, looks like it worked. The
responder then compares two firewalls, or two time windows, and believes the
comparison.

So navigation is built rather than written, and this file is the contract:

1. **Every destination comes from `uids.py`.** A UID is never typed at a call site,
   the three retired UIDs can never reappear, and a destination that does not exist
   yet (`opnsense-exporter-health`, #431) emits no link at all — the registry's
   `exists` flag is what stops us shipping a link to a 404.
2. **Every internal link carries context.** Time range, selected instance, and the
   datasource travel with the click; a link that drops one of them is the silent
   failure this issue exists to prevent.
3. **Nothing stack-specific is embedded.** No hostname, no datasource UID, no
   absolute Grafana URL — the dashboard is imported by strangers.
4. **A field link may only template a label its own panel returns.** `${__field.
   labels.interface}` on a panel whose query never keeps `interface` interpolates to
   nothing and silently navigates with an empty variable.
5. **Tab targeting matches the layout.** A `dtab` slug is derived from the tab titles
   this build actually produced, so renaming a tab breaks the build instead of the
   link.
"""

import json
import re
import sys
import unittest
from pathlib import Path
from urllib.parse import parse_qsl, quote, unquote, urlsplit

GRAFANA_DIR = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(GRAFANA_DIR))

import build_dashboard  # noqa: E402
import uids  # noqa: E402


# The five panel families #419 requires drilldowns on, spelled out panel by panel
# rather than matched by substring: a family satisfied by "some panel somewhere"
# regresses invisibly the moment that one panel is renamed or deleted.
REQUIRED_DRILLDOWN_PANELS = {
    # interface
    "Interface RX Throughput": "interface",
    "Interface TX Throughput": "interface",
    "Interface Errors": "interface",
    "Link State": "interface",
    # firewall
    "Inbound Pass Packets/s": "firewall",
    "Outbound Block Packets/s": "firewall",
    "Recent Firewall Log Entries per Interface": "firewall",
    # flow
    "Throughput by Interface (bits/sec)": "flow",
    "Packet Rate by Interface & Direction": "flow",
    # gateway / HA
    "Gateway Status": "gateway",
    "Gateway RTT": "gateway",
    "CARP VIP Status": "gateway",
    # log shipping
    "Records Shipped (rate)": "logship",
    "Sink Errors (rate)": "logship",
}

REQUIRED_FAMILIES = {"interface", "firewall", "flow", "gateway", "logship"}

# Anything that looks like somebody's Grafana rather than the reader's.
STACK_SPECIFIC = re.compile(
    r"grafanacloud-|grafana\.net|grafana\.com/orgs|\.m7kni\.|localhost:3000|https?://[^/]*grafana")


def build():
    return build_dashboard.build_all()


def manifest(b):
    return b.manifest(title="t", description="d", tags=[])


def all_links(spec):
    """Yield (where, panel_title_or_None, link_dict) for every DataLink in a spec."""
    for link in spec.get("links", []):
        yield "dashboard", None, link
    for element in spec["elements"].values():
        pspec = element["spec"]
        title = pspec["title"]
        for link in pspec.get("links", []):
            yield "panel", title, link
        defaults = pspec["vizConfig"]["spec"].get("fieldConfig", {}).get("defaults", {})
        for link in defaults.get("links", []):
            yield "field", title, link


def panel_exprs(pspec):
    out = []
    for query in pspec["data"]["spec"]["queries"]:
        out.append(query["spec"]["query"]["spec"].get("expr", ""))
    return out


class LinkRegistryTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.b = build()
        cls.spec = manifest(cls.b)["spec"]
        cls.links = list(all_links(cls.spec))
        cls.blob = json.dumps(cls.spec)

    # ---- registry ------------------------------------------------------
    def test_links_exist_at_all(self):
        self.assertTrue(self.links, "the dashboard generates no links (#419)")

    def test_every_internal_link_targets_an_existing_registered_destination(self):
        for where, title, link in self.links:
            url = link["url"]
            if not url.startswith("/d/"):
                continue
            uid = urlsplit(url).path.split("/")[2]
            dest = uids.DESTINATIONS.get(uid)
            self.assertIsNotNone(
                dest, f"{where} link {link['title']!r} on {title!r} targets "
                      f"unregistered uid {uid!r} — add it to uids.DESTINATIONS")
            self.assertTrue(
                dest.exists,
                f"{where} link {link['title']!r} on {title!r} targets {uid!r}, which is "
                "RESERVED and not generated yet: the link would 404")

    def test_retired_uids_appear_nowhere_in_the_dashboard(self):
        for uid, reason in uids.RETIRED_UIDS.items():
            self.assertNotIn(uid, self.blob, f"retired uid {uid!r} is back ({reason})")

    def test_reserved_destinations_emit_no_link(self):
        for uid, dest in uids.DESTINATIONS.items():
            if not dest.exists:
                self.assertNotIn(
                    f"/d/{uid}", self.blob,
                    f"{uid} is reserved (not generated yet) but a link points at it")

    def test_external_links_are_allowlisted_project_urls(self):
        for where, title, link in self.links:
            url = link["url"]
            if url.startswith("/"):
                continue
            self.assertTrue(
                any(url.startswith(base) for base in uids.EXTERNAL_LINK_BASES),
                f"{where} link {link['title']!r} on {title!r} points outside the "
                f"allowlisted project URLs: {url}")

    # ---- context preservation ------------------------------------------
    def test_every_internal_link_preserves_time_instance_and_datasource(self):
        for where, title, link in self.links:
            url = link["url"]
            if not url.startswith("/d/"):
                continue
            for token in (uids.URL_TIME_RANGE, uids.INSTANCE_PARAM, uids.DS_PARAM):
                self.assertIn(
                    token, url,
                    f"{where} link {link['title']!r} on {title!r} drops {token} — "
                    "navigation would land on a different window or instance")

    def test_no_link_embeds_a_stack_specific_url_or_datasource_uid(self):
        for where, title, link in self.links:
            hit = STACK_SPECIFIC.search(link["url"])
            self.assertIsNone(
                hit, f"{where} link {link['title']!r} on {title!r} embeds "
                     f"stack-specific {hit.group(0) if hit else ''!r}: {link['url']}")

    def test_link_variables_are_declared_and_visible(self):
        declared = {v["spec"]["name"]: v["spec"] for v in self.spec["variables"]}
        hidden = {n for n, s in declared.items() if s.get("hide") == "hideVariable"}
        for where, title, link in self.links:
            url = link["url"]
            if not url.startswith("/d/"):
                continue
            query = urlsplit(url).query
            for key, _ in parse_qsl(query, keep_blank_values=True):
                if not key.startswith("var-"):
                    continue
                name = key[4:]
                self.assertIn(name, declared,
                              f"{where} link on {title!r} sets undeclared var {name!r}")
                self.assertNotIn(
                    name, hidden,
                    f"{where} link on {title!r} propagates HIDDEN sentinel {name!r}; "
                    "sentinels are presence probes, not navigation context")
            for name in hidden:
                self.assertNotIn(f"var-{name}", url)
                self.assertNotIn(f"${{{name}", url)

    # ---- field links ---------------------------------------------------
    def test_field_links_only_template_labels_their_panel_returns(self):
        by_title = {e["spec"]["title"]: e["spec"] for e in self.spec["elements"].values()}
        for where, title, link in self.links:
            if where != "field":
                continue
            for label in re.findall(r"\$\{__field\.labels\.([a-zA-Z0-9_]+)\}", link["url"]):
                exprs = " ".join(panel_exprs(by_title[title]))
                self.assertIn(
                    label, exprs,
                    f"field link {link['title']!r} on {title!r} templates label "
                    f"{label!r}, which the panel's own queries never return — it "
                    "would navigate with an empty variable")

    # ---- tab targeting -------------------------------------------------
    def test_tab_targets_match_the_generated_layout(self):
        slugs = {}
        for tab in self.spec["layout"]["spec"]["tabs"]:
            domain = uids.tab_slug(tab["spec"]["title"])
            layout = tab["spec"]["layout"]
            leaves = ([c["spec"]["title"] for c in layout["spec"]["tabs"]]
                      if layout["kind"] == "TabsLayout" else [])
            slugs[domain] = {uids.tab_slug(t) for t in leaves}
        for where, title, link in self.links:
            url = link["url"]
            if not url.startswith("/d/"):
                continue
            params = dict(parse_qsl(urlsplit(url).query, keep_blank_values=True))
            domain = params.get("dtab")
            if domain is None:
                continue
            self.assertIn(domain, slugs,
                          f"{where} link on {title!r} targets unknown domain tab {domain!r}")
            leaf_key = f"{domain}-dtab"
            leaf = params.get(leaf_key)
            if leaf is not None:
                self.assertIn(leaf, slugs[domain],
                              f"{where} link on {title!r} targets unknown leaf tab "
                              f"{leaf!r} under {domain!r}")

    def test_tab_slugs_are_percent_encoded_in_urls(self):
        for where, title, link in self.links:
            url = link["url"]
            if "dtab" not in url:
                continue
            query = urlsplit(url).query
            for pair in query.split("&"):
                if "dtab" not in pair:
                    continue
                _, _, value = pair.partition("=")
                # Round-trip rather than re-encode: `quote()` on an already-encoded
                # value double-escapes the % and would fail every correct link.
                self.assertEqual(
                    value, quote(unquote(value), safe="-_.~"),
                    f"{where} link on {title!r} carries an unencoded tab slug "
                    f"{value!r}; a raw & or space truncates the parameter")

    # ---- coverage ------------------------------------------------------
    def test_required_panel_families_have_drilldowns(self):
        linked = {t for _, t, _ in self.links if t}
        titles = {e["spec"]["title"] for e in self.spec["elements"].values()}
        for title, family in REQUIRED_DRILLDOWN_PANELS.items():
            self.assertIn(title, titles,
                          f"{title!r} ({family}) is named in REQUIRED_DRILLDOWN_PANELS "
                          "but no such panel exists — retitle the entry or the panel")
            self.assertIn(title, linked,
                          f"{title!r} has no drilldown; #419 requires the {family} "
                          "family to be navigable")
        self.assertEqual(REQUIRED_FAMILIES, set(REQUIRED_DRILLDOWN_PANELS.values()))

    def test_dashboard_level_links_are_present_and_titled(self):
        dash = [l for w, _, l in self.links if w == "dashboard"]
        self.assertTrue(dash, "the dashboard has no dashboard-level links")
        for link in dash:
            self.assertTrue(link["title"].strip())
            self.assertIn("url", link)


class UrlBuilderTest(unittest.TestCase):
    """Unit-level contract of the builder itself, independent of the dashboard."""

    def test_slug_collapses_space_runs_only(self):
        self.assertEqual(uids.tab_slug("Log-derived Events"), "Log-derived-Events")
        self.assertEqual(uids.tab_slug("DNS - Unbound"), "DNS---Unbound")
        self.assertEqual(uids.tab_slug("VPN &  remote access"), "VPN-&-remote-access")

    def test_dash_url_orders_and_encodes_parameters(self):
        url = uids.dash_url(tab=("Observability", "Log Shipping"),
                            variables={"interface": "${__field.labels.interface}"})
        self.assertTrue(url.startswith(f"/d/{uids.MAIN_UID}?"))
        self.assertIn(uids.URL_TIME_RANGE, url)
        self.assertIn("dtab=Observability", url)
        self.assertIn("Observability-dtab=Log-Shipping", url)
        self.assertIn("var-interface=${__field.labels.interface}", url)

    def test_dash_url_refuses_a_reserved_destination(self):
        with self.assertRaises(ValueError):
            uids.dash_url(uid=uids.HEALTH_UID)

    def test_dash_url_refuses_an_unregistered_or_retired_destination(self):
        with self.assertRaises(ValueError):
            uids.dash_url(uid="something-else")
        for uid in uids.RETIRED_UIDS:
            with self.assertRaises(ValueError):
                uids.dash_url(uid=uid)

    def test_loki_destinations_carry_the_loki_datasource(self):
        self.assertIn(uids.LOKI_DS_PARAM, uids.dash_url(loki=True))
        self.assertNotIn(uids.LOKI_DS_PARAM, uids.dash_url())

    def test_every_registered_destination_states_why_and_its_state(self):
        for uid, dest in uids.DESTINATIONS.items():
            self.assertEqual(uid, dest.uid)
            self.assertTrue(dest.title.strip())
            self.assertTrue(dest.why.strip(), f"{uid} must say what it is for")
            self.assertIsInstance(dest.exists, bool)
        for uid, reason in uids.RETIRED_UIDS.items():
            self.assertTrue(reason.strip(), f"retired {uid} must say why it is retired")
            self.assertNotIn(uid, uids.DESTINATIONS)


if __name__ == "__main__":
    unittest.main()
