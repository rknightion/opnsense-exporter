"""Unit tests for config_lint.py (stdlib unittest, matching grafana/tests)."""

import io
import unittest
import xml.etree.ElementTree as ET

import config_lint as cl


def cfg(body: str) -> ET.Element:
    return ET.fromstring(f"<opnsense>{body}</opnsense>")


IFACES = """
<interfaces>
  <wan><if>vtnet0</if></wan>
  <lan><if>vtnet1</if></lan>
  <opt1><if>vtnet2</if><descr>TESTLAN</descr></opt1>
</interfaces>
"""


class TestAssignedInterfaces(unittest.TestCase):
    def test_collects_keys_not_devices(self):
        # The rules reference the config KEY (opt1), never the device (vtnet2);
        # fault 1 was an opt4 rule surviving with no opt4 stanza.
        self.assertEqual(cl.assigned_interfaces(cfg(IFACES)), {"wan", "lan", "opt1"})

    def test_missing_interfaces_section(self):
        self.assertEqual(cl.assigned_interfaces(cfg("")), set())


class TestOrphanInterfaceRefs(unittest.TestCase):
    def test_flags_legacy_rule_naming_unassigned_interface(self):
        f = cl.orphan_interface_refs(cfg(IFACES + """
        <filter><rule><interface>opt4</interface><descr>tailnet API</descr></rule></filter>
        """))
        self.assertEqual([x.ref for x in f], ["opt4"])
        self.assertIn("tailnet API", f[0].where)

    def test_flags_mvc_rule_naming_unassigned_interface(self):
        f = cl.orphan_interface_refs(cfg(IFACES + """
        <OPNsense><Firewall><Filter><rules>
          <rule uuid="abc"><interface>opt4</interface><description>CI canary</description></rule>
        </rules></Filter></Firewall></OPNsense>
        """))
        self.assertEqual([x.ref for x in f], ["opt4"])

    def test_accepts_assigned_interface(self):
        self.assertEqual(cl.orphan_interface_refs(cfg(IFACES + """
        <filter><rule><interface>opt1</interface></rule></filter>
        """)), [])

    def test_comma_separated_list_checks_every_member(self):
        f = cl.orphan_interface_refs(cfg(IFACES + """
        <filter><rule><interface>lan,opt1,opt9</interface></rule></filter>
        """))
        self.assertEqual([x.ref for x in f], ["opt9"])

    def test_ignores_pseudo_interfaces(self):
        # 'any'/'lo0'/group names are legitimate rule targets with no stanza of
        # their own; flagging them would bury the real finding in noise.
        self.assertEqual(cl.orphan_interface_refs(cfg(IFACES + """
        <filter>
          <rule><interface>any</interface></rule>
          <rule><interface>lo0</interface></rule>
          <rule><interface>openvpn</interface></rule>
        </filter>
        """)), [])

    def test_covers_vips_gateways_and_radvd(self):
        f = cl.orphan_interface_refs(cfg(IFACES + """
        <virtualip><vip><interface>opt5</interface><descr>v</descr></vip></virtualip>
        <OPNsense>
          <Gateways><gateway_item><name>GW</name><interface>opt6</interface></gateway_item></Gateways>
          <radvd><entries uuid="e"><interface>opt7</interface></entries></radvd>
        </OPNsense>
        """))
        self.assertEqual(sorted(x.ref for x in f), ["opt5", "opt6", "opt7"])


class TestDuplicateInterfaceKeys(unittest.TestCase):
    def test_flags_duplicate_opt_stanza(self):
        # The 2026-07-13 near-miss: the assignment API handed out an optN that
        # was already in use, producing two <opt4> stanzas.
        f = cl.duplicate_interface_keys(cfg("""
        <interfaces><opt4><if>a</if></opt4><opt4><if>b</if></opt4></interfaces>
        """))
        self.assertEqual([x.ref for x in f], ["opt4"])

    def test_clean_config(self):
        self.assertEqual(cl.duplicate_interface_keys(cfg(IFACES)), [])


class TestDisabledGateways(unittest.TestCase):
    def test_reports_disabled_items(self):
        f = cl.disabled_gateways(cfg("""
        <OPNsense><Gateways>
          <gateway_item><name>WAN_DHCP</name><disabled>0</disabled></gateway_item>
          <gateway_item><name>LAN_DHCP</name><disabled>1</disabled></gateway_item>
        </Gateways></OPNsense>
        """))
        self.assertEqual([x.ref for x in f], ["LAN_DHCP"])


class TestPluginListDrift(unittest.TestCase):
    def test_listed_but_not_installed(self):
        f = cl.plugin_list_drift(cfg("""
        <system><firmware><plugins>os-netbird,os-tor</plugins></firmware></system>
        """), {"os-tor"})
        self.assertEqual([x.ref for x in f], ["os-netbird"])

    def test_installed_but_not_listed_is_info_only(self):
        # The testbeds were provisioned with bare `pkg install`, so 16 plugins are in
        # this state on both boxes; at WARN it would bury the one that matters.
        f = cl.plugin_list_drift(cfg("""
        <system><firmware><plugins>os-tor</plugins></firmware></system>
        """), {"os-tor", "os-tailscale"})
        self.assertEqual([(x.level, x.ref) for x in f], [("INFO", "os-tailscale")])

    def test_info_findings_are_hidden_unless_verbose(self):
        c = cfg("<system><firmware><plugins>os-tor</plugins></firmware></system>")
        quiet, loud = io.StringIO(), io.StringIO()
        cl.lint(c, "box", {"os-tor", "os-tailscale"}, quiet)
        cl.lint(c, "box", {"os-tor", "os-tailscale"}, loud, verbose=True)
        self.assertNotIn("os-tailscale", quiet.getvalue())
        self.assertIn("1 INFO finding(s) hidden", quiet.getvalue())
        self.assertIn("os-tailscale", loud.getvalue())

    def test_no_drift(self):
        self.assertEqual(cl.plugin_list_drift(cfg("""
        <system><firmware><plugins>os-tor</plugins></firmware></system>
        """), {"os-tor"}), [])


class TestReport(unittest.TestCase):
    def test_exit_code_is_one_when_an_error_is_found(self):
        out = io.StringIO()
        rc = cl.lint(cfg(IFACES + "<filter><rule><interface>opt4</interface></rule></filter>"),
                     "box", None, out)
        self.assertEqual(rc, 1)
        self.assertIn("opt4", out.getvalue())

    def test_exit_code_is_zero_for_warnings_only(self):
        out = io.StringIO()
        rc = cl.lint(cfg(IFACES + """
        <OPNsense><Gateways>
          <gateway_item><name>LAN_DHCP</name><disabled>1</disabled></gateway_item>
        </Gateways></OPNsense>
        """), "box", None, out)
        self.assertEqual(rc, 0)
        self.assertIn("LAN_DHCP", out.getvalue())


class TestCompare(unittest.TestCase):
    def test_reports_entities_present_on_one_side_only(self):
        a = cfg("<virtualip><vip><descr>TESTLAN CARP VIP</descr></vip>"
                "<vip><descr>IPsec tunnel target</descr></vip></virtualip>")
        b = cfg("<virtualip><vip><descr>TESTLAN CARP VIP</descr></vip></virtualip>")
        out = io.StringIO()
        cl.compare(a, b, "102", "106", out)
        self.assertIn("only 102: IPsec tunnel target", out.getvalue())

    def test_matching_section_is_collapsed_to_one_line(self):
        a = b = cfg("<virtualip><vip><descr>same</descr></vip></virtualip>")
        out = io.StringIO()
        cl.compare(a, b, "102", "106", out)
        self.assertRegex(out.getvalue(), r"virtual IPs +1 both")

    def test_registered_plugin_lists_are_compared(self):
        a = cfg("<system><firmware><plugins>os-tor</plugins></firmware></system>")
        b = cfg("<system><firmware><plugins>os-tor,os-tailscale</plugins></firmware></system>")
        out = io.StringIO()
        cl.compare(a, b, "102", "106", out)
        self.assertIn("only 106: os-tailscale", out.getvalue())


if __name__ == "__main__":
    unittest.main()
