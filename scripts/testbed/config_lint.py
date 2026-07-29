#!/usr/bin/env python3
"""Lint an OPNsense config.xml for silently-inert configuration, and compare two boxes.

Written for the testbed pair (VM 102 nightly / VM 106 release, a disk clone of 102 that
diverged), after four latent faults were found on 106 in one day - none by looking for
them, all by tripping over them (#504). Three shared one signature: configuration that
reads as working and does nothing. A firewall rule naming an interface the box does not
have never binds and never errors. A duplicate <optN> stanza silently shadows one of
them. A gateway item flagged disabled leaves an interface with a lease, host routes and
successful pings but no default route. None of these show up on a status page.

  ./config_lint.py 102.xml                        # lint one config
  ./config_lint.py 102.xml --plugins "$(ssh box 'pkg query -e "%a = 0" %n | grep ^os-')"
  ./config_lint.py --compare 102.xml 106.xml      # structural divergence between two

Exit status is 1 if any ERROR was found, else 0. WARNs never fail the run: a disabled
gateway is a legitimate configuration, it just needs to be a deliberate one.

The one check that cannot live here is `pfctl -nf /tmp/rules.debug`, which has to run on
the box - pf silently keeps running the last ruleset that loaded, so an unloadable one is
invisible until a reboot. Run it alongside this:

    ssh <box> 'sh -c "pfctl -nf /tmp/rules.debug; echo exit=$?"'

Root's shell on OPNsense is csh, so wrap remote commands in `sh -c` or redirections fail
with "Ambiguous output redirect".

Input is a config.xml pulled from a firewall you control. It is parsed with the stdlib
ElementTree, which does not resolve external entities but is not hardened against
entity-expansion; do not point this at a config from an untrusted source.
"""

import argparse
import sys
import xml.etree.ElementTree as ET  # noqa: S314 - trusted, operator-supplied config
from collections import Counter
from dataclasses import dataclass

# Rule targets that are legitimately not <interfaces> children. Interface *groups*
# (openvpn, wireguard, enc0) and the loopback are real pf targets with no stanza of
# their own, and "any"/"" mean no interface constraint at all.
PSEUDO_INTERFACES = {"", "any", "lo0", "loopback", "openvpn", "wireguard", "enc0", "ipsec"}


@dataclass(frozen=True)
class Finding:
    level: str  # ERROR | WARN
    check: str
    ref: str  # the offending value, e.g. "opt4"
    where: str  # human-readable location


def assigned_interfaces(root: ET.Element) -> set:
    """The interface KEYS a rule may name: the child tags of <interfaces>.

    Rules reference the key (opt4), never the device (tailscale0), which is why a rule
    can outlive the assignment that gave it meaning.
    """
    ifaces = root.find("interfaces")
    return set() if ifaces is None else {c.tag for c in ifaces}


def _label(el: ET.Element, fallback: str) -> str:
    for k in ("descr", "description", "name"):
        v = el.findtext(k)
        if v and v.strip():
            return f"{fallback} {v.strip()!r}"
    uuid = el.attrib.get("uuid")
    return f"{fallback} uuid={uuid}" if uuid else fallback


# (xpath, field, label) triples: everywhere an interface key is referenced.
_IFACE_REFS = (
    ("./filter/rule", "interface", "legacy filter rule"),
    ("./nat/rule", "interface", "legacy nat rule"),
    ("./nat/onetoone", "interface", "legacy 1:1 nat"),
    ("./nat/outbound/rule", "interface", "legacy outbound nat"),
    ("./OPNsense/Firewall/Filter/rules/rule", "interface", "firewall rule"),
    ("./OPNsense/Firewall/Filter/snatrules/rule", "interface", "source-nat rule"),
    ("./virtualip/vip", "interface", "virtual IP"),
    ("./OPNsense/Gateways/gateway_item", "interface", "gateway item"),
    ("./OPNsense/radvd/entries", "interface", "radvd entry"),
)


def orphan_interface_refs(root: ET.Element) -> list:
    """Fault 1: anything naming an interface key with no matching stanza.

    Such a rule is accepted, saved, displayed in the UI and never loaded into pf.
    """
    assigned = assigned_interfaces(root)
    out = []
    for xpath, field, label in _IFACE_REFS:
        for el in root.findall(xpath):
            raw = el.findtext(field) or ""
            for ref in (r.strip() for r in raw.split(",")):
                if ref in PSEUDO_INTERFACES or ref in assigned:
                    continue
                out.append(Finding("ERROR", "orphan-interface-ref", ref, _label(el, label)))
    return out


def duplicate_interface_keys(root: ET.Element) -> list:
    """Two stanzas for one key - the 2026-07-13 duplicate-<opt4> near-miss."""
    ifaces = root.find("interfaces")
    if ifaces is None:
        return []
    return [
        Finding("ERROR", "duplicate-interface-key", tag, "<interfaces> section")
        for tag, n in sorted(Counter(c.tag for c in ifaces).items())
        if n > 1
    ]


def disabled_gateways(root: ET.Element) -> list:
    """Fault 4: a disabled gateway item leaves the interface with no default route."""
    return [
        Finding("WARN", "gateway-disabled", gw.findtext("name") or "?",
                f"gateway on interface {gw.findtext('interface') or '?'}")
        for gw in root.findall("./OPNsense/Gateways/gateway_item")
        if (gw.findtext("disabled") or "0") == "1"
    ]


def plugin_list_drift(root: ET.Element, installed: set) -> list:
    """<system><firmware><plugins> vs what pkg actually has.

    That list is not decoration: scripts/firmware/sync.subr.sh installs every listed
    package that is missing, on `firmware sync` and on every `firmware update`. A plugin
    listed but not installed will therefore be installed unattended; one installed but
    not listed (a bare `pkg install`, skipping register.php) is absent from the set the
    box will restore, so it is the one that vanishes.

    Only the first direction is a WARN. Installing a plugin with a bare `pkg install`
    leaves it unregistered, and the testbeds were provisioned that way, so the other
    direction is the normal state for 16 of their plugins and would bury the signal. It
    is still worth seeing, so it is reported at INFO - and --compare surfaces the case
    that actually matters, where the two boxes' lists disagree with each other.
    """
    listed = {p.strip() for p in (root.findtext("./system/firmware/plugins") or "").split(",") if p.strip()}
    out = [
        Finding("WARN", "plugin-listed-not-installed", p, "will be installed by the next firmware sync")
        for p in sorted(listed - installed)
    ]
    out += [
        Finding("INFO", "plugin-installed-not-listed", p, "not registered; a firmware sync will not restore it")
        for p in sorted(installed - listed)
    ]
    return out


CHECKS = (orphan_interface_refs, duplicate_interface_keys, disabled_gateways)


def lint(root: ET.Element, name: str, installed, out, verbose: bool = False) -> int:
    findings = [f for check in CHECKS for f in check(root)]
    if installed is not None:
        findings += plugin_list_drift(root, installed)
    shown = [f for f in findings if verbose or f.level != "INFO"]
    print(f"=== {name}", file=out)
    if not shown:
        print("  clean", file=out)
    for f in shown:
        print(f"  {f.level:5} {f.check:28} {f.ref:20} {f.where}", file=out)
    hidden = len(findings) - len(shown)
    if hidden:
        print(f"  ({hidden} INFO finding(s) hidden; --verbose to show)", file=out)
    return 1 if any(f.level == "ERROR" for f in findings) else 0


# Sections whose entity counts are worth eyeballing side by side. The point is not to
# diff values - the two boxes are legitimately different - but to make an entity that
# exists on one box and not the other impossible to miss.
_COMPARE_SECTIONS = (
    ("interfaces", "./interfaces/*"),
    ("filter rules", "./OPNsense/Firewall/Filter/rules/rule"),
    ("source-nat rules", "./OPNsense/Firewall/Filter/snatrules/rule"),
    ("aliases", "./OPNsense/Firewall/Alias/aliases/alias"),
    ("virtual IPs", "./virtualip/vip"),
    ("gateways", "./OPNsense/Gateways/gateway_item"),
    ("users", "./system/user"),
    ("certificates", "./cert"),
    ("CAs", "./ca"),
    ("Kea v4 subnets", "./OPNsense/Kea/dhcp4/subnets/subnet4"),
    ("Kea v6 subnets", "./OPNsense/Kea/dhcp6/subnets/subnet6"),
    ("radvd entries", "./OPNsense/radvd/entries"),
    ("swanctl connections", "./OPNsense/Swanctl/Connections/Connection"),
)

# "interface" comes last: it is the only identity a radvd entry has, but anything with a
# description should be identified by that instead.
_IDENTITY_FIELDS = ("descr", "description", "name", "ident", "refid", "interface")


def _identity(el: ET.Element) -> str:
    for k in _IDENTITY_FIELDS:
        v = el.findtext(k)
        if v and v.strip():
            return v.strip()
    return el.tag


def compare(a_root: ET.Element, b_root: ET.Element, a_name: str, b_name: str, out) -> int:
    print(f"=== {a_name} vs {b_name}", file=out)
    for label, xpath in _COMPARE_SECTIONS:
        a = {_identity(e) for e in a_root.findall(xpath)}
        b = {_identity(e) for e in b_root.findall(xpath)}
        if a == b:
            print(f"  {label:22} {len(a):3} both", file=out)
            continue
        print(f"  {label:22} {len(a):3} / {len(b):3}", file=out)
        for x in sorted(a - b):
            print(f"      only {a_name}: {x}", file=out)
        for x in sorted(b - a):
            print(f"      only {b_name}: {x}", file=out)

    a_p = {p.strip() for p in (a_root.findtext("./system/firmware/plugins") or "").split(",") if p.strip()}
    b_p = {p.strip() for p in (b_root.findtext("./system/firmware/plugins") or "").split(",") if p.strip()}
    label = "registered plugins"
    if a_p == b_p:
        print(f"  {label:22} {len(a_p):3} both", file=out)
    else:
        print(f"  {label:22} {len(a_p):3} / {len(b_p):3}", file=out)
        for x in sorted(a_p - b_p):
            print(f"      only {a_name}: {x}", file=out)
        for x in sorted(b_p - a_p):
            print(f"      only {b_name}: {x}", file=out)
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("configs", nargs="+", help="path(s) to config.xml")
    p.add_argument("--compare", action="store_true",
                   help="compare exactly two configs instead of linting")
    p.add_argument("--plugins", default=None,
                   help="whitespace/comma-separated list of installed os-* packages")
    p.add_argument("-v", "--verbose", action="store_true", help="also show INFO findings")
    args = p.parse_args(argv)

    roots = [(c, ET.parse(c).getroot()) for c in args.configs]  # noqa: S314 - see module docstring
    if args.compare:
        if len(roots) != 2:
            p.error("--compare takes exactly two configs")
        return compare(roots[0][1], roots[1][1], roots[0][0], roots[1][0], sys.stdout)

    installed = None
    if args.plugins is not None:
        installed = {t for t in args.plugins.replace(",", " ").split() if t}
    return max(lint(root, name, installed, sys.stdout, args.verbose) for name, root in roots)


if __name__ == "__main__":
    sys.exit(main())
