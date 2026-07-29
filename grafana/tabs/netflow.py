"""
NetFlow tab — all opnsense_netflow_* metrics.

Tab is gated on has_netflow (sentinel: label_values(opnsense_netflow_active, __name__)).

Rows:
  1. NetFlow Status     — enabled stat, local_collection_enabled stat, active stat,
                          collectors_count stat
  2. NetFlow Cache      — cache_packets_total rate ts, cache_source_ip_addresses ts,
                          cache_destination_ip_addresses ts
  3. Capture Coverage   — capture_expected vs capture_last_record_seconds ts,
                          the two configured timeouts as stats
  4. Hook Liveness      — flow_interface_info map table, dead-hook join table (#368)

Coverage:
  opnsense_netflow_enabled
  opnsense_netflow_local_collection_enabled
  opnsense_netflow_active
  opnsense_netflow_collectors_count
  opnsense_netflow_cache_packets_total
  opnsense_netflow_cache_source_ip_addresses
  opnsense_netflow_cache_destination_ip_addresses
  opnsense_netflow_capture_expected
  opnsense_netflow_capture_last_record_seconds
  opnsense_netflow_capture_active_timeout_seconds
  opnsense_netflow_capture_inactive_timeout_seconds
  opnsense_flow_interface_info   (owned by the Flow tab's family, joined here)
"""

from builder import Builder, sel, RATE, ENABLED


# Custom mapping for netflow_active: 0=Inactive/red, 1=Active/green
_ACTIVE = {"0": ("Inactive", "red"), "1": ("Active", "green")}


def build(b: Builder):
    # ---- Sentinel --------------------------------------------------------
    b.sentinel("has_netflow", metric="opnsense_netflow_active")

    # ======================================================================
    # Row 1 – NetFlow Status
    # ======================================================================
    nf_enabled = b.stat(
        "NetFlow Capture",
        sel("opnsense_netflow_enabled"),
        unit="short",
        w=6, h=4,
        mappings=ENABLED,
        color_mode="background",
        graph="none",
        instant=True,
        desc="Whether NetFlow packet capture is enabled (1=Enabled, 0=Disabled).",
    )
    nf_local = b.stat(
        "Local Collection",
        sel("opnsense_netflow_local_collection_enabled"),
        unit="short",
        w=6, h=4,
        mappings=ENABLED,
        color_mode="background",
        graph="none",
        instant=True,
        desc="Whether local NetFlow collection is enabled (1=Enabled, 0=Disabled).",
    )
    nf_active = b.stat(
        "NetFlow Service",
        sel("opnsense_netflow_active"),
        unit="short",
        w=6, h=4,
        mappings=_ACTIVE,
        color_mode="background",
        graph="none",
        instant=True,
        desc="Whether the NetFlow service is currently active (1=Active, 0=Inactive).",
    )
    nf_collectors = b.stat(
        "Collectors",
        sel("opnsense_netflow_collectors_count"),
        unit="short",
        w=6, h=4,
        graph="none",
        instant=True,
        desc="Number of active NetFlow collector destinations configured.",
    )

    # ======================================================================
    # Row 2 – NetFlow Cache
    # ======================================================================
    # NetFlow cache metrics label `interface` with the kernel DEVICE name (pppoe0,
    # ixl0_vlan25), not the configured description — so filter on $device, not the
    # description-space $interface variable (#98).
    iface = 'interface=~"$device"'
    nf_packets_ts = b.ts(
        "Cache Packets (rate)",
        [(f'rate({sel("opnsense_netflow_cache_packets_total", iface)}[{RATE}])',
          "{{interface}}")],
        unit="pps",
        w=8, h=8,
        desc="NetFlow cache packets observed per second by interface.",
    )
    nf_src_ips_ts = b.ts(
        "Unique Source IPs in Cache",
        [(sel("opnsense_netflow_cache_source_ip_addresses", iface),
          "{{interface}}")],
        unit="short",
        w=8, h=8,
        desc="Number of unique source IP addresses currently tracked in the NetFlow cache by interface.",
    )
    nf_dst_ips_ts = b.ts(
        "Unique Destination IPs in Cache",
        [(sel("opnsense_netflow_cache_destination_ip_addresses", iface),
          "{{interface}}")],
        unit="short",
        w=8, h=8,
        desc="Number of unique destination IP addresses currently tracked in the NetFlow cache by interface.",
    )

    # ======================================================================
    # Row 3 – Capture Coverage (#366)
    # ======================================================================
    # UNLIKE the cache metrics above, the capture_* metrics label `interface` with
    # the configured DESCRIPTION (AAISP, LAN) — they come from the netflow config
    # model, whose option-dict values are the descriptions. So these filter on
    # $interface, NOT $device. Getting this backwards yields an empty panel.
    desc_iface = 'interface=~"$interface"'
    nf_capture = b.ts(
        "Capture Coverage: Expected vs Last Record",
        [(sel("opnsense_netflow_capture_expected", desc_iface), "expected: {{interface}}"),
         (sel("opnsense_netflow_capture_last_record_seconds", desc_iface),
          "last record (s): {{interface}}")],
        # The age series is seconds — the two stats the description says to compare it
        # against both use "s". The expected series is a 0/1 flag that the age axis
        # flattens onto the baseline, so give it its own axis rather than losing it (#513).
        unit="s",
        overrides=[{"matcher": {"id": "byRegexp", "options": "expected: .*"},
             "properties": [{"id": "unit", "value": "short"}, {"id": "custom.axisPlacement", "value": "right"}, {"id": "max", "value": 1}]}],
        w=16, h=8,
        desc="expected=1 means the firewall is configured to capture NetFlow on that interface; "
             "the paired series is how long since this exporter last received a record naming it. "
             "The fault this makes expressible is \"configured to capture, exporting nothing\": "
             "expected=1 with an age well past capture_active_timeout_seconds. No verdict is baked "
             "in and no alert ships with it, deliberately — a guest VLAN can be legitimately silent "
             "for hours, so the threshold is yours. An interface with expected=1 and NO age series "
             "at all has produced nothing since the exporter started, which is also the normal state "
             "for the first minutes after a restart; \"never seen\" and \"seen, then stopped\" are "
             "different states and are deliberately not rendered the same. "
             "READ THIS BEFORE TRUSTING A FRESH AGE: ng_netflow stamps the capturing hook's index on "
             "one side of a flow and fills the OTHER side from a FIB lookup, so records captured on "
             "the LAN hook also name the egress WAN. A fresh age therefore proves the interface is "
             "being NAMED, not that its own capture hook is alive. Measured on the reference box "
             "2026-07-24: netflow_pppoe0 had processed zero packets while 11 GB was attributed to "
             "that interface. For per-hook liveness use the Cache Packets panel above — a "
             "netflow_<device> node stuck at zero is the box's own view of a dead hook.",
    )
    nf_active_to = b.stat(
        "Active Flow Timeout",
        sel("opnsense_netflow_capture_active_timeout_seconds"),
        unit="s",
        w=4, h=4,
        graph="none",
        instant=True,
        desc="The box's configured active timeout — how long a long-running flow sits in the cache "
             "before ng_netflow exports it anyway. An interface cannot be judged silent until well "
             "past this; derive your threshold from it rather than guessing.",
    )
    nf_inactive_to = b.stat(
        "Inactive Flow Timeout",
        sel("opnsense_netflow_capture_inactive_timeout_seconds"),
        unit="s",
        w=4, h=4,
        graph="none",
        instant=True,
        desc="The box's configured inactive timeout — how long an idle flow waits before export. "
             "The floor on how quickly any interface can be observed to have stopped.",
    )

    # ======================================================================
    # Row 4 – Hook Liveness (#368)
    # ======================================================================
    # This row is the join between the two label spaces the rows above cannot
    # cross. opnsense_flow_interface_info carries device + description + ifIndex
    # on one series, which is what makes `group_left` possible at all.
    nf_ifindex_map = b.table(
        "ifIndex / Device / Interface",
        [sel("opnsense_flow_interface_info")],
        w=10, h=8,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "ifindex": "ifIndex",
            "device": "Device",
            "interface": "Interface",
            "opnsense_instance": "Instance",
        },
        sort_by="ifIndex", sort_desc=False,
        desc="The resolved NetFlow ifIndex map. Read it straight down against the firewall's own "
             "ifinfo output: ifIndex is a POSITION in that list, not an identifier, so adding or "
             "removing any interface renumbers everything below it. An empty Device on ifIndex 0 is "
             "correct - that is traffic the firewall itself originated. An empty Interface is a port "
             "with no OPNsense assignment, which still holds its slot. This table is also the key to "
             "every other panel here: the cache metrics are keyed by Device, the capture and flow "
             "metrics by Interface.",
    )
    nf_incapable = b.table(
        "Interfaces That Can Never Capture",
        [sel("opnsense_flow_interface_capture_unsupported")],
        w=10, h=6,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "interface": "Interface",
            "device": "Device",
            "reason": "Reason",
            "opnsense_instance": "Instance",
        },
        desc="Interfaces selected for capture whose kernel device CANNOT produce NetFlow, whatever "
             "the box's configuration says. Empty on most boxes. A row is not a fault and not "
             "actionable beyond unticking the interface: reason=pppoe_framing_node means ng_netflow "
             "attached to mpd's framing node rather than the ng_iface node ng_pppoe exposes, so the "
             "hook was accepted and counts zero forever (#368). Nothing is lost - ng_netflow fills "
             "the far side of every flow from a FIB lookup, so that WAN's traffic is still captured "
             "through the other interfaces' hooks and still attributed to it. These rows are excluded "
             "from the dead-hook table beside this one, and from OPNsenseNetFlowHookDead, because a "
             "permanent unclearable alert is worse than no alert.",
    )
    nf_dead_hooks = b.table(
        "Dead Capture Hooks (configured, own node frozen)",
        [
            "max by (opnsense_instance, interface, device) ("
            f'({sel("opnsense_netflow_capture_expected", desc_iface)} == 1)'
            " * on (opnsense_instance, interface) group_left (device) "
            f'{sel("opnsense_flow_interface_info")}'
            ")"
            # label_join, not label_replace: the cache and pf metrics both put a
            # DEVICE in their `interface` label, so it has to be copied into a
            # `device` label to join on. label_replace would need a "$1" capture
            # reference, and Grafana interpolates anything matching $\w+ before the
            # query is sent.
            " and on (opnsense_instance, device) max by (opnsense_instance, device) ("
            f'label_join(increase({sel("opnsense_netflow_cache_packets_total")}[45m]),'
            ' "device", "", "interface") == 0'
            ")"
            " and on (opnsense_instance, device) max by (opnsense_instance, device) ("
            f'label_join(increase({sel("opnsense_firewall_in_ipv4_pass_bytes_total")}[45m]),'
            ' "device", "", "interface") > 0'
            ")"
            " and on (opnsense_instance) ("
            f'{sel("opnsense_netflow_capture_active_timeout_seconds")} < 2700'
            ")"
            # A device that can NEVER capture is not a dead hook, it is a
            # selection that was never possible. Reporting it here would make the
            # table permanently non-empty on every PPPoE WAN, which trains the
            # reader to ignore a table whose whole contract is "a row here is a
            # fault" (#521).
            " unless on (opnsense_instance, interface) ("
            f'{sel("opnsense_flow_interface_capture_unsupported")} == 1'
            ")"
        ],
        w=14, h=8,
        excludes=["Value", "__name__", "job", "instance"],
        renames={
            "interface": "Interface",
            "device": "Device",
            "opnsense_instance": "Instance",
        },
        desc="A ROW HERE IS A FAULT: the firewall is configured to capture NetFlow on that "
             "interface, real traffic is passing on its device, and its own ng_netflow node has "
             "counted nothing for 45 minutes. Four clauses, and each one is load-bearing. "
             "(1) capture_expected==1, joined through the ifIndex map because the configured set is "
             "in DESCRIPTION space and everything per-hook is in DEVICE space. (2) The box's own "
             "per-node counter flat - this is the only signal a dead hook cannot hide from: a fresh "
             "record age proves the interface was NAMED, not that its hook is alive, because "
             "ng_netflow fills the far side of every flow from a FIB lookup. Measured on the "
             "reference box 2026-07-24: netflow_pppoe0 had processed zero packets while 11 GB, 92% "
             "of all volume, was attributed to that interface. (3) pf says bytes actually passed on "
             "the device, which is what separates a dead hook from an interface that is simply idle - "
             "a quiet guest VLAN's node is legitimately flat and is NOT a fault, and without this "
             "clause it would read identically. (4) The window must exceed the box's own active "
             "timeout or 'nothing exported' means nothing; 45m clears the 30m default, and the clause "
             "drops the whole query if the configured timeout is 45m or more rather than letting the "
             "window quietly become a lie. Absent from this table, deliberately: an interface with no "
             "cache_packets_total series at all (a hook that was never created) - check the map on "
             "the left. (5) An interface whose DEVICE can never capture at all is excluded - "
             "opnsense_flow_interface_capture_unsupported marks those and every PPPoE WAN is one, so "
             "without this clause the table would be permanently non-empty on such a box with no "
             "action available to clear it. Needs the firewall collector for clause 3; with it "
             "disabled this panel is empty rather than wrong.",
    )

    # ======================================================================
    # Assemble tab (gated on has_netflow)
    # ======================================================================
    b.tab("NetFlow", [
        b.row("NetFlow Status", [nf_enabled, nf_local, nf_active, nf_collectors]),
        b.row("NetFlow Cache", [nf_packets_ts, nf_src_ips_ts, nf_dst_ips_ts]),
        b.row("Capture Coverage", [nf_capture, nf_active_to, nf_inactive_to]),
        b.row("Hook Liveness", [nf_ifindex_map, nf_dead_hooks]),
        b.row("Capture Feasibility", [nf_incapable]),
    ], present="has_netflow")
