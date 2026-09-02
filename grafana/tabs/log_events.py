"""
Log-derived event panels — Prometheus counters derived from received syslog lines
(opnsense_log_events_*, the log_events collector, #258).

**This module builds no tab of its own (#523).** It used to own an "Log-derived
Events" leaf under an Observability domain, which put firewall block rates, external
SSH login failures, IDS alerts and VPN flapping in a place an operator reaches only
by knowing the metrics are log-derived — an implementation detail of how the number
was produced, not a question anybody asks. Every row below now hangs off the domain
tab that already owns its subsystem, so `Firewall & PF` carries both the pf counters
and the filterlog events, `VPN` carries both the tunnel state and the transitions
that produced it, and so on.

Each function returns a `b.row(...)` (or a list of them) and registers only the
sentinel that row is gated on, so importing one family does not drag in the others.
The consuming tab module owns placement; this module owns the queries and the prose.
`collector_pressure_row` is the exception in destination rather than in shape: it
describes the exporter's own derived-metric budget, so it goes on the health
dashboard's Log Shipping tab.

These describe OPNsense activity (firewall blocks, HAProxy state changes, sshd
and RADIUS auth outcomes, DHCP leases, config/audit events, IDS alerts, IPsec and
OpenVPN tunnel lifecycle, UPnP/NAT-PMP mapping events) extracted from the syslog the
receiver ingests — NOT the pipeline self-metrics on the Log Shipping tab. They exist
so a busy box can graph rates cheaply and sample the raw lines away
(--logs.syslog.sample) without losing the aggregate.

All are true cumulative counters → rate(). IPs, ports, SIDs, MACs, usernames,
certificate subjects, IKE identities and free-text rule descriptions are never
labels here (they stay as log-line metadata).
"""

from builder import Builder, sel, grp, loki_sel, RATE


CONFIGCHANGE_STREAM = loki_sel('opnsense_source="configchange"')


def firewall_row(b: Builder):
    """filterlog events — belongs beside the pf counters on Firewall & PF."""
    b.sentinel("has_log_events_firewall", metric="opnsense_log_events_firewall_total")
    fw_action = b.ts(
        "Firewall Events by Action & Scope (rate)",
        [(f'sum {grp("action", "scope")} (rate({sel("opnsense_log_events_firewall_total")}[{RATE}]))',
          "{{action}} / {{scope}}")],
        unit="ops",
        desc="opnsense_log_events_firewall_total: filterlog events per second by action and "
             "source scope. Every line is counted including passes, so this is accurate even "
             "when --logs.syslog.sample drops the raw pass lines. action=block from scope=remote "
             "is inbound denies from outside. This counts LOG LINES the box emitted; the pf "
             "counters above count packets pf evaluated, so the two answer different questions "
             "and will not agree numerically.",
    )
    blocks = sel("opnsense_log_events_firewall_total", 'action!="pass"')
    fw_rule = b.ts(
        "Top Firewall Rules by Block Rate",
        [(f'topk {grp()} (20, sum {grp("rule_name", "rule_id", "interface")} (rate({blocks}[{RATE}])))',
          "{{rule_name}} ({{interface}})")],
        unit="ops",
        desc="opnsense_log_events_firewall_total (action != pass): the busiest blocking rules by "
             "name and interface. rule_name is the rule's description used as its name; rule_id is "
             "the stable OPNsense rule id. Free-text is never a metric label beyond these bounded values.",
    )
    return b.row("Firewall Events (log-derived)", [fw_action, fw_rule],
                 present="has_log_events_firewall")


def upnp_row(b: Builder):
    """miniupnpd mapping events — NAT state, so it belongs on Firewall & PF."""
    b.sentinel("has_log_events_upnp", metric="opnsense_log_events_upnp_total")
    upnp = b.ts(
        "UPnP / NAT-PMP Mapping Events by Event & Result (rate)",
        [(f'sum {grp("event", "result", "protocol")} (rate({sel("opnsense_log_events_upnp_total")}[{RATE}]))',
          "{{event}} / {{result}} / {{protocol}}")],
        unit="ops",
        desc="opnsense_log_events_upnp_total: miniupnpd mapping events per second. The vocabulary "
             "is closed and code-defined: event=expired (a mapping reached the end of its lease "
             "and was torn down, the only ok result), cleanup_failed (the daemon could not find "
             "the pf nat or redirect rule it was deleting), unauthorized (a PCP client asked to "
             "remove a mapping it does not own) or lease_file_error; protocol=tcp, udp, or empty "
             "on the grammars that name none. THERE IS NO ACTIVE-MAPPING COUNT here and none can "
             "be derived: the plugin's status page runs pfctl to list mappings rather than "
             "exposing them through an API, an event stream cannot see pre-existing mappings or "
             "survive a daemon restart, and expired is a decrement with no matching increment. A "
             "successful add or delete is absent too - miniupnpd logs those at a verbosity "
             "os-upnp does not expose, and no attempt line is treated as proof of success. So "
             "read this as a health signal, not an inventory: a steady cleanup_failed rate means "
             "the daemon and pf disagree about which rules exist, and unauthorized means a client "
             "is trying to remove somebody else's mapping. Ports, the daemon's opaque addr= "
             "token, lease-file paths, mapping descriptions and client identities are never "
             "labels; the ports ship on the log record as upnp.port.external / "
             "upnp.port.internal, which is the only place the specific failing mapping can be "
             "identified.",
    )
    return b.row("UPnP / NAT-PMP Mappings", [upnp], present="has_log_events_upnp")


def sshd_row(b: Builder):
    b.sentinel("has_log_events_sshd", metric="opnsense_log_events_sshd_total")
    sshd = b.ts(
        "sshd Auth Events by Result (rate)",
        [(f'sum {grp("result", "method", "scope")} (rate({sel("opnsense_log_events_sshd_total")}[{RATE}]))',
          "{{result}} / {{method}} / {{scope}}")],
        unit="ops",
        desc="opnsense_log_events_sshd_total: firewall sshd authentication outcomes per second. "
             "result=failed / invalid-user from scope=remote is external login attempts against "
             "the firewall — the primary security signal on this tab.",
    )
    return b.row("SSH Authentication", [sshd], present="has_log_events_sshd")


def audit_row(b: Builder):
    b.sentinel("has_log_events_audit", metric="opnsense_log_events_audit_total")
    audit = b.ts(
        "Config / Audit Events by Type & Result (rate)",
        [(f'sum {grp("event", "result")} (rate({sel("opnsense_log_events_audit_total")}[{RATE}]))',
          "{{event}} / {{result}}")],
        unit="ops",
        desc="opnsense_log_events_audit_total: audit events per second — event=config_change tracks "
             "configuration writes, event=authorization tracks GUI/API auth decisions.",
    )
    return b.row("Config / Audit", [audit], present="has_log_events_audit")


def configchange_row(b: Builder):
    b.loki_sentinel("has_configchange_logs", matchers='opnsense_source="configchange"',
                    label="opnsense_source")
    raw = b.logs(
        "Configuration Revision Diffs",
        CONFIGCHANGE_STREAM,
        desc="One retained OPNsense configuration revision per record from "
             "--logs.configchange.enabled. The body is the upstream unified diff; who, "
             "revision and uri are structured metadata. Fresh or retention-evicted "
             "cursors re-baseline without replay, so an empty window is not evidence "
             "that the historical backup window was shipped.",
        w=24,
    )
    return b.row("Configuration Revision Diffs", [raw], present="has_configchange_logs")


def radius_row(b: Builder):
    b.sentinel("has_log_events_radius", metric="opnsense_log_events_radius_total")
    radius = b.ts(
        "RADIUS Access Events by Result (rate)",
        [(f'sum {grp("event", "result", "client_scope")} (rate({sel("opnsense_log_events_radius_total")}[{RATE}]))',
          "{{event}} / {{result}} / {{client_scope}}")],
        unit="ops",
        desc="opnsense_log_events_radius_total: FreeRADIUS access outcomes per second. The closed "
             "vocabulary is event=access, result=accepted or rejected, and "
             "client_scope=configured. Accounting is not supported because normal Start, "
             "Interim-Update and Stop requests emitted no syslog records in the capture. "
             "Usernames, client/NAS identities, station addresses, source addresses, reply text "
             "and credentials are never labels.",
    )
    return b.row("RADIUS Authentication", [radius], present="has_log_events_radius")


def haproxy_row(b: Builder):
    b.sentinel("has_log_events_haproxy", metric="opnsense_log_events_haproxy_total")
    haproxy = b.ts(
        "HAProxy Events by Event, State & Status (rate)",
        [(f'sum {grp("event", "state", "status_class")} (rate({sel("opnsense_log_events_haproxy_total")}[{RATE}]))',
          "{{event}} / {{state}} / {{status_class}}")],
        unit="ops",
        desc="opnsense_log_events_haproxy_total: HAProxy events per second. event=server_state with "
             "state=down is a backend going unhealthy; status_class=5xx is server errors. The "
             "per-connection 'connect' noise is dropped by sampling but still counted here.",
    )
    haproxy_backend = b.ts(
        "HAProxy Events by Backend/Server (rate)",
        [(f'topk {grp()} (20, sum {grp("backend", "server")} (rate({sel("opnsense_log_events_haproxy_total")}[{RATE}])))',
          "{{backend}} / {{server}}")],
        unit="ops",
        desc="opnsense_log_events_haproxy_total by backend and server — where the HAProxy activity is. "
             "Log-derived, so it covers the window between stats polls that the tables above cannot.",
    )
    return b.row("HAProxy Events (log-derived)", [haproxy, haproxy_backend],
                 present="has_log_events_haproxy")


def dhcp_row(b: Builder):
    b.sentinel("has_log_events_dhcp", metric="opnsense_log_events_dhcp_total")
    dhcp = b.ts(
        "DHCP Lease Events by Action (rate)",
        [(f'sum {grp("action", "interface")} (rate({sel("opnsense_log_events_dhcp_total")}[{RATE}]))',
          "{{action}} / {{interface}}")],
        unit="ops",
        desc="opnsense_log_events_dhcp_total: DHCP lease events per second by action (ack/nak/offer/…) "
             "and interface, across the Kea / dnsmasq / ISC backends. Backend-independent, so it is "
             "the one DHCP panel that keeps working across a backend migration.",
    )
    return b.row("Lease Events (log-derived)", [dhcp], present="has_log_events_dhcp")


def dhcp_client_row(b: Builder):
    """WAN DHCP client lifecycle (#541) — belongs beside the DHCP server panels.

    Distinct from dhcp_row above: that one counts leases this box HANDS OUT, this one
    tracks the lease this box HOLDS on its own WAN. A firewall can be a perfectly
    healthy DHCP server right up to the moment its own upstream lease expires.
    """
    b.sentinel("has_log_events_dhcp_client", metric="opnsense_log_events_dhcp_client_total")
    dhcp_client = b.ts(
        "WAN DHCP Client Messages (rate)",
        [(f'sum {grp("type", "interface")} (rate({sel("opnsense_log_events_dhcp_client_total")}[{RATE}]))',
          "{{type}} / {{interface}}")],
        unit="ops",
        desc="opnsense_log_events_dhcp_client_total: dhclient message rate on the WAN by type. "
             "A sustained climb in request without matching ack is a renewal storm — the "
             "leading indicator of a WAN outage, typically hours ahead of the lease actually "
             "expiring. Any nak at all is worth attention: the server is refusing the address "
             "this box is currently using.",
    )
    dhcp_client_script = b.ts(
        "WAN DHCP Client Script Events (rate)",
        [(f'sum {grp("reason", "interface")} (rate({sel("opnsense_log_events_dhcp_client_script_total")}[{RATE}]))',
          "{{reason}} / {{interface}}")],
        unit="ops",
        desc="opnsense_log_events_dhcp_client_script_total: dhclient-script invocations by "
             "reason. bound/renew/rebind are the healthy cadence; expire, fail and timeout mean "
             "the box has lost or is losing its WAN address.",
    )
    lease_countdown = b.ts(
        "WAN DHCP Lease Renewal Countdown",
        [
            (f'{sel("opnsense_log_events_dhcp_client_lease_renewal_timestamp_seconds")} - time()',
             "{{interface}} until renewal due"),
            (f'time() - {sel("opnsense_log_events_dhcp_client_lease_bound_timestamp_seconds")}',
             "{{interface}} since last bind"),
        ],
        unit="s",
        desc="Seconds until dhclient's renewal (T1) deadline, and time since the last successful "
             "bind. These are exported as absolute *_timestamp_seconds gauges and turned into a "
             "countdown here on purpose: a countdown computed in the exporter would keep "
             "counting down from a stale value, so a dead dhclient would look identical to a "
             "healthy one. Here the line crossing zero IS the fault. Note this is the renewal "
             "deadline, not absolute lease expiry — dhclient never logs the latter.",
    )
    return b.row("WAN DHCP Client (log-derived)",
                 [dhcp_client, dhcp_client_script, lease_countdown],
                 present="has_log_events_dhcp_client")


def dhcp6_client_row(b: Builder):
    """WAN DHCPv6 client and prefix delegation (#546) — the v6 twin of the row above.

    Kept separate from dhcp_client_row rather than folded into it: a v4 and a v6
    uplink fail independently, their message vocabularies do not overlap, and
    merging them would hide a v6-only outage behind a healthy v4 rate.

    Delegation is the part with no v4 equivalent. A delegated prefix carries its
    own preferred and valid lifetimes, independent of the WAN address, and losing
    it takes down every downstream v6 prefix rather than just this box's uplink.
    """
    b.sentinel("has_log_events_dhcp6c", metric="opnsense_log_events_dhcp6c_message_total")
    dhcp6c_msgs = b.ts(
        "WAN DHCPv6 Client Messages (rate)",
        [(f'sum {grp("type", "direction", "interface")} '
          f'(rate({sel("opnsense_log_events_dhcp6c_message_total")}[{RATE}]))',
          "{{type}} {{direction}} / {{interface}}")],
        unit="ops",
        desc="opnsense_log_events_dhcp6c_message_total: dhcp6c message rate on the WAN by type "
             "and direction. The pairing is the signal, not the absolute rate: sent renew "
             "climbing while received stays flat is the v6 uplink going away, and it shows up "
             "hours before the prefix lifetimes below run out.",
    )
    dhcp6c_events = b.ts(
        "WAN DHCPv6 Client Events (rate)",
        [(f'sum {grp("event", "reason", "interface")} '
          f'(rate({sel("opnsense_log_events_dhcp6c_event_total")}[{RATE}]))',
          "{{event}} {{reason}} / {{interface}}")],
        unit="ops",
        desc="opnsense_log_events_dhcp6c_event_total: prefix-delegation, address-configuration "
             "and script events. reason is legitimately EMPTY on every prefix_* and address_* "
             "event and on script_ignored — it is a script reason, and those lines carry none. "
             "Note interface means the WAN for prefix and script events but the DOWNSTREAM "
             "device for address_added/address_removed, which is the honest reading of each "
             "line: the address really is configured on the LAN device.",
    )
    prefix_lifetimes = b.ts(
        "Delegated IPv6 Prefix Lifetimes",
        [
            (f'{sel("opnsense_log_events_dhcp6c_prefix_preferred_expiry_timestamp_seconds")} - time()',
             "{{interface}} /{{prefix_length}} until deprecated"),
            (f'{sel("opnsense_log_events_dhcp6c_prefix_valid_expiry_timestamp_seconds")} - time()',
             "{{interface}} /{{prefix_length}} until invalid"),
            (f'time() - {sel("opnsense_log_events_dhcp6c_prefix_updated_timestamp_seconds")}',
             "{{interface}} /{{prefix_length}} since last refresh"),
        ],
        unit="s",
        desc="Time until the delegated prefix stops being PREFERRED and until it stops being "
             "VALID, plus time since it was last refreshed. Two separate deadlines on purpose: "
             "an ISP deprecating a prefix ahead of withdrawal shortens the preferred lifetime "
             "first, and collapsing them into one series would hide exactly that warning. "
             "Exported as absolute *_timestamp_seconds gauges and turned into a countdown here, "
             "the same reasoning as the v4 row above — a countdown computed in the exporter "
             "keeps counting down from a stale value, so a dead dhcp6c would look healthy. The "
             "prefix itself is never a label (it changes on re-delegation, which is the very "
             "event this watches); prefix_length is, because a /48 stays a /48.",
    )
    address_lifetimes = b.ts(
        "WAN IPv6 Address Lease Lifetimes",
        [
            (f'{sel("opnsense_log_events_dhcp6c_address_preferred_expiry_timestamp_seconds")} - time()',
             "{{interface}} until deprecated"),
            (f'{sel("opnsense_log_events_dhcp6c_address_valid_expiry_timestamp_seconds")} - time()',
             "{{interface}} until invalid"),
            (f'time() - {sel("opnsense_log_events_dhcp6c_address_updated_timestamp_seconds")}',
             "{{interface}} since last refresh"),
        ],
        unit="s",
        desc="Time until this firewall's OWN WAN IPv6 address (an IA_NA lease, not a delegated "
             "prefix) stops being PREFERRED and until it stops being VALID, plus time since it "
             "was last refreshed (#560) — the address counterpart of the prefix panel beside it, "
             "for a WAN that takes its address directly by DHCPv6. Same absolute-timestamp-to-"
             "countdown reasoning as the prefix row: a countdown computed in the exporter keeps "
             "counting down from a stale value, so a dead dhcp6c would look healthy. THIS SERIES "
             "CAN DISAPPEAR ON PURPOSE — an explicit address-removal line clears it rather than "
             "leaving a frozen deadline in place, which would otherwise read as a healthy lease "
             "that simply stopped renewing. The address itself is never a label; it changes on "
             "re-bind, which is one of the conditions this watches for.",
    )
    alloc_fail = b.ts(
        "DHCPv6 Server Allocation Failures (rate)",
        [(f'sum {grp("reason")} (rate({sel("opnsense_log_events_dhcp6_alloc_fail_total")}[{RATE}]))',
          "{{reason}}")],
        unit="ops",
        desc="opnsense_log_events_dhcp6_alloc_fail_total: v6 lease requests kea-dhcp6 REFUSED. "
             "The opposite direction from the panels beside it — this is the box failing its "
             "own v6 clients, not failing upstream. exhausted means the pool is full; no_pools "
             "means the subnet has no pool configured for that client at all, which is a "
             "configuration fault rather than capacity. Counted once per failed allocation: kea "
             "emits up to three lines per failure sharing a tid, and only the cause line counts.",
    )
    return b.row("WAN DHCPv6 Client & Prefix Delegation (log-derived)",
                 [dhcp6c_msgs, dhcp6c_events, prefix_lifetimes, address_lifetimes, alloc_fail],
                 present="has_log_events_dhcp6c")


def netmap_row(b: Builder):
    """Zenarmor's netmap datapath reporting a full host TX ring (#536)."""
    b.sentinel("has_log_events_netmap", metric="opnsense_log_events_netmap_ring_full_events_total")
    netmap = b.ts(
        "Netmap Host Ring Full Events (rate)",
        [(f'sum {grp("device")} (rate({sel("opnsense_log_events_netmap_ring_full_events_total")}[{RATE}]))',
          "{{device}}")],
        unit="ops",
        desc="opnsense_log_events_netmap_ring_full_events_total: intervals in which the kernel "
             "reported the netmap host TX ring full on this device — Zenarmor's packet-capture "
             "datapath dropping traffic. READ THE UNITS CAREFULLY: the kernel rate-limits this "
             "log line to 2 per second, so this counts OCCURRENCES, not dropped packets, and it "
             "saturates exactly when the problem is worst. Treat any sustained nonzero rate as "
             "serious and never infer a packet volume from it. The matching interface "
             "drop counter cannot help here either — the ixl driver overrides the kernel's "
             "oqdrops counter, so netmap's increment is invisible on precisely the 10G "
             "interfaces this tends to happen on.",
    )
    return b.row("Netmap Datapath (log-derived)", [netmap], present="has_log_events_netmap")


def arp_moves_row(b: Builder):
    """Kernel ARP address-move detection (#536) — belongs beside the ARP table."""
    b.sentinel("has_log_events_arp_moves", metric="opnsense_log_events_arp_address_moves_total")
    arp_moves = b.ts(
        "ARP Address Moves (rate)",
        [(f'sum {grp("interface")} (rate({sel("opnsense_log_events_arp_address_moves_total")}[{RATE}]))',
          "{{interface}}")],
        unit="ops",
        desc="opnsense_log_events_arp_address_moves_total: the kernel observing an IP move "
             "between MAC addresses — its own duplicate-IP, MAC-flap and ARP-spoof detector. "
             "The ARP table above CANNOT show this: polling only ever sees whichever MAC won "
             "the race, so a host flapping faster than the poll interval looks perfectly stable "
             "there. Labelled by interface only; the IP and both MACs stay on the log line, "
             "where they belong.",
    )
    return b.row("ARP Address Moves (log-derived)", [arp_moves], present="has_log_events_arp_moves")


def ids_row(b: Builder):
    b.sentinel("has_log_events_ids", metric="opnsense_log_events_ids_total")
    ids = b.ts(
        "IDS Events by Action & Severity (rate)",
        [(f'sum {grp("event_type", "action", "severity")} (rate({sel("opnsense_log_events_ids_total")}[{RATE}]))',
          "{{event_type}} / {{action}} / sev {{severity}}")],
        unit="ops",
        desc="opnsense_log_events_ids_total: Suricata EVE events per second by type, action and "
             "severity. Signature text and SID are deliberately not labels; use the raw log line "
             "(shipped in full — IDS is never sampled) for per-alert detail.",
    )
    return b.row("IDS Events (log-derived)", [ids], present="has_log_events_ids")


def vpn_row(b: Builder):
    b.sentinel("has_log_events_vpn", metric="opnsense_log_events_vpn_total")
    vpn = b.ts(
        "VPN Lifecycle Events by Backend & Event (rate)",
        [(f'sum {grp("backend", "event", "result")} (rate({sel("opnsense_log_events_vpn_total")}[{RATE}]))',
          "{{backend}} / {{event}} / {{result}}")],
        unit="ops",
        desc="opnsense_log_events_vpn_total: IPsec (charon) and OpenVPN tunnel lifecycle "
             "transitions per second. The vocabulary is closed and code-defined: backend=ipsec or "
             "openvpn; event=established, terminated, authentication_failed, liveness_failed or "
             "certificate_failed; result=success for the first two and failure for the other "
             "three. Read it beside the IPsec Phase 1/2 and OpenVPN session-state panels on this "
             "tab: those show what is up NOW, this shows the transitions that got it there - "
             "a tunnel that is up but flapping shows a steady established/terminated rate here "
             "while the state gauge looks healthy. Only the grammar captured on OPNsense "
             "27.1.a_40 (strongSwan 6.0.7, OpenVPN 2.7.5) is counted; other lines still ship as "
             "log records. Usernames, certificate subjects and serials, IKE identities, peer "
             "addresses and ports, SPIs and daemon error text are never labels.",
    )
    vpn_failures = sel("opnsense_log_events_vpn_total", 'result="failure"')
    vpn_by_connection = b.ts(
        "VPN Lifecycle Failures by Connection (rate)",
        [(f'topk {grp()} (20, sum {grp("backend", "event", "connection")} (rate({vpn_failures}[{RATE}])))',
          "{{connection}} / {{backend}} / {{event}}")],
        unit="ops",
        desc="opnsense_log_events_vpn_total (result=failure): which tunnels are failing, by the "
             "connection name configured on the firewall. connection is resolved from the IPsec "
             "connection or OpenVPN instance id against the inventory the exporter already "
             "fetches - never a raw UUID - and is empty when it could not be resolved. It is "
             "ALWAYS empty for backend=openvpn, by design: the captured OpenVPN lifecycle lines "
             "carry no instance id (OpenVPN prints it only on its MANAGEMENT socket-path line), "
             "so attribute those events using the program attribute on the raw log record "
             "(openvpn_server40) instead. IPsec "
             "authentication_failed is a wrong PSK or identity; liveness_failed is DPD giving up "
             "after retransmits; OpenVPN certificate_failed is a rejected client certificate.",
    )
    return b.row("Tunnel Lifecycle (log-derived)", [vpn, vpn_by_connection],
                 present="has_log_events_vpn")


def collector_pressure_row(b: Builder):
    """The derived-metric budget. Health dashboard, not an operational tab: every
    series here describes the exporter's own bookkeeping, and none of it says
    anything about the firewall."""
    b.sentinel("has_log_events", name_regex="opnsense_log_events_.+")
    cardinality_keys = b.ts(
        "Derived Metric Label Tuples in Use",
        [(f'sum {grp("family")} ({sel("opnsense_log_events_cardinality_keys")})',
          "{{family}}")],
        unit="short",
        desc="opnsense_log_events_cardinality_keys: distinct label tuples currently retained per "
             "derived family, against the --logs.max-metric-keys budget. Both receivers are "
             "push-based and syslog over UDP has a spoofable source, so these values are "
             "sender-controlled; the budget is what stops a sender growing this without limit. "
             "A family sitting flat AT the budget is saturated — read it with the capped counter.",
    )
    cardinality_capped = b.ts(
        "Derived Metric Tuples Folded Into Overflow (rate)",
        [(f'sum {grp("family")} (rate({sel("opnsense_log_events_cardinality_capped_total")}[{RATE}]))',
          "{{family}}")],
        unit="ops",
        desc="opnsense_log_events_cardinality_capped_total: observations per second whose label "
             "tuple was refused by the per-family key budget and folded into the overflow total. "
             "Nothing is lost — the counted series plus this overflow equal the true observed "
             "count — but the detail is gone. Sustained non-zero means either a genuinely larger "
             "ruleset/backend inventory than the budget allows (raise --logs.max-metric-keys) or "
             "a sender minting novel tuples (investigate the source).",
    )
    observation_dropped = b.ts(
        "Derived Metric Observation Drops (rate)",
        [(f'sum {grp("reason")} (rate({sel("opnsense_log_events_observation_dropped_total")}[{RATE}]))',
          "{{reason}}")],
        unit="ops",
        desc="opnsense_log_events_observation_dropped_total: derived observations refused before "
             "the map-owning collector goroutine because its bounded handoff was full. "
             "reason=handoff_full is a closed receiver-pressure signal. Syslog keeps a "
             "sample-eligible raw record when this occurs, but its derived counter was not updated.",
    )
    return b.row("Derived Metric Budget",
                 [cardinality_keys, cardinality_capped, observation_dropped],
                 present="has_log_events")
