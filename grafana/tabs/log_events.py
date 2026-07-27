"""
Log-derived Events tab — Prometheus counters derived from received syslog lines
(opnsense_log_events_*, the log_events collector, #258).

These describe OPNsense activity (firewall blocks, HAProxy state changes, sshd
and RADIUS auth outcomes, DHCP leases, config/audit events, IDS alerts, IPsec and
OpenVPN tunnel lifecycle) extracted from the syslog the receiver ingests — NOT the
pipeline self-metrics on the Log Shipping tab. They exist so a busy box can graph
rates cheaply and sample the raw lines away (--logs.syslog.sample) without losing
the aggregate.

All are true cumulative counters → rate(). IPs, ports, SIDs, MACs, usernames,
certificate subjects, IKE identities and free-text rule descriptions are never
labels here (they stay as log-line metadata).

Each family's row is gated on its own sentinel so a box that only emits some of
the programs shows only those rows; the tab itself is gated on any of them.
"""

from builder import Builder, sel, RATE


def build(b: Builder):
    b.sentinel("has_log_events", name_regex="opnsense_log_events_.+")
    b.sentinel("has_log_events_firewall", metric="opnsense_log_events_firewall_total")
    b.sentinel("has_log_events_haproxy", metric="opnsense_log_events_haproxy_total")
    b.sentinel("has_log_events_sshd", metric="opnsense_log_events_sshd_total")
    b.sentinel("has_log_events_dhcp", metric="opnsense_log_events_dhcp_total")
    b.sentinel("has_log_events_audit", metric="opnsense_log_events_audit_total")
    b.sentinel("has_log_events_ids", metric="opnsense_log_events_ids_total")
    b.sentinel("has_log_events_radius", metric="opnsense_log_events_radius_total")
    b.sentinel("has_log_events_vpn", metric="opnsense_log_events_vpn_total")

    fw_action = b.ts(
        "Firewall Events by Action & Scope (rate)",
        [(f'sum by (action, scope) (rate({sel("opnsense_log_events_firewall_total")}[{RATE}]))',
          "{{action}} / {{scope}}")],
        unit="short",
        desc="opnsense_log_events_firewall_total: filterlog events per second by action and "
             "source scope. Every line is counted including passes, so this is accurate even "
             "when --logs.syslog.sample drops the raw pass lines. action=block from scope=remote "
             "is inbound denies from outside.",
    )
    blocks = sel("opnsense_log_events_firewall_total", 'action!="pass"')
    fw_rule = b.ts(
        "Top Firewall Rules by Block Rate",
        [(f'topk(20, sum by (rule_name, rule_id, interface) (rate({blocks}[{RATE}])))',
          "{{rule_name}} ({{interface}})")],
        unit="short",
        desc="opnsense_log_events_firewall_total (action != pass): the busiest blocking rules by "
             "name and interface. rule_name is the rule's description used as its name; rule_id is "
             "the stable OPNsense rule id. Free-text is never a metric label beyond these bounded values.",
    )

    haproxy = b.ts(
        "HAProxy Events by Event, State & Status (rate)",
        [(f'sum by (event, state, status_class) (rate({sel("opnsense_log_events_haproxy_total")}[{RATE}]))',
          "{{event}} / {{state}} / {{status_class}}")],
        unit="short",
        desc="opnsense_log_events_haproxy_total: HAProxy events per second. event=server_state with "
             "state=down is a backend going unhealthy; status_class=5xx is server errors. The "
             "per-connection 'connect' noise is dropped by sampling but still counted here.",
    )
    haproxy_backend = b.ts(
        "HAProxy Events by Backend/Server (rate)",
        [(f'topk(20, sum by (backend, server) (rate({sel("opnsense_log_events_haproxy_total")}[{RATE}])))',
          "{{backend}} / {{server}}")],
        unit="short",
        desc="opnsense_log_events_haproxy_total by backend and server — where the HAProxy activity is.",
    )

    sshd = b.ts(
        "sshd Auth Events by Result (rate)",
        [(f'sum by (result, method, scope) (rate({sel("opnsense_log_events_sshd_total")}[{RATE}]))',
          "{{result}} / {{method}} / {{scope}}")],
        unit="short",
        desc="opnsense_log_events_sshd_total: firewall sshd authentication outcomes per second. "
             "result=failed / invalid-user from scope=remote is external login attempts against "
             "the firewall — the primary security signal on this tab.",
    )

    dhcp = b.ts(
        "DHCP Lease Events by Action (rate)",
        [(f'sum by (action, interface) (rate({sel("opnsense_log_events_dhcp_total")}[{RATE}]))',
          "{{action}} / {{interface}}")],
        unit="short",
        desc="opnsense_log_events_dhcp_total: DHCP lease events per second by action (ack/nak/offer/…) "
             "and interface, across the Kea / dnsmasq / ISC backends.",
    )

    audit = b.ts(
        "Config / Audit Events by Type & Result (rate)",
        [(f'sum by (event, result) (rate({sel("opnsense_log_events_audit_total")}[{RATE}]))',
          "{{event}} / {{result}}")],
        unit="short",
        desc="opnsense_log_events_audit_total: audit events per second — event=config_change tracks "
             "configuration writes, event=authorization tracks GUI/API auth decisions.",
    )

    ids = b.ts(
        "IDS Events by Action & Severity (rate)",
        [(f'sum by (event_type, action, severity) (rate({sel("opnsense_log_events_ids_total")}[{RATE}]))',
          "{{event_type}} / {{action}} / sev {{severity}}")],
        unit="short",
        desc="opnsense_log_events_ids_total: Suricata EVE events per second by type, action and "
             "severity. Signature text and SID are deliberately not labels; use the raw log line "
             "(shipped in full — IDS is never sampled) for per-alert detail.",
    )

    radius = b.ts(
        "RADIUS Access Events by Result (rate)",
        [(f'sum by (event, result, client_scope) (rate({sel("opnsense_log_events_radius_total")}[{RATE}]))',
          "{{event}} / {{result}} / {{client_scope}}")],
        unit="short",
        desc="opnsense_log_events_radius_total: FreeRADIUS access outcomes per second. The closed "
             "vocabulary is event=access, result=accepted or rejected, and "
             "client_scope=configured. Accounting is not supported because normal Start, "
             "Interim-Update and Stop requests emitted no syslog records in the capture. "
             "Usernames, client/NAS identities, station addresses, source addresses, reply text "
             "and credentials are never labels.",
    )

    vpn = b.ts(
        "VPN Lifecycle Events by Backend & Event (rate)",
        [(f'sum by (backend, event, result) (rate({sel("opnsense_log_events_vpn_total")}[{RATE}]))',
          "{{backend}} / {{event}} / {{result}}")],
        unit="short",
        desc="opnsense_log_events_vpn_total: IPsec (charon) and OpenVPN tunnel lifecycle "
             "transitions per second. The vocabulary is closed and code-defined: backend=ipsec or "
             "openvpn; event=established, terminated, authentication_failed, liveness_failed or "
             "certificate_failed; result=success for the first two and failure for the other "
             "three. Read it beside the IPsec Phase 1/2 and OpenVPN session-state panels on the "
             "VPN tab: those show what is up NOW, this shows the transitions that got it there - "
             "a tunnel that is up but flapping shows a steady established/terminated rate here "
             "while the state gauge looks healthy. Only the grammar captured on OPNsense "
             "27.1.a_40 (strongSwan 6.0.7, OpenVPN 2.7.5) is counted; other lines still ship as "
             "log records. Usernames, certificate subjects and serials, IKE identities, peer "
             "addresses and ports, SPIs and daemon error text are never labels.",
    )
    vpn_failures = sel("opnsense_log_events_vpn_total", 'result="failure"')
    vpn_by_connection = b.ts(
        "VPN Lifecycle Failures by Connection (rate)",
        [(f'topk(20, sum by (backend, event, connection) (rate({vpn_failures}[{RATE}])))',
          "{{connection}} / {{backend}} / {{event}}")],
        unit="short",
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

    cardinality_keys = b.ts(
        "Derived Metric Label Tuples in Use",
        [(f'sum by (family) ({sel("opnsense_log_events_cardinality_keys")})',
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
        [(f'sum by (family) (rate({sel("opnsense_log_events_cardinality_capped_total")}[{RATE}]))',
          "{{family}}")],
        unit="short",
        desc="opnsense_log_events_cardinality_capped_total: observations per second whose label "
             "tuple was refused by the per-family key budget and folded into the overflow total. "
             "Nothing is lost — the counted series plus this overflow equal the true observed "
             "count — but the detail is gone. Sustained non-zero means either a genuinely larger "
             "ruleset/backend inventory than the budget allows (raise --logs.max-metric-keys) or "
             "a sender minting novel tuples (investigate the source).",
    )

    observation_dropped = b.ts(
        "Derived Metric Observation Drops (rate)",
        [(f'sum by (reason) (rate({sel("opnsense_log_events_observation_dropped_total")}[{RATE}]))',
          "{{reason}}")],
        unit="short",
        desc="opnsense_log_events_observation_dropped_total: derived observations refused before "
             "the map-owning collector goroutine because its bounded handoff was full. "
             "reason=handoff_full is a closed receiver-pressure signal. Syslog keeps a "
             "sample-eligible raw record when this occurs, but its derived counter was not updated.",
    )

    b.tab("Log-derived Events", [
        b.row("Firewall", [fw_action, fw_rule], present="has_log_events_firewall"),
        b.row("HAProxy", [haproxy, haproxy_backend], present="has_log_events_haproxy"),
        b.row("SSH Authentication", [sshd], present="has_log_events_sshd"),
        b.row("DHCP", [dhcp], present="has_log_events_dhcp"),
        b.row("Config / Audit", [audit], present="has_log_events_audit"),
        b.row("IDS / IPS", [ids], present="has_log_events_ids"),
        b.row("RADIUS Authentication", [radius], present="has_log_events_radius"),
        b.row("VPN Lifecycle (IPsec / OpenVPN)", [vpn, vpn_by_connection], present="has_log_events_vpn"),
        b.row("Collector Pressure", [cardinality_keys, cardinality_capped, observation_dropped]),
    ], present="has_log_events")
