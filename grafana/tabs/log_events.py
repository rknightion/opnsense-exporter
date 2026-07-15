"""
Log-derived Events tab — Prometheus counters derived from received syslog lines
(opnsense_log_events_*, the log_events collector, #258).

These describe OPNsense activity (firewall blocks, HAProxy state changes, sshd
auth outcomes, DHCP leases, config/audit events, IDS alerts) extracted from the
syslog the receiver ingests — NOT the pipeline self-metrics on the Log Shipping
tab. They exist so a busy box can graph rates cheaply and sample the raw lines
away (--logs.syslog.sample) without losing the aggregate.

All are true cumulative counters → rate(). IPs, ports, SIDs, MACs and free-text
rule descriptions are never labels here (they stay as log-line metadata).

Each family's row is gated on its own sentinel so a box that only emits some of
the programs shows only those rows; the tab itself is gated on any of them.
"""

from builder import Builder, sel, RATE


def build(b: Builder):
    b.sentinel("has_log_events", 'label_values({__name__=~"opnsense_log_events_.+"}, __name__)')
    b.sentinel("has_log_events_firewall", "label_values(opnsense_log_events_firewall_total, __name__)")
    b.sentinel("has_log_events_haproxy", "label_values(opnsense_log_events_haproxy_total, __name__)")
    b.sentinel("has_log_events_sshd", "label_values(opnsense_log_events_sshd_total, __name__)")
    b.sentinel("has_log_events_dhcp", "label_values(opnsense_log_events_dhcp_total, __name__)")
    b.sentinel("has_log_events_audit", "label_values(opnsense_log_events_audit_total, __name__)")
    b.sentinel("has_log_events_ids", "label_values(opnsense_log_events_ids_total, __name__)")

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

    b.tab("Log-derived Events", [
        b.row("Firewall", [fw_action, fw_rule], present="has_log_events_firewall"),
        b.row("HAProxy", [haproxy, haproxy_backend], present="has_log_events_haproxy"),
        b.row("SSH Authentication", [sshd], present="has_log_events_sshd"),
        b.row("DHCP", [dhcp], present="has_log_events_dhcp"),
        b.row("Config / Audit", [audit], present="has_log_events_audit"),
        b.row("IDS / IPS", [ids], present="has_log_events_ids"),
    ], present="has_log_events")
