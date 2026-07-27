"""
IDS/IPS tab — Suricata metrics (opnsense_ids_*).

IDS is a CORE subsystem: the tab shows whenever the collector is enabled (status
is always emitted). The Alert Activity row is gated separately on has_ids_alerts
because opnsense_ids_recent_alerts is opt-in (--exporter.enable-ids-alerts).

opnsense_ids_recent_alerts is a GAUGE (windowed, saturating backend) — show RAW,
never rate(). opnsense_ids_installed_rules_total is a current count → RAW.
opnsense_ids_ruleset_last_updated_timestamp_seconds is a unix timestamp → shown
as age: time() - <ts>.

No Loki row here: verified live (`gcx logs labels --label opnsense_subsystem`) that the
shipped syslog stream's `opnsense_subsystem` values are audit/auth/cron/dhcp/dns/firewall/
flow/gateways/ipsec/kernel/logging/ntp/packages/proxy/tls/web — there is no "ids"/"suricata"
lane. Lines mentioning suricata are configd RPC audit entries (rule sync/lookup calls), not
eve/alert lines, so there's no real stream to gate a row on. Revisit if a Suricata eve.json
lane is ever added to logship.
"""

from builder import Builder, sel, ENABLED, YESNO

IDS_STATUS = {"-1": ("Disabled", "text"), "0": ("Stopped", "red"), "1": ("Running", "green")}
IPS_MODE = {"0": ("IDS (passive)", "blue"), "1": ("IPS (inline)", "orange")}


def build(b: Builder):
    b.sentinel("has_ids", metric="opnsense_ids_status")
    b.sentinel("has_ids_alerts", metric="opnsense_ids_recent_alerts")

    # ------------------------------------------------------------------ #
    # Row 1: Overview                                                      #
    # ------------------------------------------------------------------ #
    status = b.stat(
        "IDS Status",
        sel("opnsense_ids_status"),
        mappings=IDS_STATUS, color_mode="background",
        thresholds=[{"color": "text", "value": None}, {"color": "green", "value": 1}],
        w=4, h=4,
        desc="Suricata service state (1 = running, 0 = stopped, -1 = disabled/unconfigured).",
    )
    ips = b.stat(
        "Detection Mode",
        sel("opnsense_ids_ips_mode_enabled"),
        mappings=IPS_MODE, color_mode="background",
        w=4, h=4,
        desc="Whether Suricata drops traffic inline as an IPS (1) or observes passively as an IDS (0).",
    )
    promisc = b.stat(
        "Promiscuous Mode",
        sel("opnsense_ids_promiscuous_mode_enabled"),
        mappings=YESNO, w=4, h=4,
        desc="Whether the monitoring interface is in promiscuous mode.",
    )
    rules = b.stat(
        "Installed Rules",
        sel("opnsense_ids_installed_rules_total"),
        unit="short", w=4, h=4,
        desc="Total rules loaded in the Suricata rule cache (current count, not a rate).",
    )
    logfiles = b.stat(
        "eve Log Files",
        sel("opnsense_ids_alert_log_files"),
        unit="short", w=4, h=4,
        desc="Number of Suricata eve log files on disk (live eve.json plus rotated copies).",
    )

    # ------------------------------------------------------------------ #
    # Row 2: eve Log Files                                                 #
    # ------------------------------------------------------------------ #
    log_sizes = b.bargauge(
        "eve Log File Sizes",
        [(sel("opnsense_ids_alert_log_size_bytes"), "{{filename}}")],
        unit="bytes", w=24, h=8,
        desc="Size of each Suricata eve log file. A stalled rotation or a runaway alert rate shows here.",
    )

    # ------------------------------------------------------------------ #
    # Row 3: Rulesets                                                      #
    # ------------------------------------------------------------------ #
    ruleset_state = b.statetimeline(
        "Ruleset Enabled State",
        [(sel("opnsense_ids_ruleset_enabled"), "{{ruleset}}")],
        ENABLED, w=24, h=8,
        desc="Which installable rulesets are enabled over time.",
    )
    ruleset_table = b.table(
        "Ruleset Freshness",
        [
            sel("opnsense_ids_ruleset_enabled"),
            f'time() - {sel("opnsense_ids_ruleset_last_updated_timestamp_seconds")}',
        ],
        w=24, h=10,
        excludes=["__name__", "job", "instance"],
        renames={
            "ruleset": "Ruleset",
            "Value #A": "Enabled",
            "Value #B": "Last Updated Age (s)",
        },
        unit_overrides={"Last Updated Age (s)": "s"},
        sort_by="Last Updated Age (s)",
        desc=(
            "Per-ruleset enabled flag and age since last download. "
            "Rows never downloaded have no age. Use this to catch rulesets that have gone stale."
        ),
    )

    # ------------------------------------------------------------------ #
    # Row 4: Alert Activity (opt-in)                                       #
    # ------------------------------------------------------------------ #
    recent = b.ts(
        "Recent Alerts by Action",
        [(sel("opnsense_ids_recent_alerts"), "{{action}}")],
        unit="short", w=24, h=8,
        desc=(
            "Suricata alerts within the lookback window (--exporter.ids-alert-lookback), by action. "
            "A gauge, not a counter; a floor when more than 500 alerts fall inside the window. "
            "Requires --exporter.enable-ids-alerts."
        ),
    )

    b.tab("IDS/IPS", [
        b.row("Suricata Overview", [status, ips, promisc, rules, logfiles], present="has_ids"),
        b.row("eve Log Files", [log_sizes], present="has_ids"),
        b.row("Rulesets", [ruleset_state, ruleset_table], present="has_ids"),
        b.row("Alert Activity", [recent], present="has_ids_alerts"),
    ])
