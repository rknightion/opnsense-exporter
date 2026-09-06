"""
IDS/IPS tab — Suricata metrics (opnsense_ids_*).

IDS is a CORE subsystem: the tab shows whenever the collector is enabled (status
is always emitted). The Alert Activity row is gated separately on has_ids_alerts
because opnsense_ids_recent_alerts is opt-in (--exporter.enable-ids-alerts).

opnsense_ids_recent_alerts is a GAUGE (windowed, saturating backend) — show RAW,
never rate(). opnsense_ids_installed_rules is a current count → RAW.
opnsense_ids_ruleset_last_updated_timestamp_seconds is a unix timestamp → shown
as age: time() - <ts>.

## The Loki row, and the note it replaces (#591 item 5)

This module used to carry a note saying there was no Loki row because the shipped
SYSLOG stream has no `ids` subsystem — lines mentioning suricata there are configd
RPC audit entries, not eve alerts. That observation is still true and is still why
no panel here selects `opnsense_subsystem="ids"`. It was the wrong conclusion: the
"Suricata eve.json lane" it said to revisit for ALREADY EXISTS as its own poll
source (`--logs.ids.enabled`, internal/logship/ids.go), shipping full eve records
under `opnsense_source="ids"` with alert_sid / signature / alert_action / src_ip /
dest_ip / in_iface / proto per alert. Nothing read a byte of it.

**Select on `opnsense_source`, never on `opnsense_subsystem`.** The lane builds its
attributes without `logship.AttrSubsystem`, so its records carry no subsystem label
at all and a selector naming one matches nothing while reporting no error — the same
trap that produced the note above. `tests/test_loki_scoping.py` pins both ends.

The lane is mutually exclusive with the syslog receiver (options/logs_syslog.go
refuses both), so a box running the syslog receiver has this row's sentinel absent
and the row hidden, which is correct rather than a gap.
"""

from builder import Builder, sel, loki_sel, loki_grp, ENABLED, YESNO
from tabs import log_events

IDS_STATUS = {"-1": ("Disabled", "text"), "0": ("Stopped", "red"), "1": ("Running", "green")}
IPS_MODE = {"0": ("IDS (passive)", "blue"), "1": ("IPS (inline)", "orange")}

# The eve-alert log lane. Hoisted so the row's panels cannot drift apart.
IDS_STREAM = loki_sel('opnsense_source="ids"')
# The lane's own synthetic self-observability record: query_alerts is a windowed,
# saturating backend, and when a poll's window fills before reaching the prior cursor
# the alerts in between were never observed. The lane emits one of these describing
# the bounds rather than losing them silently (internal/logship/ids.go). `event` is
# structured metadata, so it filters after the `|`, not in the selector.
IDS_GAPS = f'{IDS_STREAM} | event="gap_detected"'


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
        sel("opnsense_ids_installed_rules"),
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

    # ------------------------------------------------------------------ #
    # Row 5: Alert Records (Loki, --logs.ids.enabled) — #591 item 5 / #592 item 3
    # ------------------------------------------------------------------ #
    b.loki_sentinel("has_ids_logs", matchers='opnsense_source="ids"',
                    label="opnsense_source")

    # The first `loki_stat` in the project, so the shape is worth stating. It is a
    # RANGE query (the helper has no instant mode) whose range selector is the WHOLE
    # dashboard window, reduced with lastNotNull: every step's window looks back
    # $__range, so the final point's window is exactly the selected range and the
    # reduction reads "gaps in this window" rather than "gaps in the last step".
    # $__auto would give the latter, which reports a clean 0 while an hour-old gap
    # sits on screen. Loki emits no sample for an empty window rather than a zero, so
    # the helper's noValue:"0" is what makes a genuinely gap-free box read 0 instead
    # of "No data" — the distinction this whole panel exists to make.
    ids_gaps = b.loki_stat(
        "Alert Coverage Gaps",
        f'sum {loki_grp()} (count_over_time({IDS_GAPS} [$__range]))',
        unit="short", w=4, h=4,
        # Non-zero is not an error to fix in the exporter, it is alerts that were
        # never seen — so it colours as a warning rather than a failure.
        thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}],
        color_mode="background",
        desc="Synthetic gap records over the selected range: times the query_alerts window "
             "saturated before reaching the poll cursor, so Suricata alerts in between were "
             "never observed. This is accepted, BOUNDED loss by design — the point of the "
             "record is that the loss is visible instead of silent, and this stat is what makes "
             "it so. Non-zero means the panels above and the Recent Alerts gauge are an "
             "incomplete sample for that window, not a quiet network; each record's body carries "
             "the gap_start/gap_end bounds. Sustained non-zero means alerts are firing faster "
             "than the 30s poll can drain the window.",
    )
    ids_alert_rate = b.loki_ts(
        "Alert Records/s by Disposition",
        [(f'sum {loki_grp("opnsense_action")} (rate({IDS_STREAM} [$__auto]))',
          "{{opnsense_action}}")],
        unit="ops", w=20, h=8,
        desc="eve alert records per second from the `ids` log stream, by normalised disposition "
             "(block = Suricata acted on it inline, pass = it alerted only). Read against Recent "
             "Alerts above, which is a GAUGE over a lookback window and floors at 500: this is a "
             "true rate and does not saturate. A series with an empty disposition is the "
             "synthetic gap record, which carries no action.",
    )
    ids_signatures = b.loki_table(
        "Top Alert Signatures",
        [f'topk {loki_grp()} (200, sum {loki_grp("signature")} (count_over_time({IDS_STREAM} '
         '| signature!="" [$__range])))'],
        field_title="Signature",
        desc="Which Suricata rules actually fired, ranked over the selected range. The signature "
             "text is structured metadata on the eve record and is deliberately not a metric "
             "label, so this is the only place the estate can say WHICH rule is producing the "
             "alert rate — Recent Alerts by Action gives the count and nothing else. A single "
             "signature dominating is usually a noisy rule worth suppressing rather than an "
             "incident. The `| signature!=\"\"` filter also excludes the synthetic gap records, "
             "which carry no signature; Alert Coverage Gaps counts those separately.",
    )
    ids_alert_raw = b.logs(
        "Raw Alert Records",
        IDS_STREAM,
        desc="Unfiltered `ids` log stream (--logs.ids.enabled): the full eve JSON per alert as "
             "the body, with alert_sid, signature, alert_action, src_ip, dest_ip, in_iface and "
             "proto as structured metadata. Note the destination key is `dest_ip`, Suricata's own "
             "spelling, not `dst_ip` — the firewall log lane uses the other one. Open the log "
             "details on a line to filter on any of them.",
        w=24,
    )

    b.tab("IDS/IPS", [
        b.autogrid_row("Suricata Overview", [status, ips, promisc, rules, logfiles], present="has_ids"),
        b.row("eve Log Files", [log_sizes], present="has_ids"),
        b.row("Rulesets", [ruleset_state, ruleset_table], present="has_ids"),
        b.row("Alert Activity", [recent], present="has_ids_alerts"),
        # #523: EVE events by type/action/severity, moved here from the retired
        # Observability domain. It reads beside Alert Activity: that one is the
        # exporter's alert-log sample, this one is every event Suricata emitted.
        log_events.ids_row(b),
        # Collapsed (#422): cold-load cost is round-trip COUNT, and these are range
        # queries over a per-alert stream. The row is also the tab's drill-down —
        # opened after the metric panels above have raised a question, not before.
        b.row("Alert Records", [ids_gaps, ids_alert_rate, ids_signatures, ids_alert_raw],
              present="has_ids_logs", collapse=True),
    ])
