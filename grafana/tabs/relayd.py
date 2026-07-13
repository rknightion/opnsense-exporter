"""
Relayd tab — relayd (redirect/relay) load balancer health metrics
(opnsense_relayd_*).

Plugin-gated: tab hidden unless os-relayd is installed AND has at least one
virtual server configured (relayd stays stopped with "no actions, nothing to
do" until a real topology exists — see FetchRelaydStatus). All metrics are
gauges (instantaneous 0/1 health + an availability percentage); there are no
_total counters here.
"""

from builder import Builder, sel, UPDOWN


def build(b: Builder):
    b.sentinel("has_relayd",
               "label_values(opnsense_relayd_virtualserver_status, __name__)")

    # ------------------------------------------------------------------ #
    # Row 1: Overview                                                     #
    # ------------------------------------------------------------------ #
    vs_active = b.stat(
        "Virtual Servers Active",
        f'sum({sel("opnsense_relayd_virtualserver_status")})',
        unit="short", w=6, h=4,
        desc="Number of relayd redirects/relays currently active.",
    )
    tables_active = b.stat(
        "Tables Active",
        f'sum({sel("opnsense_relayd_table_active")})',
        unit="short", w=6, h=4,
        desc="Number of relayd tables currently active (have at least one host).",
    )
    hosts_up = b.stat(
        "Hosts Up",
        f'sum({sel("opnsense_relayd_host_up")})',
        unit="short", w=6, h=4,
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        desc="Number of table member hosts currently passing health checks.",
    )
    hosts_total = b.stat(
        "Hosts Configured",
        f'count({sel("opnsense_relayd_host_up")})',
        unit="short", w=6, h=4,
        desc="Total number of table member hosts relayd is tracking.",
    )

    # ------------------------------------------------------------------ #
    # Row 2: Virtual Server & Table Status                                #
    # ------------------------------------------------------------------ #
    vs_timeline = b.statetimeline(
        "Virtual Server Status",
        [(sel("opnsense_relayd_virtualserver_status"), "{{name}} ({{type}})")],
        UPDOWN, w=24, h=8,
        desc="Relayd virtual server (redirect/relay) status over time (1 = active, 0 = otherwise).",
    )
    table_timeline = b.statetimeline(
        "Table Status",
        [(sel("opnsense_relayd_table_active"), "{{virtualserver}} / {{table}}")],
        UPDOWN, w=24, h=8,
        desc="Relayd table status over time (1 = active with at least one host, 0 = otherwise).",
    )

    # ------------------------------------------------------------------ #
    # Row 3: Host Health                                                  #
    # ------------------------------------------------------------------ #
    host_timeline = b.statetimeline(
        "Host Health",
        [(sel("opnsense_relayd_host_up"), "{{host}} ({{address}}) — {{virtualserver}}/{{table}}")],
        UPDOWN, w=24, h=8,
        desc="Relayd table host health check status over time (1 = up, 0 = otherwise).",
    )
    host_table = b.table(
        "Host Details",
        [
            sel("opnsense_relayd_host_up"),
            sel("opnsense_relayd_host_availability_percent"),
        ],
        w=24, h=10,
        excludes=["__name__", "job", "instance"],
        renames={
            "virtualserver": "Virtual Server",
            "table": "Table",
            "host": "Host",
            "address": "Address",
            "Value #A": "Up",
            "Value #B": "Availability %",
        },
        unit_overrides={"Value #B": "percent"},
        sort_by="Virtual Server",
        desc=(
            "Current up/down state and availability percentage for every relayd "
            "table host. Availability is omitted when relayd has not yet run a "
            "health check against that host."
        ),
    )

    b.tab("Relayd", [
        b.row("Relayd Overview",
              [vs_active, tables_active, hosts_up, hosts_total],
              present="has_relayd"),
        b.row("Virtual Server & Table Status",
              [vs_timeline, table_timeline],
              present="has_relayd"),
        b.row("Host Health",
              [host_timeline, host_table],
              present="has_relayd"),
    ])
