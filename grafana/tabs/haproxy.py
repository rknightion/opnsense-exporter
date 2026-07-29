"""
HAProxy tab — HAProxy statistics via os-haproxy plugin (opnsense_haproxy_*).

Plugin-gated: tab and all rows hidden unless haproxy metrics are present.

Counters (sessions_total, bytes_in/out_total, request_errors_total,
requests_denied_total, http_responses_total, connections_total,
requests_total, connection_errors_total, response_errors_total,
retries_total, redispatches_total, check_failures_total,
downtime_seconds_total) are cumulative -> rate().
Gauges shown raw: service_running, process_*, frontend/backend/server status,
current_sessions, queue_current, active/backup_servers, weight.

Added for #201 (stick-table occupancy + show-stat latency/health-transition/
capacity fields — several go absent for tcp-mode proxies or older HAProxy
builds and are simply not emitted, never a fabricated 0, so a "no data" panel
is expected in that case):
- connection_limit / ssl_current_connections: process-level capacity gauges.
- frontend_requests_total (rate) / frontend_session_limit (gauge, saturation
  vs current_sessions).
- backend/server *_time_avg_seconds: rolling averages (last 1024 requests) ->
  gauges, shown raw (never rate()'d — they are already an average, not a
  counter).
- backend_selected_total / backend_aborts_total: cumulative -> rate().
- server_check_downs_total: cumulative UP->DOWN transitions -> rate().
- server_last_state_change_seconds: gauge, seconds since last transition
  (ticks up with wall-clock time, resets to ~0 on a transition) — shown raw.
- stick_table_size / stick_table_used: gauges, table occupancy.
"""

from builder import Builder, sel, RATE, RUNSTOP, UPDOWN
from tabs import log_events


def build(b: Builder):
    b.sentinel("has_haproxy", metric="opnsense_haproxy_frontend_status")
    b.sentinel("has_haproxy_stick_tables", metric="opnsense_haproxy_stick_table_size")

    # ------------------------------------------------------------------ #
    # Row 1: HAProxy Overview                                              #
    # ------------------------------------------------------------------ #
    svc = b.stat(
        "HAProxy Service",
        sel("opnsense_haproxy_service_running"),
        mappings=RUNSTOP, color_mode="background",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        w=4, h=4,
        desc="HAProxy service state (1 = running, 0 = stopped).",
    )
    uptime = b.stat(
        "Process Uptime",
        sel("opnsense_haproxy_process_uptime_seconds"),
        unit="s", w=4, h=4,
        desc="HAProxy process uptime in seconds.",
    )
    curr_conns = b.stat(
        "Current Connections",
        sel("opnsense_haproxy_process_current_connections"),
        unit="short", w=4, h=4,
        desc="Current number of connections on the HAProxy process.",
    )
    idle_pct = b.stat(
        "Idle Time %",
        sel("opnsense_haproxy_process_idle_time_percent"),
        unit="percent", w=4, h=4,
        thresholds=[
            {"color": "red", "value": None},
            {"color": "orange", "value": 20},
            {"color": "green", "value": 50},
        ],
        desc="HAProxy process idle time percentage (higher = less loaded).",
    )
    conn_rate = b.ts(
        "Connection & Request Rate",
        [
            (f'rate({sel("opnsense_haproxy_process_connections_total")}[{RATE}])',
             "connections/s"),
            (f'rate({sel("opnsense_haproxy_process_requests_total")}[{RATE}])',
             "requests/s"),
        ],
        unit="reqps", w=8, h=4,
        desc="HAProxy process-level connection and HTTP request rates.",
    )
    conn_capacity = b.ts(
        "Connection Capacity",
        [
            (sel("opnsense_haproxy_process_current_connections"), "current"),
            (sel("opnsense_haproxy_connection_limit"), "limit (Maxconn)"),
            (sel("opnsense_haproxy_ssl_current_connections"), "current SSL"),
        ],
        unit="short", w=12, h=4,
        desc="HAProxy process-wide connection capacity (#201): current vs the "
             "configured Maxconn limit, plus current SSL/TLS connections.",
    )

    # ------------------------------------------------------------------ #
    # Row 2: Frontend Traffic                                              #
    # ------------------------------------------------------------------ #
    fe_status = b.statetimeline(
        "Frontend Status",
        [(sel("opnsense_haproxy_frontend_status"), "{{frontend}}")],
        UPDOWN, w=24, h=6,
        desc="HAProxy frontend status over time (1 = OPEN, 0 = otherwise).",
    )
    fe_sess_rate = b.ts(
        "Frontend Session Rate",
        [(f'rate({sel("opnsense_haproxy_frontend_sessions_total")}[{RATE}])',
          "{{frontend}}")],
        unit="ops", w=12, h=8,
        desc="Cumulative sessions per second per frontend.",
    )
    fe_curr_sess = b.ts(
        "Frontend Current Sessions",
        [(sel("opnsense_haproxy_frontend_current_sessions"), "{{frontend}}")],
        unit="short", w=12, h=8,
        desc="Active sessions on each frontend.",
    )
    fe_bytes = b.ts(
        "Frontend Throughput",
        [
            (f'rate({sel("opnsense_haproxy_frontend_bytes_in_total")}[{RATE}])*8',
             "{{frontend}} in"),
            (f'rate({sel("opnsense_haproxy_frontend_bytes_out_total")}[{RATE}])*8',
             "{{frontend}} out"),
        ],
        unit="bps", w=12, h=8,
        desc="Frontend bytes in/out per second (×8 for bits).",
    )
    fe_errors = b.ts(
        "Frontend Errors & Denied",
        [
            (f'rate({sel("opnsense_haproxy_frontend_request_errors_total")}[{RATE}])',
             "{{frontend}} req errors"),
            (f'rate({sel("opnsense_haproxy_frontend_requests_denied_total")}[{RATE}])',
             "{{frontend}} denied"),
        ],
        unit="ops", w=12, h=8,
        desc="Frontend request errors and denied requests per second.",
    )
    fe_responses = b.ts(
        "Frontend HTTP Responses by Code",
        [(f'rate({sel("opnsense_haproxy_frontend_http_responses_total")}[{RATE}])',
          "{{frontend}} {{code}}")],
        unit="ops", w=24, h=8, stack=True,
        desc="Frontend HTTP response rate by status code class (1xx–5xx, other).",
    )
    fe_req_rate = b.ts(
        "Frontend HTTP Request Rate",
        [(f'rate({sel("opnsense_haproxy_frontend_requests_total")}[{RATE}])',
          "{{frontend}}")],
        unit="reqps", w=12, h=8,
        desc="HTTP requests per second per frontend (#201, req_tot — absent "
             "for tcp-mode frontends).",
    )
    fe_session_limit = b.ts(
        "Frontend Sessions vs Limit",
        [
            (sel("opnsense_haproxy_frontend_current_sessions"), "{{frontend}} current"),
            (sel("opnsense_haproxy_frontend_session_limit"), "{{frontend}} limit"),
        ],
        unit="short", w=12, h=8,
        desc="Current sessions against the configured session limit (#201, "
             "slim) — approaching the limit means new connections start "
             "queuing or getting refused.",
    )

    # ------------------------------------------------------------------ #
    # Row 3: Backend Traffic                                               #
    # ------------------------------------------------------------------ #
    be_status = b.statetimeline(
        "Backend Status",
        [(sel("opnsense_haproxy_backend_status"), "{{backend}}")],
        UPDOWN, w=24, h=6,
        desc="HAProxy backend status over time (1 = UP, 0 = otherwise).",
    )
    be_sess_rate = b.ts(
        "Backend Session Rate",
        [(f'rate({sel("opnsense_haproxy_backend_sessions_total")}[{RATE}])',
          "{{backend}}")],
        unit="ops", w=12, h=8,
        desc="Cumulative sessions per second per backend.",
    )
    be_curr_sess = b.ts(
        "Backend Current Sessions & Queue",
        [
            (sel("opnsense_haproxy_backend_current_sessions"), "{{backend}} sessions"),
            (sel("opnsense_haproxy_backend_queue_current"), "{{backend}} queue"),
        ],
        unit="short", w=12, h=8,
        desc="Active sessions and queued requests on each backend.",
    )
    be_bytes = b.ts(
        "Backend Throughput",
        [
            (f'rate({sel("opnsense_haproxy_backend_bytes_in_total")}[{RATE}])*8',
             "{{backend}} in"),
            (f'rate({sel("opnsense_haproxy_backend_bytes_out_total")}[{RATE}])*8',
             "{{backend}} out"),
        ],
        unit="bps", w=12, h=8,
        desc="Backend bytes in/out per second (×8 for bits).",
    )
    be_errors = b.ts(
        "Backend Error & Retry Rates",
        [
            (f'rate({sel("opnsense_haproxy_backend_connection_errors_total")}[{RATE}])',
             "{{backend}} conn errors"),
            (f'rate({sel("opnsense_haproxy_backend_response_errors_total")}[{RATE}])',
             "{{backend}} resp errors"),
            (f'rate({sel("opnsense_haproxy_backend_retries_total")}[{RATE}])',
             "{{backend}} retries"),
            (f'rate({sel("opnsense_haproxy_backend_redispatches_total")}[{RATE}])',
             "{{backend}} redispatches"),
        ],
        unit="ops", w=12, h=8,
        desc="Backend connection/response error rates, retries, and redispatches.",
    )
    be_servers = b.ts(
        "Backend Active/Backup Servers",
        [
            (sel("opnsense_haproxy_backend_active_servers"), "{{backend}} active"),
            (sel("opnsense_haproxy_backend_backup_servers"), "{{backend}} backup"),
        ],
        unit="short", w=12, h=8,
        desc="Number of active and backup servers per backend.",
    )
    be_responses = b.ts(
        "Backend HTTP Responses by Code",
        [(f'rate({sel("opnsense_haproxy_backend_http_responses_total")}[{RATE}])',
          "{{backend}} {{code}}")],
        unit="ops", w=24, h=8, stack=True,
        desc="Backend HTTP response rate by status code class (1xx–5xx, other).",
    )
    be_latency = b.ts(
        "Backend Latency (avg over last 1024 requests)",
        [
            (sel("opnsense_haproxy_backend_queue_time_avg_seconds"), "{{backend}} queue"),
            (sel("opnsense_haproxy_backend_connect_time_avg_seconds"), "{{backend}} connect"),
            (sel("opnsense_haproxy_backend_response_time_avg_seconds"), "{{backend}} response"),
            (sel("opnsense_haproxy_backend_total_time_avg_seconds"), "{{backend}} total"),
        ],
        unit="s", w=12, h=8,
        desc="Rolling average queue/connect/response/total time per backend "
             "(#201, qtime/ctime/rtime/ttime) — a rising queue time with "
             "current_sessions climbing signals the backend is saturating.",
    )
    be_selected_aborts = b.ts(
        "Backend Selections & Aborts",
        [
            (f'rate({sel("opnsense_haproxy_backend_selected_total")}[{RATE}])',
             "{{backend}} selected"),
            (f'rate({sel("opnsense_haproxy_backend_aborts_total")}[{RATE}])',
             "{{backend}} {{side}} aborts"),
        ],
        unit="ops", w=12, h=8,
        desc="Load-balancer selection rate (#201, lbtot) and client/server "
             "abort rate (cli_abrt/srv_abrt) per backend.",
    )

    # ------------------------------------------------------------------ #
    # Row 4: Server Details                                                #
    # ------------------------------------------------------------------ #
    srv_status = b.statetimeline(
        "Server Status",
        [(sel("opnsense_haproxy_server_status"), "{{backend}}/{{server}}")],
        UPDOWN, w=24, h=8,
        desc="Individual server status over time (1 = UP, 0 = DOWN/MAINT/DRAIN).",
    )
    srv_table = b.table(
        "Server Details",
        [
            sel("opnsense_haproxy_server_status"),
            sel("opnsense_haproxy_server_weight"),
            sel("opnsense_haproxy_server_current_sessions"),
            sel("opnsense_haproxy_server_queue_current"),
        ],
        w=24, h=10,
        excludes=["__name__", "job", "instance"],
        renames={
            "backend": "Backend",
            "server": "Server",
            "Value #A": "Status",
            "Value #B": "Weight",
            "Value #C": "Sessions",
            "Value #D": "Queue",
        },
        sort_by="Backend",
        desc="Per-server status, weight, active sessions and queue depth.",
    )
    srv_sess_rate = b.ts(
        "Server Session Rate",
        [(f'rate({sel("opnsense_haproxy_server_sessions_total")}[{RATE}])',
          "{{backend}}/{{server}}")],
        unit="ops", w=12, h=8,
        desc="Sessions per second per server.",
    )
    srv_bytes = b.ts(
        "Server Throughput",
        [
            (f'rate({sel("opnsense_haproxy_server_bytes_in_total")}[{RATE}])*8',
             "{{backend}}/{{server}} in"),
            (f'rate({sel("opnsense_haproxy_server_bytes_out_total")}[{RATE}])*8',
             "{{backend}}/{{server}} out"),
        ],
        unit="bps", w=12, h=8,
        desc="Server bytes in/out per second (×8 for bits).",
    )
    srv_errors = b.ts(
        "Server Error & Downtime Rates",
        [
            (f'rate({sel("opnsense_haproxy_server_connection_errors_total")}[{RATE}])',
             "{{backend}}/{{server}} conn errors"),
            (f'rate({sel("opnsense_haproxy_server_response_errors_total")}[{RATE}])',
             "{{backend}}/{{server}} resp errors"),
            (f'rate({sel("opnsense_haproxy_server_check_failures_total")}[{RATE}])',
             "{{backend}}/{{server}} check failures"),
            (f'rate({sel("opnsense_haproxy_server_downtime_seconds_total")}[{RATE}])',
             "{{backend}}/{{server}} downtime rate"),
        ],
        unit="ops", w=24, h=8,
        desc="Server-level error rates, check failures, and downtime accumulation rate.",
    )
    srv_latency = b.ts(
        "Server Latency (avg over last 1024 requests)",
        [
            (sel("opnsense_haproxy_server_queue_time_avg_seconds"), "{{backend}}/{{server}} queue"),
            (sel("opnsense_haproxy_server_connect_time_avg_seconds"), "{{backend}}/{{server}} connect"),
            (sel("opnsense_haproxy_server_response_time_avg_seconds"), "{{backend}}/{{server}} response"),
            (sel("opnsense_haproxy_server_total_time_avg_seconds"), "{{backend}}/{{server}} total"),
        ],
        unit="s", w=12, h=8,
        desc="Rolling average queue/connect/response/total time per server (#201).",
    )
    srv_health_transitions = b.ts(
        "Server Health Transitions",
        [
            (f'rate({sel("opnsense_haproxy_server_check_downs_total")}[{RATE}])',
             "{{backend}}/{{server}} down transitions/s"),
            (sel("opnsense_haproxy_server_last_state_change_seconds"),
             "{{backend}}/{{server}} time since change"),
        ],
        unit="s", w=12, h=8,
        # The panel unit belongs to lastchg; without this override the chkdown RATE is
        # formatted as a duration, so one transition a minute reads "16.7 ms" (#513).
        overrides=[{"matcher": {"id": "byRegexp", "options": ".*down transitions/s$"},
             "properties": [{"id": "unit", "value": "short"}]}],
        desc="UP->DOWN health-check transition rate (#201, chkdown) and "
             "seconds since the last state change (lastchg, resets on every "
             "transition) — a low 'time since change' value alongside "
             "server_status flapping is a failing health check.",
    )

    # ------------------------------------------------------------------ #
    # Row 5: Stick Tables (#201) — only present when at least one frontend#
    # or backend has `stick-table` configured.                             #
    # ------------------------------------------------------------------ #
    stick_table_occupancy = b.ts(
        "Stick Table Occupancy",
        [
            (sel("opnsense_haproxy_stick_table_used"), "{{table}} ({{type}}) used"),
            (sel("opnsense_haproxy_stick_table_size"), "{{table}} ({{type}}) size"),
        ],
        unit="short", w=16, h=8,
        desc="Stick-table entry count vs configured maximum size (#201) — a "
             "table pinned at size silently stops tracking new entries, "
             "which degrades rate limiting / stickiness with no other signal.",
    )
    stick_table_table = b.table(
        "Stick Tables",
        [
            sel("opnsense_haproxy_stick_table_size"),
            sel("opnsense_haproxy_stick_table_used"),
        ],
        w=8, h=8,
        excludes=["__name__", "job", "instance"],
        renames={
            "table": "Table",
            "type": "Type",
            "Value #A": "Size",
            "Value #B": "Used",
        },
        sort_by="Table",
        desc="Configured stick tables with their type, size and current entry count.",
    )

    b.tab("HAProxy", [
        b.row("HAProxy Overview",
              [svc, uptime, curr_conns, idle_pct, conn_rate, conn_capacity],
              present="has_haproxy"),
        b.row("Frontend Traffic",
              [fe_status, fe_sess_rate, fe_curr_sess,
               fe_bytes, fe_errors, fe_responses,
               fe_req_rate, fe_session_limit],
              present="has_haproxy"),
        b.row("Backend Traffic",
              [be_status, be_sess_rate, be_curr_sess,
               be_bytes, be_errors, be_servers, be_responses,
               be_latency, be_selected_aborts],
              present="has_haproxy"),
        b.row("Server Details",
              [srv_status, srv_table, srv_sess_rate, srv_bytes, srv_errors,
               srv_latency, srv_health_transitions],
              present="has_haproxy"),
        b.row("Stick Tables",
              [stick_table_occupancy, stick_table_table],
              present="has_haproxy_stick_tables"),
        # #523: log-derived HAProxy events, moved here from the retired Observability
        # domain. Gated on its own sentinel because the stats socket and the syslog
        # stream are independently available — a box can have one without the other.
        log_events.haproxy_row(b),
    ])
