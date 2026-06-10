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
"""

from builder import Builder, sel, RATE, RUNSTOP, UPDOWN


def build(b: Builder):
    b.sentinel("has_haproxy",
               "label_values(opnsense_haproxy_frontend_status, __name__)")

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
        unit="short", w=8, h=4,
        desc="HAProxy process-level connection and HTTP request rates.",
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
        unit="short", w=12, h=8,
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
        unit="short", w=12, h=8,
        desc="Frontend request errors and denied requests per second.",
    )
    fe_responses = b.ts(
        "Frontend HTTP Responses by Code",
        [(f'rate({sel("opnsense_haproxy_frontend_http_responses_total")}[{RATE}])',
          "{{frontend}} {{code}}")],
        unit="short", w=24, h=8, stack=True,
        desc="Frontend HTTP response rate by status code class (1xx–5xx, other).",
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
        unit="short", w=12, h=8,
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
        unit="short", w=12, h=8,
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
        unit="short", w=24, h=8, stack=True,
        desc="Backend HTTP response rate by status code class (1xx–5xx, other).",
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
            "opnsense_haproxy_server_status": "Status",
            "opnsense_haproxy_server_weight": "Weight",
            "opnsense_haproxy_server_current_sessions": "Sessions",
            "opnsense_haproxy_server_queue_current": "Queue",
        },
        sort_by="Backend",
        desc="Per-server status, weight, active sessions and queue depth.",
    )
    srv_sess_rate = b.ts(
        "Server Session Rate",
        [(f'rate({sel("opnsense_haproxy_server_sessions_total")}[{RATE}])',
          "{{backend}}/{{server}}")],
        unit="short", w=12, h=8,
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
        unit="short", w=24, h=8,
        desc="Server-level error rates, check failures, and downtime accumulation rate.",
    )

    b.tab("HAProxy", [
        b.row("HAProxy Overview",
              [svc, uptime, curr_conns, idle_pct, conn_rate],
              present="has_haproxy"),
        b.row("Frontend Traffic",
              [fe_status, fe_sess_rate, fe_curr_sess,
               fe_bytes, fe_errors, fe_responses],
              present="has_haproxy"),
        b.row("Backend Traffic",
              [be_status, be_sess_rate, be_curr_sess,
               be_bytes, be_errors, be_servers, be_responses],
              present="has_haproxy"),
        b.row("Server Details",
              [srv_status, srv_table, srv_sess_rate, srv_bytes, srv_errors],
              present="has_haproxy"),
    ])
