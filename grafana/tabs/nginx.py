"""
Nginx tab — nginx VTS (vhost_traffic_status) metrics via os-nginx plugin
(opnsense_nginx_*).

Plugin-gated: tab hidden unless nginx VTS metrics are present.
If the nginx service is stopped or VTS yields nothing the plugin returns 404
on the VTS endpoint so ALL metrics are absent (fully silent; the tab hides).

Counters (connections_accepted_total, connections_handled_total,
requests_total, server_zone_requests_total, server_zone_bytes_in/out_total,
server_zone_responses_total, server_zone_cache_responses_total,
server_zone_request_seconds_total, upstream_server_requests_total,
upstream_server_bytes_in/out_total, upstream_server_responses_total,
upstream_server_request/response_seconds_total, cache_zone_bytes_in/out_total,
cache_zone_responses_total) are cumulative -> rate().
Gauges shown raw: service_running, connections_active/reading/writing/waiting,
shared_memory_*, upstream_server_down, upstream_server_response_time_seconds,
cache_zone_max/used_bytes, config_load_timestamp_seconds, bans,
ban_last_timestamp_seconds.

Cache zone metrics (#200) are additionally gated on has_nginx_cache: a vts
build without the cache-status extension, or a box with no proxy_cache_path
configured, never emits opnsense_nginx_cache_zone_* nor
server_zone_cache_responses_total, so that row hides independently of the
rest of the tab.
"""

from builder import Builder, sel, epoch_ms, RATE, RUNSTOP, DOWNUP


def build(b: Builder):
    b.sentinel("has_nginx", metric="opnsense_nginx_connections_active")
    b.sentinel("has_nginx_cache", metric="opnsense_nginx_cache_zone_max_bytes")

    # ------------------------------------------------------------------ #
    # Row 1: nginx Overview                                                #
    # ------------------------------------------------------------------ #
    svc = b.stat(
        "Nginx Service",
        sel("opnsense_nginx_service_running"),
        mappings=RUNSTOP, color_mode="background",
        thresholds=[{"color": "red", "value": None}, {"color": "green", "value": 1}],
        w=4, h=4,
        desc="Nginx service state (1 = running, 0 = stopped).",
    )
    active = b.stat(
        "Active Connections",
        sel("opnsense_nginx_connections_active"),
        unit="short", w=4, h=4,
        desc="Total number of active connections (including reading/writing/waiting).",
    )
    req_rate = b.ts(
        "Request Rate",
        [(f'rate({sel("opnsense_nginx_requests_total")}[{RATE}])', "requests/s")],
        unit="reqps", w=8, h=4,
        desc="Total HTTP request rate across all server zones.",
    )
    conn_gauges = b.ts(
        "Connection States",
        [
            (sel("opnsense_nginx_connections_reading"), "reading"),
            (sel("opnsense_nginx_connections_writing"), "writing"),
            (sel("opnsense_nginx_connections_waiting"), "waiting"),
        ],
        unit="short", w=8, h=4,
        desc="Current reading/writing/waiting connection states.",
    )
    conn_rate = b.ts(
        "Connection Accept/Handle Rate",
        [
            (f'rate({sel("opnsense_nginx_connections_accepted_total")}[{RATE}])',
             "accepted/s"),
            (f'rate({sel("opnsense_nginx_connections_handled_total")}[{RATE}])',
             "handled/s"),
        ],
        unit="ops", w=8, h=4,
        desc="Connection accept and handle rates (accepted - handled = dropped).",
    )

    # ------------------------------------------------------------------ #
    # Row 2: Shared Memory                                                 #
    # ------------------------------------------------------------------ #
    shm_max = b.stat(
        "Shared Memory Max",
        sel("opnsense_nginx_shared_memory_max_bytes"),
        unit="bytes", w=4, h=4,
        desc="Maximum VTS shared memory zone size in bytes.",
    )
    shm_used = b.stat(
        "Shared Memory Used",
        sel("opnsense_nginx_shared_memory_used_bytes"),
        unit="bytes", w=4, h=4,
        desc="Current VTS shared memory usage in bytes.",
    )
    shm_nodes = b.stat(
        "Shared Memory Nodes",
        sel("opnsense_nginx_shared_memory_used_nodes"),
        unit="short", w=4, h=4,
        desc="Number of VTS shared memory nodes in use.",
    )
    shm_util = b.gauge(
        "Shared Memory Utilization",
        f'100 * {sel("opnsense_nginx_shared_memory_used_bytes")} '
        f'/ {sel("opnsense_nginx_shared_memory_max_bytes")}',
        unit="percent", w=4, h=6,
        thresholds=[
            {"color": "green", "value": None},
            {"color": "orange", "value": 70},
            {"color": "red", "value": 90},
        ],
    )

    # ------------------------------------------------------------------ #
    # Row 3: Server Zones                                                  #
    # ------------------------------------------------------------------ #
    zone_req_rate = b.ts(
        "Server Zone Request Rate",
        [(f'rate({sel("opnsense_nginx_server_zone_requests_total")}[{RATE}])',
          "{{zone}}")],
        unit="reqps", w=12, h=8,
        desc="HTTP request rate per server zone (aggregate zone '*' excluded).",
    )
    zone_bytes = b.ts(
        "Server Zone Throughput",
        [
            (f'rate({sel("opnsense_nginx_server_zone_bytes_in_total")}[{RATE}])*8',
             "{{zone}} in"),
            (f'rate({sel("opnsense_nginx_server_zone_bytes_out_total")}[{RATE}])*8',
             "{{zone}} out"),
        ],
        unit="bps", w=12, h=8,
        desc="Server zone bytes in/out per second (×8 for bits).",
    )
    zone_responses = b.ts(
        "Server Zone Responses by Code",
        [(f'rate({sel("opnsense_nginx_server_zone_responses_total")}[{RATE}])',
          "{{zone}} {{code}}")],
        unit="ops", w=24, h=8, stack=True,
        desc="HTTP response rate by status code class (1xx–5xx) per server zone.",
    )
    # #584: correctness of the counters above, not a new traffic signal.
    # nginx-module-vts's own overCounts wrap-detection counter: a non-zero
    # rate here means one of this zone's requests/bytes/response-code
    # counters wrapped, so a rate()/increase() spanning that point on those
    # series is briefly wrong (the same class of correctness gap as 12abef6).
    zone_counter_wraps = b.ts(
        "Server Zone Counter Wraps",
        [(f'rate({sel("opnsense_nginx_server_zone_counter_wraps_total")}[{RATE}])',
          "{{zone}}")],
        unit="ops", w=24, h=6,
        desc=(
            "Rate of detected counter-wrap events per server zone (vhost-traffic-"
            "status's own overCounts field). Normally flat at zero; a nonzero "
            "reading flags a wrap in one of this zone's other counters around "
            "that time, which briefly distorts any rate()/increase() spanning it."
        ),
    )

    # ------------------------------------------------------------------ #
    # Row 4: Upstream Servers                                              #
    # ------------------------------------------------------------------ #
    up_down = b.statetimeline(
        "Upstream Server Down",
        [(sel("opnsense_nginx_upstream_server_down"),
          "{{upstream}}/{{server}}")],
        DOWNUP, w=24, h=8,
        desc="Upstream server down flag over time (1 = down, 0 = up).",
    )
    up_req_rate = b.ts(
        "Upstream Server Request Rate",
        [(f'rate({sel("opnsense_nginx_upstream_server_requests_total")}[{RATE}])',
          "{{upstream}}/{{server}}")],
        unit="reqps", w=8, h=8,
        desc="Request rate per upstream server.",
    )
    up_bytes = b.ts(
        "Upstream Server Throughput",
        [
            (f'rate({sel("opnsense_nginx_upstream_server_bytes_in_total")}[{RATE}])*8',
             "{{upstream}}/{{server}} in"),
            (f'rate({sel("opnsense_nginx_upstream_server_bytes_out_total")}[{RATE}])*8',
             "{{upstream}}/{{server}} out"),
        ],
        unit="bps", w=8, h=8,
        desc="Upstream server bytes in/out per second (×8 for bits).",
    )
    up_resp_time = b.ts(
        "Upstream Server Response Time",
        [(sel("opnsense_nginx_upstream_server_response_time_seconds"),
          "{{upstream}}/{{server}}")],
        unit="s", w=8, h=8,
        desc="Average response time in seconds per upstream server.",
    )
    up_responses = b.ts(
        "Upstream Server Responses by Code",
        [(f'rate({sel("opnsense_nginx_upstream_server_responses_total")}[{RATE}])',
          "{{upstream}}/{{server}} {{code}}")],
        unit="ops", w=24, h=8, stack=True,
        desc="Upstream server HTTP response rate by status code class.",
    )
    up_req_latency = b.ts(
        "Upstream Server Avg Request Time",
        [(f'rate({sel("opnsense_nginx_upstream_server_request_seconds_total")}[{RATE}])'
          f' / rate({sel("opnsense_nginx_upstream_server_requests_total")}[{RATE}])',
          "{{upstream}}/{{server}}")],
        unit="s", w=12, h=8,
        desc="Average request processing time per upstream server, derived from the "
             "cumulative request-time counter (rate/rate — distinct from the "
             "instantaneous responseMsec moving average above).",
    )
    up_resp_latency = b.ts(
        "Upstream Server Avg Response Time",
        [(f'rate({sel("opnsense_nginx_upstream_server_response_seconds_total")}[{RATE}])'
          f' / rate({sel("opnsense_nginx_upstream_server_requests_total")}[{RATE}])',
          "{{upstream}}/{{server}}")],
        unit="s", w=12, h=8,
        desc="Average upstream response time per upstream server, derived from the "
             "cumulative response-time counter (rate/rate).",
    )
    # #584: upstream twin of Server Zone Counter Wraps above.
    upstream_counter_wraps = b.ts(
        "Upstream Server Counter Wraps",
        [(f'rate({sel("opnsense_nginx_upstream_server_counter_wraps_total")}[{RATE}])',
          "{{upstream}}/{{server}}")],
        unit="ops", w=24, h=6,
        desc=(
            "Rate of detected counter-wrap events per upstream server (vhost-"
            "traffic-status's own overCounts field). Normally flat at zero."
        ),
    )

    # ------------------------------------------------------------------ #
    # Row 5: Server Zone Cache Status & Latency                            #
    # ------------------------------------------------------------------ #
    zone_cache_responses = b.ts(
        "Server Zone Cache Status",
        [(f'rate({sel("opnsense_nginx_server_zone_cache_responses_total")}[{RATE}])',
          "{{zone}} {{cache_status}}")],
        unit="ops", w=24, h=8, stack=True,
        desc="Per-server-zone response rate by cache outcome (hit/miss/bypass/…); "
             "only present when this vts build reports cache status.",
    )
    zone_avg_latency = b.ts(
        "Server Zone Avg Request Time",
        [(f'rate({sel("opnsense_nginx_server_zone_request_seconds_total")}[{RATE}])'
          f' / rate({sel("opnsense_nginx_server_zone_requests_total")}[{RATE}])',
          "{{zone}}")],
        unit="s", w=24, h=8,
        desc="Average request processing time per server zone, derived from the "
             "cumulative request-time counter (rate/rate).",
    )

    # ------------------------------------------------------------------ #
    # Row 6: Cache Zones (proxy_cache_path) — hidden with no cache configured
    # ------------------------------------------------------------------ #
    cz_size = b.ts(
        "Cache Zone Size (Max vs Used)",
        [
            (sel("opnsense_nginx_cache_zone_max_bytes"), "{{zone}} max"),
            (sel("opnsense_nginx_cache_zone_used_bytes"), "{{zone}} used"),
        ],
        unit="bytes", w=12, h=8,
        desc="Configured maximum and currently used size of each proxy_cache_path zone.",
    )
    cz_throughput = b.ts(
        "Cache Zone Throughput",
        [
            (f'rate({sel("opnsense_nginx_cache_zone_bytes_in_total")}[{RATE}])*8',
             "{{zone}} in"),
            (f'rate({sel("opnsense_nginx_cache_zone_bytes_out_total")}[{RATE}])*8',
             "{{zone}} out"),
        ],
        unit="bps", w=12, h=8,
        desc="Cache zone bytes in/out per second (×8 for bits).",
    )
    cz_responses = b.ts(
        "Cache Zone Responses by Status",
        [(f'rate({sel("opnsense_nginx_cache_zone_responses_total")}[{RATE}])',
          "{{zone}} {{cache_status}}")],
        unit="ops", w=24, h=8, stack=True,
        desc="Per-cache-zone response rate by cache outcome (hit/miss/bypass/…).",
    )

    # ------------------------------------------------------------------ #
    # Row 7: Config Reload & Autoblock                                     #
    # ------------------------------------------------------------------ #
    reload_ts = b.stat(
        "Last Config Reload",
        epoch_ms(sel("opnsense_nginx_config_load_timestamp_seconds")),
        unit="dateTimeAsIso", w=8, h=4,
        desc="Time of the last nginx config (re)load, as reported by the vts module.",
    )
    bans_stat = b.stat(
        "Active Autoblock Bans",
        sel("opnsense_nginx_bans"),
        unit="short", w=8, h=4,
        thresholds=[{"color": "green", "value": None}, {"color": "orange", "value": 1}],
        desc="Current number of IPs banned by the nginx autoblock cron "
             "(bot User-Agent / request-rate ACL matches).",
    )
    ban_last_ts = b.stat(
        "Last Autoblock Ban",
        epoch_ms(sel("opnsense_nginx_ban_last_timestamp_seconds")),
        unit="dateTimeAsIso", w=8, h=4,
        desc="Time of the most recent autoblock ban.",
    )

    b.tab("Nginx", [
        b.row("Nginx Overview",
              [svc, active, req_rate, conn_gauges, conn_rate],
              present="has_nginx"),
        b.row("Shared Memory",
              [shm_max, shm_used, shm_nodes, shm_util],
              present="has_nginx"),
        b.row("Server Zones",
              [zone_req_rate, zone_bytes, zone_responses, zone_counter_wraps],
              present="has_nginx"),
        b.row("Upstream Servers",
              [up_down, up_req_rate, up_bytes, up_resp_time, up_responses,
               up_req_latency, up_resp_latency, upstream_counter_wraps],
              present="has_nginx"),
        b.row("Server Zone Cache Status & Latency",
              [zone_cache_responses, zone_avg_latency],
              present="has_nginx"),
        b.row("Cache Zones",
              [cz_size, cz_throughput, cz_responses],
              present="has_nginx_cache"),
        b.row("Config Reload & Autoblock",
              [reload_ts, bans_stat, ban_last_ts],
              present="has_nginx"),
    ])
