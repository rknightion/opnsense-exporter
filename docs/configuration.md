---
title: Configuration
description: Complete reference for all OPNsense Exporter CLI flags, environment variables, and collector switches
tags:
  - Configuration
---

# Configuration

The OPNsense Exporter follows standard Prometheus ecosystem conventions. It can be configured using command-line flags, environment variables, or a combination of both. Environment variables take the prefix `OPNSENSE_EXPORTER_` unless noted otherwise.

The flag tables on this page are generated from the exporter's own flag definitions by `make docs`, so they always match the binary. The definitions themselves live in
[`internal/options/` on GitHub](https://github.com/rknightion/opnsense-exporter/tree/main/internal/options).

## OPNsense connection

These settings control how the exporter connects to the OPNsense API.

<!-- docgen:begin:flags-connection -->
| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--opnsense.address` | `OPNSENSE_EXPORTER_OPS_API` | -- | **Required.** Hostname or IP address of OPNsense API |
| `--opnsense.api-key` | `OPNSENSE_EXPORTER_OPS_API_KEY` | -- | API key to use to connect to OPNsense API. This flag/ENV or the OPS_API_KEY_FILE may be set. |
| `--opnsense.api-secret` | `OPNSENSE_EXPORTER_OPS_API_SECRET` | -- | API secret to use to connect to OPNsense API. This flag/ENV or the OPS_API_SECRET_FILE may be set. |
| `--opnsense.insecure` | `OPNSENSE_EXPORTER_OPS_INSECURE` | `false` | Disable TLS certificate verification |
| `--opnsense.max-concurrent-requests` | `OPNSENSE_EXPORTER_OPS_MAX_CONCURRENT_REQUESTS` | `16` | Maximum number of background OPNsense API requests in flight across all scheduled collector polls, including nested sub-requests. Bounds the simultaneous PHP/configd load on the firewall: lower it (e.g. 4-8) to protect a low-power appliance at the cost of queued or longer polls; raise it to let more independent polls progress concurrently on capable hardware. It does not affect /metrics replay. Must be >= 1. |
| `--opnsense.max-retries` | `OPNSENSE_EXPORTER_OPS_MAX_RETRIES` | `3` | Number of attempts for a failed OPNsense API request (transport errors / retryable 5xx). Worst-case block time is --opnsense.timeout x this value. |
| `--opnsense.protocol` | `OPNSENSE_EXPORTER_OPS_PROTOCOL` | -- | **Required.** Protocol to use to connect to OPNsense API. One of: [http, https] |
| `--opnsense.timeout` | `OPNSENSE_EXPORTER_OPS_TIMEOUT` | `15s` | Per-request HTTP timeout for calls to the OPNsense API. Combined with --opnsense.max-retries this bounds one endpoint attempt sequence inside a background collector poll (timeout x retries). Keep that product below --exporter.max-scrape-duration so the poll deadline, rather than a request retry, remains the outer bound. Prometheus scrape_timeout applies only to replaying /metrics. |
<!-- docgen:end:flags-connection -->

!!! note
    `--opnsense.api-key` / `--opnsense.api-secret` are not marked required because the
    file-based secrets below are an alternative source - but one of the two must be set
    for each credential. See [Security: File-based secrets](security.md#file-based-secrets).

### File-based secrets

In containers and orchestrated environments, credentials can be read from files:

| Env Var | Description |
|---------|-------------|
| `OPS_API_KEY_FILE` | Path to a file containing the API key (first line is read) |
| `OPS_API_SECRET_FILE` | Path to a file containing the API secret (first line is read) |

!!! note
    These environment variables do **not** use the `OPNSENSE_EXPORTER_` prefix. They are checked first: if a file-based secret is set and non-empty, it takes precedence over the flag/env var value.

## Exporter settings

<!-- docgen:begin:flags-exporter -->
| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--collector.health-poll-interval` | `OPNSENSE_EXPORTER_COLLECTOR_HEALTH_POLL_INTERVAL` | `60s` | Interval at which the exporter polls the OPNsense health endpoint (#386). This is the circuit-breaker cadence: the health poll sets and clears the process-wide 'firewall unreachable' flag, so it bounds how quickly collectors resume after the box recovers. Independent of --collector.poll-interval since #386, which previously controlled it by accident. Clamped to [5s, 15m]. |
| `--collector.poll-interval` | `OPNSENSE_EXPORTER_COLLECTOR_POLL_INTERVAL` | `60s` | Default interval at which each collector polls the OPNsense API into the in-memory snapshot that /metrics and the OTLP bridge replay (#336). A collector may declare its own faster/slower tier; every interval is clamped to [5s, 15m]. |
| `--collector.poll-interval-override` | `OPNSENSE_EXPORTER_COLLECTOR_POLL_INTERVAL_OVERRIDE` | -- | Override a specific collector's poll interval as <collector>=<duration> (repeatable; clamped to [5s, 15m]). Wins over the collector's built-in tier. Example: --collector.poll-interval-override=gateways=10s --collector.poll-interval-override=smart=1h. |
| `--config.check` | -- | -- | Validate the effective configuration and exit, without binding any port, starting the poll scheduler, contacting OPNsense, or exporting telemetry. Exits 0 when the configuration is usable and 1 otherwise. Referenced files (API key/secret, TLS keypairs) are read; network reachability is deliberately not checked (that is what /-/ready is for). Has no env var by design: an ambient one would turn every start into a no-op. |
| `--exporter.cache-ttl` | `OPNSENSE_EXPORTER_CACHE_TTL` | `1h0m0s` | How long to cache responses from slow-moving API endpoints (system/CPU identity, certificate inventory, Unbound DNS blocklist policy config) and to remember that a plugin-gated endpoint is absent (its 404). This data changes only on an admin action - a config edit, a certificate renewal, a plugin install - so re-fetching it on every poll only costs firewall CPU. Set it above the collector poll interval or it can never serve a hit. The cost is staleness: a newly installed plugin, or a cert change, can take up to this long to show up. Set to 0 to fetch everything on every poll. Live data (counters, rates, service run-state) is never cached regardless of this setting. |
| `--exporter.firmware-cache-ttl` | `OPNSENSE_EXPORTER_FIRMWARE_CACHE_TTL` | `12h0m0s` | How long to cache firmware API responses (status and, when enabled, package details). The firmware data OPNsense serves is the stored result of the box's own update check, which it refreshes roughly daily, so re-fetching it on every poll only costs firewall CPU. Set to 0 to fetch on every poll. |
| `--exporter.ids-alert-lookback` | `OPNSENSE_EXPORTER_IDS_ALERT_LOOKBACK` | `15m` | Lookback window over which opnsense_ids_recent_alerts counts Suricata eve alerts (a gauge). Only used when --exporter.enable-ids-alerts is set. Counts are a floor when more than 500 alerts fall inside the window. |
| `--exporter.instance-label` | `OPNSENSE_EXPORTER_INSTANCE_LABEL` | -- | Label to use to identify the instance in every metric. If you have multiple instances of the exporter, you can differentiate them by using different value in this flag, that represents the instance of the target OPNsense. If left empty, it defaults to the configured OPNsense address (deterministic). Set --exporter.instance-use-hostname to derive it from the OPNsense hostname instead. |
| `--exporter.instance-use-hostname` | `OPNSENSE_EXPORTER_INSTANCE_USE_HOSTNAME` | `false` | When --exporter.instance-label is empty, derive the instance label from the OPNsense hostname reported by the API instead of the configured address. This lookup is deterministic: it blocks at startup and, if the hostname cannot be obtained, the exporter refuses to start (rather than silently falling back to the address, which would make the label depend on startup timing and flip between restarts). |
| `--exporter.max-scrape-duration` | `OPNSENSE_EXPORTER_MAX_SCRAPE_DURATION` | `50s` | Upper bound on a single collector poll (#336). Since serving /metrics now replays an in-memory snapshot rather than calling the API, this bounds each background poll so a stalled/blackholed endpoint frees its poll-concurrency slot instead of holding it open. Serving itself is never blocked by it. |
| `--flow.correlate` | `OPNSENSE_EXPORTER_FLOW_CORRELATE` | `true` | Correlate NetFlow fragments and Zenarmor conn documents into one merged flow record per connection-window. A pass-through when only one source is present. Off emits NetFlow records raw and per-fragment. |
| `--flow.correlate.max-entries` | `OPNSENSE_EXPORTER_FLOW_CORRELATE_MAX_ENTRIES` | `50000` | Hard cap on live correlator entries. At the cap the oldest is force-emitted (never dropped) and counted. The NetFlow ingress is unauthenticated, so this bounds memory against a flood. 0 is unbounded (unwise with the listener on). |
| `--flow.correlate.window` | `OPNSENSE_EXPORTER_FLOW_CORRELATE_WINDOW` | `3m` | How long the correlator holds a connection-window before emitting. Also the maximum a flow log is delayed. NetFlow export lag runs to ~30m for long flows (#346), so a flow whose records straddle the window emits a partial per window rather than one joined record. |
| `--flow.dns-cache.size` | `OPNSENSE_EXPORTER_FLOW_DNS_CACHE_SIZE` | `50000` | Entries in the DNS answer cache that gives a flow to a bare IP its dst.domain, fed by the Zenarmor dns family. Over the cap it stops inserting rather than evicting hot entries. 0 disables domain enrichment. |
| `--flow.enabled` | `OPNSENSE_EXPORTER_FLOW_ENABLED` | `true` | Enable flow rollups: bounded byte and packet volume counters derived from flow records. Costs nothing where no flow source is configured - the metrics are simply silent, like log_events without the syslog receiver. Set --exporter.disable-flow to remove the collector entirely. |
| `--flow.log-mode` | `OPNSENSE_EXPORTER_FLOW_LOG_MODE` | `per_flow` | Flow log emission: "per_flow" ships one OTLP log record per correlated flow on the shared log pipeline; "off" ships none while still deriving all metrics. Zenarmor conn documents ship on their own lane regardless. |
| `--flow.max-keys` | `OPNSENSE_EXPORTER_FLOW_MAX_KEYS` | `2500` | Maximum distinct label combinations the flow accumulator tracks in memory. A separate bound from --flow.top-n: this caps memory between scrapes, that caps emitted series. Combinations first seen at the cap fold into __other__ and are counted by opnsense_flow_rollup_capped_total. 0 is unbounded. |
| `--flow.max-logs-per-window` | `OPNSENSE_EXPORTER_FLOW_MAX_LOGS_PER_WINDOW` | `0` | Cap on flow log records shipped per minute; excess is TRUNCATED (never sampled) and counted. A flood guard on the unauthenticated NetFlow ingress. 0 is unlimited. Metrics are never truncated. |
| `--flow.netflow.allowed-peers` | `OPNSENSE_EXPORTER_FLOW_NETFLOW_ALLOWED_PEERS` | -- | CIDR allowlist of exporters permitted to send flow records, repeatable. Empty means accept from anyone, which is a deliberate decision to trust the network rather than a default to drift into: anything that can reach the port can inject flow records. |
| `--flow.netflow.debug-capture` | `OPNSENSE_EXPORTER_FLOW_NETFLOW_DEBUG_CAPTURE` | `off` | Dump raw NetFlow datagrams to --logs.debug-capture.dir. "unidentified" writes only datagrams carrying something the decoder could not interpret (an unmodelled template element, an options template, an unknown flowset, or a datagram that would not decode at all) - cheap, and the mode worth leaving on. "all" writes every datagram, for regenerating a replay fixture or measuring the export; deliberately heavy, bounded only by --logs.debug-capture.max-bytes. Requires --flow.netflow.enabled and the shared dir. |
| `--flow.netflow.enabled` | `OPNSENSE_EXPORTER_FLOW_NETFLOW_ENABLED` | `false` | Enable the NetFlow v5/v9 receiver. Opens an UNAUTHENTICATED UDP socket: NetFlow has no authentication of any kind, so restrict it with --flow.netflow.allowed-peers or by firewalling the port. Requires --flow.enabled. |
| `--flow.netflow.ifindex-map` | `OPNSENSE_EXPORTER_FLOW_NETFLOW_IFINDEX_MAP` | -- | Override the derived NetFlow ifIndex-to-device map, as comma-separated index=device pairs (e.g. "1=ixl0,5=igb0,13=ixl0_vlan50"). Entries listed here beat the derived map; indices not listed still use it, so pin every index that carries traffic. Read yours off the box with: ifinfo \| awk '$1 == "Interface" { n++; print n, $2 }' - that is the whole enumeration. ngctl list \| grep netflow shows only the interfaces netflow captures, and an egress index can legitimately name one it does not. |
| `--flow.netflow.listen` | `OPNSENSE_EXPORTER_FLOW_NETFLOW_LISTEN` | `:2055` | Address the NetFlow receiver binds, host:port. Bound eagerly at startup, so a port already in use is a startup error rather than a receiver that is silently never there. |
| `--flow.top-n` | `OPNSENSE_EXPORTER_FLOW_TOP_N` | `1000` | Maximum flow series emitted per scrape. Everything beyond folds into a single __other__ series per source, so the family still sums exactly at any limit. 0 emits every tracked combination. |
| `--flow.top-talkers` | `OPNSENSE_EXPORTER_FLOW_TOP_TALKERS` | `false` | Emit opnsense_flow_top_talker_bytes_total: bytes per internal host and direction, top-N with an __other__ remainder. OFF by default because the host label is high cardinality; the top-N bounds it but a host label is still one series per host. |
| `--flow.zenarmor` | `OPNSENSE_EXPORTER_FLOW_ZENARMOR` | `true` | Derive flow records from the Zenarmor receiver's conn documents. Adds no new log records to Loki: the conn document ships exactly as before and this only feeds the metric rollup. Requires --logs.zenarmor.enabled to produce anything. |
| `--log.format` | -- | `logfmt` | Output format of log messages. One of: [logfmt, json] |
| `--log.level` | -- | `info` | Only log messages with the given severity or above. One of: [debug, info, warn, error] |
| `--logs.batch-max` | `OPNSENSE_EXPORTER_LOGS_BATCH_MAX` | `1000` | Maximum number of records the emitter hands to the sink per batch. |
| `--logs.buffer-max-bytes` | `OPNSENSE_EXPORTER_LOGS_BUFFER_MAX_BYTES` | `134217728` | Aggregate byte budget for the in-memory backpressure queue. The record-count cap (--logs.buffer-size) alone does not bound memory: a receiver preserves each record's raw body, so a few large records can outweigh thousands of small ones. On overflow the oldest record is dropped and counted, exactly as for the count cap. 0 disables the byte budget. |
| `--logs.buffer-size` | `OPNSENSE_EXPORTER_LOGS_BUFFER_SIZE` | `4096` | Capacity of the in-memory backpressure queue between pollers and the sink. On overflow the oldest record is dropped and counted (logs_dropped_total). |
| `--logs.crowdsec.enabled` | `OPNSENSE_EXPORTER_LOGS_CROWDSEC_ENABLED` | `false` | Enable the crowdsec log source: ships CrowdSec alert and decision records to Loki (there is no native syslog path for these - the plugin registers no syslog scope; alerts live only in the LAPI). Requires --logs.enabled. Polls at a 60s floor regardless of --logs.poll-interval. Silent when the os-crowdsec plugin is absent. Off by default. |
| `--logs.debug-capture.dir` | `OPNSENSE_EXPORTER_LOGS_DEBUG_CAPTURE_DIR` | -- | Directory to dump UNMODELLED receiver signals into for inspection, as NDJSON under <dir>/<receiver>/ (files are 0600 and carry real network data - addresses, DNS queries, TLS SNI, HTTP hosts). Off unless set. Enable capture per receiver with --logs.zenarmor.debug-capture / --logs.syslog.debug-capture. Point a writable bind mount here; only signals the exporter cannot model are written, never the full stream. |
| `--logs.debug-capture.max-bytes` | `OPNSENSE_EXPORTER_LOGS_DEBUG_CAPTURE_MAX_BYTES` | `256MiB` | Total size cap for --logs.debug-capture.dir (e.g. 256MiB, 1GB). Capture STOPS when the dir reaches this, keeping the oldest samples; it never deletes to make room, so a debug capture can never fill the disk. Counts bytes left by previous runs. |
| `--logs.enabled` | `OPNSENSE_EXPORTER_LOGS_ENABLED` | `false` | Enable the opt-in log/event shipping pipeline (polls OPNsense event APIs and ships to Loki via OTLP). Off by default. Independent of --otlp.enabled (which gates metrics). |
| `--logs.ids.enabled` | `OPNSENSE_EXPORTER_LOGS_IDS_ENABLED` | `false` | Enable the IDS (Suricata EVE alert) log source: ships full Suricata alert records polled via ids/service/query_alerts. Off by default. Requires --logs.enabled. If the box already forwards EVE JSON via syslog (ids.general.syslog_eve), prefer that native path instead of also enabling this source - do not ship the same alerts twice. |
| `--logs.max-metric-keys` | `OPNSENSE_EXPORTER_LOGS_MAX_METRIC_KEYS` | `5000` | Maximum distinct label tuples retained per derived log_events metric family. Receivers are push-based and syslog over UDP has a spoofable source, so tuple values are sender-controlled: without this bound a sender can grow process-lifetime metric state without limit. Tuples beyond the cap fold into a counted overflow series rather than being dropped silently. 0 disables the cap. |
| `--logs.max-record-bytes` | `OPNSENSE_EXPORTER_LOGS_MAX_RECORD_BYTES` | `1048576` | Maximum estimated retained size for a single record - its body, source and attributes plus a fixed overhead allowance, measured the same way as --logs.buffer-max-bytes so the two read against one number. A record larger than this is rejected at ingest and counted rather than queued, so one oversized record cannot occupy the whole queue budget or become a batch the sink permanently refuses. 0 disables the per-record cap. |
| `--logs.poll-interval` | `OPNSENSE_EXPORTER_LOGS_POLL_INTERVAL` | `10s` | Base interval between event polls per source (floor 5s). Sources may raise their own floor. |
| `--logs.ship-max-attempts` | `OPNSENSE_EXPORTER_LOGS_SHIP_MAX_ATTEMPTS` | `10` | Maximum delivery attempts for one batch before it is dropped and counted (logs_dropped_total{reason="ship_failed_permanent"}). Retries are exponentially backed off. Without this bound a batch the sink permanently refuses is retried forever by the single emitter goroutine, wedging all subsequent delivery. 0 restores unlimited retries. |
| `--logs.sink` | `OPNSENSE_EXPORTER_LOGS_SINK` | `otlp` | Log shipping sink: otlp (OTLP logs, reuses the --otlp.* transport) or stdout (one JSON line per event). |
| `--logs.state-file` | `OPNSENSE_EXPORTER_LOGS_STATE_FILE` | -- | Optional path to persist per-source cursors across restarts (atomic JSON). Empty = in-memory only (resume from now on restart). |
| `--logs.syslog.allowed-peers` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_ALLOWED_PEERS` | -- | Comma-separated CIDR allowlist of hosts permitted to send syslog (e.g. 10.0.0.254/32). Empty accepts any sender. Syslog is unauthenticated, so set this on a shared network. |
| `--logs.syslog.debug-capture` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_DEBUG_CAPTURE` | `false` | Dump syslog lines this receiver cannot parse (unknown program, no matching parser, or an unparseable envelope) to --logs.debug-capture.dir for inspection. Requires --logs.debug-capture.dir. Additive - these lines still ship as generic records. |
| `--logs.syslog.enabled` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_ENABLED` | `false` | Enable the syslog receiver: listens for logs pushed by OPNsense (RFC5424 or RFC3164, UDP and/or TCP) and ships them enriched with rule descriptions, interface names and hostnames. Off by default. Requires --logs.enabled. Configure a matching target on the firewall under System > Settings > Logging > Targets. |
| `--logs.syslog.enrich` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_ENRICH` | `true` | Enrich received syslog records from the OPNsense API: firewall rule descriptions (including auto-generated system rules), friendly interface names, DHCP hostnames, MAC addresses, local/remote scope and well-known service names. |
| `--logs.syslog.exclude-programs` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_EXCLUDE_PROGRAMS` | -- | Comma-separated syslog programs to DROP (e.g. radvd,cron). Empty ships everything. Dropped records are counted in opnsense_exporter_logs_rejected_total{reason="filtered"} - never silently discarded. |
| `--logs.syslog.include-programs` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_INCLUDE_PROGRAMS` | -- | Comma-separated syslog programs to ship, dropping everything else. Empty ships everything. Mutually exclusive with --logs.syslog.exclude-programs. |
| `--logs.syslog.listen-tcp` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_LISTEN_TCP` | `:5514` | TCP listen address for the syslog receiver. Empty disables the TCP listener. Prefer TCP for firewall logs: UDP datagram loss is silent and unrecoverable. |
| `--logs.syslog.listen-tls` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_LISTEN_TLS` | -- | TLS listen address for the syslog receiver (RFC5424 over TLS, OPNsense tls4/tls6). Empty disables the TLS listener. Requires --logs.syslog.tls-cert-file and --logs.syslog.tls-key-file. |
| `--logs.syslog.listen-udp` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_LISTEN_UDP` | `:5514` | UDP listen address for the syslog receiver. Empty disables the UDP listener. Port 5514 (not 514) because 514 is privileged and the container runs non-root. |
| `--logs.syslog.max-conns` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_MAX_CONNS` | `64` | Maximum concurrent connections to the syslog receiver, applied PER TRANSPORT: plain TCP and TLS each get this budget from a separate pool. They are separate so a plaintext flood cannot starve authenticated mTLS senders out of the capacity they need. Bounds goroutine growth on an unauthenticated ingress; with both transports enabled the worst-case connection count is twice this value. |
| `--logs.syslog.min-severity` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_MIN_SEVERITY` | -- | Drop records less severe than this (emerg, alert, crit, err, warning, notice, info, debug). E.g. notice drops info and debug. Empty ships every severity. |
| `--logs.syslog.sample` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_SAMPLE` | `false` | Sample (drop) high-volume raw log lines AFTER their metrics have been derived: keep firewall block/reject lines and drop passes, keep HAProxy state changes and errors and drop the per-connection noise. Low-volume programs (sshd, dhcp, audit, ids) are kept in full. Off by default. Requires the log_events collector (exporter.disable-log-events must not be set) so every dropped line is counted first. |
| `--logs.syslog.sampled-attribute` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_SAMPLED_ATTRIBUTE` | `true` | When sampling is on, stamp a sampled="true" attribute on every shipped line so consumers know the log stream is incomplete and must use the derived counters for totals. On by default; only takes effect when --logs.syslog.sample is set. |
| `--logs.syslog.tls-cert-file` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_TLS_CERT_FILE` | -- | PEM server certificate for the TLS syslog listener. |
| `--logs.syslog.tls-client-ca-file` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_TLS_CLIENT_CA_FILE` | -- | PEM CA bundle to verify sender client certificates on the TLS syslog listener. When set, a sender MUST present a certificate signed by this CA - the only real sender authentication syslog offers. Empty accepts any TLS client (encryption only). |
| `--logs.syslog.tls-key-file` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_TLS_KEY_FILE` | -- | PEM private key for the TLS syslog listener. |
| `--logs.unbound.enabled` | `OPNSENSE_EXPORTER_LOGS_UNBOUND_ENABLED` | `false` | Enable the opt-in Unbound per-query DNS log source (pi-hole-style query log to Loki: domain, client, action, resolution source, blocklist and dnssec_status per query). Off by default; requires --logs.enabled. CAVEAT: without a per-client filter, Unbound's query-log backend (DuckDB) only ever exposes the newest 1000 rows across the WHOLE resolver - on a firewall sustaining more than roughly 1000 queries between polls, older rows silently fall out of that window before this exporter ever sees them. This is accepted, honestly-counted sampling loss, not a bug: it is tracked via opnsense_exporter_logs_possible_gap_total{source="unbound"}, never silently dropped. Homelab/SMB query volumes are fine; a busy enterprise resolver should not enable this. Also requires Unbound reporting/statistics enabled on the firewall. Poll floor 15s regardless of --logs.poll-interval. |
| `--logs.zenarmor.allowed-peers` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_ALLOWED_PEERS` | -- | Comma-separated CIDR allowlist of hosts permitted to stream (e.g. 10.0.0.254/32). Empty accepts any sender. The receiver is unauthenticated unless --logs.zenarmor.auth-user is set, so set this on a shared network. |
| `--logs.zenarmor.auth-password` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_AUTH_PASSWORD` | -- | Password for --logs.zenarmor.auth-user. |
| `--logs.zenarmor.auth-user` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_AUTH_USER` | -- | Require HTTP basic auth on the Zenarmor receiver, with this username. Set the same credentials in Zenarmor's streaming settings. Empty disables auth. |
| `--logs.zenarmor.debug-capture` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_DEBUG_CAPTURE` | `false` | Dump Zenarmor signals this receiver does not model (unhandled Elasticsearch endpoints, unknown families, documents that would not parse) to --logs.debug-capture.dir for inspection. Requires --logs.debug-capture.dir. While on, the unhandled-endpoint warning is suppressed - the capture file carries the same signal. |
| `--logs.zenarmor.drop-self-traffic` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_DROP_SELF_TRAFFIC` | `true` | Drop records describing the exporter's own Elasticsearch ingest connection - Zenarmor inspects the link the receiver listens on, so it reports the very connection delivering its records (roughly 15% of all volume, and most of the http family). Matched on the streaming peer's address plus the receiver's listen port, never the destination address, which a containerised exporter cannot know. Set false to keep them; drops are counted as logs_rejected_total{reason="self_traffic"}. |
| `--logs.zenarmor.enabled` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_ENABLED` | `false` | Enable the Zenarmor receiver: poses as an Elasticsearch node so Zenarmor can stream its reporting data (connections, DNS, TLS, HTTP, threat alerts) to the exporter, which ships it enriched over OTLP. Off by default. Requires --logs.enabled. Configure the firewall under Configuration/Zenarmor > Settings > Streaming Data > 'Stream Reporting Data to External Elasticsearch' - NOT the initial wizard's 'Remote Elasticsearch Database', which replaces local reporting irreversibly. |
| `--logs.zenarmor.enrich` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_ENRICH` | `true` | Enrich received Zenarmor records from the OPNsense API: friendly interface names, local/remote scope and well-known service names. Zenarmor resolves hostnames, MACs and device identity itself, so this adds only what it does not already know. |
| `--logs.zenarmor.exclude` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_EXCLUDE` | -- | Drop Zenarmor records whose FIELD matches REGEX, as FIELD=~REGEX (e.g. 'server_name=~.*\.grafana\.net'). Repeatable; default off. The field name is validated at startup against the receiver's attribute vocabulary - a typo is a startup error, never a silent no-op. Derived counters are observed BEFORE the drop, so opnsense_log_events_zenarmor_total stays complete; drops are counted as logs_rejected_total{reason="excluded"} and logs_zenarmor_excluded_total{rule}. EXCLUSION IS LOSSY: the derived counters carry no server_name, query or device_name, so an excluded record's forensic detail is gone for good. Prefer a query-time filter unless volume genuinely forces this. Set via env as one rule per LINE. |
| `--logs.zenarmor.families` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_FAMILIES` | -- | Comma-separated Zenarmor families to ship (conn, dns, tls, http, alert, sip). Empty ships all of them. Prefer restricting this at the Zenarmor end instead - data cut at source never crosses the wire. Zenarmor streams ~2.5-3.3M records/day (~4-6 GB/day of JSON), of which conn is ~61%. |
| `--logs.zenarmor.listen-http` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_LISTEN_HTTP` | `:9200` | Listen address for the Zenarmor receiver. Point Zenarmor's streaming URI at it. |
| `--logs.zenarmor.max-concurrent-requests` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_MAX_CONCURRENT_REQUESTS` | `8` | Maximum bulk requests processed concurrently by the Zenarmor receiver. The per-request body limit bounds one request; without this, N simultaneous requests each buffer that full allowance. Excess requests are refused with 503 before a body is read. 0 disables the limit. |
| `--logs.zenarmor.tls-cert-file` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_TLS_CERT_FILE` | -- | PEM server certificate for the Zenarmor receiver. Set with --logs.zenarmor.tls-key-file to serve HTTPS, and use an https:// URI in Zenarmor's streaming settings. |
| `--logs.zenarmor.tls-key-file` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_TLS_KEY_FILE` | -- | PEM private key for --logs.zenarmor.tls-cert-file. |
| `--logs.zenarmor.transport` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_TRANSPORT` | `elasticsearch` | How Zenarmor delivers its reporting data: 'elasticsearch' (default) runs the built-in Elasticsearch receiver on --logs.zenarmor.listen-http; 'syslog' ingests it through the shared syslog receiver (requires --logs.syslog.enabled and a business-tier Zenarmor licence). families/exclude/enrich/drop-self-traffic apply to either transport. |
| `--web.config.file` | -- | -- | Path to configuration file that can enable TLS or authentication. See: https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md |
| `--web.disable-exporter-metrics` | `OPNSENSE_EXPORTER_DISABLE_EXPORTER_METRICS` | -- | Exclude metrics about the exporter itself (process_*, go_*). |
| `--web.listen-address` | -- | `:8080` | Addresses on which to expose metrics and web interface. Repeatable for multiple addresses. Examples: `:9100` or `[::1]:9100` for http, `vsock://:9100` for vsock |
| `--web.systemd-socket` | -- | -- | Use systemd socket activation listeners instead of port listeners (Linux only). |
| `--web.telemetry-path` | `OPNSENSE_EXPORTER_WEB_TELEMETRY_PATH` | `/metrics` | Path under which to expose metrics. |
| `--web.ui-disable-config` | `OPNSENSE_EXPORTER_WEB_UI_DISABLE_CONFIG` | `false` | Hide the /config page. |
| `--web.ui-disable-devices` | `OPNSENSE_EXPORTER_WEB_UI_DISABLE_DEVICES` | `false` | Hide the /devices page (exposes MAC/hostname). |
| `--web.ui-enabled` | `OPNSENSE_EXPORTER_WEB_UI_ENABLED` | `true` | Serve the operator console at / (else the minimal landing page). |
| `--web.ui-refresh-interval` | `OPNSENSE_EXPORTER_WEB_UI_REFRESH_INTERVAL` | `5s` | Live-poll interval for the console's dynamic pages. |
<!-- docgen:end:flags-exporter -->

### Poll intervals and the response cache

Two different caches sit between the firewall and a scrape, and they do not overlap:

- **The poll snapshot** removes API work from the **scrape** path. Each collector polls on its own interval (`--collector.poll-interval`, its built-in tier, or a `--collector.poll-interval-override`) into an in-memory snapshot; `/metrics` and the OTLP bridge replay that snapshot and never call the firewall. Scrape as often as you like - it costs the box nothing.
- **The response cache** (`--exporter.cache-ttl`, `--exporter.firmware-cache-ttl`) removes API work from the **poll** path, for the handful of endpoints whose payload only changes on an admin action. A collector on the 15-minute tier would otherwise ask the box four times an hour for a certificate inventory that changes once a quarter.

Because the response cache is consumed by polls, **set its TTL longer than the poll interval of the collectors that use it** - a TTL below the poll interval can never serve a hit and just adds a lookup. Poll intervals are clamped to a 15-minute ceiling, so both defaults (1h and 12h) are above the slowest possible poll. Setting either to `0` disables that cache and sends every poll to the firewall.

A plugin-gated endpoint's `404` is remembered separately, under the same `--exporter.cache-ttl`. That is a fact about the route (the plugin is not installed), not about payload freshness, so it applies regardless of how a collector polls.

## Health endpoints & scrape filtering

The exporter serves two probe endpoints alongside `/metrics`:

| Path | Behavior |
|------|----------|
| `/-/healthy` | Liveness: always `200 OK` while the process is serving. No upstream dependency. |
| `/-/ready` | Readiness: `200 OK` when the OPNsense API health check succeeds **and** the poll scheduler has warmed up (every enabled collector has completed its first poll), `503` otherwise. Results (including failures) are cached for 10 seconds so Kubernetes probes cannot hammer the firewall API; each upstream probe is bounded to 5 seconds and detached from the prober's own request timeout. |

!!! info "Readiness covers warm-up, not just reachability"
    Collectors poll on their own intervals into an in-memory snapshot that `/metrics` replays, so a freshly started exporter serves a *partial* metric set until every collector has polled once - typically a few tens of seconds, bounded by the startup jitter and the poll-concurrency cap. `/-/ready` stays `503` for that window, which makes it the right gate for ordered startup and for any script that asserts against a complete scrape. A failed first poll still counts as warmed up (it is reported by `opnsense_exporter_scrape_collector_success=0`), so one broken plugin cannot hold readiness open indefinitely.

!!! warning "Kubernetes: do not gate readiness on the firewall"
    `/-/ready` depends on the OPNsense API. If Prometheus discovers the exporter via Kubernetes Service endpoints, a not-ready pod drops out of the endpoints list - so an unreachable firewall would stop the exporter being scraped and you would lose the `opnsense_up=0` signal exactly when the firewall is down. **Do not use `/-/ready` as a `readinessProbe` in that setup - use `/-/healthy` for both probes** (as the bundled `deploy/k8s/deployment.yaml` does). `/-/ready` is intended for ordered startup and manual/external checks.

Note: if you configure `basic_auth_users` in the exporter-toolkit web config file (`--web.config.file`), authentication applies to **all** endpoints including `/-/healthy` and `/-/ready` - Kubernetes probes cannot easily send basic-auth credentials, so prefer network-level protection over basic auth when probes are in use.

`/metrics` supports node_exporter-style per-scrape collector filtering:

```
curl 'http://localhost:8080/metrics?collect[]=gateways&collect[]=interfaces'
curl 'http://localhost:8080/metrics?exclude[]=firewall_rule'
```

`collect[]` and `exclude[]` are mutually exclusive (`400` if both are given); unknown collector names return `400` listing the valid names (the subsystem names of the collectors enabled in this instance). The always-on metrics (`opnsense_up`, health/status, `opnsense_exporter_*`) are emitted regardless of filtering.

Prometheus's scrape timeout bounds only the `/metrics` HTTP request. The request
replays the latest in-memory collector snapshots and never starts OPNsense API
calls. Background polls have their own intervals, request timeout, and concurrency
limit; use the poll freshness, duration, and success metrics to diagnose a slow
firewall endpoint.

## Continuous profiling (Pyroscope)

The exporter can push continuous profiles to Grafana Cloud Pyroscope using the
`pyroscope-go` SDK. Profiling is **disabled by default** and activates only when
`--pyroscope.server-address` (env `OPNSENSE_EXPORTER_PYROSCOPE_SERVER_ADDRESS`)
is set. There are no unauthenticated `/debug/pprof/*` endpoints.

<!-- docgen:begin:flags-pyroscope -->
| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--pyroscope.application-name` | `OPNSENSE_EXPORTER_PYROSCOPE_APPLICATION_NAME` | `opnsense-exporter` | Pyroscope application name profiles are reported under. |
| `--pyroscope.auth-password` | `OPNSENSE_EXPORTER_PYROSCOPE_AUTH_PASSWORD` | -- | HTTP basic auth password for Pyroscope (Grafana Cloud Access Policy token). This flag/ENV or PYROSCOPE_AUTH_PASSWORD_FILE may be set. |
| `--pyroscope.auth-user` | `OPNSENSE_EXPORTER_PYROSCOPE_AUTH_USER` | -- | HTTP basic auth user for Pyroscope (Grafana Cloud stack/instance ID). This flag/ENV or PYROSCOPE_AUTH_USER_FILE may be set. |
| `--pyroscope.disable-mutex-block` | `OPNSENSE_EXPORTER_PYROSCOPE_DISABLE_MUTEX_BLOCK` | `false` | Disable mutex/block contention profiling. On by default; disabling drops the two contention profiles and their process-global sampling rates. CPU, memory, goroutine (and goroutine-leak, when built with the experiment) profiling are unaffected. |
| `--pyroscope.server-address` | `OPNSENSE_EXPORTER_PYROSCOPE_SERVER_ADDRESS` | -- | Grafana Cloud Pyroscope endpoint URL. When empty, continuous profiling is disabled. |
| `--pyroscope.tenant-id` | `OPNSENSE_EXPORTER_PYROSCOPE_TENANT_ID` | -- | Pyroscope tenant ID (only needed for multi-tenancy; unused for Grafana Cloud). |
<!-- docgen:end:flags-pyroscope -->

### File-based secrets

Like the OPNsense API credentials, the auth user and password can be read from
files instead of flags/env vars: set `PYROSCOPE_AUTH_USER_FILE` and/or
`PYROSCOPE_AUTH_PASSWORD_FILE` to a path whose first line holds the value. The
file value takes precedence over the corresponding flag/env var when present
and non-empty.

Profiles are tagged with `instance` (the resolved instance label) and `version`.

## OTLP metrics export

In addition to the `/metrics` pull endpoint, the exporter can **push** the exact
same metrics to an OpenTelemetry (OTLP) endpoint. A Prometheus-bridge producer reads
the existing registry on each export tick, so OTLP metric names, labels and values
are identical to what `/metrics` exposes (no native renaming) - existing dashboards
keep working against either backend. Export is **disabled by default** and activates
only when `--otlp.enabled` (env `OPNSENSE_EXPORTER_OTLP_ENABLED`) is set. The pull
endpoint is unaffected whether or not OTLP is enabled.

`--otlp.endpoint`, `--otlp.headers` and `--otlp.service-name` fall through to the
corresponding **standard OpenTelemetry environment variable** when left empty
(`OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_EXPORTER_OTLP_HEADERS`, `OTEL_SERVICE_NAME`),
and `OTEL_RESOURCE_ATTRIBUTES` is read natively by the OTEL SDK. Explicit `--otlp.*`
flags take precedence over those env vars.

`OTEL_EXPORTER_OTLP_PROTOCOL` and `OTEL_METRIC_EXPORT_INTERVAL` are **not** consulted.
`--otlp.protocol` and `--otlp.export-interval` always carry a value (an empty protocol
is rejected at startup rather than defaulted), so the exporter passes both explicitly
and those two env vars never apply - set the flags instead.

<!-- docgen:begin:flags-otlp -->
| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--otlp.enabled` | `OPNSENSE_EXPORTER_OTLP_ENABLED` | `false` | Enable pushing metrics to an OTLP endpoint (in addition to the /metrics pull endpoint). Off by default. |
| `--otlp.endpoint` | `OPNSENSE_EXPORTER_OTLP_ENDPOINT` | -- | OTLP endpoint URL. When empty, the standard OTEL_EXPORTER_OTLP_ENDPOINT env var is used. |
| `--otlp.export-interval` | `OPNSENSE_EXPORTER_OTLP_EXPORT_INTERVAL` | `60s` | Interval between OTLP metric exports (independent of Prometheus scrapes). |
| `--otlp.fast-export-interval` | `OPNSENSE_EXPORTER_OTLP_FAST_EXPORT_INTERVAL` | `0s` | Optional second OTLP export lane for fast-tier collectors only (#390). Zero (the default) keeps the single-stream behaviour exactly. When set, fast-tier collectors (gateways, interfaces, protocol, pf_stats, activity, netflow, carp — or whatever --collector.poll-interval-override makes fast) export at this interval while everything else stays on --otlp.export-interval. Must be shorter than --otlp.export-interval. Fast-tier series are a small fraction of the total, so 15s here costs far less than setting --otlp.export-interval=15s for everything. |
| `--otlp.grafana-cloud-endpoint` | `OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_ENDPOINT` | -- | Grafana Cloud OTLP gateway base URL (required when using the Grafana Cloud shortcut). |
| `--otlp.grafana-cloud-instance-id` | `OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_INSTANCE_ID` | -- | Grafana Cloud OTLP instance ID. With --otlp.grafana-cloud-token, synthesizes basic-auth. This flag/ENV or OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_INSTANCE_ID_FILE may be set. |
| `--otlp.grafana-cloud-token` | `OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_TOKEN` | -- | Grafana Cloud Access Policy token. This flag/ENV or OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_TOKEN_FILE may be set. |
| `--otlp.headers` | `OPNSENSE_EXPORTER_OTLP_HEADERS` | -- | OTLP headers as comma-separated key=value pairs (e.g. X-Scope-OrgID=1,Authorization=Bearer x). When set, replaces OTEL_EXPORTER_OTLP_HEADERS entirely; when empty, that env var is used. |
| `--otlp.insecure` | `OPNSENSE_EXPORTER_OTLP_INSECURE` | `false` | Disable TLS for the OTLP connection (plaintext). |
| `--otlp.protocol` | `OPNSENSE_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` | OTLP transport protocol: grpc or http/protobuf. Defaults to http/protobuf; an empty value is rejected. |
| `--otlp.service-name` | `OPNSENSE_EXPORTER_OTLP_SERVICE_NAME` | `opnsense-exporter` | service.name resource attribute for exported metrics. |
| `--otlp.tls-ca-file` | `OPNSENSE_EXPORTER_OTLP_TLS_CA_FILE` | -- | Path to a CA certificate file used to verify the OTLP server. |
| `--otlp.tls-cert-file` | `OPNSENSE_EXPORTER_OTLP_TLS_CERT_FILE` | -- | Path to a client certificate file for OTLP mutual TLS (requires --otlp.tls-key-file). |
| `--otlp.tls-key-file` | `OPNSENSE_EXPORTER_OTLP_TLS_KEY_FILE` | -- | Path to a client key file for OTLP mutual TLS (requires --otlp.tls-cert-file). |
<!-- docgen:end:flags-otlp -->

The metric set exported over OTLP is the same as the Prometheus
catalogue (see the [metrics reference](metrics/metrics.md)), with one addition
described below: a synthetic `up` series.

### Delivery health

`--otlp.enabled` starting cleanly proves nothing about delivery: the OTLP exporter
connects lazily, so the "otlp metrics export enabled" log line is written before any
network I/O happens. A wrong endpoint, an expired credential or a backend outage can
therefore deliver zero metrics indefinitely.

Four self-metrics make that visible on `/metrics` and on the operator console:
`opnsense_exporter_otlp_exports_total{result="success"|"error"}`,
`opnsense_exporter_otlp_consecutive_failures`,
`opnsense_exporter_otlp_last_success_timestamp_seconds` and
`opnsense_exporter_otlp_enabled`. Note that `otlp_enabled = 1` means the pipeline is
**running**, not that it is **working** - the outage signal is a rising
`consecutive_failures`.

These cannot reach a pure-OTLP backend during an outage, because an exporter cannot
ship its own failure through the path that is failing. On a pure-push deployment they
are for the local console and for post-recovery forensics; the in-band symptom at the
backend is data staleness. Where `/metrics` is also scraped, they alert normally.

Construction failure is **fatal**. If `--otlp.enabled` is set and the exporter cannot
be built, the process exits rather than serving `/metrics` behind a permanently dead
push pipeline. Export failures after startup are not fatal - they are counted, logged
(rate-limited) and retried, so a flaky backend never takes down the pull endpoint.

### Two-speed export (`--otlp.fast-export-interval`)

Collectors already poll on data-volatility tiers, but OTLP exports the whole snapshot
on one interval. Setting `--otlp.export-interval=15s` to get responsive gateway and
interface graphs therefore re-sends every cold and medium series four times a minute
as well, even though almost none of them changed.

`--otlp.fast-export-interval` adds an optional second export lane carrying **only**
the fast-tier collectors, while everything else stays on `--otlp.export-interval`. It
is **off by default (`0s`)**, and the default configuration builds exactly one reader,
byte-for-byte as before. It must be shorter than `--otlp.export-interval`; a fast lane
that is not faster is rejected at startup rather than silently doubling export calls.

Measured on a live deployment (7,226 total series, of which 494 are fast-tier):

| Configuration | Data points per minute | vs 60s baseline |
|---|---|---|
| `--otlp.export-interval=60s` (default) | 7,226 | 1.00x |
| `--otlp.export-interval=15s` (everything fast) | 28,904 | 4.00x |
| `--otlp.export-interval=60s` + `--otlp.fast-export-interval=15s` | 8,708 | **1.21x** |

Fast-tier membership follows each collector's **effective** poll interval, so a
`--collector.poll-interval-override` moves a collector between lanes in either
direction. The two lanes are disjoint by construction - the base lane carries every
non-fast collector plus the health, `up` and exporter self-metrics, the fast lane
carries fast-tier collectors only - so no series is ever exported twice. Per-collector
scheduler metrics travel with their collector, keeping them at the same resolution as
the data they describe.

The trade-off to understand is **backend staleness**: non-fast series now arrive only
once per `--otlp.export-interval`, exactly as before, so a dashboard mixing a fast
series with a cold one will show the cold one stepping at the base interval. That is
already true of the underlying poll tiers - a 15m-tier collector cannot be fresher
than 15m no matter how often it is exported - so exporting it more often only inflates
cost, never resolution.

### Liveness (`up`) in push mode

When Prometheus **scrapes** `/metrics` it synthesizes an `up` series per target for
free - `1` when the scrape succeeded, `0`/absent when the exporter was unreachable -
and liveness alerts (`up == 0`, `absent(up)`) key off it. In **OTLP push mode there
is no scraper**, so nothing generates that series and those alerts silently stop
working.

To keep them working, the exporter emits its own `up` series, but **only over
OTLP**: a gauge fixed at `1` while the exporter is running and exporting, labelled
with `opnsense_instance`. When the exporter stops, it stops pushing and the series
goes stale/absent - exactly the signal an `absent(up)` (or staleness) alert needs.
This mirrors Prometheus target-up semantics: `up` reports whether the **exporter**
is alive, not whether the firewall behind it is healthy (that is
[`opnsense_up`](metrics/metrics.md), which reflects OPNsense API reachability).

The synthetic `up` is deliberately **not** exposed at `/metrics`: a literal `up`
there would collide with the `up` a Prometheus server generates for the scrape
target. It therefore exists in the pushed OTLP stream alone, and does not appear in
the [metrics reference](metrics/metrics.md) (which catalogues the pull endpoint).

### Grafana Cloud shortcut

Setting `--otlp.grafana-cloud-instance-id`, `--otlp.grafana-cloud-token` and
`--otlp.grafana-cloud-endpoint` together synthesizes the
`Authorization: Basic base64(instanceID:token)` header and uses the gateway URL as
the endpoint, so you do not have to assemble the basic-auth header yourself. An
explicit `--otlp.endpoint` or `Authorization` header always wins over the shortcut.
The instance ID and token also support `*_FILE` secret variants
(`OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_INSTANCE_ID_FILE`,
`OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_TOKEN_FILE`), whose file contents take
precedence over the flag/env value, mirroring the OPNsense API credentials.

### Temporality

Exported metrics are always **cumulative**, and this is not configurable. They are
sourced from the Prometheus registry via a bridge producer, so they arrive already
aggregated as cumulative (Prometheus' model) and are exported as-is - exactly the
temporality Grafana Cloud's metrics backend (Mimir) and Prometheus' OTLP ingest
require. An exporter-side temporality selector cannot re-aggregate
producer-supplied metrics, so no delta option is offered.

### Resource attributes and `service_version`

The exporter puts `service.name`, `service.version` (the build) and
`service.instance.id` on the OTLP **resource**, alongside whatever the SDK's
detectors and `OTEL_RESOURCE_ATTRIBUTES` contribute. None of them are copied onto
individual datapoints: under the OTLP→Prometheus convention a resource attribute
stays on the resource, and the backend decides what to make of it. Conventionally
that means `service.name`(+`service.namespace`) becomes `job`,
`service.instance.id` becomes `instance`, and everything else lands on the
`target_info` series.

Backends deviate, though, and Grafana Cloud in particular **promotes a fixed list
of resource attributes to a label on every series** - `service.version` among
them, so metrics pushed there carry `service_version="<build>"` on each series as
well as on `target_info`. That is the gateway's behaviour rather than the
exporter's, and it cannot be switched off from this side; changing the list means
[asking Grafana Support](https://grafana.com/docs/grafana-cloud/send-data/otlp/otlp-format-considerations/#metrics).

That matters if you run per-commit builds rather than release tags.
Each version is then a distinct series, so for a few minutes after a redeploy a
rate-based aggregation sees the old build's series decaying alongside the new
one's and over-reports. Aggregating the label away does not help - that sums both
series, which is the same thing - so give alerts a `for:` window longer than the
overlap, or deploy release tags.

Reading the version back does not depend on any of that. The exporter's own info
metric carries it on every backend, pull or push:

```promql
opnsense_exporter_build_info{opnsense_instance="my-firewall"}
```

On a backend that leaves resource attributes on `target_info` instead of
promoting them, join it in:

```promql
opnsense_up * on(job, instance) group_left(service_version) target_info
```

## Collector switches

All collectors are **enabled by default** unless noted otherwise. Each can be individually disabled or enabled using CLI flags or environment variables.

### Enabled by default (disable with flag)

<!-- docgen:begin:flags-collectors-default-on -->
| Flag | Env Var | Collector | Description |
|------|---------|-----------|-------------|
| `--exporter.disable-acme` | `OPNSENSE_EXPORTER_DISABLE_ACME` | ACME Client | Disable the scraping of ACME client certificate renewal status and expiry metrics (silent when the os-acme-client plugin is absent) |
| `--exporter.disable-apcupsd` | `OPNSENSE_EXPORTER_DISABLE_APCUPSD` | APC UPS (apcupsd) | Disable the scraping of APC UPS (apcupsd) metrics (silent when the os-apcupsd plugin is absent) |
| `--exporter.disable-arp-table` | `OPNSENSE_EXPORTER_DISABLE_ARP_TABLE` | ARP Table | Disable the scraping of the ARP table |
| `--exporter.disable-activity` | `OPNSENSE_EXPORTER_DISABLE_ACTIVITY` | Activity | Disable the scraping of system activity metrics (CPU percentages, thread counts) |
| `--exporter.disable-bpf` | `OPNSENSE_EXPORTER_DISABLE_BPF` | BPF Statistics | Disable the scraping of BPF listener statistics |
| `--exporter.disable-carp` | `OPNSENSE_EXPORTER_DISABLE_CARP` | CARP | Disable the scraping of CARP/VIP status metrics |
| `--exporter.disable-captiveportal` | `OPNSENSE_EXPORTER_DISABLE_CAPTIVEPORTAL` | Captive Portal | Disable the scraping of captive portal zone/session metrics (silent when no zones are configured) |
| `--exporter.disable-certificates` | `OPNSENSE_EXPORTER_DISABLE_CERTIFICATES` | Certificates | Disable the scraping of certificate expiry metrics |
| `--exporter.disable-chrony` | `OPNSENSE_EXPORTER_DISABLE_CHRONY` | Chrony | Disable the scraping of chrony NTP tracking/source metrics (silent when the os-chrony plugin is absent) |
| `--exporter.disable-clamav` | `OPNSENSE_EXPORTER_DISABLE_CLAMAV` | ClamAV | Disable the scraping of ClamAV engine version and signature database freshness metrics (silent when the os-clamav plugin is absent) |
| `--exporter.disable-backup` | `OPNSENSE_EXPORTER_DISABLE_BACKUP` | Config Backup | Disable the scraping of config backup freshness metrics (last backup timestamp/count/size) |
| `--exporter.disable-cron-table` | `OPNSENSE_EXPORTER_DISABLE_CRON_TABLE` | Cron | Disable the scraping of the cron table |
| `--exporter.disable-crowdsec` | `OPNSENSE_EXPORTER_DISABLE_CROWDSEC` | CrowdSec | Disable the scraping of CrowdSec alert/decision/bouncer/machine counts (silent when the os-crowdsec plugin is absent) |
| `--exporter.disable-dnsmasq` | `OPNSENSE_EXPORTER_DISABLE_DNSMASQ` | Dnsmasq DHCP | Disable the scraping of Dnsmasq DHCP leases |
| `--exporter.disable-dyndns` | `OPNSENSE_EXPORTER_DISABLE_DYNDNS` | DynDNS | Disable the scraping of DynDNS (ddclient) account update status metrics (silent when the os-ddclient plugin is absent) |
| `--exporter.disable-frr` | `OPNSENSE_EXPORTER_DISABLE_FRR` | FRR Routing (BGP/OSPF/BFD) | Disable the scraping of FRR routing metrics (BGP/OSPF/BFD; silent when the os-frr plugin is absent) |
| `--exporter.disable-firewall` | `OPNSENSE_EXPORTER_DISABLE_FIREWALL` | Firewall | Disable the scraping of the firewall (pf) metrics |
| `--exporter.disable-alias` | `OPNSENSE_EXPORTER_DISABLE_ALIAS` | Firewall Aliases | Disable the scraping of firewall alias table sizes |
| `--exporter.disable-firewall-rules` | `OPNSENSE_EXPORTER_DISABLE_FIREWALL_RULES` | Firewall Rules | Disable the scraping of firewall rule statistics |
| `--exporter.disable-firmware` | `OPNSENSE_EXPORTER_DISABLE_FIRMWARE` | Firmware | Disable the scraping of the firmware metrics |
| `--exporter.disable-flow` | `OPNSENSE_EXPORTER_DISABLE_FLOW` | Flow Volume | Disable the flow collector (Prometheus byte/packet volume counters rolled up from flow records, on bounded dimensions). Silent until a flow source - today the Zenarmor receiver - is enabled and feeding it. |
| `--exporter.disable-gateways` | `OPNSENSE_EXPORTER_DISABLE_GATEWAYS` | Gateways | Disable the scraping of gateway status metrics (RTT, packet loss, gateway state) |
| `--exporter.disable-haproxy` | `OPNSENSE_EXPORTER_DISABLE_HAPROXY` | HAProxy | Disable the scraping of HAProxy statistics (silent when the os-haproxy plugin is absent) |
| `--exporter.disable-hardware` | `OPNSENSE_EXPORTER_DISABLE_HARDWARE` | Hardware | Disable the scraping of hardware identity/PSU metrics (DMI system info via os-dmidecode; Deciso DEC-series PSU status via os-dec-hw). Silent when neither plugin is installed. |
| `--exporter.disable-hostdiscovery` | `OPNSENSE_EXPORTER_DISABLE_HOSTDISCOVERY` | Host Discovery | Disable the scraping of the discovered-host inventory (Interfaces > Host discovery / hostwatch): interface+source host counts, low-cardinality. A core OPNsense feature (not a plugin); reads absent/silent on releases predating it. |
| `--exporter.disable-ids` | `OPNSENSE_EXPORTER_DISABLE_IDS` | IDS/IPS (Suricata) | Disable the scraping of Suricata IDS/IPS metrics (service status, IPS mode, eve log and ruleset inventory, installed-rule count; silent structures when IDS is unconfigured) |
| `--exporter.disable-ipsec` | `OPNSENSE_EXPORTER_DISABLE_IPSEC` | IPsec | Disable the scraping of IPSec service |
| `--exporter.disable-dhcpv4` | `OPNSENSE_EXPORTER_DISABLE_DHCPV4` | ISC DHCPv4 | Disable the scraping of ISC DHCPv4 leases (silent when the legacy ISC DHCP backend is absent) |
| `--exporter.disable-dhcpv6` | `OPNSENSE_EXPORTER_DISABLE_DHCPV6` | ISC DHCPv6 | Disable the scraping of ISC DHCPv6 leases and delegated prefixes (silent when the legacy ISC DHCP backend is absent) |
| `--exporter.disable-interfaces` | `OPNSENSE_EXPORTER_DISABLE_INTERFACES` | Interfaces | Disable the interfaces collector (per-interface traffic/link metrics) |
| `--exporter.disable-kea` | `OPNSENSE_EXPORTER_DISABLE_KEA` | Kea DHCP | Disable the scraping of Kea DHCP lease metrics |
| `--exporter.disable-lldpd` | `OPNSENSE_EXPORTER_DISABLE_LLDPD` | LLDP Neighbors | Disable the scraping of LLDP neighbor table metrics (silent when the os-lldpd plugin is absent) |
| `--exporter.disable-auth` | `OPNSENSE_EXPORTER_DISABLE_AUTH` | Local Auth | Disable the scraping of local-auth security-posture metrics (user/group/API-key counts, aggregates only - no per-user data) |
| `--exporter.disable-log-events` | `OPNSENSE_EXPORTER_DISABLE_LOG_EVENTS` | Log-derived Events | Disable the log_events collector (Prometheus counters derived from received syslog lines: firewall/haproxy/sshd/dhcp/audit/ids event totals). Silent until the syslog receiver is enabled and feeding it. |
| `--exporter.disable-mbuf` | `OPNSENSE_EXPORTER_DISABLE_MBUF` | Mbuf | Disable the scraping of mbuf statistics |
| `--exporter.disable-monit` | `OPNSENSE_EXPORTER_DISABLE_MONIT` | Monit | Disable the scraping of Monit service check status (silent when Monit is not running) |
| `--exporter.disable-ndp` | `OPNSENSE_EXPORTER_DISABLE_NDP` | NDP | Disable the scraping of the NDP (IPv6 neighbor discovery) table |
| `--exporter.disable-ntp` | `OPNSENSE_EXPORTER_DISABLE_NTP` | NTP | Disable the scraping of NTP peer metrics |
| `--exporter.disable-nut` | `OPNSENSE_EXPORTER_DISABLE_NUT` | NUT UPS | Disable the scraping of NUT UPS metrics (silent when the os-nut plugin is absent) |
| `--exporter.disable-netbird` | `OPNSENSE_EXPORTER_DISABLE_NETBIRD` | NetBird | Disable the scraping of NetBird management/signal connectivity, relay and peer metrics (silent when the os-netbird plugin is absent) |
| `--exporter.disable-nginx` | `OPNSENSE_EXPORTER_DISABLE_NGINX` | Nginx | Disable the scraping of nginx VTS statistics (silent when the os-nginx plugin is absent) |
| `--exporter.disable-openvpn` | `OPNSENSE_EXPORTER_DISABLE_OPENVPN` | OpenVPN | Disable the scraping of OpenVPN service |
| `--exporter.disable-pf-stats` | `OPNSENSE_EXPORTER_DISABLE_PF_STATS` | PF Statistics | Disable the scraping of PF statistics (state table, counters, memory limits, timeouts) |
| `--exporter.disable-protocol` | `OPNSENSE_EXPORTER_DISABLE_PROTOCOL` | Protocol Statistics | Disable the protocol-statistics collector (TCP/UDP/IP/ICMP/ARP/CARP/pfsync counters) |
| `--exporter.disable-qfeeds` | `OPNSENSE_EXPORTER_DISABLE_QFEEDS` | Q-Feeds | Disable the scraping of Q-Feeds threat intelligence statistics (silent when the os-q-feeds-connector plugin is absent) |
| `--exporter.disable-relayd` | `OPNSENSE_EXPORTER_DISABLE_RELAYD` | Relayd Load Balancer | Disable the scraping of relayd virtual server/table/host health (silent when the os-relayd plugin is absent) |
| `--exporter.disable-services` | `OPNSENSE_EXPORTER_DISABLE_SERVICES` | Services | Disable the services collector (per-service running state) |
| `--exporter.disable-siproxd` | `OPNSENSE_EXPORTER_DISABLE_SIPROXD` | Siproxd | Disable the scraping of the siproxd active SIP registration count (silent when the os-siproxd plugin is absent) |
| `--exporter.disable-syslog` | `OPNSENSE_EXPORTER_DISABLE_SYSLOG` | Syslog | Disable the scraping of syslog-ng statistics |
| `--exporter.disable-system` | `OPNSENSE_EXPORTER_DISABLE_SYSTEM` | System | Disable the scraping of system resource metrics (memory, uptime, disk, swap) |
| `--exporter.disable-tailscale` | `OPNSENSE_EXPORTER_DISABLE_TAILSCALE` | Tailscale | Disable the scraping of Tailscale node-local metrics (silent when the os-tailscale plugin is absent; complementary to tailscale2otel) |
| `--exporter.disable-temperature` | `OPNSENSE_EXPORTER_DISABLE_TEMPERATURE` | Temperature | Disable the scraping of temperature metrics |
| `--exporter.disable-trafficshaper` | `OPNSENSE_EXPORTER_DISABLE_TRAFFICSHAPER` | Traffic Shaper | Disable the scraping of traffic shaper pipe/queue/rule statistics (silent when the shaper is unconfigured) |
| `--exporter.disable-unbound` | `OPNSENSE_EXPORTER_DISABLE_UNBOUND` | Unbound DNS | Disable the scraping of Unbound service |
| `--exporter.disable-wireguard` | `OPNSENSE_EXPORTER_DISABLE_WIREGUARD` | Wireguard | Disable the scraping of Wireguard service |
| `--exporter.disable-snapshots` | `OPNSENSE_EXPORTER_DISABLE_SNAPSHOTS` | ZFS Boot Environments | Disable the scraping of ZFS boot-environment inventory metrics (silent/zero on non-ZFS filesystems such as UFS) |
<!-- docgen:end:flags-collectors-default-on -->

!!! info "Always-on collectors"
    The **Interfaces**, **Protocol Statistics**, **Services**, and built-in health-check
    collectors are always enabled and have no disable flag.

### Disabled by default (opt-in with flag)

These collectors are disabled by default because each scheduled poll adds API calls or expensive work on OPNsense. Enable them only if you need the data.

<!-- docgen:begin:flags-collectors-opt-in -->
| Flag | Env Var | Collector | Description |
|------|---------|-----------|-------------|
| `--exporter.enable-hasync` | `OPNSENSE_EXPORTER_ENABLE_HASYNC` | HA Sync Status | Enable the HA sync status collector (performs a live XML-RPC call to the CARP peer on every scheduled poll). Disabled by default. |
| `--exporter.enable-netflow` | `OPNSENSE_EXPORTER_ENABLE_NETFLOW` | NetFlow | Enable the netflow collector (enabled status, service status, cache stats). Disabled by default. |
| `--exporter.enable-network-diagnostics` | `OPNSENSE_EXPORTER_ENABLE_NETWORK_DIAGNOSTICS` | Network Diagnostics | Enable the network diagnostics collector (netisr, sockets, routes). Disabled by default. |
| `--exporter.enable-smart` | `OPNSENSE_EXPORTER_ENABLE_SMART` | SMART Disk Health | Enable the SMART disk health collector. Off by default: each scheduled poll does a per-disk POST fanout that runs `smartctl -a` on the firewall (extra API/latency cost, and wakes spun-down disks). Silent when the os-smart plugin is absent. |
| `--exporter.enable-tor` | `OPNSENSE_EXPORTER_ENABLE_TOR` | Tor | Enable the Tor circuit/stream telemetry collector (control-port GETINFO via the os-tor plugin). Off by default: each scheduled poll does two extra configd execs to query the control port, and requires the plugin's control port + password to be configured. Silent when the os-tor plugin is absent. |
| `--exporter.enable-vnstat` | `OPNSENSE_EXPORTER_ENABLE_VNSTAT` | Vnstat Traffic Accounting | Enable the vnstat persistent traffic accounting collector (day/month/total bytes per interface, survives reboots). Off by default: each scheduled poll does one interface_list call plus one get_json_data call per interface vnstat tracks. Silent when the os-vnstat plugin is absent. |
<!-- docgen:end:flags-collectors-opt-in -->

### High-cardinality detail options

These flags enable per-item detail metrics that can produce a large number of time series. Each unique label combination creates a separate time series in Prometheus.

!!! warning "Evaluate before enabling"
    On a firewall with hundreds of DHCP leases or firewall rules, enabling detail metrics can produce thousands of time series. Monitor your Prometheus storage and ingestion rate after enabling.

<!-- docgen:begin:flags-collectors-details -->
| Flag | Env Var | Collector | Description |
|------|---------|-----------|-------------|
| `--exporter.enable-arp-details` | `OPNSENSE_EXPORTER_ENABLE_ARP_DETAILS` | ARP Table | Enable per-entry ARP metrics (ip/mac/hostname labels - high, churning cardinality). Off by default; the low-cardinality entries_total aggregate is always emitted. |
| `--exporter.enable-dnsmasq-details` | `OPNSENSE_EXPORTER_ENABLE_DNSMASQ_DETAILS` | Dnsmasq DHCP | Enable per-lease detail metrics for Dnsmasq DHCP (high cardinality on large networks) |
| `--exporter.enable-frr-routes` | `OPNSENSE_EXPORTER_ENABLE_FRR_ROUTES` | FRR Routing (BGP/OSPF/BFD) | Enable FRR routing-state volume gauges (zebra RIB / OSPF route table / LSDB counts by protocol, route type, area and LSA type - never per-prefix or per-LSA series). Off by default: the underlying bootgrid endpoints have no success-body caching and their payload size scales with route-table size (up to 6 extra vtysh execs per scheduled poll). |
| `--exporter.enable-firewall-nat-counts` | `OPNSENSE_EXPORTER_ENABLE_FIREWALL_NAT_COUNTS` | Firewall | Enable the NAT rule inventory count metric (opnsense_firewall_nat_rules), broken down by type (source_nat, d_nat, one_to_one, npt) and enabled state. Off by default: each scheduled poll does four extra GETs, one per NAT rule type. Rules created before an admin migrated to the MVC-managed NAT backend are not counted; NAT rule pf hit/byte statistics do not exist upstream. |
| `--exporter.enable-alias-details` | `OPNSENSE_EXPORTER_ENABLE_ALIAS_DETAILS` | Firewall Aliases | Enable per-table pf evaluation/packet/byte counters for firewall aliases (~10 series per alias table) |
| `--exporter.enable-firewall-rules-details` | `OPNSENSE_EXPORTER_ENABLE_FIREWALL_RULES_DETAILS` | Firewall Rules | Enable per-rule detail metrics for firewall rules (high cardinality on large rulesets) |
| `--exporter.enable-firmware-package-details` | `OPNSENSE_EXPORTER_ENABLE_FIRMWARE_PACKAGE_DETAILS` | Firmware | Enable per-package firmware detail metrics (pending package updates and installed plugin inventory; adds one extra API call per scheduled poll) |
| `--exporter.enable-ids-alerts` | `OPNSENSE_EXPORTER_ENABLE_IDS_ALERTS` | IDS/IPS (Suricata) | Enable the Suricata recent-alerts gauge (opnsense_ids_recent_alerts by action). Off by default: each scheduled poll triggers a reverse read of eve.json on the box. Window set by --exporter.ids-alert-lookback. |
| `--exporter.enable-ipsec-lease-details` | `OPNSENSE_EXPORTER_ENABLE_IPSEC_LEASE_DETAILS` | IPsec | Enable per-lease IPsec mode-cfg detail metrics (opnsense_ipsec_lease_online with an unbounded road-warrior user label). Off by default; the per-pool lease aggregates stay always-on. |
| `--exporter.enable-dhcpv4-details` | `OPNSENSE_EXPORTER_ENABLE_DHCPV4_DETAILS` | ISC DHCPv4 | Enable per-lease detail metrics for ISC DHCPv4 (high cardinality on large networks) |
| `--exporter.enable-dhcpv6-details` | `OPNSENSE_EXPORTER_ENABLE_DHCPV6_DETAILS` | ISC DHCPv6 | Enable per-lease detail metrics for ISC DHCPv6 (high cardinality on large networks) |
| `--exporter.enable-kea-details` | `OPNSENSE_EXPORTER_ENABLE_KEA_DETAILS` | Kea DHCP | Enable per-lease detail metrics for Kea DHCP (high cardinality on large networks) |
| `--exporter.enable-ndp-details` | `OPNSENSE_EXPORTER_ENABLE_NDP_DETAILS` | NDP | Enable per-entry NDP metrics (ip/mac labels - high, churning cardinality from IPv6 privacy-address rotation). Off by default; the low-cardinality entries_total aggregate is always emitted. |
| `--exporter.enable-netbird-details` | `OPNSENSE_EXPORTER_ENABLE_NETBIRD_DETAILS` | NetBird | Enable per-peer detail metrics for NetBird (per-peer cardinality; peer FQDN labels) |
| `--exporter.enable-openvpn-details` | `OPNSENSE_EXPORTER_ENABLE_OPENVPN_DETAILS` | OpenVPN | Enable per-session detail metrics for OpenVPN (exposes usernames and per-client tunnel addresses) |
| `--exporter.enable-tailscale-peer-details` | `OPNSENSE_EXPORTER_ENABLE_TAILSCALE_PEER_DETAILS` | Tailscale | Enable per-peer detail metrics for Tailscale (per-peer cardinality; peer hostname labels) |
| `--exporter.enable-unbound-qstats` | `OPNSENSE_EXPORTER_ENABLE_UNBOUND_QSTATS` | Unbound DNS | Enable Unbound DNSBL query-stats totals and blocklist size metrics, plus local-zone/data/insecure-domain counts. Off by default: the query-stats totals call is backed by an expensive configd+python+pandas+DuckDB query (~1s per scheduled poll) - skipped entirely while query-stats logging (general.stats) is off on the box, but still paid for on every scheduled poll once it is on. |
| `--exporter.enable-unbound-infra` | `OPNSENSE_EXPORTER_ENABLE_UNBOUND_INFRA` | Unbound DNS | Enable per-upstream infra cache RTT metrics from Unbound (cardinality scales with the resolver's infra cache; one series pair per upstream ip/host) |
<!-- docgen:end:flags-collectors-details -->

## Full flag reference

Every flag the exporter accepts, generated from the binary's own flag definitions
(`--help` shows the same set):

<!-- docgen:begin:flags-full-reference -->
| Flag | Env Var | Default | Description |
|------|---------|---------|-------------|
| `--collector.health-poll-interval` | `OPNSENSE_EXPORTER_COLLECTOR_HEALTH_POLL_INTERVAL` | `60s` | Interval at which the exporter polls the OPNsense health endpoint (#386). This is the circuit-breaker cadence: the health poll sets and clears the process-wide 'firewall unreachable' flag, so it bounds how quickly collectors resume after the box recovers. Independent of --collector.poll-interval since #386, which previously controlled it by accident. Clamped to [5s, 15m]. |
| `--collector.poll-interval` | `OPNSENSE_EXPORTER_COLLECTOR_POLL_INTERVAL` | `60s` | Default interval at which each collector polls the OPNsense API into the in-memory snapshot that /metrics and the OTLP bridge replay (#336). A collector may declare its own faster/slower tier; every interval is clamped to [5s, 15m]. |
| `--collector.poll-interval-override` | `OPNSENSE_EXPORTER_COLLECTOR_POLL_INTERVAL_OVERRIDE` | -- | Override a specific collector's poll interval as <collector>=<duration> (repeatable; clamped to [5s, 15m]). Wins over the collector's built-in tier. Example: --collector.poll-interval-override=gateways=10s --collector.poll-interval-override=smart=1h. |
| `--config.check` | -- | -- | Validate the effective configuration and exit, without binding any port, starting the poll scheduler, contacting OPNsense, or exporting telemetry. Exits 0 when the configuration is usable and 1 otherwise. Referenced files (API key/secret, TLS keypairs) are read; network reachability is deliberately not checked (that is what /-/ready is for). Has no env var by design: an ambient one would turn every start into a no-op. |
| `--exporter.cache-ttl` | `OPNSENSE_EXPORTER_CACHE_TTL` | `1h0m0s` | How long to cache responses from slow-moving API endpoints (system/CPU identity, certificate inventory, Unbound DNS blocklist policy config) and to remember that a plugin-gated endpoint is absent (its 404). This data changes only on an admin action - a config edit, a certificate renewal, a plugin install - so re-fetching it on every poll only costs firewall CPU. Set it above the collector poll interval or it can never serve a hit. The cost is staleness: a newly installed plugin, or a cert change, can take up to this long to show up. Set to 0 to fetch everything on every poll. Live data (counters, rates, service run-state) is never cached regardless of this setting. |
| `--exporter.disable-acme` | `OPNSENSE_EXPORTER_DISABLE_ACME` | `false` | Disable the scraping of ACME client certificate renewal status and expiry metrics (silent when the os-acme-client plugin is absent) |
| `--exporter.disable-activity` | `OPNSENSE_EXPORTER_DISABLE_ACTIVITY` | `false` | Disable the scraping of system activity metrics (CPU percentages, thread counts) |
| `--exporter.disable-alias` | `OPNSENSE_EXPORTER_DISABLE_ALIAS` | `false` | Disable the scraping of firewall alias table sizes |
| `--exporter.disable-apcupsd` | `OPNSENSE_EXPORTER_DISABLE_APCUPSD` | `false` | Disable the scraping of APC UPS (apcupsd) metrics (silent when the os-apcupsd plugin is absent) |
| `--exporter.disable-arp-table` | `OPNSENSE_EXPORTER_DISABLE_ARP_TABLE` | `false` | Disable the scraping of the ARP table |
| `--exporter.disable-auth` | `OPNSENSE_EXPORTER_DISABLE_AUTH` | `false` | Disable the scraping of local-auth security-posture metrics (user/group/API-key counts, aggregates only - no per-user data) |
| `--exporter.disable-backup` | `OPNSENSE_EXPORTER_DISABLE_BACKUP` | `false` | Disable the scraping of config backup freshness metrics (last backup timestamp/count/size) |
| `--exporter.disable-bpf` | `OPNSENSE_EXPORTER_DISABLE_BPF` | `false` | Disable the scraping of BPF listener statistics |
| `--exporter.disable-captiveportal` | `OPNSENSE_EXPORTER_DISABLE_CAPTIVEPORTAL` | `false` | Disable the scraping of captive portal zone/session metrics (silent when no zones are configured) |
| `--exporter.disable-carp` | `OPNSENSE_EXPORTER_DISABLE_CARP` | `false` | Disable the scraping of CARP/VIP status metrics |
| `--exporter.disable-certificates` | `OPNSENSE_EXPORTER_DISABLE_CERTIFICATES` | `false` | Disable the scraping of certificate expiry metrics |
| `--exporter.disable-chrony` | `OPNSENSE_EXPORTER_DISABLE_CHRONY` | `false` | Disable the scraping of chrony NTP tracking/source metrics (silent when the os-chrony plugin is absent) |
| `--exporter.disable-clamav` | `OPNSENSE_EXPORTER_DISABLE_CLAMAV` | `false` | Disable the scraping of ClamAV engine version and signature database freshness metrics (silent when the os-clamav plugin is absent) |
| `--exporter.disable-cron-table` | `OPNSENSE_EXPORTER_DISABLE_CRON_TABLE` | `false` | Disable the scraping of the cron table |
| `--exporter.disable-crowdsec` | `OPNSENSE_EXPORTER_DISABLE_CROWDSEC` | `false` | Disable the scraping of CrowdSec alert/decision/bouncer/machine counts (silent when the os-crowdsec plugin is absent) |
| `--exporter.disable-dhcpv4` | `OPNSENSE_EXPORTER_DISABLE_DHCPV4` | `false` | Disable the scraping of ISC DHCPv4 leases (silent when the legacy ISC DHCP backend is absent) |
| `--exporter.disable-dhcpv6` | `OPNSENSE_EXPORTER_DISABLE_DHCPV6` | `false` | Disable the scraping of ISC DHCPv6 leases and delegated prefixes (silent when the legacy ISC DHCP backend is absent) |
| `--exporter.disable-dnsmasq` | `OPNSENSE_EXPORTER_DISABLE_DNSMASQ` | `false` | Disable the scraping of Dnsmasq DHCP leases |
| `--exporter.disable-dyndns` | `OPNSENSE_EXPORTER_DISABLE_DYNDNS` | `false` | Disable the scraping of DynDNS (ddclient) account update status metrics (silent when the os-ddclient plugin is absent) |
| `--exporter.disable-firewall` | `OPNSENSE_EXPORTER_DISABLE_FIREWALL` | `false` | Disable the scraping of the firewall (pf) metrics |
| `--exporter.disable-firewall-rules` | `OPNSENSE_EXPORTER_DISABLE_FIREWALL_RULES` | `false` | Disable the scraping of firewall rule statistics |
| `--exporter.disable-firmware` | `OPNSENSE_EXPORTER_DISABLE_FIRMWARE` | `false` | Disable the scraping of the firmware metrics |
| `--exporter.disable-flow` | `OPNSENSE_EXPORTER_DISABLE_FLOW` | `false` | Disable the flow collector (Prometheus byte/packet volume counters rolled up from flow records, on bounded dimensions). Silent until a flow source - today the Zenarmor receiver - is enabled and feeding it. |
| `--exporter.disable-frr` | `OPNSENSE_EXPORTER_DISABLE_FRR` | `false` | Disable the scraping of FRR routing metrics (BGP/OSPF/BFD; silent when the os-frr plugin is absent) |
| `--exporter.disable-gateways` | `OPNSENSE_EXPORTER_DISABLE_GATEWAYS` | `false` | Disable the scraping of gateway status metrics (RTT, packet loss, gateway state) |
| `--exporter.disable-haproxy` | `OPNSENSE_EXPORTER_DISABLE_HAPROXY` | `false` | Disable the scraping of HAProxy statistics (silent when the os-haproxy plugin is absent) |
| `--exporter.disable-hardware` | `OPNSENSE_EXPORTER_DISABLE_HARDWARE` | `false` | Disable the scraping of hardware identity/PSU metrics (DMI system info via os-dmidecode; Deciso DEC-series PSU status via os-dec-hw). Silent when neither plugin is installed. |
| `--exporter.disable-hostdiscovery` | `OPNSENSE_EXPORTER_DISABLE_HOSTDISCOVERY` | `false` | Disable the scraping of the discovered-host inventory (Interfaces > Host discovery / hostwatch): interface+source host counts, low-cardinality. A core OPNsense feature (not a plugin); reads absent/silent on releases predating it. |
| `--exporter.disable-ids` | `OPNSENSE_EXPORTER_DISABLE_IDS` | `false` | Disable the scraping of Suricata IDS/IPS metrics (service status, IPS mode, eve log and ruleset inventory, installed-rule count; silent structures when IDS is unconfigured) |
| `--exporter.disable-interfaces` | `OPNSENSE_EXPORTER_DISABLE_INTERFACES` | `false` | Disable the interfaces collector (per-interface traffic/link metrics) |
| `--exporter.disable-ipsec` | `OPNSENSE_EXPORTER_DISABLE_IPSEC` | `false` | Disable the scraping of IPSec service |
| `--exporter.disable-kea` | `OPNSENSE_EXPORTER_DISABLE_KEA` | `false` | Disable the scraping of Kea DHCP lease metrics |
| `--exporter.disable-lldpd` | `OPNSENSE_EXPORTER_DISABLE_LLDPD` | `false` | Disable the scraping of LLDP neighbor table metrics (silent when the os-lldpd plugin is absent) |
| `--exporter.disable-log-events` | `OPNSENSE_EXPORTER_DISABLE_LOG_EVENTS` | `false` | Disable the log_events collector (Prometheus counters derived from received syslog lines: firewall/haproxy/sshd/dhcp/audit/ids event totals). Silent until the syslog receiver is enabled and feeding it. |
| `--exporter.disable-mbuf` | `OPNSENSE_EXPORTER_DISABLE_MBUF` | `false` | Disable the scraping of mbuf statistics |
| `--exporter.disable-monit` | `OPNSENSE_EXPORTER_DISABLE_MONIT` | `false` | Disable the scraping of Monit service check status (silent when Monit is not running) |
| `--exporter.disable-ndp` | `OPNSENSE_EXPORTER_DISABLE_NDP` | `false` | Disable the scraping of the NDP (IPv6 neighbor discovery) table |
| `--exporter.disable-netbird` | `OPNSENSE_EXPORTER_DISABLE_NETBIRD` | `false` | Disable the scraping of NetBird management/signal connectivity, relay and peer metrics (silent when the os-netbird plugin is absent) |
| `--exporter.disable-nginx` | `OPNSENSE_EXPORTER_DISABLE_NGINX` | `false` | Disable the scraping of nginx VTS statistics (silent when the os-nginx plugin is absent) |
| `--exporter.disable-ntp` | `OPNSENSE_EXPORTER_DISABLE_NTP` | `false` | Disable the scraping of NTP peer metrics |
| `--exporter.disable-nut` | `OPNSENSE_EXPORTER_DISABLE_NUT` | `false` | Disable the scraping of NUT UPS metrics (silent when the os-nut plugin is absent) |
| `--exporter.disable-openvpn` | `OPNSENSE_EXPORTER_DISABLE_OPENVPN` | `false` | Disable the scraping of OpenVPN service |
| `--exporter.disable-pf-stats` | `OPNSENSE_EXPORTER_DISABLE_PF_STATS` | `false` | Disable the scraping of PF statistics (state table, counters, memory limits, timeouts) |
| `--exporter.disable-protocol` | `OPNSENSE_EXPORTER_DISABLE_PROTOCOL` | `false` | Disable the protocol-statistics collector (TCP/UDP/IP/ICMP/ARP/CARP/pfsync counters) |
| `--exporter.disable-qfeeds` | `OPNSENSE_EXPORTER_DISABLE_QFEEDS` | `false` | Disable the scraping of Q-Feeds threat intelligence statistics (silent when the os-q-feeds-connector plugin is absent) |
| `--exporter.disable-relayd` | `OPNSENSE_EXPORTER_DISABLE_RELAYD` | `false` | Disable the scraping of relayd virtual server/table/host health (silent when the os-relayd plugin is absent) |
| `--exporter.disable-services` | `OPNSENSE_EXPORTER_DISABLE_SERVICES` | `false` | Disable the services collector (per-service running state) |
| `--exporter.disable-siproxd` | `OPNSENSE_EXPORTER_DISABLE_SIPROXD` | `false` | Disable the scraping of the siproxd active SIP registration count (silent when the os-siproxd plugin is absent) |
| `--exporter.disable-snapshots` | `OPNSENSE_EXPORTER_DISABLE_SNAPSHOTS` | `false` | Disable the scraping of ZFS boot-environment inventory metrics (silent/zero on non-ZFS filesystems such as UFS) |
| `--exporter.disable-syslog` | `OPNSENSE_EXPORTER_DISABLE_SYSLOG` | `false` | Disable the scraping of syslog-ng statistics |
| `--exporter.disable-system` | `OPNSENSE_EXPORTER_DISABLE_SYSTEM` | `false` | Disable the scraping of system resource metrics (memory, uptime, disk, swap) |
| `--exporter.disable-tailscale` | `OPNSENSE_EXPORTER_DISABLE_TAILSCALE` | `false` | Disable the scraping of Tailscale node-local metrics (silent when the os-tailscale plugin is absent; complementary to tailscale2otel) |
| `--exporter.disable-temperature` | `OPNSENSE_EXPORTER_DISABLE_TEMPERATURE` | `false` | Disable the scraping of temperature metrics |
| `--exporter.disable-trafficshaper` | `OPNSENSE_EXPORTER_DISABLE_TRAFFICSHAPER` | `false` | Disable the scraping of traffic shaper pipe/queue/rule statistics (silent when the shaper is unconfigured) |
| `--exporter.disable-unbound` | `OPNSENSE_EXPORTER_DISABLE_UNBOUND` | `false` | Disable the scraping of Unbound service |
| `--exporter.disable-wireguard` | `OPNSENSE_EXPORTER_DISABLE_WIREGUARD` | `false` | Disable the scraping of Wireguard service |
| `--exporter.enable-alias-details` | `OPNSENSE_EXPORTER_ENABLE_ALIAS_DETAILS` | `false` | Enable per-table pf evaluation/packet/byte counters for firewall aliases (~10 series per alias table) |
| `--exporter.enable-arp-details` | `OPNSENSE_EXPORTER_ENABLE_ARP_DETAILS` | `false` | Enable per-entry ARP metrics (ip/mac/hostname labels - high, churning cardinality). Off by default; the low-cardinality entries_total aggregate is always emitted. |
| `--exporter.enable-dhcpv4-details` | `OPNSENSE_EXPORTER_ENABLE_DHCPV4_DETAILS` | `false` | Enable per-lease detail metrics for ISC DHCPv4 (high cardinality on large networks) |
| `--exporter.enable-dhcpv6-details` | `OPNSENSE_EXPORTER_ENABLE_DHCPV6_DETAILS` | `false` | Enable per-lease detail metrics for ISC DHCPv6 (high cardinality on large networks) |
| `--exporter.enable-dnsmasq-details` | `OPNSENSE_EXPORTER_ENABLE_DNSMASQ_DETAILS` | `false` | Enable per-lease detail metrics for Dnsmasq DHCP (high cardinality on large networks) |
| `--exporter.enable-firewall-nat-counts` | `OPNSENSE_EXPORTER_ENABLE_FIREWALL_NAT_COUNTS` | `false` | Enable the NAT rule inventory count metric (opnsense_firewall_nat_rules), broken down by type (source_nat, d_nat, one_to_one, npt) and enabled state. Off by default: each scheduled poll does four extra GETs, one per NAT rule type. Rules created before an admin migrated to the MVC-managed NAT backend are not counted; NAT rule pf hit/byte statistics do not exist upstream. |
| `--exporter.enable-firewall-rules-details` | `OPNSENSE_EXPORTER_ENABLE_FIREWALL_RULES_DETAILS` | `false` | Enable per-rule detail metrics for firewall rules (high cardinality on large rulesets) |
| `--exporter.enable-firmware-package-details` | `OPNSENSE_EXPORTER_ENABLE_FIRMWARE_PACKAGE_DETAILS` | `false` | Enable per-package firmware detail metrics (pending package updates and installed plugin inventory; adds one extra API call per scheduled poll) |
| `--exporter.enable-frr-routes` | `OPNSENSE_EXPORTER_ENABLE_FRR_ROUTES` | `false` | Enable FRR routing-state volume gauges (zebra RIB / OSPF route table / LSDB counts by protocol, route type, area and LSA type - never per-prefix or per-LSA series). Off by default: the underlying bootgrid endpoints have no success-body caching and their payload size scales with route-table size (up to 6 extra vtysh execs per scheduled poll). |
| `--exporter.enable-hasync` | `OPNSENSE_EXPORTER_ENABLE_HASYNC` | `false` | Enable the HA sync status collector (performs a live XML-RPC call to the CARP peer on every scheduled poll). Disabled by default. |
| `--exporter.enable-ids-alerts` | `OPNSENSE_EXPORTER_ENABLE_IDS_ALERTS` | `false` | Enable the Suricata recent-alerts gauge (opnsense_ids_recent_alerts by action). Off by default: each scheduled poll triggers a reverse read of eve.json on the box. Window set by --exporter.ids-alert-lookback. |
| `--exporter.enable-ipsec-lease-details` | `OPNSENSE_EXPORTER_ENABLE_IPSEC_LEASE_DETAILS` | `false` | Enable per-lease IPsec mode-cfg detail metrics (opnsense_ipsec_lease_online with an unbounded road-warrior user label). Off by default; the per-pool lease aggregates stay always-on. |
| `--exporter.enable-kea-details` | `OPNSENSE_EXPORTER_ENABLE_KEA_DETAILS` | `false` | Enable per-lease detail metrics for Kea DHCP (high cardinality on large networks) |
| `--exporter.enable-ndp-details` | `OPNSENSE_EXPORTER_ENABLE_NDP_DETAILS` | `false` | Enable per-entry NDP metrics (ip/mac labels - high, churning cardinality from IPv6 privacy-address rotation). Off by default; the low-cardinality entries_total aggregate is always emitted. |
| `--exporter.enable-netbird-details` | `OPNSENSE_EXPORTER_ENABLE_NETBIRD_DETAILS` | `false` | Enable per-peer detail metrics for NetBird (per-peer cardinality; peer FQDN labels) |
| `--exporter.enable-netflow` | `OPNSENSE_EXPORTER_ENABLE_NETFLOW` | `false` | Enable the netflow collector (enabled status, service status, cache stats). Disabled by default. |
| `--exporter.enable-network-diagnostics` | `OPNSENSE_EXPORTER_ENABLE_NETWORK_DIAGNOSTICS` | `false` | Enable the network diagnostics collector (netisr, sockets, routes). Disabled by default. |
| `--exporter.enable-openvpn-details` | `OPNSENSE_EXPORTER_ENABLE_OPENVPN_DETAILS` | `false` | Enable per-session detail metrics for OpenVPN (exposes usernames and per-client tunnel addresses) |
| `--exporter.enable-smart` | `OPNSENSE_EXPORTER_ENABLE_SMART` | `false` | Enable the SMART disk health collector. Off by default: each scheduled poll does a per-disk POST fanout that runs `smartctl -a` on the firewall (extra API/latency cost, and wakes spun-down disks). Silent when the os-smart plugin is absent. |
| `--exporter.enable-tailscale-peer-details` | `OPNSENSE_EXPORTER_ENABLE_TAILSCALE_PEER_DETAILS` | `false` | Enable per-peer detail metrics for Tailscale (per-peer cardinality; peer hostname labels) |
| `--exporter.enable-tor` | `OPNSENSE_EXPORTER_ENABLE_TOR` | `false` | Enable the Tor circuit/stream telemetry collector (control-port GETINFO via the os-tor plugin). Off by default: each scheduled poll does two extra configd execs to query the control port, and requires the plugin's control port + password to be configured. Silent when the os-tor plugin is absent. |
| `--exporter.enable-unbound-infra` | `OPNSENSE_EXPORTER_ENABLE_UNBOUND_INFRA` | `false` | Enable per-upstream infra cache RTT metrics from Unbound (cardinality scales with the resolver's infra cache; one series pair per upstream ip/host) |
| `--exporter.enable-unbound-qstats` | `OPNSENSE_EXPORTER_ENABLE_UNBOUND_QSTATS` | `false` | Enable Unbound DNSBL query-stats totals and blocklist size metrics, plus local-zone/data/insecure-domain counts. Off by default: the query-stats totals call is backed by an expensive configd+python+pandas+DuckDB query (~1s per scheduled poll) - skipped entirely while query-stats logging (general.stats) is off on the box, but still paid for on every scheduled poll once it is on. |
| `--exporter.enable-vnstat` | `OPNSENSE_EXPORTER_ENABLE_VNSTAT` | `false` | Enable the vnstat persistent traffic accounting collector (day/month/total bytes per interface, survives reboots). Off by default: each scheduled poll does one interface_list call plus one get_json_data call per interface vnstat tracks. Silent when the os-vnstat plugin is absent. |
| `--exporter.firmware-cache-ttl` | `OPNSENSE_EXPORTER_FIRMWARE_CACHE_TTL` | `12h0m0s` | How long to cache firmware API responses (status and, when enabled, package details). The firmware data OPNsense serves is the stored result of the box's own update check, which it refreshes roughly daily, so re-fetching it on every poll only costs firewall CPU. Set to 0 to fetch on every poll. |
| `--exporter.ids-alert-lookback` | `OPNSENSE_EXPORTER_IDS_ALERT_LOOKBACK` | `15m` | Lookback window over which opnsense_ids_recent_alerts counts Suricata eve alerts (a gauge). Only used when --exporter.enable-ids-alerts is set. Counts are a floor when more than 500 alerts fall inside the window. |
| `--exporter.instance-label` | `OPNSENSE_EXPORTER_INSTANCE_LABEL` | -- | Label to use to identify the instance in every metric. If you have multiple instances of the exporter, you can differentiate them by using different value in this flag, that represents the instance of the target OPNsense. If left empty, it defaults to the configured OPNsense address (deterministic). Set --exporter.instance-use-hostname to derive it from the OPNsense hostname instead. |
| `--exporter.instance-use-hostname` | `OPNSENSE_EXPORTER_INSTANCE_USE_HOSTNAME` | `false` | When --exporter.instance-label is empty, derive the instance label from the OPNsense hostname reported by the API instead of the configured address. This lookup is deterministic: it blocks at startup and, if the hostname cannot be obtained, the exporter refuses to start (rather than silently falling back to the address, which would make the label depend on startup timing and flip between restarts). |
| `--exporter.max-scrape-duration` | `OPNSENSE_EXPORTER_MAX_SCRAPE_DURATION` | `50s` | Upper bound on a single collector poll (#336). Since serving /metrics now replays an in-memory snapshot rather than calling the API, this bounds each background poll so a stalled/blackholed endpoint frees its poll-concurrency slot instead of holding it open. Serving itself is never blocked by it. |
| `--flow.correlate` | `OPNSENSE_EXPORTER_FLOW_CORRELATE` | `true` | Correlate NetFlow fragments and Zenarmor conn documents into one merged flow record per connection-window. A pass-through when only one source is present. Off emits NetFlow records raw and per-fragment. |
| `--flow.correlate.max-entries` | `OPNSENSE_EXPORTER_FLOW_CORRELATE_MAX_ENTRIES` | `50000` | Hard cap on live correlator entries. At the cap the oldest is force-emitted (never dropped) and counted. The NetFlow ingress is unauthenticated, so this bounds memory against a flood. 0 is unbounded (unwise with the listener on). |
| `--flow.correlate.window` | `OPNSENSE_EXPORTER_FLOW_CORRELATE_WINDOW` | `3m` | How long the correlator holds a connection-window before emitting. Also the maximum a flow log is delayed. NetFlow export lag runs to ~30m for long flows (#346), so a flow whose records straddle the window emits a partial per window rather than one joined record. |
| `--flow.dns-cache.size` | `OPNSENSE_EXPORTER_FLOW_DNS_CACHE_SIZE` | `50000` | Entries in the DNS answer cache that gives a flow to a bare IP its dst.domain, fed by the Zenarmor dns family. Over the cap it stops inserting rather than evicting hot entries. 0 disables domain enrichment. |
| `--flow.enabled` | `OPNSENSE_EXPORTER_FLOW_ENABLED` | `true` | Enable flow rollups: bounded byte and packet volume counters derived from flow records. Costs nothing where no flow source is configured - the metrics are simply silent, like log_events without the syslog receiver. Set --exporter.disable-flow to remove the collector entirely. |
| `--flow.log-mode` | `OPNSENSE_EXPORTER_FLOW_LOG_MODE` | `per_flow` | Flow log emission: "per_flow" ships one OTLP log record per correlated flow on the shared log pipeline; "off" ships none while still deriving all metrics. Zenarmor conn documents ship on their own lane regardless. |
| `--flow.max-keys` | `OPNSENSE_EXPORTER_FLOW_MAX_KEYS` | `2500` | Maximum distinct label combinations the flow accumulator tracks in memory. A separate bound from --flow.top-n: this caps memory between scrapes, that caps emitted series. Combinations first seen at the cap fold into __other__ and are counted by opnsense_flow_rollup_capped_total. 0 is unbounded. |
| `--flow.max-logs-per-window` | `OPNSENSE_EXPORTER_FLOW_MAX_LOGS_PER_WINDOW` | `0` | Cap on flow log records shipped per minute; excess is TRUNCATED (never sampled) and counted. A flood guard on the unauthenticated NetFlow ingress. 0 is unlimited. Metrics are never truncated. |
| `--flow.netflow.allowed-peers` | `OPNSENSE_EXPORTER_FLOW_NETFLOW_ALLOWED_PEERS` | -- | CIDR allowlist of exporters permitted to send flow records, repeatable. Empty means accept from anyone, which is a deliberate decision to trust the network rather than a default to drift into: anything that can reach the port can inject flow records. |
| `--flow.netflow.debug-capture` | `OPNSENSE_EXPORTER_FLOW_NETFLOW_DEBUG_CAPTURE` | `off` | Dump raw NetFlow datagrams to --logs.debug-capture.dir. "unidentified" writes only datagrams carrying something the decoder could not interpret (an unmodelled template element, an options template, an unknown flowset, or a datagram that would not decode at all) - cheap, and the mode worth leaving on. "all" writes every datagram, for regenerating a replay fixture or measuring the export; deliberately heavy, bounded only by --logs.debug-capture.max-bytes. Requires --flow.netflow.enabled and the shared dir. |
| `--flow.netflow.enabled` | `OPNSENSE_EXPORTER_FLOW_NETFLOW_ENABLED` | `false` | Enable the NetFlow v5/v9 receiver. Opens an UNAUTHENTICATED UDP socket: NetFlow has no authentication of any kind, so restrict it with --flow.netflow.allowed-peers or by firewalling the port. Requires --flow.enabled. |
| `--flow.netflow.ifindex-map` | `OPNSENSE_EXPORTER_FLOW_NETFLOW_IFINDEX_MAP` | -- | Override the derived NetFlow ifIndex-to-device map, as comma-separated index=device pairs (e.g. "1=ixl0,5=igb0,13=ixl0_vlan50"). Entries listed here beat the derived map; indices not listed still use it, so pin every index that carries traffic. Read yours off the box with: ifinfo \| awk '$1 == "Interface" { n++; print n, $2 }' - that is the whole enumeration. ngctl list \| grep netflow shows only the interfaces netflow captures, and an egress index can legitimately name one it does not. |
| `--flow.netflow.listen` | `OPNSENSE_EXPORTER_FLOW_NETFLOW_LISTEN` | `:2055` | Address the NetFlow receiver binds, host:port. Bound eagerly at startup, so a port already in use is a startup error rather than a receiver that is silently never there. |
| `--flow.top-n` | `OPNSENSE_EXPORTER_FLOW_TOP_N` | `1000` | Maximum flow series emitted per scrape. Everything beyond folds into a single __other__ series per source, so the family still sums exactly at any limit. 0 emits every tracked combination. |
| `--flow.top-talkers` | `OPNSENSE_EXPORTER_FLOW_TOP_TALKERS` | `false` | Emit opnsense_flow_top_talker_bytes_total: bytes per internal host and direction, top-N with an __other__ remainder. OFF by default because the host label is high cardinality; the top-N bounds it but a host label is still one series per host. |
| `--flow.zenarmor` | `OPNSENSE_EXPORTER_FLOW_ZENARMOR` | `true` | Derive flow records from the Zenarmor receiver's conn documents. Adds no new log records to Loki: the conn document ships exactly as before and this only feeds the metric rollup. Requires --logs.zenarmor.enabled to produce anything. |
| `--log.format` | -- | `logfmt` | Output format of log messages. One of: [logfmt, json] |
| `--log.level` | -- | `info` | Only log messages with the given severity or above. One of: [debug, info, warn, error] |
| `--logs.batch-max` | `OPNSENSE_EXPORTER_LOGS_BATCH_MAX` | `1000` | Maximum number of records the emitter hands to the sink per batch. |
| `--logs.buffer-max-bytes` | `OPNSENSE_EXPORTER_LOGS_BUFFER_MAX_BYTES` | `134217728` | Aggregate byte budget for the in-memory backpressure queue. The record-count cap (--logs.buffer-size) alone does not bound memory: a receiver preserves each record's raw body, so a few large records can outweigh thousands of small ones. On overflow the oldest record is dropped and counted, exactly as for the count cap. 0 disables the byte budget. |
| `--logs.buffer-size` | `OPNSENSE_EXPORTER_LOGS_BUFFER_SIZE` | `4096` | Capacity of the in-memory backpressure queue between pollers and the sink. On overflow the oldest record is dropped and counted (logs_dropped_total). |
| `--logs.crowdsec.enabled` | `OPNSENSE_EXPORTER_LOGS_CROWDSEC_ENABLED` | `false` | Enable the crowdsec log source: ships CrowdSec alert and decision records to Loki (there is no native syslog path for these - the plugin registers no syslog scope; alerts live only in the LAPI). Requires --logs.enabled. Polls at a 60s floor regardless of --logs.poll-interval. Silent when the os-crowdsec plugin is absent. Off by default. |
| `--logs.debug-capture.dir` | `OPNSENSE_EXPORTER_LOGS_DEBUG_CAPTURE_DIR` | -- | Directory to dump UNMODELLED receiver signals into for inspection, as NDJSON under <dir>/<receiver>/ (files are 0600 and carry real network data - addresses, DNS queries, TLS SNI, HTTP hosts). Off unless set. Enable capture per receiver with --logs.zenarmor.debug-capture / --logs.syslog.debug-capture. Point a writable bind mount here; only signals the exporter cannot model are written, never the full stream. |
| `--logs.debug-capture.max-bytes` | `OPNSENSE_EXPORTER_LOGS_DEBUG_CAPTURE_MAX_BYTES` | `256MiB` | Total size cap for --logs.debug-capture.dir (e.g. 256MiB, 1GB). Capture STOPS when the dir reaches this, keeping the oldest samples; it never deletes to make room, so a debug capture can never fill the disk. Counts bytes left by previous runs. |
| `--logs.enabled` | `OPNSENSE_EXPORTER_LOGS_ENABLED` | `false` | Enable the opt-in log/event shipping pipeline (polls OPNsense event APIs and ships to Loki via OTLP). Off by default. Independent of --otlp.enabled (which gates metrics). |
| `--logs.ids.enabled` | `OPNSENSE_EXPORTER_LOGS_IDS_ENABLED` | `false` | Enable the IDS (Suricata EVE alert) log source: ships full Suricata alert records polled via ids/service/query_alerts. Off by default. Requires --logs.enabled. If the box already forwards EVE JSON via syslog (ids.general.syslog_eve), prefer that native path instead of also enabling this source - do not ship the same alerts twice. |
| `--logs.max-metric-keys` | `OPNSENSE_EXPORTER_LOGS_MAX_METRIC_KEYS` | `5000` | Maximum distinct label tuples retained per derived log_events metric family. Receivers are push-based and syslog over UDP has a spoofable source, so tuple values are sender-controlled: without this bound a sender can grow process-lifetime metric state without limit. Tuples beyond the cap fold into a counted overflow series rather than being dropped silently. 0 disables the cap. |
| `--logs.max-record-bytes` | `OPNSENSE_EXPORTER_LOGS_MAX_RECORD_BYTES` | `1048576` | Maximum estimated retained size for a single record - its body, source and attributes plus a fixed overhead allowance, measured the same way as --logs.buffer-max-bytes so the two read against one number. A record larger than this is rejected at ingest and counted rather than queued, so one oversized record cannot occupy the whole queue budget or become a batch the sink permanently refuses. 0 disables the per-record cap. |
| `--logs.poll-interval` | `OPNSENSE_EXPORTER_LOGS_POLL_INTERVAL` | `10s` | Base interval between event polls per source (floor 5s). Sources may raise their own floor. |
| `--logs.ship-max-attempts` | `OPNSENSE_EXPORTER_LOGS_SHIP_MAX_ATTEMPTS` | `10` | Maximum delivery attempts for one batch before it is dropped and counted (logs_dropped_total{reason="ship_failed_permanent"}). Retries are exponentially backed off. Without this bound a batch the sink permanently refuses is retried forever by the single emitter goroutine, wedging all subsequent delivery. 0 restores unlimited retries. |
| `--logs.sink` | `OPNSENSE_EXPORTER_LOGS_SINK` | `otlp` | Log shipping sink: otlp (OTLP logs, reuses the --otlp.* transport) or stdout (one JSON line per event). |
| `--logs.state-file` | `OPNSENSE_EXPORTER_LOGS_STATE_FILE` | -- | Optional path to persist per-source cursors across restarts (atomic JSON). Empty = in-memory only (resume from now on restart). |
| `--logs.syslog.allowed-peers` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_ALLOWED_PEERS` | -- | Comma-separated CIDR allowlist of hosts permitted to send syslog (e.g. 10.0.0.254/32). Empty accepts any sender. Syslog is unauthenticated, so set this on a shared network. |
| `--logs.syslog.debug-capture` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_DEBUG_CAPTURE` | `false` | Dump syslog lines this receiver cannot parse (unknown program, no matching parser, or an unparseable envelope) to --logs.debug-capture.dir for inspection. Requires --logs.debug-capture.dir. Additive - these lines still ship as generic records. |
| `--logs.syslog.enabled` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_ENABLED` | `false` | Enable the syslog receiver: listens for logs pushed by OPNsense (RFC5424 or RFC3164, UDP and/or TCP) and ships them enriched with rule descriptions, interface names and hostnames. Off by default. Requires --logs.enabled. Configure a matching target on the firewall under System > Settings > Logging > Targets. |
| `--logs.syslog.enrich` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_ENRICH` | `true` | Enrich received syslog records from the OPNsense API: firewall rule descriptions (including auto-generated system rules), friendly interface names, DHCP hostnames, MAC addresses, local/remote scope and well-known service names. |
| `--logs.syslog.exclude-programs` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_EXCLUDE_PROGRAMS` | -- | Comma-separated syslog programs to DROP (e.g. radvd,cron). Empty ships everything. Dropped records are counted in opnsense_exporter_logs_rejected_total{reason="filtered"} - never silently discarded. |
| `--logs.syslog.include-programs` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_INCLUDE_PROGRAMS` | -- | Comma-separated syslog programs to ship, dropping everything else. Empty ships everything. Mutually exclusive with --logs.syslog.exclude-programs. |
| `--logs.syslog.listen-tcp` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_LISTEN_TCP` | `:5514` | TCP listen address for the syslog receiver. Empty disables the TCP listener. Prefer TCP for firewall logs: UDP datagram loss is silent and unrecoverable. |
| `--logs.syslog.listen-tls` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_LISTEN_TLS` | -- | TLS listen address for the syslog receiver (RFC5424 over TLS, OPNsense tls4/tls6). Empty disables the TLS listener. Requires --logs.syslog.tls-cert-file and --logs.syslog.tls-key-file. |
| `--logs.syslog.listen-udp` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_LISTEN_UDP` | `:5514` | UDP listen address for the syslog receiver. Empty disables the UDP listener. Port 5514 (not 514) because 514 is privileged and the container runs non-root. |
| `--logs.syslog.max-conns` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_MAX_CONNS` | `64` | Maximum concurrent connections to the syslog receiver, applied PER TRANSPORT: plain TCP and TLS each get this budget from a separate pool. They are separate so a plaintext flood cannot starve authenticated mTLS senders out of the capacity they need. Bounds goroutine growth on an unauthenticated ingress; with both transports enabled the worst-case connection count is twice this value. |
| `--logs.syslog.min-severity` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_MIN_SEVERITY` | -- | Drop records less severe than this (emerg, alert, crit, err, warning, notice, info, debug). E.g. notice drops info and debug. Empty ships every severity. |
| `--logs.syslog.sample` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_SAMPLE` | `false` | Sample (drop) high-volume raw log lines AFTER their metrics have been derived: keep firewall block/reject lines and drop passes, keep HAProxy state changes and errors and drop the per-connection noise. Low-volume programs (sshd, dhcp, audit, ids) are kept in full. Off by default. Requires the log_events collector (exporter.disable-log-events must not be set) so every dropped line is counted first. |
| `--logs.syslog.sampled-attribute` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_SAMPLED_ATTRIBUTE` | `true` | When sampling is on, stamp a sampled="true" attribute on every shipped line so consumers know the log stream is incomplete and must use the derived counters for totals. On by default; only takes effect when --logs.syslog.sample is set. |
| `--logs.syslog.tls-cert-file` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_TLS_CERT_FILE` | -- | PEM server certificate for the TLS syslog listener. |
| `--logs.syslog.tls-client-ca-file` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_TLS_CLIENT_CA_FILE` | -- | PEM CA bundle to verify sender client certificates on the TLS syslog listener. When set, a sender MUST present a certificate signed by this CA - the only real sender authentication syslog offers. Empty accepts any TLS client (encryption only). |
| `--logs.syslog.tls-key-file` | `OPNSENSE_EXPORTER_LOGS_SYSLOG_TLS_KEY_FILE` | -- | PEM private key for the TLS syslog listener. |
| `--logs.unbound.enabled` | `OPNSENSE_EXPORTER_LOGS_UNBOUND_ENABLED` | `false` | Enable the opt-in Unbound per-query DNS log source (pi-hole-style query log to Loki: domain, client, action, resolution source, blocklist and dnssec_status per query). Off by default; requires --logs.enabled. CAVEAT: without a per-client filter, Unbound's query-log backend (DuckDB) only ever exposes the newest 1000 rows across the WHOLE resolver - on a firewall sustaining more than roughly 1000 queries between polls, older rows silently fall out of that window before this exporter ever sees them. This is accepted, honestly-counted sampling loss, not a bug: it is tracked via opnsense_exporter_logs_possible_gap_total{source="unbound"}, never silently dropped. Homelab/SMB query volumes are fine; a busy enterprise resolver should not enable this. Also requires Unbound reporting/statistics enabled on the firewall. Poll floor 15s regardless of --logs.poll-interval. |
| `--logs.zenarmor.allowed-peers` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_ALLOWED_PEERS` | -- | Comma-separated CIDR allowlist of hosts permitted to stream (e.g. 10.0.0.254/32). Empty accepts any sender. The receiver is unauthenticated unless --logs.zenarmor.auth-user is set, so set this on a shared network. |
| `--logs.zenarmor.auth-password` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_AUTH_PASSWORD` | -- | Password for --logs.zenarmor.auth-user. |
| `--logs.zenarmor.auth-user` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_AUTH_USER` | -- | Require HTTP basic auth on the Zenarmor receiver, with this username. Set the same credentials in Zenarmor's streaming settings. Empty disables auth. |
| `--logs.zenarmor.debug-capture` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_DEBUG_CAPTURE` | `false` | Dump Zenarmor signals this receiver does not model (unhandled Elasticsearch endpoints, unknown families, documents that would not parse) to --logs.debug-capture.dir for inspection. Requires --logs.debug-capture.dir. While on, the unhandled-endpoint warning is suppressed - the capture file carries the same signal. |
| `--logs.zenarmor.drop-self-traffic` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_DROP_SELF_TRAFFIC` | `true` | Drop records describing the exporter's own Elasticsearch ingest connection - Zenarmor inspects the link the receiver listens on, so it reports the very connection delivering its records (roughly 15% of all volume, and most of the http family). Matched on the streaming peer's address plus the receiver's listen port, never the destination address, which a containerised exporter cannot know. Set false to keep them; drops are counted as logs_rejected_total{reason="self_traffic"}. |
| `--logs.zenarmor.enabled` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_ENABLED` | `false` | Enable the Zenarmor receiver: poses as an Elasticsearch node so Zenarmor can stream its reporting data (connections, DNS, TLS, HTTP, threat alerts) to the exporter, which ships it enriched over OTLP. Off by default. Requires --logs.enabled. Configure the firewall under Configuration/Zenarmor > Settings > Streaming Data > 'Stream Reporting Data to External Elasticsearch' - NOT the initial wizard's 'Remote Elasticsearch Database', which replaces local reporting irreversibly. |
| `--logs.zenarmor.enrich` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_ENRICH` | `true` | Enrich received Zenarmor records from the OPNsense API: friendly interface names, local/remote scope and well-known service names. Zenarmor resolves hostnames, MACs and device identity itself, so this adds only what it does not already know. |
| `--logs.zenarmor.exclude` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_EXCLUDE` | -- | Drop Zenarmor records whose FIELD matches REGEX, as FIELD=~REGEX (e.g. 'server_name=~.*\.grafana\.net'). Repeatable; default off. The field name is validated at startup against the receiver's attribute vocabulary - a typo is a startup error, never a silent no-op. Derived counters are observed BEFORE the drop, so opnsense_log_events_zenarmor_total stays complete; drops are counted as logs_rejected_total{reason="excluded"} and logs_zenarmor_excluded_total{rule}. EXCLUSION IS LOSSY: the derived counters carry no server_name, query or device_name, so an excluded record's forensic detail is gone for good. Prefer a query-time filter unless volume genuinely forces this. Set via env as one rule per LINE. |
| `--logs.zenarmor.families` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_FAMILIES` | -- | Comma-separated Zenarmor families to ship (conn, dns, tls, http, alert, sip). Empty ships all of them. Prefer restricting this at the Zenarmor end instead - data cut at source never crosses the wire. Zenarmor streams ~2.5-3.3M records/day (~4-6 GB/day of JSON), of which conn is ~61%. |
| `--logs.zenarmor.listen-http` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_LISTEN_HTTP` | `:9200` | Listen address for the Zenarmor receiver. Point Zenarmor's streaming URI at it. |
| `--logs.zenarmor.max-concurrent-requests` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_MAX_CONCURRENT_REQUESTS` | `8` | Maximum bulk requests processed concurrently by the Zenarmor receiver. The per-request body limit bounds one request; without this, N simultaneous requests each buffer that full allowance. Excess requests are refused with 503 before a body is read. 0 disables the limit. |
| `--logs.zenarmor.tls-cert-file` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_TLS_CERT_FILE` | -- | PEM server certificate for the Zenarmor receiver. Set with --logs.zenarmor.tls-key-file to serve HTTPS, and use an https:// URI in Zenarmor's streaming settings. |
| `--logs.zenarmor.tls-key-file` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_TLS_KEY_FILE` | -- | PEM private key for --logs.zenarmor.tls-cert-file. |
| `--logs.zenarmor.transport` | `OPNSENSE_EXPORTER_LOGS_ZENARMOR_TRANSPORT` | `elasticsearch` | How Zenarmor delivers its reporting data: 'elasticsearch' (default) runs the built-in Elasticsearch receiver on --logs.zenarmor.listen-http; 'syslog' ingests it through the shared syslog receiver (requires --logs.syslog.enabled and a business-tier Zenarmor licence). families/exclude/enrich/drop-self-traffic apply to either transport. |
| `--opnsense.address` | `OPNSENSE_EXPORTER_OPS_API` | -- | **Required.** Hostname or IP address of OPNsense API |
| `--opnsense.api-key` | `OPNSENSE_EXPORTER_OPS_API_KEY` | -- | API key to use to connect to OPNsense API. This flag/ENV or the OPS_API_KEY_FILE may be set. |
| `--opnsense.api-secret` | `OPNSENSE_EXPORTER_OPS_API_SECRET` | -- | API secret to use to connect to OPNsense API. This flag/ENV or the OPS_API_SECRET_FILE may be set. |
| `--opnsense.insecure` | `OPNSENSE_EXPORTER_OPS_INSECURE` | `false` | Disable TLS certificate verification |
| `--opnsense.max-concurrent-requests` | `OPNSENSE_EXPORTER_OPS_MAX_CONCURRENT_REQUESTS` | `16` | Maximum number of background OPNsense API requests in flight across all scheduled collector polls, including nested sub-requests. Bounds the simultaneous PHP/configd load on the firewall: lower it (e.g. 4-8) to protect a low-power appliance at the cost of queued or longer polls; raise it to let more independent polls progress concurrently on capable hardware. It does not affect /metrics replay. Must be >= 1. |
| `--opnsense.max-retries` | `OPNSENSE_EXPORTER_OPS_MAX_RETRIES` | `3` | Number of attempts for a failed OPNsense API request (transport errors / retryable 5xx). Worst-case block time is --opnsense.timeout x this value. |
| `--opnsense.protocol` | `OPNSENSE_EXPORTER_OPS_PROTOCOL` | -- | **Required.** Protocol to use to connect to OPNsense API. One of: [http, https] |
| `--opnsense.timeout` | `OPNSENSE_EXPORTER_OPS_TIMEOUT` | `15s` | Per-request HTTP timeout for calls to the OPNsense API. Combined with --opnsense.max-retries this bounds one endpoint attempt sequence inside a background collector poll (timeout x retries). Keep that product below --exporter.max-scrape-duration so the poll deadline, rather than a request retry, remains the outer bound. Prometheus scrape_timeout applies only to replaying /metrics. |
| `--otlp.enabled` | `OPNSENSE_EXPORTER_OTLP_ENABLED` | `false` | Enable pushing metrics to an OTLP endpoint (in addition to the /metrics pull endpoint). Off by default. |
| `--otlp.endpoint` | `OPNSENSE_EXPORTER_OTLP_ENDPOINT` | -- | OTLP endpoint URL. When empty, the standard OTEL_EXPORTER_OTLP_ENDPOINT env var is used. |
| `--otlp.export-interval` | `OPNSENSE_EXPORTER_OTLP_EXPORT_INTERVAL` | `60s` | Interval between OTLP metric exports (independent of Prometheus scrapes). |
| `--otlp.fast-export-interval` | `OPNSENSE_EXPORTER_OTLP_FAST_EXPORT_INTERVAL` | `0s` | Optional second OTLP export lane for fast-tier collectors only (#390). Zero (the default) keeps the single-stream behaviour exactly. When set, fast-tier collectors (gateways, interfaces, protocol, pf_stats, activity, netflow, carp — or whatever --collector.poll-interval-override makes fast) export at this interval while everything else stays on --otlp.export-interval. Must be shorter than --otlp.export-interval. Fast-tier series are a small fraction of the total, so 15s here costs far less than setting --otlp.export-interval=15s for everything. |
| `--otlp.grafana-cloud-endpoint` | `OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_ENDPOINT` | -- | Grafana Cloud OTLP gateway base URL (required when using the Grafana Cloud shortcut). |
| `--otlp.grafana-cloud-instance-id` | `OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_INSTANCE_ID` | -- | Grafana Cloud OTLP instance ID. With --otlp.grafana-cloud-token, synthesizes basic-auth. This flag/ENV or OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_INSTANCE_ID_FILE may be set. |
| `--otlp.grafana-cloud-token` | `OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_TOKEN` | -- | Grafana Cloud Access Policy token. This flag/ENV or OPNSENSE_EXPORTER_OTLP_GRAFANA_CLOUD_TOKEN_FILE may be set. |
| `--otlp.headers` | `OPNSENSE_EXPORTER_OTLP_HEADERS` | -- | OTLP headers as comma-separated key=value pairs (e.g. X-Scope-OrgID=1,Authorization=Bearer x). When set, replaces OTEL_EXPORTER_OTLP_HEADERS entirely; when empty, that env var is used. |
| `--otlp.insecure` | `OPNSENSE_EXPORTER_OTLP_INSECURE` | `false` | Disable TLS for the OTLP connection (plaintext). |
| `--otlp.protocol` | `OPNSENSE_EXPORTER_OTLP_PROTOCOL` | `http/protobuf` | OTLP transport protocol: grpc or http/protobuf. Defaults to http/protobuf; an empty value is rejected. |
| `--otlp.service-name` | `OPNSENSE_EXPORTER_OTLP_SERVICE_NAME` | `opnsense-exporter` | service.name resource attribute for exported metrics. |
| `--otlp.tls-ca-file` | `OPNSENSE_EXPORTER_OTLP_TLS_CA_FILE` | -- | Path to a CA certificate file used to verify the OTLP server. |
| `--otlp.tls-cert-file` | `OPNSENSE_EXPORTER_OTLP_TLS_CERT_FILE` | -- | Path to a client certificate file for OTLP mutual TLS (requires --otlp.tls-key-file). |
| `--otlp.tls-key-file` | `OPNSENSE_EXPORTER_OTLP_TLS_KEY_FILE` | -- | Path to a client key file for OTLP mutual TLS (requires --otlp.tls-cert-file). |
| `--pyroscope.application-name` | `OPNSENSE_EXPORTER_PYROSCOPE_APPLICATION_NAME` | `opnsense-exporter` | Pyroscope application name profiles are reported under. |
| `--pyroscope.auth-password` | `OPNSENSE_EXPORTER_PYROSCOPE_AUTH_PASSWORD` | -- | HTTP basic auth password for Pyroscope (Grafana Cloud Access Policy token). This flag/ENV or PYROSCOPE_AUTH_PASSWORD_FILE may be set. |
| `--pyroscope.auth-user` | `OPNSENSE_EXPORTER_PYROSCOPE_AUTH_USER` | -- | HTTP basic auth user for Pyroscope (Grafana Cloud stack/instance ID). This flag/ENV or PYROSCOPE_AUTH_USER_FILE may be set. |
| `--pyroscope.disable-mutex-block` | `OPNSENSE_EXPORTER_PYROSCOPE_DISABLE_MUTEX_BLOCK` | `false` | Disable mutex/block contention profiling. On by default; disabling drops the two contention profiles and their process-global sampling rates. CPU, memory, goroutine (and goroutine-leak, when built with the experiment) profiling are unaffected. |
| `--pyroscope.server-address` | `OPNSENSE_EXPORTER_PYROSCOPE_SERVER_ADDRESS` | -- | Grafana Cloud Pyroscope endpoint URL. When empty, continuous profiling is disabled. |
| `--pyroscope.tenant-id` | `OPNSENSE_EXPORTER_PYROSCOPE_TENANT_ID` | -- | Pyroscope tenant ID (only needed for multi-tenancy; unused for Grafana Cloud). |
| `--web.config.file` | -- | -- | Path to configuration file that can enable TLS or authentication. See: https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md |
| `--web.disable-exporter-metrics` | `OPNSENSE_EXPORTER_DISABLE_EXPORTER_METRICS` | -- | Exclude metrics about the exporter itself (process_*, go_*). |
| `--web.listen-address` | -- | `:8080` | Addresses on which to expose metrics and web interface. Repeatable for multiple addresses. Examples: `:9100` or `[::1]:9100` for http, `vsock://:9100` for vsock |
| `--web.systemd-socket` | -- | -- | Use systemd socket activation listeners instead of port listeners (Linux only). |
| `--web.telemetry-path` | `OPNSENSE_EXPORTER_WEB_TELEMETRY_PATH` | `/metrics` | Path under which to expose metrics. |
| `--web.ui-disable-config` | `OPNSENSE_EXPORTER_WEB_UI_DISABLE_CONFIG` | `false` | Hide the /config page. |
| `--web.ui-disable-devices` | `OPNSENSE_EXPORTER_WEB_UI_DISABLE_DEVICES` | `false` | Hide the /devices page (exposes MAC/hostname). |
| `--web.ui-enabled` | `OPNSENSE_EXPORTER_WEB_UI_ENABLED` | `true` | Serve the operator console at / (else the minimal landing page). |
| `--web.ui-refresh-interval` | `OPNSENSE_EXPORTER_WEB_UI_REFRESH_INTERVAL` | `5s` | Live-poll interval for the console's dynamic pages. |
<!-- docgen:end:flags-full-reference -->
