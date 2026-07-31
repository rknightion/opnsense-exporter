---
title: API Landmines
description: Endpoints and modules the API-surface audit ruled out, so no future collector work rediscovers them the hard way
tags:
  - OPNsense
  - development
---

# API Landmines

The [API-surface audit](https://github.com/rknightion/opnsense2otel/issues/227) walked every
OPNsense controller looking for collector candidates. Some endpoints look like harmless status
reads and are not: they start services, flush databases, regenerate config, or shell out to an
external upload on every call. Others are technically safe to call but return misleading or lossy
data if polled the way a Prometheus scraper polls. This page is the permanent record of both
groups, plus the modules the audit confirmed have nothing left to collect.

**This list is not a TODO. Do not re-audit any endpoint or module named here** without first
reading the reasoning below: each entry was checked against OPNsense source, not guessed at. If a
future OPNsense release changes one of these controllers, update the entry in place rather than
re-running the survey from scratch.

**Last re-verified 2026-07-30 against a live OPNsense 26.7.1_1 box** (source read directly off the
appliance via SSH; the four plugin-gated entries not installed there — Redis, HAProxy, hw-probe,
nginx — were checked against `opnsense/plugins@master` instead, since the box under test doesn't
run every plugin). Every row below carries the file (and, where stable, the line) the verdict rests
on. Result: **every entry still holds**. Nothing here was dropped, chased, or absorbed this round.

## Never-scrape endpoints

These are verified in OPNsense source (`os-*` plugin repos and core). Every one of them looks like
a status read from its name or its GET method, and none of them are: calling one on a scrape
interval starts a service, mutates config, or ships data off-box.

| Endpoint | Method | Why it must never be scraped | Still true because |
| --- | --- | --- | --- |
| `api/iperf/instance/query` | GET | If the iperf-manager socket is absent, `send_command()` falls through to configd `iperf restart`/`start` (a GET request that starts a service and rewrites pf anchor rules). It also only ever returns manually-launched one-shot test results, purged after an hour, so there is no steady-state series to collect anyway. | `OPNsense\iperf\Api\InstanceController::queryAction()` still calls `send_command('query', $backend)`, and `send_command()` still falls back to `configdRun('iperf restart')` on a failed `stream_socket_client()` connect. Read on-box 2026-07-30 (os-iperf-1.0_2, `.../controllers/OPNsense/iperf/Api/InstanceController.php`). Unchanged. |
| `api/redis/service/resetdb` | GET | Flushes the Redis database. | `ServiceController::resetdbAction()` still runs `configdRun("redis resetdb")` unconditionally. Redis plugin not installed on the box audited 2026-07-30; checked instead against `opnsense/plugins@master`, `databases/redis/.../Api/ServiceController.php`. Unchanged. |
| `api/haproxy/maintenance/*` | POST | Every action in this controller looks like a status read but responds only to POST and fires `configdRun('template reload OPNsense/HAProxy')` on every single call: full config regeneration per scheduled poll if used by a collector. The server-state data it exposes is redundant with `show stat` anyway. | `MaintenanceController`'s `getData()`/`saveData()`/`syncCerts()` helpers still gate on `$this->request->isPost()` (returning `status: unavailable` otherwise) and every read action (`searchServerAction`, `searchCertificateDiffAction`, etc.) still runs `configdRun('template reload OPNsense/HAProxy')` before returning data. HAProxy plugin not installed on the box audited 2026-07-30; checked against `opnsense/plugins@master`, `net/haproxy/.../Api/MaintenanceController.php`. Unchanged. |
| `api/hwprobe/service/report` | GET | Runs `hw-probe -all -upload`, which uploads the box's hardware profile to linux-hardware.org. An exporter must never cause outbound data exfiltration as a side effect of a scrape. | `ServiceController::reportAction()` still calls `configdRun("hwprobe report")`, and the configd action `[report]` in `actions_hwprobe.conf` still maps that to `/usr/local/bin/hw-probe -all -upload`. hw-probe plugin not installed on the box audited 2026-07-30; checked against `opnsense/plugins@master`, `sysutils/hw-probe/src/opnsense/service/conf/actions.d/actions_hwprobe.conf`. Unchanged. |
| `api/tailscale/status/net` | GET | Runs `tailscale netcheck`, an active multi-second network probe, and returns plain text rather than structured JSON. | `StatusController::netAction()` still runs `configdRun('tailscale tailscale-netcheck')` and returns `['result' => $response]` — the raw trimmed backend string, never `json_decode`d. The configd action still shells to `tailscale netcheck; exit 0`. Read on-box 2026-07-30 (os-tailscale-1.4). Unchanged. |
| `api/diagnostics/carp_status` | POST | A setter despite the read-sounding name: it enables/disables CARP or flips maintenance mode. | `InterfaceController::carpStatusAction($status)` still gates on `$this->request->isPost()` and still calls `configdpRun('interface carp_set_status', [$status])`. Read on-box 2026-07-30, `.../Diagnostics/Api/InterfaceController.php`. Unchanged. |
| `api/unbound/diagnostics/dumpcache` | GET | Dumps the entire unbound message cache. The payload is unbounded and scales with resolver traffic, not with anything worth graphing. | `dumpcacheAction()` still calls `configdRun("unbound dumpcache")` with no size cap or pagination. Read on-box 2026-07-30, `.../Unbound/Api/DiagnosticsController.php`. Unchanged. |
| `api/diagnostics/traffic/_top` | GET | An iftop-style sampling capture that runs for up to 10 seconds per call, with unbounded per-host cardinality. Not something a scrape interval should be triggering. | `TrafficController::TopAction()` still calls `configdpRun('interface show top', ...)`, which runs `/usr/local/opnsense/scripts/interfaces/traffic_top.py`; that script still shells to `iftop -nNb -i <if> -s 2 -t` per interface under a 10-second `subprocess.run(..., timeout=10)`, and the output is one line per observed host pair — no cap. Read on-box 2026-07-30. Unchanged (the 2-second iftop sample plus 10-second subprocess ceiling is the same shape the original entry described). |
| `api/nginx/bans/get` | GET | Inherited `getAction()` behaviour returns the entire nginx model just to expose two fields. Use `searchban` instead if ban data is ever wanted. | `BansController` still declares no `getModelNodes()` override, so the inherited `ApiMutableModelControllerBase::getAction()` still returns `$this->getModel()->getNodes()` — the whole nginx config model — for a controller that only exposes `ban.ip`/`ban.time`. Confirmed the base method on-box 2026-07-30 (`.../Base/ApiMutableModelControllerBase.php:203`); nginx plugin itself not installed there, so `BansController.php` was checked against `opnsense/plugins@master`, `www/nginx/.../Api/BansController.php`. Unchanged. |

## Lossy or sampling transports

These endpoints are safe to call (nothing mutates and nothing gets uploaded), but their transport
or caching behaviour silently drops or samples data under a naive poll-on-interval pattern. They
are not "do not call," they are "do not use as an ingestion source the way you'd expect."

**On SSE specifically:** the two entries below are rejected for a data-correctness defect in the
*endpoint itself* — a lossy throttle, and a follow mechanism that stalls on rotation — not because
the transport is SSE. The exporter does consume outbound SSE elsewhere: see
[Outbound SSE: the pilot](#outbound-sse-the-pilot) below. An earlier version of this page implied
SSE was unsuitable as a class; that implication is what this rewrite removes.

| Endpoint | Why | Still true because |
| --- | --- | --- |
| `api/diagnostics/firewall/stream_log` (SSE) | Lossy by design: the streamer throttles to 10 lines per 100ms window and silently drops the rest, including the line straddling the window boundary. The paged `?digest=` endpoint is the lossless path; never wire this SSE stream up as an ingestion transport. | `/usr/local/opnsense/scripts/filter/read_log.py` still throttles at `line_threshold = 10` over `throttle_interval = 100` (ms): a matched line is emitted only when `elapsed < throttle_interval and line_count <= line_threshold`; once `elapsed >= throttle_interval` the counters reset **without emitting the line that tripped the reset**, so the boundary line is dropped, not delayed. Read on-box 2026-07-30, lines ~184-215 (line numbers drift release to release; if this citation goes stale, search `line_threshold` in the same file). Unchanged. Since #248 the exporter no longer needs this path at all — syslog is now pushed to us directly (`internal/logship`), which is strictly better than tailing OPNsense's own HTTP log stream. |
| `api/diagnostics/log/<module>/<scope>/live` (SSE) | Tails with `tail -f`, not `-F`: it silently stalls after the underlying log rotates, while keepalive frames keep flowing so nothing looks broken. Poll with `validFrom` instead of holding this stream open. | The configd action `[diag.log_live]` in `actions_system.conf` still maps to `/usr/local/opnsense/scripts/syslog/streamLog.py`, which still calls `LogMatcher.live_match_records()`; that method still opens the tail process as `['tail', '-f', '-n 0', latest]` (`/usr/local/opnsense/scripts/syslog/log_matcher.py:65`, read on-box 2026-07-30) — `-f`, not `-F`, so a log rotation orphans the held file descriptor and the stream goes silently stale while `streamLog.py`'s own `event: keepalive` frames keep flowing. Unchanged. Same #248 note as above: the exporter receives syslog pushed directly rather than needing to hold this open. |
| `api/qfeeds/settings/search_events` | A filtered, 300s-configd-cached, port-only re-parse of the firewall log restricted to qfeeds tables. It is strictly a stale subset of the firewall log endpoint, where qfeeds blocks already appear natively with their rule label. | `SettingsController::searchEventsAction()` still calls `configdRun('qfeeds logs')`; the configd action `[logs]` in `actions_qfeeds.conf` still carries `cache_ttl: 300`, and the backing `QFeedsActions.logs()` (`scripts/qfeeds/lib/__init__.py`) still filters the firewall log through a `PFLogCrawler` scoped to the `__qfeeds_<feed_type>` alias tables only. Read on-box 2026-07-30 (os-q-feeds-connector-1.6_1). Unchanged. |
| `api/unbound/overview/search_queries` without a client filter | Only ever returns the latest 1000 rows: the `client` + `timeStart` + `timeEnd` form is the only mode that gets a real time range. Naive polling silently samples on a busy resolver. See [#233](https://github.com/rknightion/opnsense2otel/issues/233) for the accepted-loss design this drove. | `OverviewController::searchQueriesAction()` still branches: with `client` + `timeStart` + `timeEnd` all set it calls `configdpRun('unbound qstats query', [$client, $time_start, $time_end])`; otherwise it still falls back to `configdpRun('unbound qstats details', [1000])` — the literal `1000` row cap, unfiltered by time. Read on-box 2026-07-30. Unchanged. |

## Outbound SSE: the pilot

**Decision locked 2026-07-30 (issue [#553](https://github.com/rknightion/opnsense2otel/issues/553)):**
the exporter may consume outbound SSE — scoped to `api/diagnostics/cpu_usage/stream` only, as a
pilot. Every other stream endpoint on this page stays rejected until the pilot has run in
production for a while; this is not a general green light for SSE ingestion.

| Endpoint | Verdict | Why it's different from the rejected log streams |
| --- | --- | --- |
| `api/diagnostics/cpu_usage/stream` (SSE) | **Safe to consume, as a stream, under the pilot.** Implemented in `internal/cpustream/` (`stream.go`, `accumulator.go`) and wired into the `cpu` collector (`internal/collector/cpu.go`). | It is `iostat -w 1 cpu` behind `text/event-stream`: `/usr/local/opnsense/scripts/system/cpu.py`, dispatched by the configd action `[cpu.stream]` in `actions_system.conf`, served by `CpuUsageController::streamAction()` (all confirmed on-box 2026-07-30). Frames are ~70 bytes/sec, continuous 1-second aggregate-CPU samples — no per-core breakdown, no thread counts, so it does not replace the `activity` collector's `get_activity` poll (which still owns thread-level data). The failure mode the two rejected streams have — silent stall while keepalives keep flowing — is real here too (this box's `lighttpd_webgui/lighttpd.conf` still sets `server.max-write-idle = 999`), so the pilot's consumer treats it as a defect to defend against rather than a reason to reject the endpoint: a data-freshness watchdog tears down and re-dials the connection when no frame has arrived for `StallAfter` (10s default), independent of the socket looking alive. Two implementation hazards specific to this endpoint: `iostat`'s *first* report after each connect is a since-boot average, not an interval delta, and is unconditionally discarded (`accumulator.beginConnection()`/`observe()`); and the metric shape is cumulative counters (`cpu_seconds_total{mode}`), not gauges, because a 1-second stream only survives a 60-second export interval if it's accumulated rather than last-value-sampled. |

## Won't-build

Recorded so the same collector idea does not get proposed twice.

- **A "watched plugin services" collector** fanning out to per-plugin `service/status` endpoints.
  Every relevant plugin already registers in `api/core/service/search`, which the exporter exports
  as `opnsense_services_status{name}`. The one plugin that does not register there (os-beats, which
  ships no `plugins.inc.d` file) is too thin on its own to justify a dedicated collector.
- **`hostdiscovery/service/search`** silently falls back to ARP+NDP (`source: "arp-ndp"`) when the
  discovery daemon is off. Any future consumer of this data must stay source-aware rather than
  assuming active discovery is always what produced a row.

These two are architectural notes, not endpoint claims tied to a specific source line, and neither
plugin (os-beats, hostdiscovery) was installed on the box audited 2026-07-30 — left as recorded,
not re-verified this round.

### Confirmed-empty modules

The audit checked every module below for telemetry beyond config CRUD and service running-state
(already covered by the services collector) and found nothing further to collect. Do not re-run
this survey against them:

`caddy`, `bind`, `dnscrypt-proxy`, `freeradius`, `radsecproxy`, `turnserver`, `sslh`,
`shadowsocks`, `stunnel`, `tinc`, `openconnect`, `zerotier` (runtime data exists only in a UI
controller, not the API), `postfix` (no queue stats in the API), `squid`/proxy (cachemgr not
bridged), `cicap`, `ftpproxy`, `rspamd` (own controller not bridged into the OPNsense API; it can
self-export Prometheus directly), `maltrail`, `wazuhagent`, `telegraf`, `netdata`, `collectd`,
`zabbix` agent/proxy, `nodeexporter`, `muninnode`, `nrpe`, `netsnmp`, `ntopng`, `cloudflared`,
`qemuguestagent`, `puppetagent`, `tftp`, `wol`, `dhcrelay`, `radvd`, `tayga`, `ndpproxy`,
`ndproxy`, `mdnsrepeater`, `udpbroadcastrelay`, `dnsmasq` (fully covered already), `dyndns` (fully
covered already), `trafficshaper` (fully covered already), routes/routing (gateway status is
redundant with the already-covered `searchGateway`), trust CRL (no expiry fields; per-CA OCSP text
parsing was judged not worth it), and Kea HA plus Kea statistics (not exposed by the OPNsense API
at all).

**2026-07-30 spot check (light, per standing rule — not a re-survey):** none of these plugins were
installed on the box audited, which is itself consistent with most of them being niche/legacy
add-ons rather than something that shipped a new API surface since the original audit. `radvd` and
`dnsmasq` do have their own controllers on-box, as expected — they're listed here as "fully
covered already" by existing collectors, not as absent. Nothing found that warrants pulling any
entry off this list.

## See also

- [API contract canary](../compatibility.md#how-drift-is-caught) - the automated checks that catch
  renamed or removed endpoints; this page is the manual counterpart for endpoints that are safe to
  reach but wrong to poll.
- [Adding a Collector](adding-collector.md) - before wiring up a new endpoint, check it is not
  listed above.
