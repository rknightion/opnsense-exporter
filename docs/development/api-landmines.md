---
title: API Landmines
description: Endpoints and modules the API-surface audit ruled out, so no future collector work rediscovers them the hard way
tags:
  - OPNsense
  - development
---

# API Landmines

The [API-surface audit](https://github.com/rknightion/opnsense-exporter/issues/227) walked every
OPNsense controller looking for collector candidates. Some endpoints look like harmless status
reads and are not: they start services, flush databases, regenerate config, or shell out to an
external upload on every call. Others are technically safe to call but return misleading or lossy
data if polled the way a Prometheus scraper polls. This page is the permanent record of both
groups, plus the modules the audit confirmed have nothing left to collect.

**This list is not a TODO. Do not re-audit any endpoint or module named here** without first
reading the reasoning below — each entry was checked against OPNsense source, not guessed at. If a
future OPNsense release changes one of these controllers, update the entry in place rather than
re-running the survey from scratch.

## Never-scrape endpoints

These are verified in OPNsense source (`os-*` plugin repos and core). Every one of them looks like
a status read from its name or its GET method, and none of them are — calling one on a scrape
interval starts a service, mutates config, or ships data off-box.

| Endpoint | Method | Why it must never be scraped |
| --- | --- | --- |
| `api/iperf/instance/query` | GET | If the iperf-manager socket is absent, `send_command()` falls through to configd `iperf restart`/`start` — a GET request that starts a service and rewrites pf anchor rules. It also only ever returns manually-launched one-shot test results, purged after an hour, so there is no steady-state series to collect anyway. |
| `api/redis/service/resetdb` | GET | Flushes the Redis database. |
| `api/haproxy/maintenance/*` | POST | Every action in this controller looks like a status read but responds only to POST and fires `configdRun('template reload OPNsense/HAProxy')` on every single call — full config regeneration per scrape. The server-state data it exposes is redundant with `show stat` anyway. |
| `api/hwprobe/service/report` | GET | Runs `hw-probe -all -upload`, which uploads the box's hardware profile to linux-hardware.org. An exporter must never cause outbound data exfiltration as a side effect of a scrape. |
| `api/tailscale/status/net` | GET | Runs `tailscale netcheck`, an active multi-second network probe, and returns plain text rather than structured JSON. |
| `api/diagnostics/carp_status` | POST | A setter despite the read-sounding name — it enables/disables CARP or flips maintenance mode. |
| `api/unbound/diagnostics/dumpcache` | GET | Dumps the entire unbound message cache. The payload is unbounded and scales with resolver traffic, not with anything worth graphing. |
| `api/diagnostics/traffic/_top` | GET | An iftop-style sampling capture that runs for up to 10 seconds per call, with unbounded per-host cardinality. Not something a scrape interval should be triggering. |
| `api/nginx/bans/get` | GET | Inherited `getAction()` behaviour returns the entire nginx model just to expose two fields. Use `searchban` instead if ban data is ever wanted. |

## Lossy or sampling transports

These endpoints are safe to call — nothing mutates and nothing gets uploaded — but their transport
or caching behaviour silently drops or samples data under a naive poll-on-interval pattern. They
are not "do not call," they are "do not use as an ingestion source the way you'd expect."

| Endpoint | Why |
| --- | --- |
| `api/diagnostics/firewall/stream_log` (SSE) | Lossy by design: the streamer throttles to 10 lines per 100ms window and silently drops the rest, including the line straddling the window boundary (`read_log.py:207-214`). The paged `?digest=` endpoint is the lossless path; never wire this SSE stream up as an ingestion transport. |
| `api/diagnostics/log/<module>/<scope>/live` (SSE) | Tails with `tail -f`, not `-F` — it silently stalls after the underlying log rotates, while keepalive frames keep flowing so nothing looks broken. Poll with `validFrom` instead of holding this stream open. |
| `api/qfeeds/settings/search_events` | A filtered, 300s-configd-cached, port-only re-parse of the firewall log restricted to qfeeds tables. It is strictly a stale subset of the firewall log endpoint, where qfeeds blocks already appear natively with their rule label. |
| `api/unbound/overview/search_queries` without a client filter | Only ever returns the latest 1000 rows — the `client` + `timeStart` + `timeEnd` form is the only mode that gets a real time range. Naive polling silently samples on a busy resolver. See [#233](https://github.com/rknightion/opnsense-exporter/issues/233) for the accepted-loss design this drove. |

## Won't-build

Recorded so the same collector idea does not get proposed twice.

- **A "watched plugin services" collector** fanning out to per-plugin `service/status` endpoints.
  Every relevant plugin already registers in `api/core/service/search`, which the exporter exports
  as `opnsense_services_status{name}`. The one plugin that does not register there — os-beats, which
  ships no `plugins.inc.d` file — is too thin on its own to justify a dedicated collector.
- **`hostdiscovery/service/search`** silently falls back to ARP+NDP (`source: "arp-ndp"`) when the
  discovery daemon is off. Any future consumer of this data must stay source-aware rather than
  assuming active discovery is always what produced a row.

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

## See also

- [API contract canary](compatibility.md#how-drift-is-caught) — the automated checks that catch
  renamed or removed endpoints; this page is the manual counterpart for endpoints that are safe to
  reach but wrong to poll.
- [Adding a Collector](adding-collector.md) — before wiring up a new endpoint, check it is not
  listed above.
