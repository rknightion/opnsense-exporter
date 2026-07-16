---
title: Zenarmor receiver
description: Receive Zenarmor's per-flow, DNS, TLS, HTTP and alert reporting data by posing as an Elasticsearch node, enriched and shipped through the log pipeline
---

# Zenarmor receiver

The exporter can receive Zenarmor's reporting data directly, without touching syslog. It
does this by posing as an Elasticsearch node: Zenarmor's own "Stream Reporting Data to
External Elasticsearch" feature writes its per-flow, DNS, TLS, HTTP, alert and SIP
records straight to the exporter over the Elasticsearch `_bulk` API. The exporter parses
what it receives, enriches it, and ships it on through the [log pipeline](log-shipping.md).

This is off by default. It needs configuration on **both** sides: the receiver on the
exporter, and the streaming destination in the Zenarmor GUI.

## Why this exists

Zenarmor's syslog export — the obvious path for this data — is licence-gated above the
Home tier. Its Elasticsearch streaming is not. Posing as the Elasticsearch node it
streams to is therefore the only way to get per-flow connection records, per-query DNS,
TLS/SNI, HTTP metadata and threat alerts off a Home-tier box at all. Without it, the only
Zenarmor data reaching Loki is its own diagnostic service log, which carries none of that.

## Set up the exporter

```bash
opnsense-exporter \
  --logs.enabled \
  --logs.zenarmor.enabled
```

| Flag | Default | Notes |
| --- | --- | --- |
| `--logs.zenarmor.enabled` | `false` | Enables the receiver. Also needs `--logs.enabled`. |
| `--logs.zenarmor.listen-http` | `:9200` | Elasticsearch's conventional port. Zenarmor's own port field accepts any value, so this only needs to match what you configure on the Zenarmor side. |
| `--logs.zenarmor.allowed-peers` | *(any)* | CIDR allowlist of permitted senders. The ingress is otherwise unauthenticated. |
| `--logs.zenarmor.families` | *(all)* | Comma-separated subset to ship: `conn,dns,tls,http,alert,sip` (Zenarmor's own index tokens; the exporter's own family names `flow,dns,tls,web,ids,voip` are also accepted). Prefer cutting families in Zenarmor's own `indexes` setting instead — see [Volume](#volume) below. |
| `--logs.zenarmor.enrich` | `true` | Enrich records from the OPNsense API. |
| `--logs.zenarmor.auth-user` / `--logs.zenarmor.auth-password` | *(none)* | Require HTTP basic auth on the ingress. Zenarmor's streaming config has matching username/password fields. |
| `--logs.zenarmor.tls-cert-file` / `--logs.zenarmor.tls-key-file` | *(none)* | Serve HTTPS instead of plain HTTP. Zenarmor's URI field accepts `https://`. |

The receiver binds its listen address **eagerly at startup** — a port already in use is
a configuration error you see immediately, not a receiver that is silently dead for the
life of the process.

## Set up Zenarmor

In the Zenarmor GUI: **Configuration/Zenarmor → Settings → Streaming Data → Stream
Reporting Data to External Elasticsearch**.

| Field | Value |
| --- | --- |
| **URI** | `http://<exporter-host>:9200` (or `https://` if you set the TLS flags above) |
| **Port** | must match `--logs.zenarmor.listen-http` |
| **Elasticsearch version** | `8.11.3` |
| **Username / Password** | leave blank unless you set `--logs.zenarmor.auth-user` / `--logs.zenarmor.auth-password` |

Then apply.

!!! warning "Not the same as the install-time 'Remote Elasticsearch Database' option"
    Zenarmor's initial setup wizard offers a **different** option that also involves
    Elasticsearch: "Remote Elasticsearch Database". That one **replaces local storage
    entirely** — Zenarmor's own docs say no report data will be stored locally — and
    **cannot be changed after the wizard completes**. Streaming Data is not that. It is
    a mirror: your local reporting database and the Zenarmor GUI's own reports stay
    fully intact, and the exporter simply receives a second copy of the same documents.
    Do not confuse the two, and do not go looking for this receiver's data in the
    wizard's option.

## What you get

Each of Zenarmor's six reporting families becomes an `opnsense.subsystem` value:

| Zenarmor family | `opnsense.subsystem` | Carries |
| --- | --- | --- |
| `conn` | `flow` | per-connection src/dst, app name/proto/category, verdict, byte and packet counts, device fingerprint |
| `dns` | `dns` | query, qtype, answers, rcode, domain categories |
| `tls` | `tls` | SNI (`server_name`), JA3 fingerprint |
| `http` | `web` | method, host, URI, user agent, status |
| `alert` | `ids` | signature, category, severity |
| `sip` | `voip` | SIP method, URI, status |

Every record also carries `opnsense.source=zenarmor` and, where the document states a
disposition, `opnsense.action` (`pass` or `block`) — see [Label model](#label-model). The
full document survives verbatim as the log **body**, so nothing is ever lost, including
fields not promoted to attributes.

## Volume

Measured on a live box: **~39 documents/second**, roughly **2.5–3.3 million records a
day** — **~4–6 GB/day of raw JSON**. This is not a small stream. The family mix:

| Family | Share |
| --- | --- |
| `conn` | 61% |
| `dns` | 26% |
| `tls` | 10% |
| `http` | 3% |

If you need to cut this down, **do it in Zenarmor's own `indexes` setting, not with
`--logs.zenarmor.families`.** Data cut at the Zenarmor end never crosses the wire; data
cut with `--logs.zenarmor.families` still costs the bandwidth and CPU to receive and
parse before being discarded.

## Label model

`opnsense.source=zenarmor`, `opnsense.subsystem=<family>` and `opnsense.action=pass|block`
all live on the OTLP **resource**, which is what makes them promotable to Loki index
labels — see the [Loki label model](log-shipping.md#loki-label-model). Everything else —
IPs, ports, MACs, hostnames, `app_name`, `ja3`, `community_id`, `conn_uuid`, `query`,
`uri`, and every other per-record field — is structured metadata: filterable with `|`,
never a label, and never promotable regardless of tenant configuration.

Promoting `opnsense.action` needs the same tenant `otlp_config` change as
`opnsense.source` and `opnsense.subsystem` — see
[Promoting opnsense.source and opnsense.subsystem](log-shipping.md#promoting-opnsensesource-and-opnsensesubsystem)
and add `opnsense.action` to the same `attributes` list.

## Derived counters

`opnsense_log_events_zenarmor_total{family,action,category,interface,rcode,severity,status_class}`
counts every document Zenarmor sends, by family, whether or not it parsed cleanly. Only
bounded dimensions are ever labels here — `app_name`, any IP or port, hostname, MAC,
JA3, session/community/connection id, signature, URI and query never become one, and
never will. Because Loki's retention is finite and this is the highest-volume stream the
exporter handles, this counter — not the raw log stream — is how you ask rate questions
that need to outlive 31 days.

The receiver's own health is on `/metrics` too:

- `opnsense_exporter_logs_zenarmor_bulk_requests_total` / `..._bulk_bytes_total` —
  accepted `_bulk` writes and their decompressed size.
- `opnsense_exporter_logs_parse_errors_total{source="zenarmor",stage="document"}` — a
  document that didn't decode as JSON. It still ships, with its raw body.
- `opnsense_exporter_logs_parse_errors_total{source="zenarmor",stage="bulk"}` — a bulk
  action line (the metadata naming the operation) that didn't decode. The document it
  was paired with is lost, since there is no index to route it by.
- `opnsense_exporter_logs_rejected_total{source="zenarmor",reason=...}` — input refused
  before parsing: `peer` (outside `--logs.zenarmor.allowed-peers`), `auth` (basic auth
  failed), `body` (an oversized or corrupt request body), `unknown_family` (a document
  addressed to an index the receiver doesn't recognise), `filtered` (excluded by
  `--logs.zenarmor.families`), or `unhandled_endpoint` (see below).

## Operational notes

**Records arrive at flow close, near-real-time, with no backfill on connect.** There is
no catch-up window: turning the receiver on gets you everything from that point
forward, nothing from before it.

**An unknown endpoint is answered `200` and counted, not treated as an error.** If
Zenarmor's Elasticsearch client ever calls something this receiver doesn't implement,
the receiver keeps functioning and the change shows up as
`opnsense_exporter_logs_rejected_total{source="zenarmor",reason="unhandled_endpoint"}`
climbing — a visible signal instead of a silent outage.

**`src_username`/`dst_username` are empty unless an identity provider (AD, Azure AD) is
wired into Zenarmor itself.** The exporter models the fields regardless, so they
populate automatically the moment Zenarmor has something to put in them.

**`asn` is always `0` on a box with no GeoIP database configured.** Same story: modelled,
just empty until Zenarmor has data to give it.

## See also

- [Log shipping](log-shipping.md) — the pipeline this receiver ships through, its sinks,
  delivery semantics and self-metrics.
- [Syslog receiver](syslog-receiver.md) — the other push source, for everything Zenarmor
  doesn't see (firewall, auth, DHCP, IPsec/OpenVPN and more).
