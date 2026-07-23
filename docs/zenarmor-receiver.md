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

Zenarmor changes its payloads between releases. If a record family stops being ingested,
[open an issue on GitHub](https://github.com/rknightion/opnsense-exporter/issues/new) with a
captured document, or read the receiver in
[`internal/logship/` on GitHub](https://github.com/rknightion/opnsense-exporter/tree/main/internal/logship).

## Why this exists

Zenarmor's syslog export — the obvious path for this data — is licence-gated above the
Home tier. Its Elasticsearch streaming is not. Posing as the Elasticsearch node it
streams to is therefore the only way to get per-flow connection records, per-query DNS,
TLS/SNI, HTTP metadata and threat alerts off a Home-tier box at all. Without it, the only
Zenarmor data reaching Loki is its own diagnostic service log, which carries none of that.

## Transport

`--logs.zenarmor.transport` selects how the data reaches the exporter. It takes two
values:

- `elasticsearch` (default) — the built-in receiver described above, posing as an
  Elasticsearch node on `--logs.zenarmor.listen-http`. This is everything documented
  so far in this page.
- `syslog` — rides the [syslog receiver](syslog-receiver.md) instead of running its
  own listener. The exporter recognises Zenarmor's syslog line shape automatically
  (`daemon=zenarmor, index=<family>, data=<json>`) and feeds it through the same
  processing the Elasticsearch path uses.

`transport=syslog` needs two things to be true, and checks both at startup:
Zenarmor's syslog export is licence-gated to the business tier and above (unlike its
Elasticsearch streaming, which is available on Home), and the exporter's own
`--logs.syslog.enabled` must be set. Setting `transport=syslog` without the syslog
receiver enabled is a startup error, not a silent no-op.

`--logs.zenarmor.families`, `--logs.zenarmor.exclude`, `--logs.zenarmor.enrich` and
`--logs.zenarmor.drop-self-traffic` all apply to either transport — record processing
is shared, so nothing below in this page needs restating per transport. The
self-traffic filter matches the same shape of connection over syslog as it does over
`_bulk`: the box talking to the exporter's own listener, in this case the syslog
port rather than the Elasticsearch one.

The syslog receiver's own `--logs.syslog.include-programs`, `--logs.syslog.exclude-programs`
and `--logs.syslog.min-severity` filters never see a Zenarmor line — the registered
Zenarmor processor gets first refusal on anything tagged `zenarmor`, ahead of those
generic program filters, so it's `--logs.zenarmor.families` and `--logs.zenarmor.exclude`
above that decide what ships, not the syslog-side flags.

Only one transport ingests at a time — `transport` picks exactly one receiver to
register, so there is no dual-ship path to reason about and no risk of the same
record arriving twice. The syslog copy carries `opnsense.source=zenarmor` in Loki
identically to the Elasticsearch copy, so dashboards, alerts and the derived
counters below are transport-agnostic; nothing downstream needs to know which one
is configured.

On the Zenarmor side, point its syslog target at the exporter's syslog listener —
whichever of `--logs.syslog.listen-udp`, `--logs.syslog.listen-tcp` or
`--logs.syslog.listen-tls` you have enabled — instead of the Elasticsearch streaming
target described below.

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
| `--logs.zenarmor.drop-self-traffic` | `true` | Drop records describing the receiver's own ingest connection — see [Self-traffic](#self-traffic) below. |
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

## Excluding known-boring traffic

`--logs.zenarmor.exclude` drops records whose field matches a regex. It is
**repeatable** and **off by default** — no implicit blind spots.

```
--logs.zenarmor.exclude='server_name=~.*\.grafana\.net'
--logs.zenarmor.exclude='query=~.*\.grafana\.net'
```

Each rule is `FIELD=~REGEX`. Only the regex operator `=~` exists; use `^value$` for an
exact match. The regex tests **that field's value only** — a `server_name` rule never
matches the value of `host`. Rules are OR-ed: any one match drops the record. Via the
environment, put **one rule per line** (`OPNSENSE_EXPORTER_LOGS_ZENARMOR_EXCLUDE`), not
comma-separated, so a regex containing a comma survives.

The field name is **validated at startup** against the receiver's attribute vocabulary.
A typo is a startup error, never a silent no-op — the same reasoning as
`--logs.zenarmor.families`: a filter that quietly does nothing looks exactly like a
quiet network. The error names the near-miss it was probably meant to be.

### This is lossy, and not the way sampling is

**Read this before turning it on.** `--logs.syslog.sample` is safe to reach for because
a line it drops is one whose value already survives in a counter:
`opnsense_log_events_firewall_total` carries `action`, `interface` and `rule`, and a
line that was never counted is never dropped.

**Exclusion has no such backstop.** `opnsense_log_events_zenarmor_total` carries only
family / action / category / interface / rcode / severity / status_class — deliberately,
for cardinality. It has **no `server_name`, no `query`, no `device_name`**. The derived
counters *are* observed before the drop, so the *shape* of excluded traffic survives
both the exclusion and Loki's retention. But the record itself, and every
high-cardinality field on it, is gone for good — and unlike a query-time filter, that
decision cannot be revisited after the fact.

So the honest summary: exclusion trades forensic detail for bytes, permanently. Prefer
filtering at query time, or cutting families at the Zenarmor end, unless volume
genuinely forces this.

### Drops are counted, per rule

```
opnsense_exporter_logs_rejected_total{source="zenarmor", reason="excluded"}
opnsense_exporter_logs_zenarmor_excluded_total{rule="server_name=~.*\\.grafana\\.net"}
```

The first puts an exclusion alongside every other configured drop. The second names the
**rule** that did it, so the blind spot is visible on the Log Shipping dashboard rather
than inferred from the exporter's command line — the aggregate alone cannot tell a rule
that drops nothing from one quietly eating the stream. Both are published at **zero**
from startup, so a rule that has never matched reads `0` rather than vanishing.

### On the Grafana Cloud case specifically

The motivating example is real: on one live box `camden`, the observability host, is
**57k of 78k records (~73%)** — it spends its life talking to
`otlp-gateway-prod-*.grafana.net` and `profiles-prod-*.grafana.net`, which dominate
every top-N panel.

**There is deliberately no default rule for it, and filtering Grafana-side is the better
first move.** `camden` is the most privileged host on that network, and "high-volume
encrypted egress to a cloud endpoint" is precisely the shape exfiltration takes.
Dropping it at ingest to save bytes means the one host worth watching most closely
becomes the one you log least. The knob exists because the operator who wants it should
have it per deployment — not because this is a recommended default.

## Self-traffic

Zenarmor inspects traffic on the link the receiver listens on, so it reports **the
connection that is delivering its own records to us** — and without intervention the
exporter ships a record describing the connection that carried the record.

It converges rather than runs away: one `_bulk` request carries many records, so it
settles at roughly one extra record per request instead of multiplying. But it is not
small. Measured on a live box within an hour of enabling the receiver:

| Family | To the receiver's port | Share of that family |
| --- | --- | --- |
| `web` | 6,194 | **76%** |
| `flow` | 5,808 | 11% |
| **combined** | **~12,000/hour** | **~15% of all records** |

That is roughly 600–900 MB/day describing nothing but our own ingest, and it makes the
`web` family useless: its top hosts and URIs are all `POST /zenarmor_<uuid>_<family>_write/_bulk`.

**`--logs.zenarmor.drop-self-traffic` is on by default**, because such a record is an
artefact of measuring rather than traffic — and
`opnsense_exporter_logs_zenarmor_bulk_requests_total` already describes that same
connection properly. Dropped records are counted as
`opnsense_exporter_logs_rejected_total{source="zenarmor", reason="self_traffic"}`, so
the drop is visible rather than silent, and they are **not** counted into
`opnsense_log_events_zenarmor_total` — our own bookkeeping does not belong in the
figures you read as your network.

A record is recognised as ours when it was **sent by the peer currently streaming to
us** and is **addressed to a port the receiver bound** (over syslog the receiver may
bind several — UDP, TCP and TLS — and Zenarmor may stream to any of them, so the record
matches on any bound port). The destination address is
deliberately never compared: a containerised exporter binds `0.0.0.0:9200` inside its
own network namespace and cannot know the host address the firewall actually dialled
(the record says `10.0.0.5`; the container is `172.17.0.2`), so an address-based filter
would silently never fire in the deployment nearly everyone runs.

The one case this gets wrong, stated rather than hidden: if the **firewall itself**
opens a connection to a real Elasticsearch on the same port number the receiver listens
on, that record is dropped too. It requires the Zenarmor host specifically as the source
— a LAN client talking to an Elasticsearch is unaffected — and
`--logs.zenarmor.drop-self-traffic=false` turns the behaviour off entirely.

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
