---
title: Native Log Export
description: Ship OPNsense logs to Loki with native syslog-ng and NetFlow instead of the exporter, plus the decision matrix for choosing between the native path and exporter log shipping
tags:
  - logging
  - OPNsense
---

# Native Log Export

OPNsense can hand its own logs and flow data to Loki without going through this
exporter at all: syslog-ng ships structured syslog off-box, Suricata can embed
full alert JSON in its syslog stream, and NetFlow exports v5/v9 records to any
flow collector. This page is the native-path recipe, and the companion to
[Log shipping](log-shipping.md), which covers the exporter's own opt-in
pipeline (`--logs.enabled`). Read both before picking a path - see
[Decision matrix](#decision-matrix) below.

**Run no agent on the firewall itself.** OPNsense's own plugins cover this:
`os-beats` is Filebeat-to-Elasticsearch only (no Loki output), `os-telegraf`
has no Loki output either, and hand-installing Alloy, Vector, or Promtail
directly on OPNsense is unsupported and not how any of the recipes below work.
Every recipe here runs the collector **off-box** - OPNsense only ever pushes
syslog or NetFlow packets to it.

## Syslog-ng recipe: OPNsense to Alloy to Loki

### 1. Configure the Target in OPNsense

**System ‣ Settings ‣ Logging / targets**, add a Target:

- **Transport**: TCP or TLS (TLS supports client-certificate auth against your
  collector).
- **Format**: RFC 5424 (structured `APP-NAME`, easier to route downstream than
  legacy BSD syslog).
- **Applications**: filter the target to the programs you actually want
  shipped, rather than the full firehose. Common candidates: `filterlog`
  (firewall log), `suricata`, `audit`, `dpinger` (gateway monitoring),
  `openvpn`, `kea-dhcp4`/`kea-dhcp6`, `captiveportal`, and plugin programs such
  as `squid-*`.

Each Target can point at a different collector or all at the same one - add
multiple Targets if you want to split transports (e.g. TLS for the WAN-facing
collector, plain TCP for a LAN-only one).

### 2. Off-box collector: Grafana Alloy

Run Alloy on a host that isn't the firewall (a jump box, a Docker container,
wherever Loki is reachable from). `loki.source.syslog` is the listener:

```alloy
loki.source.syslog "opnsense" {
  listener {
    address        = "0.0.0.0:1514"
    protocol       = "tcp"
    syslog_format  = "rfc5424"
    label_structured_data = true
    use_rfc5424_message   = true

    // Preserve the __syslog_ labels (app-name, hostname, severity) instead of
    // letting Alloy strip them before the next stage.
    relabel_rules = loki.relabel.syslog.rules
  }

  forward_to = [loki.process.opnsense.receiver]
}

loki.relabel "syslog" {
  rule {
    action = "labelmap"
    regex  = "__syslog_(.+)"
  }
}
```

For TLS transport, add a `tls_config` block inside the `listener`:

```alloy
  listener {
    address  = "0.0.0.0:6514"
    protocol = "tcp"
    tls_config {
      ca_pem   = "/etc/ssl/certs/ca-certificates.crt"
      cert_pem = "/etc/ssl/private/syslog.pem"
      key_pem  = "/etc/ssl/private/syslog.key"
    }
  }
```

Route on `message_app_name` before writing, so each program lands with the
processing it needs (a JSON-parsing stage for `suricata`, a CSV-aware stage
for `filterlog`, and so on):

```alloy
loki.process "opnsense" {
  stage.match {
    selector = `{message_app_name="filterlog"}`
    stage.static_labels { values = { source = "filterlog" } }
  }

  stage.match {
    selector = `{message_app_name="suricata"}`
    stage.static_labels { values = { source = "suricata" } }
  }

  stage.match {
    selector = `{message_app_name="audit"}`
    stage.static_labels { values = { source = "audit" } }
  }

  forward_to = [loki.write.default.receiver]
}

loki.write "default" {
  endpoint {
    url = "https://logs-prod-xxx.grafana.net/loki/api/v1/push"
    basic_auth {
      username = env("LOKI_USERNAME")
      password = env("LOKI_API_KEY")
    }
  }
}
```

Point `loki.write` at the Grafana Cloud Loki push endpoint or any self-hosted
Loki 3.x instance.

### Community pipelines for `filterlog`

`filterlog` is a headerless CSV line keyed by rule **hash**, not a label - see
[Known gaps](#known-gaps-of-the-native-path) below. The exporter's
[syslog receiver](syslog-receiver.md) resolves the rule hash to a rule name and the
interface to its OS name for you; if you want that labelling on the **native** path
instead, two community pipelines do the same parsing in Alloy/Promtail stages:

- [rudimartinsen.com's OPNsense filterlog pipeline](https://www.rudimartinsen.com/)
- [roguesecurity.dev's filterlog + GeoIP pipeline](https://roguesecurity.dev/)

## Suricata: `syslog_eve` vs fastlog `syslog`

OPNsense's Suricata plugin has two independent syslog toggles - pick the one
that matches what you want out of the native path:

- **`syslog_eve`** ships the **full EVE alert JSON** (the same record shape as
  `eve.json`) over syslog, one alert per line. This is the closer analogue to
  the exporter's IDS log source (#231) if you want native delivery: full alert
  fidelity, no polling. It shares the `suricata` program name and facility
  with Suricata's other engine logs, so add a demux stage (a `stage.json` that
  tries to parse `event_type`, or a line filter on `"event_type":"alert"`)
  before treating every `suricata`-tagged line as an alert.
- **`syslog`** (fastlog) is the lightweight alternative: one compact line per
  alert (timestamp, signature, classification, src/dst) instead of the full
  EVE object. Use it if you only need alert-level visibility and want to keep
  volume down.

Enable at most one of these per deployment alongside the exporter's IDS
source - see the [decision matrix](#decision-matrix).

## NetFlow v5/v9: native export, not the exporter

**Reporting ‣ NetFlow** exports NetFlow v5 or v9 directly from OPNsense, with
samplicate fan-out to multiple collectors at once. Point it at a flow
pipeline - [goflow2](https://github.com/netsampler/goflow2),
[Akvorado](https://github.com/akvorado/akvorado), or
[ntopng](https://www.ntop.org/products/traffic-analysis/ntop/) are common
choices - and it ingests independently of Loki/Prometheus.

This page used to say flow data "does not belong in this exporter and never
will". That was written about the **poll/API** path, where it is still true and
worth keeping: the OPNsense API exposes only **pre-aggregated Insight data**
(already-bucketed traffic summaries), never per-flow records, so no polling
collector could produce flow telemetry however hard it tried.

What changed is that the exporter is no longer only a poller. It now runs push
receivers - syslog and Zenarmor - and flow data arrives on those, not from the
API. So the exporter does ship flow telemetry today: the Zenarmor receiver's
per-connection records become bounded byte and packet metrics, and a NetFlow
v5/v9 receiver is in progress. See [Flow volume](flow.md).

Both paths remain valid and they answer different questions. A dedicated flow
pipeline is still the right tool for arbitrary 5-tuple forensics and long-term
per-flow storage; the exporter is not a flow browser and will not become one.
What it can do that a generic collector cannot is **repair** flow data using the
firewall's own configuration - splitting VLAN traffic off the parent interface,
resolving policy-routed egress that a FIB lookup gets wrong, and naming
interfaces the export only numbers.

## Decision matrix

Pick **one** path per log type. Enabling both the exporter's log shipping
pipeline and native syslog for the same log type double-ships the same events
into Loki under different pipelines - the [Log shipping](log-shipping.md#delivery-semantics)
page states this as a hard rule and it applies symmetrically here.

| Log type | Native syslog wins when… | Exporter log shipping wins when… |
| --- | --- | --- |
| Firewall (`filterlog`) | You need high volume with zero exporter memory/queue state, and raw fidelity (every line, no polling gaps) matters more than labels. | You want rule **labels** and OS interface names attached instead of raw rule-hash CSV (#229). |
| IDS (Suricata) | You already run `syslog_eve` and want alerts flowing the moment Suricata writes them, with no exporter poll interval. | You want the exporter's structured EVE ingestion (#231) without standing up a syslog listener/demux stage. |
| Audit (config changes) | - | The exporter parses the single prose audit line into structured fields (#230); native syslog ships it as one unparsed string. |
| Gateway / CARP / captive portal / DHCP | You just want the raw log lines in Loki with no extra infrastructure beyond syslog-ng. | You want these correlated with the exporter's other structured sources through one poll loop (#230). |
| Unbound per-query DNS | Not available - unbound has no per-query syslog output. | Only path: DuckDB/API-only enrichment (#233), with the sampling caveats documented there. |
| CrowdSec alerts/decisions | Not available - CrowdSec has **no syslog path** at all. | Only path: the exporter's CrowdSec source (#232). |

Rule of thumb: native syslog wins on **volume and zero exporter
state**; exporter log shipping wins on **parsed/enriched records and a single
pull-based agent** instead of standing up syslog listener infrastructure.
Two sources (Unbound, CrowdSec) have no native path at all, so the exporter is
the only option for them.

## Known gaps of the native path

These are the reasons the exporter's log shipping sources (#229–#233) exist
alongside native syslog:

- **`filterlog` is headerless CSV keyed by rule MD5**, not a label - no rule
  name, no OS-level interface name, just positional fields and a hash you have
  to look up separately.
- **`audit` ships as one prose line** - no structured fields for actor,
  action, or target; a downstream parser has to regex it back apart.
- **Unbound per-query enrichment (client, blocklist/policy hit) is DuckDB/API-only**
  - unbound has no per-query syslog output to tap.
- **Captive portal sessions and VPN session tables are API-only** - syslog
  carries individual auth events, not the live session table.

## See also

- [Log shipping](log-shipping.md) - the exporter's own opt-in log pipeline
  (`--logs.enabled`), its Loki label model, and delivery semantics.
- [API Landmines](development/api-landmines.md) - why `stream_log` and the
  generic `/live` SSE endpoints are unsuitable as ingestion transports, native
  or exporter-side.
- [API-surface roadmap (#227)](https://github.com/rknightion/opnsense-exporter/issues/227) -
  the tracker for the exporter's per-source log shipping work.
