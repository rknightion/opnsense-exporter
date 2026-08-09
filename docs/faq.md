---
title: FAQ
description: Answers to common questions about running opnsense2otel - polling load, HA/CARP pairs, flow vs metrics, and missing data.
tags:
  - faq
  - troubleshooting
  - configuration
---

# Frequently Asked Questions

Short answers to common questions. Each answer links to the authoritative page for the full
detail - treat those linked pages as the source of truth.

## Getting started

### What does it need on the firewall?

Nothing is installed on OPNsense. The exporter runs off-box and just needs an API key and
network reach to the firewall's HTTPS port. See [Getting Started](getting-started.md) and
[Why This Exporter](comparison.md#design-choices-specific-to-this-exporter).

### Which OPNsense versions are supported?

The current stable release and the previous stable - today that's 26.1.x and 25.7. Older
releases are best-effort. One binary handles every supported payload shape by reading
whichever field a given firewall actually sends, so there's no version flag to set. See
[Compatibility](compatibility.md).

## Polling and load

### Does scraping the exporter hit the firewall's API?

No. A Prometheus scrape reads an in-memory snapshot built by a background poll scheduler; it
makes no OPNsense API call. Polling and scraping run on independent schedules, so scraping
more often - or from two Prometheus servers at once - costs the firewall nothing extra. See
[Architecture: Data flow](architecture.md#data-flow).

### How often does it poll each subsystem?

Each collector follows its own data-volatility tier rather than one global interval: fast
(15s), medium (60s, the default), slow (5m), or cold (15m). An operator can override any
single collector's cadence with `--collector.poll-interval-override`. See
[Architecture: Package structure](architecture.md#internalcollector-prometheus-collectors).

### A collector's data looks stale - how do I tell if it's actually stuck?

Check `opnsense_exporter_collector_snapshot_timestamp_seconds` for the age of the buffered
data a scrape replays, alongside `opnsense_exporter_collector_last_success_timestamp_seconds`
for the last fully clean poll. A collector that's failing every poll while still replaying
old data advances the first without advancing the second, which is how "refreshed but
degraded" is distinguished from "stuck". See [Troubleshooting](troubleshooting.md#data-is-stale-or-collector-polls-are-slow).

## HA / CARP pairs

### How does it monitor a CARP HA pair?

The default-on CARP collector scrapes VIP status from whichever box the exporter is pointed
at, so it reports that firewall's own CARP/VIP state (`--exporter.disable-carp` turns it
off). There's also an opt-in HA sync status collector (`--exporter.enable-hasync`) that makes
a live XML-RPC call to the CARP peer on every scheduled poll, disabled by default because of
that extra round-trip. See [Configuration](configuration.md#collector-switches).

### Do I need one exporter instance per firewall in the pair?

Yes. The exporter polls one OPNsense API at a time, so each box in a CARP pair needs its own
instance (and its own `--exporter.instance-label`) if you want metrics from both. One
instance can watch several *unrelated* firewalls the same way - it just can't see through one
box to its peer, other than via the opt-in HA sync collector above.

## Metrics

### Why is a metric or a whole collector missing?

Three different causes, and the exporter tells you which:

- **Switched off** - `opnsense_exporter_collector_enabled{collector="<name>"}` is `0` because
  a `--exporter.disable-*` flag was set, or an opt-in collector's `--exporter.enable-*` flag
  was never set.
- **Plugin not installed** - plugin-backed collectors (ACME, SMART, DynDNS, ISC DHCPv4, and
  others) go silent when their OPNsense plugin is absent; the API 404s and the exporter treats
  that as "feature absent" by design. `opnsense_feature_available{feature="<name>"}` tells you
  whether the plugin answered at all.
- **Removed upstream** - OPNsense itself stopped sending some fields on newer releases (for
  example the NDP `type` label, or Kea's DHCPv4 pool `interface` label), and no exporter
  version can bring those back. See the version-dependent table in
  [Compatibility](compatibility.md#version-dependent-data-availability).

See [Troubleshooting](troubleshooting.md#a-collectors-metrics-are-missing) for the full
diagnostic flow.

### Why are my Unbound DNS metrics mostly missing?

Unbound now ships with extended statistics off by default (`extended-statistics: no`), and
most `opnsense_unbound_dns_*` series - queries by type, answers by rcode, cache size, memory -
are built from that block. Enable *Services > Unbound DNS > Advanced > Extended Statistics* on
the firewall; the exporter picks it up on the next scheduled poll with no restart needed. Core
totals like `opnsense_unbound_dns_queries_total` and cache hit/miss counters aren't affected
either way. See [Compatibility](compatibility.md#version-dependent-data-availability).

### How do I limit the number of time series it produces?

Leave the high-cardinality detail flags (`--exporter.enable-*-details`) off unless you need
per-item data - they emit one series per DHCP lease, firewall rule or VPN session and can add
thousands of series on a busy network. `--exporter.series-budget` gives cardinality a declared
ceiling, checked against `opnsense_exporter_series_total`. See
[Configuration: high-cardinality detail options](configuration.md#high-cardinality-detail-options).

## Flow, syslog and Zenarmor

### What's the difference between flow volume and log shipping?

Log shipping ships individual events (firewall log lines, IDS alerts, DNS/TLS/HTTP records) as
OTLP logs, with high-cardinality fields like addresses and ports kept out of metric labels.
Flow volume is a separate, bounded rollup built from Zenarmor `conn` records and/or NetFlow -
byte and packet counters by interface, direction and application category - answerable from
Prometheus for years instead of scanning gigabytes of logs. Both can run from the same
Zenarmor stream at once. See [Flow Volume](flow.md) and [Log Shipping](log-shipping.md).

### Do I need the syslog or Zenarmor receivers to get any data at all?

No - the 65 polling collectors and their ~1006 metrics work with just an API key, no receiver
required. The syslog and Zenarmor receivers are separate, opt-in **push** sources that add
event-level data (parsed, enriched firewall/IDS/DNS logs) the polling collectors don't cover.
Flow volume metrics specifically need at least one of the Zenarmor receiver or the NetFlow
receiver enabled to have any data to roll up. See [Log Shipping](log-shipping.md#sources) and
[Flow Volume](flow.md#enabling-it).

### Why would I use the Zenarmor receiver instead of just enabling Zenarmor's syslog export?

Zenarmor's syslog export is licence-gated above the Home tier. Its Elasticsearch streaming
feature isn't, and the exporter's Zenarmor receiver gets the same per-flow, DNS, TLS/SNI, HTTP
and threat-alert data by posing as that Elasticsearch target - the only way to get it off a
Home-tier box. See [Zenarmor receiver: Why this exists](zenarmor-receiver.md#why-this-exists).

### Is the syslog or Zenarmor traffic authenticated?

Not by default. Syslog and NetFlow have no authentication of their own; the Zenarmor receiver
is unauthenticated unless `--logs.zenarmor.auth-user` is set. Restrict each with its
`--logs.*.allowed-peers` / `--flow.netflow.allowed-peers` CIDR allowlist, or firewall the
listening port - leaving it open is a deliberate decision to trust the network, not a safe
default to drift into. See [Configuration](configuration.md).

## Comparisons

### Should I use this instead of `node_exporter` on the firewall?

They complement each other rather than compete. `node_exporter` sees the FreeBSD host - CPU,
memory, disk - and runs on the box itself. This exporter reads the OPNsense API and has no
concept of host-level metrics, but also doesn't need anything installed on a security
appliance. See [Why This Exporter](comparison.md#the-three-common-approaches).

### Is this overkill for a single firewall with a handful of panels?

Possibly. A small fixed-interval script against a few `api/*` endpoints is genuinely a
reasonable choice there. Most of what this exporter adds - decoupled polling, per-collector
tiers, cardinality budgeting, plugin-absence caching - exists for problems that show up with
several firewalls, plugin churn, or a metrics bill, not for one box and a dozen panels. See
[Why This Exporter: When to pick something else](comparison.md#when-to-pick-something-else).
