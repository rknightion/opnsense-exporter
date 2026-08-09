---
title: Why This Exporter
description: A factual, dated account of how this exporter's design differs from running node_exporter on the firewall or polling the OPNsense API on a fixed interval, and when to pick each.
tags:
  - comparison
  - architecture
  - OPNsense
---

# Why This Exporter

*Last reviewed: 2026-08.*

There is more than one reasonable way to get metrics out of an OPNsense firewall, and for a
lot of estates the simplest one is the right one. This page states what this exporter does
differently and why, so you can decide whether the extra surface area earns its place in your
deployment. It describes this codebase, not anyone else's, and does not claim any alternative
is worse.

For what runs where, see [Architecture](architecture.md); for the full metric list, the
[Metrics Reference](metrics/index.md).

## The three common approaches

**`node_exporter` on the firewall.** Gives you the host: CPU, memory, disk, network
interfaces at the OS level. It runs *on* the box, and it sees FreeBSD, not OPNsense — it has
no concept of a gateway, a firewall alias, an IPsec tunnel or a DHCP lease. This exporter
complements it rather than replacing it, which is why the [index page](index.md) says so
outright.

**A fixed-interval script against the OPNsense API.** Poll a handful of `api/*` endpoints
every 30 seconds, print gauges, done. For a single firewall and a dozen panels this is
genuinely a good answer: it is small, you can read all of it, and there is nothing to
operate. Most of what follows is about what stops being true once you have several
firewalls, plugins that come and go, or a metrics bill.

**This exporter.** 65 collectors, 1006 metrics, polling decoupled from scraping, and both a
Prometheus endpoint and native OTLP output. What that buys, and what it costs, is below.

## Design choices specific to this exporter

**A scrape does not call the firewall.** Since the poll scheduler landed, each collector runs
on its own interval and writes into an in-memory snapshot; `/metrics` replays that snapshot
and makes no OPNsense API call at all. The practical effect is that scrape frequency and API
load are independent — you can scrape every 15s without asking the firewall anything more
often, and a second Prometheus scraping the same exporter costs the firewall nothing. It also
means `opnsense_exporter_scrapes_total` counts *serving*, not collecting; for collection,
`opnsense_exporter_collector_last_poll_timestamp_seconds` is the metric that matters.

**Per-collector intervals, not one global one.** Certificate expiry and firmware status do
not change on the same timescale as interface throughput, so each collector has its own poll
interval off `--collector.poll-interval`, overridable individually with
`--collector.poll-interval-override`. A fixed-interval design has to pick one number and be
wrong for something.

**Data age is a first-class metric, separately from liveness.** Three timestamps exist
because they answer different questions: `..._last_poll_timestamp_seconds` (the scheduler
tried), `..._snapshot_timestamp_seconds` (the buffer was actually replaced — the true age of
what a scrape replays), and `..._last_success_timestamp_seconds` (a fully clean poll). A
collector failing every poll while replaying stale data keeps advancing the first and not the
others, so "refreshed but degraded" is distinguishable from "healthy" and from "stuck". This
is the failure mode that a single `up`-style gauge cannot express.

**Absent plugins are cached as absent.** OPNsense endpoints are plugin-gated: ask for a
HAProxy stat on a box without HAProxy and you get a 404, every poll, forever. Those 404s are
cached under `--exporter.cache-ttl` alongside slow-moving response bodies, so a firewall
running few plugins stops paying for endpoints it will never have.
`opnsense_exporter_api_cache_hits_total` splits `kind="absent"` from `kind="body"` so you can
see which is which.

**Cardinality has a declared budget.** `--exporter.series-budget` is compared against
`opnsense_exporter_series_total`, and the web UI's cardinality report replays the same set.
1006 metrics is a lot of metrics; the budget exists so that "a lot" stays a number somebody
chose rather than a number somebody discovers on an invoice.

**Prometheus and OTLP, not one or the other.** `--otlp.enabled` pushes native OTLP metrics
*and logs*, with first-class Grafana Cloud endpoint/token flags, while the Prometheus
endpoint keeps serving. If you are consolidating on OTLP you do not have to put a collector
in front of this to translate.

**It also receives.** Beyond polling, the exporter accepts syslog from OPNsense, and turns
NetFlow and Zenarmor records into bounded flow-volume metrics with optional GeoIP
enrichment — see [Log Shipping](log-shipping.md) and [Flow Volume](flow.md). Flow data is
unbounded by nature, so this path is about aggregation into bounded series, not about
shipping every record.

**It runs off-box.** Nothing is installed on the firewall; it needs an API key and network
reach. That keeps a monitoring agent off a security appliance and out of its upgrade path,
and it is the reason one instance can watch several firewalls.

## When to pick something else

**You want host-level FreeBSD metrics.** Run `node_exporter` on the firewall. This exporter
reads the OPNsense API and will not tell you about a process table.

**One firewall, a handful of panels, no appetite for another service.** A fixed-interval
script is less to run and less to understand. Most of the machinery above exists for
problems — plugin churn, API rate pressure, cardinality cost, multiple consumers — that a
small deployment does not have.

**You need something the API does not expose.** The API is the ceiling here. Where OPNsense
does not expose a thing, no exporter can; the
[API Landmines](development/api-landmines.md) and
[API-Absent Telemetry](development/api-absent-telemetry.md) notes are honest about where
those edges are.

**You are on an OPNsense version outside the supported range.** See
[Compatibility](compatibility.md) before committing.

## See also

- [Architecture](architecture.md) — package structure and data flow
- [Collectors](collectors/index.md) — what each of the 65 collectors reads
- [Metrics Reference](metrics/index.md) — all 1006 metrics with types and labels
- [Security](security.md) — API key scope and what the exporter can reach
