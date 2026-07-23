# Flow volume

Bounded byte and packet metrics derived from flow records, so volume questions —
how much traffic, on which interface, in which direction, for which application
category — are answerable from Prometheus for years instead of by scanning several
GB/day of logs with a 31-day retention.

There are two sources: the [Zenarmor receiver](log-shipping.md)'s per-connection
`conn` records, and a NetFlow v5/v9 receiver. Both produce the same normalized
record, and both feed the same bounded rollup.

This is **not** a flow browser. Arbitrary 5-tuple forensics stays a log query, and
addresses, ports, hostnames, application names and connection ids are deliberately
never metric labels — they stay as structured metadata on the shipped record, where
they are still filterable but cannot multiply series.

The rollup, the NetFlow receiver and the flow correlator are implemented in
[`internal/flow/` on GitHub](https://github.com/rknightion/opnsense-exporter/tree/main/internal/flow).

## Enabling it

Flow rollups are **on by default** and cost nothing where no flow source is
configured: the metrics are silent, in the same way `log_events` is silent
without the syslog receiver. Nothing new is shipped to Loki — the Zenarmor `conn`
record ships exactly as it did before, and this only adds metrics.

| Flag | Default | Purpose |
|---|---|---|
| `--flow.enabled` | `true` | master switch for flow rollups |
| `--flow.zenarmor` | `true` | derive records from the Zenarmor receiver's `conn` documents |
| `--flow.top-n` | `1000` | maximum series emitted per scrape |
| `--flow.max-keys` | `2500` | maximum label combinations held in memory |
| `--exporter.disable-flow` | *(off)* | remove the collector entirely |

To get any data you also need the Zenarmor receiver running
(`--logs.zenarmor.enabled`), the NetFlow receiver below, or both.

## The NetFlow receiver

Unlike the Zenarmor lane this is **off by default**: the Zenarmor lane derives
counters from documents the exporter already receives, while this one opens a UDP
socket.

| Flag | Default | Purpose |
|---|---|---|
| `--flow.netflow.enabled` | `false` | enable the receiver |
| `--flow.netflow.listen` | `:2055` | bind address, bound eagerly at startup |
| `--flow.netflow.allowed-peers` | *(empty)* | CIDR allowlist, repeatable |
| `--flow.netflow.ifindex-map` | *(derived)* | pin the ifIndex map, e.g. `1=ixl0,5=igb0` |

!!! warning "NetFlow has no authentication"

    None. Anything that can reach the port can inject flow records and move every
    number on your dashboards. `--flow.netflow.allowed-peers` is the only control
    the protocol admits, so set it or firewall the port. Leaving it empty is a
    decision to trust the network; the exporter logs a warning at startup so it
    cannot be one you made by accident.

Point **Reporting ‣ NetFlow** at the exporter's address. v9 and v5 are both decoded;
OPNsense emits v9. No on-disk template cache is needed or kept — ng_netflow resends
its templates about every two minutes, so a cold start is blind for at most that
long, and records arriving before their template are counted as
`records_dropped_total{reason="no_template"}` rather than guessed at.

### What this lane repairs

A generic flow collector gets three things wrong on OPNsense, and only something
holding the firewall's own configuration can fix them.

**VLAN traffic is captured twice.** ng_netflow captures the trunk *and* each VLAN
child, so every tagged packet appears on both — and the trunk copy attributes it to
the parent interface. On the reference box that is 9,657 of 80,275 flow instances,
~4% of bytes, all of it silently inflating LAN. The exporter keeps the child copy and
drops the parent, counting each as
`records_dropped_total{reason="vlan_duplicate"}`. A flat zero there on a VLAN'd
network means the de-dup is not firing and your volume is double-counted.

**Policy-routed egress is mislabelled — the big one.** ng_netflow derives the egress
interface from a FIB route lookup, but OPNsense multi-WAN policy routing happens in
pf, which ng_netflow never sees. On the reference capture this reported 3.36 GB of
WAN2 traffic as WAN1: WAN2 read 37.8 MB against ~3.4 GB actual, a 99% under-report.
Every generic collector on that network is wrong about this today. Where a record's
source address is a known WAN address, that WAN is the true egress regardless of what
the export said; corrections are counted by `opnsense_flow_egress_corrected_total`,
and the correction only fires when the two actually disagree, so it cannot mask
ng_netflow starting to get it right.

**Direction is not exported at all.** Field 61 is absent, so direction is inferred
from the firewall's own topology and the ifIndex evidence, by the same rules the
Zenarmor lane uses. `unknown` is emitted honestly rather than guessed.

### ifIndex is positional, and that is fragile

The `ifIndex` in a record is **not** an OS or SNMP index. It is a 1-based counter over
`ifinfo` output, so **adding or removing any interface renumbers everything** and
silently remaps historical series. The exporter derives the map from the API, but that
derivation cannot be proven to reproduce `ifinfo`'s ordering on every box, so:

- an index that resolves to nothing yields an **empty** `interface` label and
  increments `opnsense_flow_ifindex_unmapped_total` — a wrong interface name is worse
  than a missing one;
- `--flow.netflow.ifindex-map` pins any index outright, and
  `opnsense_flow_ifindex_conflicts` reports how many of your pins disagree with the
  derivation. Non-zero means the indices you did *not* pin are suspect;
- `opnsense_flow_ifindex_map_age_seconds` tracks the map's freshness, which is a
  correctness signal here rather than a staleness nuisance.

### What `interface` means on this lane

A NetFlow record crosses two interfaces and the label names one: the **WAN-facing**
side — egress for outbound, ingress for inbound. That is what makes per-WAN volume
answerable, which is the entire point of the egress repair.

The cost is deliberate: a LAN host's internet traffic is attributed to the WAN it
left by, **not** to its own VLAN. Per-VLAN volume is
therefore visible for internal traffic only, and the two lanes describe the same flow
differently — Zenarmor keeps naming the VLAN child. This is a second reason, on top of
the double-counting below, to pin `source` in every query.

## The label set, and why each dimension is on it

Every flow metric carries exactly these, and nothing else:

| Label | Values |
|---|---|
| `interface` | the OPNsense interface description (`LAN`, `IOT`), or the kernel device when unnamed |
| `direction` | `inbound` \| `outbound` \| `internal` \| `unknown` |
| `transport` | `tcp` \| `udp` \| `icmp` \| `icmpv6` \| `gre` \| `esp` \| `sctp` \| `other` |
| `category` | the application category taxonomy (24 values observed live) |
| `action` | `pass` \| `block` \| empty when the source stated no verdict |
| `source` | `zenarmor` \| `netflow` \| `merged` |
| `scope` | destination scope: `self` \| `local` \| `remote` \| empty |

Each is a closed enumeration or a bounded taxonomy. An unrecognised transport
protocol folds to `other` rather than being echoed as a number, so a misbehaving
sender cannot mint label values.

### `interface` splits VLANs off the parent

Zenarmor reports the **parent** device on every `conn` record — verified across
20,476 live documents, all of which say `ixl0` — and puts the tag in a separate
field. Read naively, the label would have a single value and every VLAN's traffic
would be attributed to the LAN. The exporter reconstructs the child device
(`ixl0` + tag `50` → `ixl0_vlan50`) before resolving the name, so IOT traffic reads
as `IOT`. On the capture box that is 20.5% of flows.

### `direction` uses the firewall's own topology

Two sources of truth, each used for what it actually knows. The firewall's
configured subnets decide whether a flow is **internal**; the flow source's own
direction field decides **inbound** versus **outbound**. Multicast and link-local
destinations are internal by inspection — SSDP and mDNS never leave the L2 domain,
even though a group address sits in no configured subnet.

`internal` includes traffic to the firewall itself (DNS, the web UI, NTP): the box
is not a remote endpoint.

`unknown` is a real, emitted value. Where neither the topology nor the source can
classify a flow, that is what it says, rather than inventing a direction to avoid an
empty label.

## `__other__` — the folded remainder

`--flow.top-n` bounds how many series are emitted. Everything beyond it folds into a
single `__other__` series **per source**, so:

- **the family always sums exactly**, at any `top-n`. A dashboard's total does not
  change when the limit is retuned;
- an `interface`, `category` or `direction` of `__other__` is the remainder, **not a
  real interface or category**;
- the `source` label survives the fold, because a query that does not pin it will
  double-count once the NetFlow lane lands (see below).

One deliberate cost: a series that drops out of the top-N and later returns
**resumes from the volume it accumulated while folded**, so it
reads as a counter reset on that series. The alternative — leaving a fallen-out
series frozen at its last value forever — is the failure mode that makes a top-K
exporter quietly lie, so this trade is taken on purpose. Ranking is by cumulative
lifetime bytes, which is stable: displacing a series requires overtaking its
total since process start, not merely its recent rate.

`--flow.max-keys` is a **separate** bound and neither substitutes for the other.
`top-n` caps what is emitted; `max-keys` caps what is held in memory between
scrapes. A combination first seen when the accumulator is already at `max-keys`
folds into `__other__` and is counted by `opnsense_flow_rollup_capped_total`.

## Never sum the two sources

With both lanes enabled the family carries **two independent measurements of the
same traffic**. Zenarmor measures what it inspects; NetFlow measures the packet
path. They will legitimately disagree, and adding them is meaningless:

```promql
# WRONG with both lanes enabled — counts the same bytes twice
sum by (interface) (rate(opnsense_flow_bytes_total[5m]))

# Right: pin the source, or aggregate by it
sum by (interface) (rate(opnsense_flow_bytes_total{source="zenarmor"}[5m]))
sum by (source, interface) (rate(opnsense_flow_bytes_total[5m]))
```

The shipped dashboard panels already aggregate by `source` for this reason.

## Byte counts and the payload fallback

Zenarmor reports two byte figures per direction: wire bytes and payload bytes. Wire
bytes are the right answer and are used wherever they are present. But Zenarmor only
starts accumulating them once it has tracked a flow past its first packets, so short
UDP flows — DNS, STUN, SSDP — report zero. On the reference capture that was 27.6%
of flow-sides with a non-zero packet count, and 8.6% of documents would have
reported **zero bytes while still being counted** as records.

The exporter therefore falls back to the payload figure when the wire figure is zero
and the payload figure is not, and counts every fallback in
`opnsense_flow_payload_byte_fallback_total`. A steady rate there is normal and is the
repair working, not a fault. The byte impact is negligible — these are one and two
packet flows — the point is not reporting zero for traffic that plainly happened.

## Watching the accumulator

Four self-metrics, all published from zero so a healthy exporter reads a flat line
rather than nothing:

| Metric | Read it as |
|---|---|
| `opnsense_flow_rollup_keys` | label combinations currently tracked |
| `opnsense_flow_rollup_keys_max` | the `--flow.max-keys` ceiling |
| `opnsense_flow_rollup_keys_folded` | combinations outside the top-N right now |
| `opnsense_flow_rollup_capped_total` | records lost to the memory cap, not merely folded |

`keys` approaching `keys_max` is the one to act on: at the ceiling, every **new**
combination folds into `__other__` indefinitely, and without these an operator
cannot distinguish "a few small categories folded" from "the map saturated weeks ago
and everything new since has been invisible". `keys_folded` being non-zero is
ordinary top-N overflow and is expected.

## Related

- [Log shipping](log-shipping.md) — the Zenarmor receiver that feeds this
- [Native log export](log-export-native.md) — when a dedicated flow pipeline is the
  better tool
- [Metrics reference](metrics/metrics.md) — the full `opnsense_flow_*` family
