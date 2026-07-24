# Flow volume

Bounded byte and packet metrics derived from flow records, so volume questions -
how much traffic, on which interface, in which direction, for which application
category - are answerable from Prometheus for years instead of by scanning several
GB/day of logs with a 31-day retention.

There are two sources: the [Zenarmor receiver](log-shipping.md)'s per-connection
`conn` records, and a NetFlow v5/v9 receiver. Both produce the same normalized
record, and both feed the same bounded rollup.

This is **not** a flow browser. Arbitrary 5-tuple forensics stays a log query, and
addresses, ports, hostnames, application names and connection ids are deliberately
never metric labels - they stay as structured metadata on the shipped record, where
they are still filterable but cannot multiply series.

The rollup, the NetFlow receiver and the flow correlator are implemented in
[`internal/flow/` on GitHub](https://github.com/rknightion/opnsense-exporter/tree/main/internal/flow).

## Enabling it

Flow rollups are **on by default** and cost nothing where no flow source is
configured: the metrics are silent, in the same way `log_events` is silent
without the syslog receiver. Nothing new is shipped to Loki - the Zenarmor `conn`
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
OPNsense emits v9. No on-disk template cache is needed or kept - ng_netflow resends
its templates about every two minutes, so a cold start is blind for at most that
long, and records arriving before their template are counted as
`records_dropped_total{reason="no_template"}` rather than guessed at.

### What this lane repairs

A generic flow collector gets three things wrong on OPNsense, and only something
holding the firewall's own configuration can fix them.

**VLAN traffic is captured twice.** ng_netflow captures the trunk *and* each VLAN
child, so every tagged packet appears on both - and the trunk copy attributes it to
the parent interface. On the reference box that is 9,657 of 80,275 flow instances,
~4% of bytes, all of it silently inflating LAN. The exporter keeps the child copy and
drops the parent, counting each as
`records_dropped_total{reason="vlan_duplicate"}`. A flat zero there on a VLAN'd
network means the de-dup is not firing and your volume is double-counted.

Which copy survives is not a detail. The box flushes the trunk hook's records and
the child hook's records in separate consecutive datagrams, trunk first, so keeping
whichever arrived first keeps the trunk copy every time and collapses every VLAN
onto the parent interface. A record that could still be beaten by a copy on one of
its trunk's children is therefore held for up to two seconds before it is emitted,
and a better copy arriving inside that window takes its place. Only records naming a
trunk that actually has VLAN children wait; a box without VLANs holds nothing.
`opnsense_flow_vlan_child_preferred_total` counts the swaps and is the number that
says the attribution is right - a flat zero on a box with VLAN interfaces means it is
not. `opnsense_flow_repair_held_records` is the queue itself: it should track the
record rate and never grow without bound, and
`records_dropped_total{reason="hold_overflow"}` means the buffer filled and those
records fell back to first-arrival.

**Policy-routed egress is mislabelled - the big one.** ng_netflow derives the egress
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

### What the decoder could not interpret

A NetFlow export can carry things this decoder does not model: a template element it
has nowhere to put, an options template, a control flowset in the reserved range.
Each is stepped over by its *template-declared* length, which is the only safe thing
to do - assuming a width shifts every following field and corrupts records with no
parse error to show for it. What changed is that it no longer happens in silence.

`opnsense_flow_netflow_unidentified_total` counts them by `kind`. A non-zero
`unknown_field` is **expected**: the box's IPv4 template declares four elements the
decoder does not read (TOS, the two masks, the next hop), so it is a *change* here
that means the export gained something. It is counted once per element when a
template shape is first learned or changes, never on the roughly two-minutely
re-send, so the counter is a drift signal rather than a clock. Alongside it, a
rate-limited log line names the element or flowset ids and the exporter that sent
them - those ids are deliberately not metric labels, because the socket is
unauthenticated and a sender could mint as many as it liked.

### Capturing datagrams

| Flag | Default | Purpose |
|---|---|---|
| `--flow.netflow.debug-capture` | `off` | `unidentified` or `all` - write raw datagrams to the shared capture dir |
| `--logs.debug-capture.dir` | *(unset)* | where captures are written; shared with the log receivers |
| `--logs.debug-capture.max-bytes` | `256MiB` | total cap across the whole dir |

`unidentified` writes only datagrams carrying something the decoder could not
interpret, including one that would not decode at all. On a healthy box that is a
couple of datagrams around startup and nothing after, which is what makes it the mode
worth leaving on. A data flowset arriving before its template is deliberately *not*
counted as surprising - it is the expected state for the first two minutes after
either end restarts, and treating it as surprising would spend the whole byte cap on
a condition that resolves itself.

`all` writes every datagram. That is the mode for regenerating a replay fixture or
measuring the export, and it is deliberately heavy: turn it on for a window. The byte
cap governs the whole capture dir and *stops* capture when reached, keeping the
oldest samples rather than rotating them away, so a debug capture can never fill the
disk.

Captures are NDJSON under `<dir>/netflow/`, one line per datagram with the payload
base64-encoded, at mode 0600 - they carry real addresses and the traffic pattern of
the whole network. `cmd/flowanon` reads them (a file or a whole rotated directory)
and builds an anonymised replay fixture from a selection of them.

### ifIndex is positional, and that is fragile

The `ifIndex` in a record is **not** an OS or SNMP index. It is a **1-based position in
the device list `/usr/local/sbin/ifinfo` prints**, so **adding or removing any interface
renumbers everything** and silently remaps historical series.

OPNsense derives that position twice, and both agree. `src/etc/rc.d/netflow` counts the
list to name the netgraph hook - `ngctl mkpeer $iface: netflow lower ifaceN` - and
OPNsense's own flowd reporting counts it again to read those names back
(`scripts/netflow/lib/parse.py`). One ng_netflow node is created per captured interface,
each with a single `ifaceN` hook, rather than one node with many hooks.

The exporter reads the enumeration from **`api/diagnostics/interface/get_interface_config`**,
which returns a JSON object keyed by device and reproduces `ifinfo` order exactly. That
ordering is the only thing that decides an index. Interface metadata - names, addresses,
WAN flags, VLAN parents - still comes from `api/interfaces/overview/interfaces_info` and
is joined onto the enumeration **by device name, never by position**. A device in the
enumeration that the metadata does not know (`pfsync0` is the common one) still occupies
its slot and falls back to labelling itself with its device name, which is what keeps
every later index correct.

That split exists because the alternative was tried and was wrong. The map used to be
derived by counting `interfaces_info` rows, which **omits `pfsync0`** - 15 rows where the
kernel has 16 - so every index from 10 upward came out one too low. On the reference box
that put 93% of measured NetFlow byte volume under the wrong interface (index 15,
`pppoe0`, the PPPoE WAN, labelled as the interface belonging to index 16) and left a
further 0.9% with an empty label, for months, with every health metric reading clean.

So the guards matter more here than the mechanism:

- an index that resolves to nothing yields an **empty** `interface` label and
  increments `opnsense_flow_ifindex_unmapped_total` - a wrong interface name is worse
  than a missing one;
- `opnsense_flow_ifindex_source_disagreements` cross-checks the enumeration two ways.
  `reason="stated_index"` counts devices where the ifIndex the API states differs from the
  position we derived. The two are equal only while the index space has no gaps: **remove an
  interface permanently** and every device above it shifts down a position while its kernel
  index stays put, so the position `rc.d/netflow` counts stops matching the number the kernel
  reports. `reason="unlisted_device"` counts interfaces the box reports that the enumeration
  does not contain at all. Either one non-zero means every label is suspect;
- `--flow.netflow.ifindex-map` pins any index outright, and
  `opnsense_flow_ifindex_conflicts` reports how many of your pins disagree with the
  derivation. Non-zero means the indices you did *not* pin are suspect. Unlisted indices
  keep using the derivation, so pin every index that carries traffic:

  ```
  --flow.netflow.ifindex-map=1=ixl0,2=ixl1,7=lo0,15=pppoe0,16=tailscale0
  ```

- `opnsense_flow_ifindex_map_age_seconds` tracks the map's freshness, which is a
  correctness signal here rather than a staleness nuisance. On a failed fetch or a
  tripped guard the exporter **keeps the last good map** and lets the age rise. It never
  falls back to the old row-counting derivation.

The enumeration is re-read hourly, and immediately on either of two triggers: an
interface appearing that the enumeration does not contain, or an ifIndex arriving that
the map cannot resolve. The second is rate-limited, because the NetFlow socket is
unauthenticated and an unbounded trigger there would let any sender drive the firewall's
API load.

A **reconnect does not renumber anything**, which is worth knowing before treating the
triggers as urgent. Bouncing a PPPoE WAN was tested live: the interface was genuinely
destroyed and recreated, reclaimed the lowest free index — its own, because nothing else
had taken it — and returned to its old slot. Only a permanent removal leaves the gap that
shifts everything above it.

The resolved map is rendered on the operator console's **ifIndex** tab, so
`index → device → name` can be read straight down against `ifinfo` output without
decoding a capture.

### What `interface` means on this lane

A NetFlow record crosses two interfaces and the label names one: the **WAN-facing**
side - egress for outbound, ingress for inbound. That is what makes per-WAN volume
answerable, which is the entire point of the egress repair.

The cost is deliberate: a LAN host's internet traffic is attributed to the WAN it
left by, **not** to its own VLAN. Per-VLAN volume is
therefore visible for internal traffic only, and the two lanes describe the same flow
differently - Zenarmor keeps naming the VLAN child. This is a second reason, on top of
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

Zenarmor reports the **parent** device on every `conn` record - verified across
20,476 live documents, all of which say `ixl0` - and puts the tag in a separate
field. Read naively, the label would have a single value and every VLAN's traffic
would be attributed to the LAN. The exporter reconstructs the child device
(`ixl0` + tag `50` → `ixl0_vlan50`) before resolving the name, so IOT traffic reads
as `IOT`. On the capture box that is 20.5% of flows.

### `direction` uses the firewall's own topology

Two sources of truth, each used for what it actually knows. The firewall's
configured subnets decide whether a flow is **internal**; the flow source's own
direction field decides **inbound** versus **outbound**. Multicast and link-local
destinations are internal by inspection - SSDP and mDNS never leave the L2 domain,
even though a group address sits in no configured subnet.

`internal` includes traffic to the firewall itself (DNS, the web UI, NTP): the box
is not a remote endpoint.

`unknown` is a real, emitted value. Where neither the topology nor the source can
classify a flow, that is what it says, rather than inventing a direction to avoid an
empty label.

## `__other__` - the folded remainder

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
reads as a counter reset on that series. The alternative - leaving a fallen-out
series frozen at its last value forever - is the failure mode that makes a top-K
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
# WRONG with both lanes enabled - counts the same bytes twice
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
UDP flows - DNS, STUN, SSDP - report zero. On the reference capture that was 27.6%
of flow-sides with a non-zero packet count, and 8.6% of documents would have
reported **zero bytes while still being counted** as records.

The exporter therefore falls back to the payload figure when the wire figure is zero
and the payload figure is not, and counts every fallback in
`opnsense_flow_payload_byte_fallback_total`. A steady rate there is normal and is the
repair working, not a fault. The byte impact is negligible - these are one and two
packet flows - the point is not reporting zero for traffic that plainly happened.

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

- [Log shipping](log-shipping.md) - the Zenarmor receiver that feeds this
- [Native log export](log-export-native.md) - when a dedicated flow pipeline is the
  better tool
- [Metrics reference](metrics/metrics.md) - the full `opnsense_flow_*` family
