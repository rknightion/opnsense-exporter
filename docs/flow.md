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
[`internal/flow/` on GitHub](https://github.com/rknightion/opnsense2otel/tree/main/internal/flow).

## Enabling it

Flow rollups are **on by default** and cost nothing where no flow source is
configured: the metrics are silent, in the same way `log_events` is silent
without the syslog receiver. The Zenarmor `conn` record still ships exactly as it
did before on its own lane regardless of any flow setting below. Separately, by
default (`--flow.log-mode=per_flow`), each correlated flow **also** ships one OTLP
log record of its own on the shared log pipeline - see
[Flow log records](#flow-log-records) below for what that record contains and how
to turn it off.

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
onto the parent interface.

**The subnet is the evidence that settles it.** A trunk-named record whose relevant
address falls inside exactly one VLAN child's configured subnet is moved onto that
child immediately, so which copy the exporter flushed first stops mattering at all.
The address pairing is physical: a record that ARRIVED on the trunk came from the
VLAN, so its source address is the VLAN host's, while one LEAVING by the trunk is
heading toward the VLAN, so its destination is. `opnsense_flow_vlan_subnet_attributed_total`
counts it. This also reaches something no timing could: records with no second copy
anywhere - 247,105 of them in an 18h35m measurement, which no hold window of any size
could have attributed, because there is nothing to prefer.

The two-second hold remains as the fallback for an address that matches no child
subnet or several of them, and a record with a trunk-named side the evidence could not
place still waits for a better copy. `opnsense_flow_vlan_child_preferred_total` counts
the swaps the hold contest wins; on a box whose VLANs have configured subnets, expect
subnet attribution to carry the work and this to sit near zero.
`opnsense_flow_repair_held_records` is the queue itself: it should track the record
rate and never grow without bound, and `records_dropped_total{reason="hold_overflow"}`
means the buffer filled and those records fell back to first-arrival.

Timing alone could never have been enough, and the measurement says why: the pair-gap
p50 is 954 ms but p95 is 5.7 s, p99 is 31.2 s and the observed maximum is 108.5 s, so
a two-second window covers 70.8% of real pairs. Enlarging it is not the lever either -
covering p99 projects to several times the hold buffer's capacity, past which it
degrades to first-arrival anyway, and the widest observed gap is already 90% of the
de-duplication TTL, so a window reaching into that tail starts double-counting instead
of misattributing. What remains is counted rather than hidden:
`opnsense_flow_vlan_late_child_copies_total` is a better copy that arrived after the
first was already emitted and counted, which cannot be corrected without
double-counting real bytes. A sustained non-zero rate there means a VLAN is missing a
configured subnet, or two children's subnets overlap.

**Policy-routed egress is mislabelled - the big one.** ng_netflow derives the egress
interface from a FIB route lookup, but OPNsense multi-WAN policy routing happens in
pf, which ng_netflow never sees. On the reference capture this reported 3.36 GB of
WAN2 traffic as WAN1: WAN2 read 37.8 MB against ~3.4 GB actual, a 99% under-report.
Every generic collector on that network is wrong about this today. Where a record's
source address is a known WAN address, that WAN is the true egress regardless of what
the export said; corrections are counted by `opnsense_flow_egress_corrected_total`,
and the correction only fires when the two actually disagree, so it cannot mask
ng_netflow starting to get it right.

**The pre-NAT copy of a policy-routed flow needs pf itself.** The correction above
keys on the record's *source* address, so it can only ever fix the **post-NAT** copy
- and that copy's 5-tuple is the firewall's own WAN address, which matches nothing
Zenarmor ever saw. The **pre-NAT** copy is the only one that can correlate, and its
source is a private LAN address, so it inherits `OUTPUT_SNMP` untouched and is
labelled with the default-route WAN whatever pf did. On the reference box that put
every inspected byte that actually left by WAN2 onto WAN1, while WAN2's correlated
series stayed empty against 11.1 GB of real traffic.

The exporter resolves this from **pf's own state table**
(`api/diagnostics/firewall/query_states`, polled every minute and held as a lookup
map - never a per-flow call). pf keeps both states for a NAT'd conversation, and the
`direction: "in"` state is the pre-NAT view: its 5-tuple *is* the pre-NAT record's
5-tuple, and it already carries pf's `route-to` - the routing decision verbatim, not
an inference about it. Corrections are counted by
`opnsense_flow_policy_route_corrected_total`, and the record carries
`flow.policy_route_corrected` so a single flow can be checked against `pfctl -ss`.

Its limits, which are counted rather than hidden:

- **A state that carries no `route-to` is left alone.** That means pf used the FIB,
  which is precisely when `OUTPUT_SNMP` is already right.
- **A short flow may have no state to resolve against.** The window has two halves,
  and they behave differently.

  A state can **expire before its record arrives**: OPNsense's `inactiveTimeout` lets
  a record land 15-30 s after the conversation ended. The lookup map handles this by
  carrying a tuple forward for **three minutes** after it was last seen in a snapshot,
  so an expired state stays answerable. That carried subset is published as
  `opnsense_flow_pf_state_entries{kind="carried"}`; a fresh snapshot always overrides
  a carried entry, so a re-routed flow is corrected on the next poll rather than
  pinned by its own history.

  A state can also be **created after the last poll** - born, used and closed entirely
  between two snapshots, so it appears in none of them. Nothing but a poll faster than
  the state lifetime reaches that, and no interval reaches the shortest states. Those
  records are emitted exactly as reported and counted under
  `opnsense_flow_policy_route_refused_total{reason="no_state"}`.

  **How much of that counter is really floor, measured.** Replaying 15 minutes of a real
  production export (85,919 records) against real pf snapshots at the real one-minute
  cadence: of 24,203 pre-NAT outbound candidates, **81.6% resolved against the table at
  the moment they arrived** and **18.3% had no state in any snapshot at all**. Deferring a
  refused record by a whole extra poll and re-asking would recover **18 records, 0.1%**.
  So the miss window really is the floor the two paragraphs above describe, and a faster
  or later lookup is not the lever.

  Split the counter by `interface` to see where your own refusals sit. Refusals piling up
  on the default-route WAN are consistent with policy-routed traffic hiding inside them;
  spread evenly, they are structural.

  **Where the rest of the records go is now countable too.**
  `opnsense_flow_policy_route_skipped_total` splits the four ways the repair correctly
  declines to act, three of which previously moved no counter at all - so a box where the
  repair was never running produced the same telemetry as one where it had nothing to
  correct. `not_wan_egress` is about half of all records and healthy, but it is also
  exactly what a wrong interface map looks like, so watch it as a *share* of decoded
  records; a step change there with no configuration change is the alarm.

  The reference replay's full split, for comparison against your own box:

  | bucket | records | share of decoded |
  | --- | ---: | ---: |
  | decoded | 85,919 | |
  | `skipped{not_wan_egress}` | 43,791 | 51.0% |
  | `skipped{already_on_wan}` | 20,570 | 23.9% |
  | `refused{no_state}` | 8,391 | 9.8% |
  | `skipped{fib_agreed}` | 6,423 | 7.5% |
  | `corrected` | 402 | 0.5% |
  | `skipped{post_nat}` | 297 | 0.3% |

  One thing does not add up yet and is tracked as
  [#624](https://github.com/rknightion/opnsense2otel/issues/624): in that replay the repair
  made 402 corrections, while the live exporter processing the byte-identical export
  stream over the same window made about 45. The input is confirmed identical, so the
  difference is somewhere in the running exporter's own state - which is what the split
  above was added to find.

  The one-minute poll is sized for this. It was five minutes on the reasoning that
  the flows this repair recovers are long ones - which measurement disproved: on the
  reference box 18 of the 19 policy-routed states are sub-90-second TCP connections,
  one arriving about every ten seconds, and roughly 30% of decoded records were being
  refused. A minute reaches a ~90-second state most of the time and a 30-second one
  never. The cost is real - the full table is ~3 MB and ~650 ms, and every API request
  also costs two configd RPCs - so it is not tunable: the only thing tuning it changes
  is firewall load.
- **Ambiguity cannot arise.** The key is the tuple pf itself keys states by, so two
  LAN hosts to the same destination over different WANs get their own answers. A
  duplicate key would be a signal, not an input: it is counted as
  `opnsense_flow_pf_state_entries{kind="conflict"}` and the first row wins.

### NAT-pair de-duplication

A conversation that crosses a captured LAN interface **and** a captured ethernet WAN is
exported **twice**: pre-NAT where it entered, post-NAT where it left. They are the same
bytes, and nothing in either record says so, because the whole point of NAT is that the
5-tuples differ.

The repair pairs them from pf's own translation. The `direction="out"` state row carries
`nat_addr`/`nat_port` holding the pre-NAT endpoint, so the mapping is stated rather than
inferred - the same class of evidence the policy-route repair rests on, read from the same
snapshot on the same poll.

**Only the post-NAT copy is ever suppressed.** The pre-NAT copy carries the LAN host's own
5-tuple, which is the only tuple Zenarmor ever saw, so it is the only copy that can reach a
merged record. Suppressing it to keep the post-NAT one would trade a double count, which
shows up against the interface counter, for a hole in correlation coverage, which does not.

Measured against a live production box on 2026-08-01 - 15 minutes, 4,257 export datagrams,
85,919 flow records, 14 one-minute pf snapshots, with a 100 Mbit/s backup running over the
policy-routed WAN:

- **399 of 399 pairs matched bytes and packets exactly.** NAT does not change a packet's
  size, so volume is conserved and is what the key rests on.
- **Only 61% also matched the flow timestamps.** The two copies are expired by two
  independent `ng_netflow` nodes, so `first`/`last` differ by up to a second. The key
  deliberately omits them; including them would miss two pairs in five.
- **The copies arrive p50 20 s, p90 49 s, p99 60 s apart** (max 7m11s). A hold buffer is
  therefore the wrong mechanism - the 2-second VLAN window would pair 15.8% - and the
  existing two-minute de-duplication window is the right one, pairing 99.7%.
- **The pf mapping was available when the post-NAT copy arrived in 98.8% of pairs**, with
  the live one-minute poll and three-minute retention. That is much better than the
  policy-route repair manages, for a structural reason: this repair needs the state when
  the *later* copy lands, by which time it has been through a poll.
- **1,009 records carried a WAN address but had no twin at all** - the firewall's own
  traffic, never translated. Keying on "has a WAN address" instead of on pf's mapping
  would have destroyed every one of them.

Its limits, counted rather than hidden:

- **The residual is arrival order.** The pre-NAT copy arrives first in 89.2% of pairs. In
  the rest the post-NAT copy is already through the rollup and shipped by the time its twin
  lands, and it cannot be taken back; the pair is emitted and counted as
  `opnsense_flow_nat_pair_deduped_total{outcome="late_pre_nat"}`. Suppressing the pre-NAT
  copy at that point would fix the byte total at the cost of the correlatable record.
- **A PPPoE WAN has nothing to de-duplicate**, because it exports nothing at all. Both
  counters flat at zero on such a box is correct, not a fault.
- **Conflicts fail safe.** A post-NAT tuple already mapped to a different conversation is
  counted as `kind="conflict"` (6-14 per build against ~7,000 entries, measured) and
  resolves to the wrong conversation, whose twin then will not match on volume - so the
  record is emitted rather than suppressed.

**Direction is not exported at all.** Field 61 is absent, so direction is inferred
from the firewall's own topology and the ifIndex evidence, by the same rules the
Zenarmor lane uses. `unknown` is emitted honestly rather than guessed.

### What the decoder could not interpret

A NetFlow export can carry things this decoder does not model: a template element it
has nowhere to put, an options template, a control flowset in the reserved range.
Each is stepped over by its *template-declared* length, which is the only safe thing
to do - assuming a width shifts every following field and corrupts records with no
parse error to show for it. What changed is that it no longer happens in silence.

`opnsense_flow_netflow_unidentified_total` counts them by `kind`. On a healthy box it
reads **zero**, so any non-zero value means the export gained something new. This is a
change: until #630 the box's own templates declared four elements the decoder did not
read (TOS, the two masks, the next hop), which made a non-zero count and its warning
permanent on every install and therefore impossible to act on. All four are now
modelled. It is counted once per element when a
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

The exporter reads each device's **kernel interface index** from
**`api/diagnostics/interface/get_interface_statistics`** (`netstat -i --libxo json`, where
each interface's AF_LINK row carries `network` as the literal `<Link#N>` and N is the kernel
index), sorts by it, and takes the **rank** as the ifIndex.

Rank, not the index itself. `ifinfo` walks the kernel's interface table by row number and
skips absent rows, so its position is the rank over live indexes - and rank equals index only
while the index space is dense. A permanently removed interface leaves a gap, past which they
diverge, and `rc.d/netflow` counts the position.

This endpoint is the only one that carries an index for **every** device. `get_interface_config`
has no index at all, and `interfaces_info` omits `pfsync0` outright - which is disqualifying,
because `pfsync0` sits in the middle of the index space, so dropping it shifts every device
above it. `get_interface_config` is still fetched, but only for its device **count**, as a
cross-check that two independent sources agree on how many interfaces exist.

`api/diagnostics/traffic/interface` states an index for the *configured* interfaces and is kept
as a genuinely independent second opinion - a different producer (`ifinfo` via PHP, against
netstat) - never as an input to the derivation. Under a dense index space the derived rank must
equal the stated index for every configured device, so a divergence is direct evidence of a gap.

Every guard **refuses rather than guesses**: no `<Link#N>` rows at all, a device with two
different indexes, two devices sharing one, or a count the enumeration disagrees with. A refusal
keeps the previous map and lets `opnsense_flow_ifindex_map_age_seconds` rise.

Interface metadata - names, addresses, WAN flags, VLAN parents - comes from
`api/interfaces/overview/interfaces_info` and is joined onto the enumeration **by device
name, never by position**. A device in the enumeration that the metadata does not know
(`pfsync0` is the common one) still occupies its slot and falls back to labelling itself with
its device name, which is what keeps every later index correct.

The enumeration and that metadata are **two separate API calls made in sequence**, so for a
moment after every restart the map has every index right and not one name, and each record is
labelled with its device (`ixl0`) instead of its description (`LAN`). The map is still published
immediately - a device label is honest and joinable, where withholding the map would leave the
records unlabelled - but it is treated as **provisional**: the rebuild stays on its one-second
cold retry until names land, instead of settling to the sixty-second interval on a map that is
merely populated. A box that genuinely reports no interface descriptions is taken at its word
after five minutes, with one log line saying so. Before this, the degraded labelling lasted a
full minute on every restart and split every affected series in two.

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
- `opnsense_flow_netflow_records_unmapped_total` counts the **records** that came out of
  that with no interface at all. It is not the same number as the lookup counter above and
  cannot be swapped for it: that one counts failed lookups against a map that exists, and
  is attached to the map object, so it stays at zero for the whole cold-start window
  between the receiver starting and the first interface fetch landing. This one is the only
  thing counting during that window. Those records are still **emitted** and still counted
  in the volume totals - an empty label is honest, and dropping them would lose data - so
  this is deliberately not a `reason` on `opnsense_flow_netflow_records_dropped_total` and
  the funnel identity `decoded = emitted + dropped` is unaffected by it. A burst right after
  a restart is the cold window and should stop; a sustained rate means the enumeration
  moved;
- `opnsense_flow_ifindex_source_disagreements` cross-checks the enumeration two ways.
  `reason="stated_index"` counts devices where the ifIndex the API states differs from the
  position we derived. The two are equal only while the index space has no gaps: **remove an
  interface permanently** and every device above it shifts down a position while its kernel
  index stays put, so the position `rc.d/netflow` counts stops matching the number the kernel
  reports. `reason="unlisted_device"` counts interfaces the box reports that the enumeration
  does not contain at all. Either one non-zero means every label is suspect;
- `--flow.netflow.ifindex-map` pins any index outright, and
  `opnsense_flow_ifindex_conflicts` reports how many of your pins disagree with the
  derivation. Unlisted indices keep using the derivation, so pin every index that carries
  traffic:

  ```
  --flow.netflow.ifindex-map=1=ixl0,2=ixl1,7=lo0,15=pppoe0,16=tailscale0
  ```

  The two reasons are different problems. `reason="derived_absent"` means you pinned an
  index the derivation produced nothing for, which is expected when you pin beyond the
  enumeration and says nothing about the ordering. `reason="derived_differs"` means the
  two name different interfaces at the same index - and it does **not** tell you which is
  right. A pin is a static assertion against a *positional* index, so adding or removing
  any interface renumbers everything above it and a once-correct pin goes stale on its
  own, while still winning. That is exactly what #516 was: a VLAN added on the firewall
  shifted three pins by one, and the pin kept labelling the PPPoE WAN - 91% of the box's
  volume - as the tailnet interface, which is #361's failure reintroduced from the other
  direction. Settle it on the box, never from the metric:

  ```
  ifinfo | awk '$1 == "Interface" { n++; print n, $2 }'   # the enumeration
  ngctl show netflow_pppoe0:                              # ifaceN = the index actually stamped
  ```

  The `ifaceN` hook name is decisive: it is the number `rc.d/netflow` passed to
  `ngctl mkpeer` and therefore the number that arrives in every record. If it agrees with
  the derivation, delete the pin rather than correcting it - an unpinned index cannot go
  stale.

- `opnsense_flow_ifindex_map_age_seconds` tracks the map's freshness, which is a
  correctness signal here rather than a staleness nuisance. On a failed fetch or a
  tripped guard the exporter **keeps the last good map** and lets the age rise. It never
  falls back to the old row-counting derivation.

The enumeration is re-read hourly, and immediately on either of two triggers: an
interface appearing that the enumeration does not contain, or an ifIndex arriving that
the map cannot resolve. The second is rate-limited, because the NetFlow socket is
unauthenticated and an unbounded trigger there would let any sender drive the firewall's
API load.

A **reconnect does not renumber `ifinfo`**, and therefore does not change what the netgraph
hooks mean. Bouncing a PPPoE WAN was tested live: the interface was genuinely destroyed and
recreated, reclaimed the lowest free index - its own, because nothing else had taken it - and
`ifinfo` still listed it in its old slot. `rc.d/netflow` re-derived the hook as `iface15`,
confirming it.

What a reconnect *does* change is the **key order** of the endpoints that list devices without
an index: those are in attach order, so the recreated device moves to the end. Deriving the
enumeration from that order mislabels the WAN after every reconnect while `ifinfo`, the hooks
and the records all still agree with each other - which is exactly what happened, and why the
enumeration is built from kernel indexes instead.

Only a permanent removal leaves the gap that shifts everything above it - and that is the case
the correction refuses rather than guesses at.

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

### Detecting an interface that is configured to export but exporting nothing

A netflow capture hook can die while everything around it keeps reporting healthy. Observed
on the reference box: a PPPoE WAN was bounced, the `ng_netflow` node for it survived but lost
its `ifaceN` hook, and the box captured nothing on its primary WAN for the best part of an
hour. The service read `running`, the export socket stayed connected, and
`api/diagnostics/netflow/getconfig` still listed the interface as selected. From the
exporter's side that is indistinguishable from an idle link - there is simply an **absence**,
and absence is what a counter cannot speak about.

The missing half is the **expected set**: which interfaces the firewall has been told to
capture on. `opnsense_netflow_capture_expected{interface}` is that set, straight from the
box's own netflow config - `1` for selected, `0` for listed-but-not-selected. The set is
closed and small, so this adds no cardinality risk.

Paired with it, `opnsense_netflow_capture_last_record_seconds{interface}` is how long since
this exporter last received a record naming that interface. **It is a raw age, not a
verdict.** No threshold is baked in and no alert ships with it, for two reasons the issue
that drove this insisted on:

- a genuinely idle interface is not a fault. A guest VLAN with nothing on it is legitimately
  silent for hours, so the threshold has to be yours. Derive it from
  `opnsense_netflow_capture_active_timeout_seconds`, which is the box's own configured active
  flow timeout (1800s by default) - an interface cannot be judged silent until well past it;
- **"never seen since start" and "seen, then stopped" are different states.** An interface
  that has produced no record since the exporter started has **no age series at all**, rather
  than a large number. Every interface is silent before its first record arrives, and
  rendering that as a number would make a fresh boot look like a box-wide outage.

So the fault reads as: `capture_expected == 1`, an age series **present**, and that age well
past the active timeout.

Both metrics come from the **netflow collector**, which is opt-in - without
`--exporter.enable-netflow` neither is published, regardless of whether the receiver is running.

#### What a fresh age does *not* prove

`ng_netflow` stamps the capturing hook's index on **one** side of a flow and fills the other
side from a **FIB lookup**. So a record captured on the LAN hook also names the egress WAN,
and an interface can be named continuously while its own capture hook is producing nothing.

This was measured directly on the reference box on 2026-07-24: `ngctl msg netflow_pppoe0:
info` returned only its two timeouts - no packet or byte counters at all, meaning that node
had processed nothing - while the exporter attributed 11 GB, 92% of all volume, to that
interface over the same window. Every one of those records was captured by `netflow_ixl0` and
the VLAN nodes, which named the WAN from a route lookup.

A fresh age therefore proves the interface is being **named**, not that its hook is alive. It
still catches the cases where nothing names it at all: the receiver losing its feed, the
export target going wrong, netflow being stopped box-wide, or an interface dropping out of
the capture set.

For **per-hook** liveness, use the box's own view instead:
`opnsense_netflow_cache_packets_total{interface="<device>"}`, one series per `ng_netflow`
node. A node pinned at zero while its peers climb is the firewall itself saying that hook is
dead.

#### A PPPoE hook is dead by construction

`ng_netflow` attaches to **mpd's framing node**, not the `ng_iface` node `ng_pppoe` exposes,
so selecting a PPPoE interface for capture *succeeds* - `ngctl mkpeer` returns cleanly, the
node exists (`netflow_pppoe0`, with a real `ifaceN` hook) - and then counts **zero packets
forever**. No configuration clears it.

`opnsense_flow_interface_capture_unsupported{interface,device,reason="pppoe_framing_node"}`
marks these. The series is present only for a device that can never capture; **absent means
capable**, so it is an exception marker rather than a per-interface flag. It excludes those
interfaces from the dead-hook table and from `OPNsenseNetFlowHookDead`, because an alert that
can never be cleared is worse than no alert.

**Nothing is lost when it appears.** The FIB-lookup behaviour above is what saves it: the WAN's
traffic is captured by the *other* interfaces' hooks and still attributed to the WAN. Measured
on the reference box in one 45-minute window: 2.09 GB attributed to `AAISP` while
`opnsense_netflow_cache_packets_total{interface="pppoe0"}` read zero for the whole 7-day
retention window. Unticking the interface in **Reporting → NetFlow** stops asking for a capture
that cannot happen; leaving it selected costs only a dead netgraph node.

The match is on the **device** name and is a prefix (`pppoe*`), never the description - a device
name is the kernel's and is what netgraph attaches to, while an operator could call any
interface "pppoe-backup" and would then have silently disarmed the alert protecting it. `pptp`
and `l2tp` are built on the same mpd framing and are very likely identical, but that is
unverified and deliberately not claimed.

#### Joining the two label spaces

Three metric families describe the same interface under two different meanings of the
`interface` label:

| Family | `interface` holds | Source |
|---|---|---|
| `opnsense_netflow_cache_*` | kernel **device** - `pppoe0`, `ixl0_vlan25` | `flowctl` node names |
| `opnsense_netflow_capture_*` | configured **description** - `AAISP`, `CAM` | the netflow config model |
| `opnsense_flow_*` | configured **description** | the ifIndex map's `Name` |

`opnsense_flow_interface_info{device,interface,ifindex}` carries the correspondence on one
series - value always 1, bounded by the interface count - so the spaces join through it with
`group_left`. It is published by the flow collector whenever the NetFlow lane is running, and
it is the same map the operator console's **ifIndex** tab prints.

Two things to know before joining on it. The `interface` label is only unique across
**assigned** interfaces: OPNsense hands every unassigned device the same placeholder
description (`Unassigned Interface`), so several series can share that value and a `group_left`
whose left side carried it would fail the many-to-one uniqueness rule. Nothing worth joining
does - the capture config lists assigned interfaces only - and a query error there is a better
outcome than a plausible wrong device. Second, for the first seconds after a restart the
series exist with an empty `interface`: the enumeration and the interface metadata are separate
fetches, and the map is published as soon as the enumeration lands rather than waiting.

That makes the highest-value NetFlow health statement a single expression: **configured to
capture, real traffic passing on the device, and its own `ng_netflow` node counting nothing for
longer than the box's active timeout.**

```promql
max by (opnsense_instance, interface, device) (
  (opnsense_netflow_capture_expected == 1)
    * on (opnsense_instance, interface) group_left (device) opnsense_flow_interface_info
)
and on (opnsense_instance, device) max by (opnsense_instance, device) (
  label_join(increase(opnsense_netflow_cache_packets_total[45m]), "device", "", "interface") == 0
)
and on (opnsense_instance, device) max by (opnsense_instance, device) (
  label_join(increase(opnsense_firewall_in_ipv4_pass_bytes_total[45m]), "device", "", "interface") > 0
)
and on (opnsense_instance) (opnsense_netflow_capture_active_timeout_seconds < 2700)
unless on (opnsense_instance, interface) (opnsense_flow_interface_capture_unsupported == 1)
```

Every clause is load-bearing:

- **Clause 2** is the only signal a dead hook cannot hide from, for the FIB-lookup reason above.
- **Clause 3** separates a dead hook from an idle interface. A quiet guest VLAN's node is
  legitimately flat, and without pf confirming that bytes actually crossed the device the two
  read identically. `label_join` rather than `label_replace` because both the cache and pf
  families put a device in their `interface` label, and a `$1` capture reference would be
  eaten by Grafana's variable interpolation.
- **Clause 4** is the honesty check on the window: "exported nothing" means nothing until the
  active timeout has passed, so the query withdraws itself if the box's configured timeout is
  45m or more instead of letting `[45m]` quietly become a lie. 45m clears OPNsense's 1800s
  default.
- **Clause 5** drops any interface whose device can never capture at all - every PPPoE WAN, per
  the section above. Without it the expression is permanently non-empty on such a box, with no
  action available to clear it, which trains the reader to ignore a result whose whole contract
  is "a row here is a fault".

An interface with **no** `cache_packets_total` series at all - a hook that was never created -
is deliberately absent rather than reported; read it off the ifIndex map instead. Both the map
and this query are on the dashboard's **NetFlow → Hook Liveness** row.

Run against the reference box on 2026-07-25 the expression returned exactly one row,
`{interface="AAISP", device="pppoe0"}` - the hook whose death took a packet capture to find in
July. That row is exactly what clause 5 now suppresses: `pppoe0` is not a hook that broke, it is
a hook that could never have worked, and it had been firing continuously since.

This exact query is also a managed alert, `OPNsenseNetFlowHookDead`
(`grafana/alerts/build_rules.py`, rule `opnsense-netflow-hook-dead`) - `warning` severity, `for: 5m`
on top of the query's own 45m of evidence, one alert instance per `(opnsense_instance, interface,
device)`. It resolves on its own once `opnsense_netflow_cache_packets_total` starts counting again
on the device. See `grafana/README.md#alerts` for the full rule catalogue and deployment path.

## Flow log records

| Flag | Default | Purpose |
|---|---|---|
| `--flow.log-mode` | `per_flow` | `per_flow` ships one OTLP log record per correlated flow on the shared log pipeline; `off` ships none while still deriving all metrics above |
| `--flow.max-logs-per-window` | `0` (unlimited) | cap on flow log records shipped per minute; excess is TRUNCATED, never sampled, and counted - a flood guard for the unauthenticated NetFlow ingress |

This is separate from, and in addition to, the Zenarmor `conn` record's own lane
(`--logs.zenarmor.enabled`), which ships regardless of `--flow.log-mode`. Turning
`--flow.log-mode` off removes only the correlator's own per-flow record; it never
touches metrics or the Zenarmor lane.

**Record timestamp.** The shipped record's own timestamp is the flow's **End**
time - the correlator's authoritative close time, "when this conversation last had
traffic" - falling back to **Start**, then **Observed**, and finally the zero value
if none of the three is set (an incomplete or synthetic record). It is never the
time the exporter happened to process the record, which is what makes it usable for
"when did this actually happen" queries instead of just "when did we notice it."

**Direction of volume.** A NetFlow record is strictly unidirectional and all of its
volume lands in the transmit counters, so the two halves of a conversation are two
separate exports. On a **merged** record the correlator now keeps them apart: the
chosen orientation's volume is transmit, the reverse half's is receive, so a 2 GB
download reads as 2 GB received rather than 2 GB transmitted. The split is emitted as
`flow.nf.tx_bytes` / `flow.nf.rx_bytes` (and the packet equivalents), only on merged
records - on a raw NetFlow record it would merely restate `flow.nf.bytes` and say
nothing.

`opnsense_flow_bytes_total` is **unchanged** by this: it has always summed both
directions, so the total does not move for any existing consumer. Which half is which
is decided by the same evidence that decides the record's other dimensions, so the
answer does not depend on which datagram arrived first.

Zenarmor's own counters are deliberately left alone. They are never summed with the
NetFlow side, and whether the two sources agree on what "transmit" means has not been
checked against a real conn document.

**Interval attributes.** Every record additionally carries, as Loki structured
metadata (never a label):

| Attribute | Present when | Value |
|---|---|---|
| `flow.start_time` | `Start` is set | RFC3339Nano, UTC |
| `flow.end_time` | `End` is set | RFC3339Nano, UTC |
| `flow.duration_ms` | both `Start` and `End` are set **and** `End >= Start` | `End - Start` in milliseconds |

`flow.start_time` and `flow.end_time` are each reported independently - a record
missing one still reports the other rather than withholding both.
`flow.duration_ms` is the one derived value and is held to a stricter rule: a
malformed or synthetic record with `End` before `Start` omits *only*
`flow.duration_ms` rather than reporting a negative duration, while `flow.start_time`
and `flow.end_time` themselves are still reported since each is independently a real,
directly-observed timestamp. Nothing here is ever fabricated - an absent time or
interval means the data was not there, not that the exporter guessed a value.

**Connection-shape attributes.** Two more, on the same terms - structured metadata,
never a label:

| Attribute | Present when | Value |
|---|---|---|
| `netflow.tcp_flags` | any TCP flag bit was set on the flow | comma-separated set in wire bit order, e.g. `SYN`, `SYN,ACK`, `RST,ACK` |
| `zenarmor.encryption` | Zenarmor reported it | Zenarmor's own string, e.g. `Clear`, `TLS-Encrypted` |

`netflow.tcp_flags` is what separates a port scan (SYN, nothing back, no bytes) from
a refused service (RST) from a clean short session - a distinction nothing else in
the pipeline expresses, since Zenarmor's `IsBlocked` is the *firewall's* verdict
rather than the peer's response. The flags are **OR-unioned across every NetFlow
fragment of a connection-window**, not taken from the first: each direction is a
separate record and a long flow re-reports on the inactive timeout, so a single
fragment would render `SYN` on practically every TCP flow and destroy the
distinction. That union is not an invention - FreeBSD's `ng_netflow` already ORs the
flag byte per packet within a fragment, so extending it across the window keeps the
field meaning one thing.

A flow with no flags set emits **no attribute at all** rather than an empty one. Zero
is unambiguous here (no legal TCP segment carries an empty flag byte), so an empty
value would cost bytes on every UDP line and, because Loki distinguishes absent from
`""`, would also match records that reported nothing.

`zenarmor.encryption` answers "which internal hosts still send cleartext to the
internet" as one query joined against NetFlow volume. It rides the correlated record
specifically, that being the only one carrying both a Zenarmor verdict and NetFlow
byte counts.

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

### `unresolved` is a real interface value

The flow lanes are **push**-based: Zenarmor and ng_netflow send records on their own
schedule, while the interface descriptions come from the enrichment snapshot, which
the exporter fetches on its. So there is a window after every restart where a record
arrives naming a kernel device we cannot yet turn into a description.

Falling back to the raw device there is wrong in a specific way: the box **does** have
a description, it just had not been read, so `interface="ixl0"` appeared beside the
`interface="LAN"` the same interface got a minute later - one interface split across
two series, and every `sum by (interface)` short on both. Those records are now
labelled `interface="unresolved"` instead, counted by
`opnsense_flow_interface_unresolved_total`, and the kernel device still travels on the
log record as `flow.in_device` / `flow.out_device` so nothing is lost.

It is a startup artifact and it closes on its own. Measured over 7 days and 51
restarts on the reference box, **every** byte ever attributed to a raw kernel device
landed with the process less than **300 seconds** old, and past that the raw-device
series were completely flat. A rate that keeps climbing past a few minutes of uptime
means the interface fetch itself is failing, not that a restart happened.

A device the box genuinely has no description for is a different case and keeps its
raw name: the sentinel is for "we could not ask", not for "there is no answer".

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

## Multi-WAN: what per-WAN attribution can and cannot tell you

On a box with more than one WAN, per-WAN byte totals on this lane are **approximate,
and currently biased in a known direction**. Two open defects drive it, both measured
against a production multi-WAN OPNsense on 2026-08-01, and neither is a Zenarmor
problem — they live entirely in the NetFlow lane and its repairs.

!!! warning "Do not treat `interface` on a NetFlow record as ground truth for WAN volume"

    For per-WAN billing, capacity or failover questions, read
    `opnsense_interfaces_transmitted_bytes_total` /
    `opnsense_interfaces_received_bytes_total` instead. Those come from the kernel's own
    counters and are exact. This lane's value is *what the traffic was* — hosts,
    applications, destinations, ports — not how many bytes crossed a link.

**A NAT'd conversation used to be counted twice on a WAN — fixed in #623.**
`ng_netflow` exports one record where the flow enters (LAN, pre-NAT) and another where it
leaves (WAN, post-NAT). Where both copies resolved to the same WAN, that WAN's bytes
doubled: the reference box's policy-routed WAN read **62.40 GB against 45.05 GB actual,
+38.5%**, while the WAN whose capture hook does not work at all — a PPPoE link, see below
— read +6.2%, ordinary overhead. This is now repaired; see
[NAT-pair de-duplication](#nat-pair-de-duplication) below.

**A policy-routed flow can be labelled with the wrong WAN.** The pre-NAT copy inherits
`OUTPUT_SNMP` from a FIB lookup, so it names the default-route WAN whatever pf did. Repair
4 corrects that from pf's `route-to`, but it resolves each record against a route table
built up to a minute earlier, and short connections are typically resolved before their
state has ever appeared in a snapshot. On the reference box that refuses about 78% of
candidates — and because the pre-NAT copy is the only one that correlates with Zenarmor,
the mislabel lands specifically on **merged** records. Tracked as
[#624](https://github.com/rknightion/opnsense2otel/issues/624).

The two interact, and the direction matters: fixing the second without the first would make
the first worse, by moving more bytes into the doubled bucket.

**How to tell whether your box is affected.** Split the refusal counter by the interface
the bytes are currently attributed to:

```promql
sum by (interface) (rate(opnsense_flow_policy_route_refused_total{reason="no_state"}[5m]))
```

A large `interface="<your default WAN>"` share means candidates are being left on the
default-route WAN — some of which really did leave by another one. Then compare the lane
against the kernel:

```promql
sum by (interface) (increase(opnsense_flow_bytes_total{source="netflow",direction="outbound"}[24h]))
  / on (interface)
sum by (interface) (increase(opnsense_interfaces_transmitted_bytes_total[24h]))
```

A ratio near 1.05 is normal overhead. A ratio well under 1 means the WAN's traffic is
being attributed to a different WAN. A ratio near 1.4 was the NAT double count, and on a
current build means the de-duplication is not firing — check
`opnsense_flow_nat_pair_deduped_total`.

**A PPPoE WAN exports nothing at all**, whatever the GUI says. Selecting a PPPoE interface
for NetFlow capture is silently a no-op upstream: `ng_netflow` attaches to mpd's framing
node rather than the `ng_iface` node, and `ng_pppoe` accepts the hooks without complaint.
The node appears in `ngctl list` and exports zero records. On such a box there is no
post-NAT copy, so #623 cannot bite — and equally, nothing on the WAN side to cross-check
against.

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

### What `source_byte_delta_ratio` actually measures

`opnsense_flow_source_byte_delta_ratio` divides NetFlow bytes by Zenarmor bytes on a
merged record, and 1.0 is documented as agreement. Most of the deviation from 1.0 is
**accounting basis, not a source disagreement**, in two independent ways.

**Wire bytes against payload bytes.** NetFlow always counts wire bytes. Zenarmor's
figure is wire bytes when it has them and payload bytes when it does not, and the
fallback above fires on roughly **half** of all Zenarmor flow records. On that
population the ratio is reporting per-packet header overhead: the gap clusters at 28
bytes, the IPv4 IP+UDP header, and the p90 there alone is 1.96. Those records stay in
the histogram - excluding half the data would be worse - but each one carries
`flow.zen_bytes_are_payload`, so the two bases can be told apart.

**A window partial against a whole connection.** The correlator buckets by flow-end,
so a connection longer than `--flow.correlate.window` emits one record per window
carrying only *that window's* NetFlow bytes, while the single Zenarmor conn document
carries the *whole connection's* counters and merges into one of them. With the
reference box's 1800-second active timeout this is routine, and it reads as ratios
near 0.01 - "the firewall counted 75x fewer bytes than crossed the wire", which is
impossible. Those records are **excluded from the histogram entirely** and counted in
`opnsense_flow_source_byte_delta_excluded_total`; they still ship, with both sides'
volume and a `flow.window_partial` marker. Only the comparison is dropped.

If the underlying question is "is traffic evading inspection", use a **byte-weighted**
comparison - summed NetFlow bytes over summed Zenarmor bytes across merged records -
rather than a percentile of per-flow ratios. Byte-weighted, the reference box reads
1.22-1.36, i.e. no blind spot.

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
