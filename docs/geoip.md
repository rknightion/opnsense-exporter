# GeoIP enrichment

Optional, purely **local** geolocation and autonomous-system enrichment of flow
records **and of the filterlog/sshd/Suricata log lines** described below, from
MaxMind `.mmdb` files on disk. No lookup ever touches the network: a lookup is a
radix-tree walk costing well under a microsecond.

!!! warning "Behaviour change on upgrade"

    `--geoip.enabled` now covers **both** flow records and the filterlog/sshd/auth/
    Suricata log lines (see [Logs](#logs-filterlog-sshdauth-suricata) below) - one
    switch means geo, everywhere it can reach. An existing deployment that already
    runs `--geoip.enabled` for flow records gains real per-line byte cost on
    filterlog, the highest-volume log stream on the box, **with no config change**.
    Set `--logs.syslog.geoip=false` to keep GeoIP on flow records only.

It exists to close an asymmetry. Zenarmor's `conn` documents carry geo from
Zenarmor's own database; NetFlow-derived flows carry bare addresses and no geo at
all. Because the correlator merges the two into one flow log, **whether a given
connection got a country depended on whether Zenarmor happened to see it** - an
interface Zenarmor is not inspecting, or any traffic on a box without the plugin,
produced flow logs that were structurally identical except that the geo fields were
silently absent. On the dashboard that looks like less traffic, not like missing
data.

With this on, every external address gets a country, continent and ASN from the
exporter's own database, whether or not Zenarmor exists.

!!! note "This is not the `opnsense_firewall_geoip_*` metrics"

    Those four metrics report the *status* of OPNsense's own GeoIP **alias** feature
    - how many addresses its database loaded, when the firewall last downloaded it.
    They are unrelated to this page, and the MaxMind license key in their
    descriptions is one configured on the firewall, not here.

## Enabling it

Off by default, because it needs a database the exporter does not ship.

```bash
--geoip.enabled \
--geoip.country-database=/var/lib/geoip/GeoLite2-Country.mmdb \
--geoip.asn-database=/var/lib/geoip/GeoLite2-ASN.mmdb
```

Two supply paths, and both are supported:

* **Operator-managed files** (the default): a `geoipupdate` cron, a sidecar, or a
  mounted volume writes the files, and `--geoip.reload-interval` (15m) notices when
  one changes and hot-swaps it under the running exporter.
* **The built-in downloader** (`--geoip.download.enabled`): the exporter fetches
  from MaxMind directly, so no sidecar is needed. Requires
  `--geoip.download.account-id` and a license key. Conditional requests mean an
  unchanged database costs a 304 and no download quota. Leave
  `--geoip.country-database` / `--geoip.asn-database` unset and they default to
  what the downloader installs.

The two schedules are independent because they answer different questions.
`--geoip.download.interval` is "has MaxMind published a newer build?"; a network
question, worth asking daily since GeoLite2 rebuilds twice a week.
`--geoip.reload-interval` is "has the file on disk changed?"; a local `stat`, and
the only thing that makes the operator-managed path work at all.

## Which editions to ship

Default is **Country + ASN**. The resident cost is real and is the reason City is
not default:

| edition | resident | what it adds |
| --- | --- | --- |
| `GeoLite2-Country` | ~9 MB | country, continent |
| `GeoLite2-ASN` | ~12 MB | ASN and organization |
| `GeoLite2-City` | ~60 MB | city and region, **plus everything Country gives** |

`GeoLite2-ASN` is included by default because it is the one thing Zenarmor cannot
supply on **any** box: Zenarmor ships no ASN database at all, and its `asn` field is
the string `"0"` on every record - which is its empty value, not AS0.

**City is supported and is the right choice if you want locality without
Zenarmor**, which is most deployments. A City database is a strict superset of a
Country one, so the same `--geoip.country-database` path accepts either:

```bash
--geoip.download.editions=GeoLite2-City,GeoLite2-ASN
```

City and region reach **log records only**, never a metric label, at any setting.

## Precedence: ours vs Zenarmor's

Zenarmor is an optional enhancement, never a dependency. A record must never be
missing geo because a plugin is absent - that is the whole asymmetry this feature
closes. But where Zenarmor *is* installed, two databases answer, and the better
source differs per field:

| field | source | why |
| --- | --- | --- |
| country / continent | **ours wins**, Zenarmor's kept alongside | the dashboards read this one, so its meaning must not vary by which receiver saw the flow |
| city / region | **Zenarmor when present, ours as fallback** | theirs is a commercial GeoIP2-City build; ours is the only source on the vast majority of boxes, which have no Zenarmor |
| ASN | **ours only** | Zenarmor ships no ASN database on any box |

Ours-wins on country is not free. Read off a live firewall, Zenarmor's file
reports `database_type: GeoIP2-City` at 126 MB, against a stock free
`GeoLite2-City`'s 63 MB - a commercial or custom build, under a GeoLite2 filename.
So on a connection Zenarmor *did* see, overwriting its answer with a free GeoLite2
lookup can genuinely replace a better attribution with a worse one. That is a
deliberate trade of accuracy for consistency, and it is measured rather than
assumed:

* Zenarmor's value is **retained, never discarded**. Where it disagrees with ours
  it rides on the log record as `<src|dst>.geo.zen_country`.
* `opnsense_flow_geoip_country_comparisons_total{result="agree"|"disagree"}` counts
  every endpoint where both answered, so the cost has a rate and a denominator.

### Provenance is mandatory

Because city's source legitimately varies by deployment, **every enriched endpoint
carries an attribute naming which database answered**: `<src|dst>.geo.country_source`
and `<src|dst>.geo.city_source`, each `maxmind` or `zenarmor`. A field that quietly
means two different things depending on plugin state is exactly the class of defect
worth spending an attribute to prevent.

It matters most for region, where the two sources disagree on *format* as well as
value: MaxMind returns the ISO 3166-2 code (`ENG`), Zenarmor returns a name
(`England`). Neither is normalised into the other - inventing that mapping would be
fabricating data. Zenarmor's `city_name` is also not reliably a city: a live record
for a Grafana endpoint carried `dst_geoip_city_name: "England"`, which is a
subdivision. The provenance attribute is how you tell.

## What lands where

**Flow log records** carry geo unconditionally whenever `--geoip.enabled` is set:

| attribute | notes |
| --- | --- |
| `<src\|dst>.geo.country` | ISO 3166-1 alpha-2 |
| `<src\|dst>.geo.continent` | two-letter code |
| `<src\|dst>.geo.city` | City database, or Zenarmor |
| `<src\|dst>.geo.region` | ISO 3166-2 code (ours) or a name (Zenarmor) - see provenance above |
| `<src\|dst>.geo.asn` | e.g. `AS13335` |
| `<src\|dst>.geo.as_org` | e.g. `Cloudflare` |
| `<src\|dst>.geo.country_source` | `maxmind` or `zenarmor` |
| `<src\|dst>.geo.city_source` | `maxmind` or `zenarmor` |
| `<src\|dst>.geo.zen_country` | only when Zenarmor's answer differs from the exported one |

All of these are Loki **structured metadata**, never index labels - the same rule
every other high-cardinality flow attribute follows. A key is omitted entirely when
it carries nothing.

**Flow metrics** carry geo only behind an explicit opt-in:

```bash
--flow.geoip.metric-dims
```

which adds a single `country` label to `opnsense_flow_bytes_total`,
`_packets_total` and `_records_total`, naming the **remote** end of the flow.
Off by default and it should usually stay off: country is a ~250-value dimension
multiplied against every existing flow label, so this can multiply the family's
cardinality roughly 250-fold. `--flow.top-n` and `--flow.max-keys` still bound the
result, which means the practical effect on a busy box is that real series start
folding into `__other__` rather than that the family grows without limit.

**ASN and city never become labels at any setting.** With the opt-in off, every
series carries `country=""`, which Prometheus treats as an absent label - so the
family reads exactly as it did before this feature existed.

## Logs (filterlog, sshd/auth, Suricata)

`--geoip.enabled` also adds geo to three log lanes, and only these three: the ones
where a remote peer is the **subject** of the line, not an incidental mention.

* **filterlog** - every blocked/passed packet, both `src.ip` and `dst.ip`. This is
  what answers "which countries are hitting my WAN and getting dropped", and it
  works identically with or without Zenarmor, because filterlog never had any geo
  source at all.
* **sshd / auth** - a brute-force or login attempt's source address.
* **Suricata** (the EVE-over-syslog alert path) - an alert's source and
  destination.

**Deliberately excluded:** unbound, DHCP, and every other lane where an address
appears incidentally. Geo is not queried there, and it would be paid for on every
line for no operational benefit.

Attributes are a **subset** of the flow lane's, with the **same keys** so one Loki
query covers both streams:

| attribute | notes |
| --- | --- |
| `<src\|dst>.geo.country` | ISO 3166-1 alpha-2 |
| `<src\|dst>.geo.country_source` | always `maxmind` - these lanes have no second source to disagree with |
| `<src\|dst>.geo.continent` | two-letter code |
| `<src\|dst>.geo.asn` | e.g. `AS13335` |
| `<src\|dst>.geo.as_org` | e.g. `Cloudflare` |

**No `city`, no `region`.** They stay a flow/Zenarmor-only field: filterlog's
volume makes them a worse trade here than they already were on flow (see the
per-line cost below), and nothing on this path needs them.

Non-global addresses (loopback, RFC 1918, link-local, CGNAT) are skipped through
the same `geoip.Enrichable` check flow enrichment uses - never a second classifier,
never a lookup that could only ever miss.

**Logs-only.** Country does **not** become a `log_events` metric dimension, on any
setting, and there is no flag for it: filterlog's block-line volume is far higher
than flow volume, so the cardinality multiplication that justifies
`--flow.geoip.metric-dims` being opt-in on flow is a strictly worse trade on logs.

### The per-lane opt-out

```bash
--logs.syslog.geoip=false
```

On by default whenever `--geoip.enabled` is set - that default is the behaviour
change flagged at the top of this page. Set it to `false` to keep GeoIP on flow
records while opting these three log lanes back out. It needs no database of its
own: it only gates whether the log lanes consult the same `*geoip.DB`
`--geoip.enabled` already opened, so flipping it costs nothing beyond the toggle.

### Measured per-line cost

Measured against the repository's own filterlog test captures plus a representative
sample of real-world autonomous-system organization names (ISPs and cloud/hosting
providers commonly seen in inbound block traffic - MaxMind's tiny test fixtures do
not have enough variety to size this on their own):

| | one endpoint | both endpoints (worst case: transit traffic between two public addresses) |
| --- | --- | --- |
| average | ~116 B | ~232 B |
| worst case (longest observed `as_org`) | ~140 B | ~280 B |

(`TestGeoByteCost`, `internal/logship/syslog/geo_bytecost_test.go` - key+value byte
length summed over the attributes one `geoAttrs` call adds, against a representative
sample of real-world autonomous-system organization names rather than MaxMind's tiny
test fixtures, which do not carry enough org-name variety to size this on their own.)

`as_org` is the largest single field - about **28% of one endpoint's average added
bytes, up to 40% in the worst observed case** - but does not dominate the total:
`country`/`country_source`/`continent`/`asn` together are fixed-size overhead of
about 57 B regardless of which autonomous system answers. It is shipped per the
frozen scope decision (#528) because an ASN number with no organization name needs
an external lookup to be readable. Compare against #475, which removed Zenarmor's
latitude/longitude at 145-149 B/line for a similar reason - that number lands close
to this feature's worst case by coincidence, not because the two are the same shape
of cost.

Most filterlog lines add **zero** bytes: an internal-to-internal line, or a line
whose only public-looking address is a miss in the loaded database, gets no `.geo.`
attribute at all (fail-open). The figures above are the cost on a line that
actually resolves.

## Fail-open, always

A missing, unreadable or stale database means the geo attributes are simply absent.
It is never a startup failure and never blocks a lookup. A file that fails to parse
on reload leaves the **previously loaded** database serving: a bad update costs
freshness, never availability.

That is also the trap. A database that failed to load looks exactly like a quiet
network - every attribute absent, every counter at zero, nothing failing - which is
why these exist:

| metric | answers |
| --- | --- |
| `opnsense_flow_geoip_lookups_total{database,result}` | is either database answering? `database="skipped"` is addresses that are not globally routable, not a failure |
| `opnsense_flow_geoip_enriched_records_total` | is this feature doing anything at all? |
| `opnsense_flow_geoip_database_build_timestamp_seconds{database}` | how old is the data? Absent, never zero, when a database is not loaded |
| `opnsense_flow_geoip_reloads_total{database,result}` | did a hot-swap happen, or fail? |
| `opnsense_flow_geoip_downloads_total{result}` | `unmodified` is the healthy steady state |
| `opnsense_flow_geoip_country_comparisons_total{result}` | what is ours-wins costing? |

The build timestamp is MaxMind's **build** date, not the download time, so it is the
right staleness signal - and `OPNsenseFlowGeoIPDatabaseStale` fires on it at 14
days, which is four missed GeoLite2 builds.

## Notes

**Databases are read into the heap, not memory-mapped.** `mmap` is faster to load
and cheaper in RSS, and it is also a way to crash the process: anything that
truncates the file while a lookup is walking the mapping - a plain
`curl -o db.mmdb`, an editor, an `rsync` without `--inplace` - faults every
in-flight read with `SIGBUS` and takes the exporter down. The resident costs in the
table above are the price of that safety.

**There is no result cache**, deliberately. A lookup is a tree walk that allocates
nothing; an LRU in front would add locking, memory and a TTL surface for no gain.

**Non-global addresses are never geolocated.** Loopback, RFC 1918, link-local,
multicast and carrier-grade NAT (100.64.0.0/10) are skipped before any database is
consulted, and counted under `database="skipped"`. CGNAT is skipped because MaxMind
publishes no records for it, so a lookup could only ever miss - note that the
exporter's WAN-detection heuristic deliberately treats CGNAT the *other* way, since
it is what many ISPs hand a WAN.

**The firewall's own databases are deliberately not used.** A box running Zenarmor
or CrowdSec already has `.mmdb` files under `/usr/local/zenarmor/db/GeoIP` and
`/var/db/crowdsec/data`. The exporter talks to the firewall over the REST API and
normally runs on a different host entirely, so those paths do not exist where this
code runs. It ships its own database or it has none.

**No database is committed to this repository.** They are tens of megabytes each,
rebuilt twice a week, and covered by the GeoLite End User License Agreement. The
only `.mmdb` files in the tree are MaxMind's own synthetic test fixtures, used by
the unit tests.
