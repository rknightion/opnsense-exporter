# GeoIP enrichment

Purely **local** geolocation and autonomous-system enrichment of flow records **and
of the filterlog/sshd/Suricata log lines** described below, from `.mmdb` databases
on disk. No lookup ever touches the network: a lookup is a radix-tree walk costing
well under a microsecond.

**On by default since v4, and it works out of the box**: the container image bundles
the DB-IP Lite Country and ASN databases, so a stock deployment gets countries and
autonomous systems with no database to source and no account to create. MaxMind is
still fully supported and still more accurate - see
[Bundled databases](#bundled-databases-db-ip-lite) and
[Switching to MaxMind](#switching-to-maxmind).

!!! info "Attribution"

    IP geolocation data by [DB-IP](https://db-ip.com), licensed under
    [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). The same credit ships
    in the image at `/licenses/GEOIP-DB-IP-ATTRIBUTION.txt` and in the operator
    console footer.

!!! warning "Behaviour change on upgrade"

    **`--geoip.enabled` now defaults to `true`.** With databases in the image there
    is nothing left to source first, so geo is on unless you turn it off. Combined
    with the change below, an upgraded container deployment that had never
    configured GeoIP at all now emits geo attributes on flow records **and on
    filterlog lines**, which costs real per-line bytes on the highest-volume log
    stream on the box - see [the measured cost](#measured-per-line-cost). Set
    `--geoip.enabled=false` to opt out entirely, or `--logs.syslog.geoip=false` to
    keep geo on flow records only.

    `--geoip.enabled` also covers **both** flow records and the filterlog/sshd/auth/
    Suricata log lines (see [Logs](#logs-filterlog-sshdauth-suricata) below) - one
    switch means geo, everywhere it can reach.

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

## Bundled databases (DB-IP Lite)

The container image ships two databases, fetched unmodified from DB-IP when the
image is built and installed read-only:

| path | contents | size |
| --- | --- | --- |
| `/usr/share/opnsense2otel/geoip/dbip-country-lite.mmdb` | country + continent | ~8.2 MB |
| `/usr/share/opnsense2otel/geoip/dbip-asn-lite.mmdb` | ASN + organization | ~9.6 MB |

Those two paths are the **default values** of `--geoip.country-database` and
`--geoip.asn-database`, so nothing needs configuring to use them.

**Why DB-IP and not GeoLite2.** GeoLite2 cannot legally be bundled: redistributing
it inside a product needs MaxMind's paid, signed Commercial Redistribution License
*and* obliges the redistributor to bind every downstream user to a restrictive
EULA, which is impossible for an Apache-2.0 public image. DB-IP Lite is plain
CC BY 4.0 - redistributable as long as DB-IP is credited.

**They are not in the git repository.** They are ~17.8 MB of binary republished
monthly; committing them would grow this repository's history by that much every
month, permanently. So they are fetched at **image build time**, which has one
consequence worth stating plainly:

!!! warning "A non-container build has no bundled database"

    `make`, `go build`, `go run .` and the release **binary archives** never run the
    image build, so nothing exists at those paths. With `--geoip.enabled` on by
    default, that is the default configuration of every such build - and it is
    **fail-open**: the exporter starts normally, every geo attribute is simply
    absent, and no error is raised. Point `--geoip.country-database` /
    `--geoip.asn-database` at your own files, or use the container image.

**Refresh.** DB-IP republishes on the 1st of each month. A scheduled workflow
rebuilds and republishes the `:main` image on the 3rd once the new files are
published, and every tagged release build fetches current data as a matter of
course. The database's own build date is exported as
`opnsense_flow_geoip_database_build_timestamp_seconds{database}`, so freshness is a
query rather than a claim - and `OPNsenseFlowGeoIPDatabaseStale` fires on it.

### Accuracy: read this before trusting a city

DB-IP publishes Lite as an explicitly **reduced-coverage, reduced-accuracy subset**
of their commercial data, and the accuracy is not uniform across fields:

| field | free-tier accuracy, broadly |
| --- | --- |
| country | **>95%** everywhere, across every free provider tested independently |
| city | **~70-78%** in North America and Western Europe, and worse elsewhere |

Country is the only field that may ever become a **metric label**, and it is the
field that holds up. City and region are log attributes only. Treat a city as a
hint worth having, not as a fact worth alerting on, and use MaxMind's commercial
tiers if you need better.

### City is supported, but is not bundled

DB-IP City Lite is **125 MB** uncompressed against Country Lite's 8.2 MB, and it
would *replace* the country database rather than add to it (a City database is a
strict superset, and one flag accepts either). That is roughly +117 MB on every
image pull, forever, for data that reaches no metric - so it is not bundled.

To use it, download it yourself and point the same flag at it:

```bash
curl -fSL -o /var/lib/geoip/dbip-city-lite.mmdb.gz \
  https://download.db-ip.com/free/dbip-city-lite-$(date -u +%Y-%m).mmdb.gz
gunzip /var/lib/geoip/dbip-city-lite.mmdb.gz
```

```bash
--geoip.country-database=/var/lib/geoip/dbip-city-lite.mmdb
```

!!! warning "`region` is always empty with DB-IP City data"

    DB-IP City Lite's `subdivisions[]` entries carry only `names` - there is **no**
    `iso_code` key in the object at all. The exporter's `<src|dst>.geo.region`
    attribute is an ISO 3166-2 code, so it decodes **empty on every record** against
    a DB-IP City database even where the city name resolved fine. This is a property
    of DB-IP's Lite tier, verified against the real file, not a bug.

    Reading the subdivision *name* into that field instead is deliberately not done:
    it would silently change `region` from a code to free text and break every
    MaxMind consumer of it. A MaxMind City database populates it correctly.

## Switching to MaxMind

MaxMind is more accurate, fully supported, and **wins outright** over the bundled
copies. Two supply paths:

* **Operator-managed files**: point the flags at your own files. A `geoipupdate`
  cron, a sidecar, or a mounted volume writes them, and `--geoip.reload-interval`
  (15m) notices when one changes and hot-swaps it under the running exporter.

  ```bash
  --geoip.country-database=/var/lib/geoip/GeoLite2-Country.mmdb \
  --geoip.asn-database=/var/lib/geoip/GeoLite2-ASN.mmdb
  ```

* **The built-in downloader** (`--geoip.download.enabled`): the exporter fetches
  from MaxMind directly, so no sidecar is needed. Requires
  `--geoip.download.account-id` and a license key. Conditional requests mean an
  unchanged database costs a 304 and no download quota. Leave
  `--geoip.country-database` / `--geoip.asn-database` at their defaults and they
  switch to what the downloader installs - the bundled paths are treated as
  unclaimed precisely so this works without extra flags.

### Precedence

Resolved in this order, first match wins:

1. **MaxMind via `--geoip.download.enabled`** - configuring the downloader
   repoints both database paths at what it installs, overriding the bundled copies.
2. **An explicit `--geoip.country-database` / `--geoip.asn-database`** - your path
   is never overridden by anything.
3. **The bundled DB-IP Lite copies** - the flag defaults, used when you set neither
   of the above.

### Turning it off

```bash
--geoip.enabled=false
```

Every geo attribute disappears from flow records and log lines, and the `country`
metric label resolves to off with it (see `--flow.geoip.metric-dims` below). The
~18 MB of databases are simply never read.

The two schedules are independent because they answer different questions.
`--geoip.download.interval` is "has MaxMind published a newer build?"; a network
question, worth asking daily since GeoLite2 rebuilds twice a week.
`--geoip.reload-interval` is "has the file on disk changed?"; a local `stat`, and
the only thing that makes the operator-managed path work at all.

### What happens at startup

A start does **not** always fetch. For each configured edition, the exporter asks
MaxMind only when there is no installed database, or when the last check MaxMind
actually answered is older than `--geoip.download.interval`. A skip is logged with
the edition, when it was last checked, that check's result, and how long until the
next one:

```
geoip database download skipped; MaxMind was already asked inside the download
interval and the database is installed  edition=GeoLite2-City
last_checked=... last_result=unmodified next_check_in=22h14m0s
```

That deferral is not a permanent skip: the first scheduled check is due at
`last_checked + --geoip.download.interval`, not a whole interval after the process
started, so a container that restarts more often than the interval still updates.

The "last checked" time is kept in `download-state.json` inside
`--geoip.download.dir`, beside the databases. It cannot be the database file's
mtime, which the downloader deliberately stamps with MaxMind's `Last-Modified` so
its conditional requests are exact - that mtime is the **build** time, and a
current database checked five minutes ago routinely carries one several days old.
Delete the file and the next start simply re-checks; a hand-replaced database is
unaffected, because the record only ever defers a network check and never a load.

**Persist `--geoip.download.dir`.** Without a volume, every start has no database
and no record, so every start downloads - which on a deployment that redeploys
often is the fastest way to exhaust the account's daily limit.

**An HTTP 429 on start means the quota is spent, not that the key is broken.**
GeoLite2 download limits are per account per day, so a license key shared between
deployments exhausts sooner than any one of them expects. The exporter counts it as
`opnsense_flow_geoip_downloads_total{result="rate_limited"}` rather than `failure`,
keeps the installed database serving, and does not ask again before the next
interval - retrying is what exhausted the quota in the first place. Nothing is
broken and there is nothing to fix: enrichment carries on with the database already
installed.

## Which MaxMind editions to download

Applies to `--geoip.download.enabled` only; the bundled DB-IP copies are covered
above. Default is **Country + ASN**. The resident cost is real and is the reason
City is not default:

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
**On by default since #537**, with `--flow.top-n` and `--flow.max-keys` raised 10x
in the same change to hold it: in practice a box talks to a few dozen countries,
not the ~250 the dimension can hold, but at the old bounds even that would have
folded real series into `__other__`. Set it to `false` to drop the label; the flow
families then carry the dimensions they did before the label existed.

With `--geoip.enabled=false` the label resolves to off rather than refusing to
start, so turning geo off never costs you a startup.

**ASN and city never become labels at any setting.** With the label off, every
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
| `opnsense_flow_geoip_downloads_total{result}` | `unmodified` is the healthy steady state; `rate_limited` is an exhausted daily quota, `failure` is everything else |
| `opnsense_flow_geoip_country_comparisons_total{result}` | what is ours-wins costing? |

The build timestamp is the database's own **build** date, read from its metadata,
not the download or image-build time - so it is the right staleness signal for a
bundled copy as much as a downloaded one, and it is how you tell what data an image
actually carries. `OPNsenseFlowGeoIPDatabaseStale` fires on it at **45 days**, a
threshold chosen to cover every database the exporter can load: DB-IP Lite
republishes monthly, so anything tighter would fire on a perfectly healthy stock
deployment. It does mean a broken MaxMind updater takes 45 days to page rather than
14 - watch `opnsense_flow_geoip_downloads_total` and
`opnsense_flow_geoip_reloads_total` if you want that sooner, since a failing fetch
shows up there immediately.

On a stock deployment there is no updater to fix when this fires: the bundled copy
is exactly as old as the image, so the answer is to pull a current one.

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
republished monthly (DB-IP) or twice a week (MaxMind), and GeoLite2 is covered by
the GeoLite End User License Agreement besides. The bundled DB-IP files are fetched
by the **Dockerfile at image build time**; the only `.mmdb` files in the tree are
MaxMind's own synthetic test fixtures, used by the unit tests.

**The three-way country fallback is inert against DB-IP.** The exporter prefers
`country.iso_code`, falling back to `registered_country` then `represented_country`
- MaxMind omits `country` entirely for a large slice of the internet (1.1.1.1 is
the canonical example) and without the fallback every Cloudflare-fronted address
would read as unknown. DB-IP models neither fallback key at all and fills
`country.iso_code` on every record it has, including 1.1.1.1. So with the bundled
databases the fallback never fires; it stays because it is load-bearing the moment
an operator supplies MaxMind.
