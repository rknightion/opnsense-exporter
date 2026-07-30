// Package geoip provides optional, purely LOCAL geolocation and autonomous-system
// enrichment of external IP addresses, backed by MaxMind DB (.mmdb) files on disk.
//
// The hot path never touches the network. A lookup is a radix-tree walk costing well
// under a microsecond; decoding into the fixed structs below allocates nothing. That
// is why this package has NO result cache — an LRU in front would add locking, memory
// and a whole TTL surface for no gain. Do not add one.
//
// # Databases are read into memory, NOT memory-mapped
//
// maxminddb.Open mmaps the file, which is faster to load and cheaper in RSS (the
// pages are evictable page cache). It is also a way to crash the process: if anything
// TRUNCATES the file while a lookup is walking the mapping — a plain
// `curl -o db.mmdb`, an editor, an rsync without --inplace — every in-flight read
// faults with SIGBUS and takes the whole exporter down. That is not hypothetical; it
// is what the first version of the tailscale2otel package this is ported from did,
// and its reload test reproduced it immediately. TestReloadUnderConcurrentLookups-
// DoesNotFault is that test.
//
// So Open reads each file fully into the heap and uses maxminddb.OpenBytes. The cost
// is real and worth stating: roughly 9 MB resident for GeoLite2-Country, 12 MB for
// GeoLite2-ASN and about 60 MB for GeoLite2-City, held for the process lifetime. That
// is the price of a feature that is off by default and must never be able to kill a
// running exporter. Do not "optimize" this back to mmap.
//
// Databases are swapped atomically by Reload (see updater.go for the schedule), so an
// operator's geoipupdate cron — or this package's own MaxMind downloader
// (maxmind.go) — can rewrite the files under a running process.
//
// Everything here is fail-open. A missing, unreadable or stale database means the geo
// attributes are simply absent from the emitted telemetry; it is never a startup
// failure and never blocks a lookup.
//
// # Why not the firewall's own databases
//
// An OPNsense box running Zenarmor or CrowdSec already has .mmdb files on disk
// (/usr/local/zenarmor/db/GeoIP, /var/db/crowdsec/data). They are deliberately NOT
// used: the exporter talks to the firewall over the REST API and normally runs on a
// different host entirely, so those paths do not exist where this code runs. The
// exporter ships its own database or it has none.
package geoip

import (
	"errors"
	"fmt"
	"math"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// Lookup is the narrow, fakeable interface consumers depend on. A nil *DB satisfies
// it and reports a miss for every address, which is the value the exporter hands out
// when --geoip.enabled is off.
type Lookup interface {
	Lookup(addr netip.Addr) (Result, bool)
}

// Result is everything this package reports about an address.
//
// The fields split into two very different cardinality classes, and callers must
// respect the split:
//
//   - CountryISO and ContinentCode are BOUNDED (~250 and 7 values). They are the only
//     fields that may reach a metric label, and only when the operator opts in via
//     --flow.geoip.metric-dims.
//   - City, RegionISO, ASN and ASOrg are NOT usefully bounded. They are confined to
//     LOG records, which are not series and carry the full-fidelity view by design.
//
// The city fields require a City database (GeoLite2-City / GeoIP2-City). A Country
// database is a strict subset and simply leaves them empty, so the same configured
// path accepts either edition.
type Result struct {
	// CountryISO is the ISO 3166-1 alpha-2 code, e.g. "US". Empty when unknown.
	CountryISO string
	// ContinentCode is the two-letter continent code, e.g. "NA". Empty when unknown.
	ContinentCode string
	// City is the English city name, e.g. "London". City database only.
	City string
	// RegionISO is the ISO 3166-2 subdivision code of the most specific subdivision,
	// e.g. "ENG" for England. City database only. MaxMind orders subdivisions least-
	// to most-specific, so this is the LAST entry, not the first.
	RegionISO string
	// ASN is the autonomous-system number, e.g. 15169. Zero when unknown.
	ASN uint
	// ASOrg is the autonomous-system organization, e.g. "Google LLC". Empty when
	// unknown — the ASN database genuinely carries records with a number and no
	// organization name.
	ASOrg string
}

// Empty reports whether the result carries no usable fact at all.
func (r Result) Empty() bool { return r == Result{} }

// countryRecord is the subset of a GeoLite2/GeoIP2 Country (or City) record this
// package reads.
//
// The three country objects are not redundant. `country` is where the address is
// physically located and is the field to prefer — but MaxMind genuinely omits it for
// a large slice of the internet, carrying only `registered_country` (the country of
// the registering ISP). 1.1.1.1 is the canonical example: no `country` object at all.
// Without the fallback in countryFrom, every Cloudflare-fronted address reads as
// unknown.
//
// That is a statement about MAXMIND data specifically, and it is NOT true of the
// bundled DB-IP Lite databases (#549). DB-IP's schema does not model
// registered/represented country at all — neither key appears anywhere in the file
// — and it populates `country.iso_code` directly on every record it has, including
// 1.1.1.1 (`AU`, decoded from the real 2026-07 file). Both fields therefore always
// decode empty against DB-IP. Inert, not broken: the primary path is populated, and
// the fallback still earns its place for MaxMind. Verified field-by-field on #549.
type countryRecord struct {
	Continent struct {
		Code string `maxminddb:"code"`
	} `maxminddb:"continent"`
	Country struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"registered_country"`
	RepresentedCountry struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"represented_country"`

	// City-database-only fields. A Country database omits them entirely and they
	// decode to their zero values, which is exactly the intended behaviour: the same
	// configured path accepts either edition.
	City struct {
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"city"`
	Subdivisions []struct {
		ISOCode string `maxminddb:"iso_code"`
	} `maxminddb:"subdivisions"`
}

// asnRecord is the whole of a GeoLite2-ASN record.
type asnRecord struct {
	Number uint   `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

// countryFrom picks the best country code available in a record, preferring the
// physical location over the registering ISP's country over the represented country
// (embassies, military bases). See the countryRecord doc for why the fallback chain
// is load-bearing rather than defensive.
//
// DO NOT "simplify" the chain away after reading a DB-IP file. Against the bundled
// DB-IP Lite databases it is INERT — DB-IP always fills country.iso_code and models
// neither of the other two — so every branch below the first looks dead. It is not:
// it is the only thing that gives a country to Cloudflare-fronted addresses when an
// operator supplies a MaxMind database, which is a fully supported and better-
// accuracy configuration. Removing it would break MaxMind users silently, and the
// tests that cover it use MaxMind's fixtures precisely because DB-IP cannot express
// the case.
func countryFrom(rec countryRecord) (iso, continent string) {
	iso = rec.Country.ISOCode
	if iso == "" {
		iso = rec.RegisteredCountry.ISOCode
	}
	if iso == "" {
		iso = rec.RepresentedCountry.ISOCode
	}
	return iso, rec.Continent.Code
}

// cityFrom extracts the City-database-only fields, both of which are empty when a
// Country database is loaded instead.
//
// Only the English name is read. MaxMind ships eight localisations of every place
// name, and mixing them would split what should be one value ("London" vs "Londres")
// across a log corpus for no benefit.
//
// Coordinates are deliberately NOT extracted. #475 already removed Zenarmor's
// latitude/longitude from the shipped attributes for exactly this reason: MaxMind
// returns ~17 significant figures, the four keys measured 145-149 B/line on the flow
// family, and no consumer ranks by anything but country or city. Re-add them only for
// a map panel that plots them.
// RegionISO is empty against DB-IP City data, always (#549). DB-IP City Lite's
// subdivisions[] entries carry only `names` — there is no `iso_code` key in the
// object at all — while the city name itself decodes fine. That is a property of
// DB-IP's Lite tier, not a bug here, and it is documented in docs/geoip.md so a
// blank region is met by an answer rather than an issue. Reading names.en instead
// would change RegionISO from an ISO 3166-2 code to free text and break every
// MaxMind consumer of the field, so it is deliberately not done.
func cityFrom(rec countryRecord) (city, regionISO string) {
	city = rec.City.Names["en"]
	// Subdivisions run least- to most-specific ("England" then a county), so the LAST
	// entry is the one worth carrying. Taking the first would report the coarsest
	// division under a name that says region.
	if n := len(rec.Subdivisions); n > 0 {
		regionISO = rec.Subdivisions[n-1].ISOCode
	}
	return city, regionISO
}

// Options configures a DB. Both paths are optional and independent: an operator may
// ship only a Country database, only an ASN database, or neither (the exporter builds
// the DB before the first scheduled download has necessarily landed).
type Options struct {
	// CountryPath accepts EITHER a Country or a City database. A City database is a
	// strict superset, so one path serves both editions and the city fields are
	// simply empty when a Country database is installed.
	CountryPath string
	ASNPath     string
}

// reader pairs an open maxminddb reader with the (mtime, size) it was opened at, so
// Reload can skip an untouched file without re-reading it.
type reader struct {
	db    *maxminddb.Reader
	mtime time.Time
	size  int64
}

// maxDatabaseBytes caps how large a file this package will load. It is not a security
// boundary — the operator names the path — but it turns "pointed at the wrong file"
// and "the download wrote a 40 GB sparse file" into a clear error instead of an OOM
// kill. 512 MiB is far above any real MaxMind database (GeoIP2-City, the largest
// MaxMind publishes, is well under 200 MB).
const maxDatabaseBytes = 512 << 20

// stats holds the cumulative counters surfaced by Stats. Guarded by DB.mu.
type stats struct {
	countryHits, countryMisses int64
	asnHits, asnMisses         int64
	skipped                    int64
	countryReloads, asnReloads int64
	reloadFailures             int64
	downloadsUpdated           int64
	downloadsUnmodified        int64
	downloadsFailed            int64
}

// Stats is an absolute snapshot of the counters and the loaded databases' identity.
// The flow collector publishes it as opnsense_flow_geoip_* on each scrape.
type Stats struct {
	CountryHits, CountryMisses int64
	ASNHits, ASNMisses         int64
	Skipped                    int64
	CountryReloads, ASNReloads int64
	ReloadFailures             int64

	DownloadsUpdated    int64
	DownloadsUnmodified int64
	DownloadsFailed     int64

	// Loaded database identity. A zero build time means the database is not loaded,
	// and the collector omits the gauge entirely rather than publishing a zero — a
	// zero reads as "built in 1970" and fires every staleness alert ever written
	// against it.
	CountryPath, ASNPath           string
	CountryType, ASNType           string
	CountryBuildTime, ASNBuildTime time.Time
}

// DB holds the loaded databases and swaps them atomically on Reload.
//
// The lock is a plain RWMutex rather than an atomic pointer pair. A lookup consults
// both databases and must see a consistent pair; the counters need guarding anyway;
// and an uncontended RLock is a couple of atomics, negligible beside the tree walk it
// guards. Correctness beats the nanosecond.
type DB struct {
	countryPath string
	asnPath     string

	mu      sync.RWMutex
	country *reader
	asn     *reader
	stats   stats
}

// Open builds a DB from the configured paths. A path that does not exist yet is
// remembered and left unloaded — a cold start whose scheduled download has not landed
// must not fail. A path that exists but is not a usable MaxMind database IS reported
// as an error: the operator pointed at something real and wrong, and treating that as
// "not downloaded yet" would hide the mistake forever.
//
// The returned *DB is ALWAYS usable, even alongside a non-nil error. Whatever loaded
// is serving, whatever did not is simply absent, and the configured paths are
// retained either way so a later Reload can pick up a corrected file. main
// deliberately logs the error rather than failing startup: degraded enrichment must
// not become a failed exporter.
func Open(opts Options) (*DB, error) {
	db := &DB{countryPath: opts.CountryPath, asnPath: opts.ASNPath}
	var errs []error
	var err error
	if db.country, err = openIfPresent(opts.CountryPath); err != nil {
		errs = append(errs, err)
	}
	if db.asn, err = openIfPresent(opts.ASNPath); err != nil {
		errs = append(errs, err)
	}
	return db, errors.Join(errs...)
}

// openIfPresent loads path, returning (nil, nil) when path is empty or absent.
func openIfPresent(path string) (*reader, error) {
	if path == "" {
		return nil, nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("stat geoip database %s: %w", path, err)
	}
	return openAt(path, fi)
}

// openAt loads the database at path, whose already-taken stat result is fi (the
// callers all need it anyway, for the change check). See the package doc for why this
// reads the whole file rather than mapping it.
func openAt(path string, fi os.FileInfo) (*reader, error) {
	if fi.Size() > maxDatabaseBytes {
		return nil, fmt.Errorf("geoip database %s is %d bytes, above the %d-byte limit",
			path, fi.Size(), int64(maxDatabaseBytes))
	}
	b, err := os.ReadFile(path) //nolint:gosec // the operator names this path
	if err != nil {
		return nil, fmt.Errorf("read geoip database %s: %w", path, err)
	}
	r, err := maxminddb.OpenBytes(b)
	if err != nil {
		return nil, fmt.Errorf("open geoip database %s: %w", path, err)
	}
	return &reader{db: r, mtime: fi.ModTime(), size: fi.Size()}, nil
}

// Empty reports whether no database at all is loaded, so callers can skip work (and
// main can log a startup notice) without probing with a lookup.
func (d *DB) Empty() bool {
	if d == nil {
		return true
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.country == nil && d.asn == nil
}

// Lookup returns what the loaded databases know about addr. The boolean reports
// whether any record was found — distinct from a found record whose fields are blank,
// so the caller can count a genuine miss.
//
// Addresses that are not globally routable are skipped without consulting the
// databases. The MMDBs happen to hold no records for them, but making the contract
// depend on MaxMind's data rather than on our own code is exactly the kind of
// accident that turns into a private-address leak when the data changes.
func (d *DB) Lookup(addr netip.Addr) (Result, bool) {
	if d == nil {
		return Result{}, false
	}
	if !Enrichable(addr) {
		d.mu.Lock()
		d.stats.skipped++
		d.mu.Unlock()
		return Result{}, false
	}

	var (
		res  Result
		crec countryRecord
		arec asnRecord
		chit bool
		ahit bool
	)
	d.mu.RLock()
	countryLoaded, asnLoaded := d.country != nil, d.asn != nil
	if countryLoaded {
		if r := d.country.db.Lookup(addr); r.Found() {
			if err := r.Decode(&crec); err == nil {
				chit = true
			}
		}
	}
	if asnLoaded {
		if r := d.asn.db.Lookup(addr); r.Found() {
			if err := r.Decode(&arec); err == nil {
				ahit = true
			}
		}
	}
	d.mu.RUnlock()

	found := false
	if chit {
		res.CountryISO, res.ContinentCode = countryFrom(crec)
		res.City, res.RegionISO = cityFrom(crec)
		found = true
	}
	if ahit {
		res.ASN, res.ASOrg = arec.Number, arec.Org
		found = true
	}

	d.mu.Lock()
	if countryLoaded {
		if chit {
			d.stats.countryHits++
		} else {
			d.stats.countryMisses++
		}
	}
	if asnLoaded {
		if ahit {
			d.stats.asnHits++
		} else {
			d.stats.asnMisses++
		}
	}
	d.mu.Unlock()

	return res, found
}

// Reload re-stats each configured path and hot-swaps any database whose (mtime, size)
// has changed since it was opened, reporting whether anything was swapped. It is what
// lets an operator's geoipupdate cron — or this package's own downloader — rewrite
// the files under a running process.
//
// Change detection is (mtime, size) rather than a content hash so the common case
// (nothing changed) costs one stat per file instead of re-reading tens of megabytes
// on every tick. A rewrite that preserves both within the filesystem's timestamp
// granularity would be missed until the next genuine change; the downloader renames a
// freshly-written file into place, so in practice mtime always moves.
//
// A file that fails to open leaves the currently-loaded database serving. That is the
// fail-open contract: a bad update costs freshness, never availability. Errors for
// both databases are joined so one bad file does not hide the other.
func (d *DB) Reload() (bool, error) {
	if d == nil {
		return false, nil
	}
	var changed bool
	var errs []error

	swap := func(path string, cur **reader, reloads *int64) {
		if path == "" {
			return
		}
		fi, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				// Not an error: the scheduled download has not landed yet.
				return
			}
			errs = append(errs, fmt.Errorf("stat geoip database %s: %w", path, err))
			return
		}
		if *cur != nil && (*cur).mtime.Equal(fi.ModTime()) && (*cur).size == fi.Size() {
			return
		}
		next, err := openAt(path, fi)
		if err != nil {
			errs = append(errs, fmt.Errorf("reload geoip database: %w", err))
			return
		}
		old := *cur
		*cur = next
		if old != nil {
			// Safe under the write lock, and safe regardless: the reader owns a heap
			// slice, not a mapping, so a stale reference could not fault even if one
			// escaped. Close cannot fail for an OpenBytes reader (there is no file
			// handle or mapping to release).
			_ = old.db.Close()
		}
		*reloads++
		changed = true
	}

	d.mu.Lock()
	swap(d.countryPath, &d.country, &d.stats.countryReloads)
	swap(d.asnPath, &d.asn, &d.stats.asnReloads)
	if len(errs) > 0 {
		d.stats.reloadFailures += int64(len(errs))
	}
	d.mu.Unlock()

	// errors.Join returns nil for an all-empty slice, so a clean reload reports no
	// error, and a failure on one database never hides a failure on the other.
	return changed, errors.Join(errs...)
}

// ObserveDownload records the outcome of one edition's download attempt, so the three
// download counters move whether or not anything was installed. A 304 is the healthy
// steady state of a daily updater and is worth telling apart from an update that
// actually replaced a file.
func (d *DB) ObserveDownload(res DownloadResult, err error) {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	switch {
	case err != nil:
		d.stats.downloadsFailed++
	case res.Updated:
		d.stats.downloadsUpdated++
	default:
		d.stats.downloadsUnmodified++
	}
}

// Stats returns an absolute snapshot of the counters and the loaded databases'
// identity.
func (d *DB) Stats() Stats {
	if d == nil {
		return Stats{}
	}
	d.mu.RLock()
	defer d.mu.RUnlock()
	s := Stats{
		CountryHits:         d.stats.countryHits,
		CountryMisses:       d.stats.countryMisses,
		ASNHits:             d.stats.asnHits,
		ASNMisses:           d.stats.asnMisses,
		Skipped:             d.stats.skipped,
		CountryReloads:      d.stats.countryReloads,
		ASNReloads:          d.stats.asnReloads,
		ReloadFailures:      d.stats.reloadFailures,
		DownloadsUpdated:    d.stats.downloadsUpdated,
		DownloadsUnmodified: d.stats.downloadsUnmodified,
		DownloadsFailed:     d.stats.downloadsFailed,
		CountryPath:         d.countryPath,
		ASNPath:             d.asnPath,
	}
	if d.country != nil {
		md := d.country.db.Metadata
		s.CountryType = md.DatabaseType
		s.CountryBuildTime = buildTime(md.BuildEpoch)
	}
	if d.asn != nil {
		md := d.asn.db.Metadata
		s.ASNType = md.DatabaseType
		s.ASNBuildTime = buildTime(md.BuildEpoch)
	}
	return s
}

// Close releases the loaded databases.
func (d *DB) Close() {
	if d == nil {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.country != nil {
		_ = d.country.db.Close() // see the Reload comment: cannot fail for OpenBytes
		d.country = nil
	}
	if d.asn != nil {
		_ = d.asn.db.Close()
		d.asn = nil
	}
}

// buildTime converts an mmdb metadata build epoch to a time.
//
// BuildEpoch is a uint the database file supplies, so a corrupt or hostile file could
// carry a value past math.MaxInt64. Converting that unchecked wraps to a negative,
// which would surface as a build date in 1901 and fire the staleness alert
// permanently. Anything that absurd is treated as "unknown" (zero), which callers
// already handle by omitting the gauge entirely.
func buildTime(epoch uint) time.Time {
	if epoch > math.MaxInt64 {
		return time.Time{}
	}
	return time.Unix(int64(epoch), 0).UTC()
}

// cgnat is RFC 6598 carrier-grade NAT space. netip.Addr.IsPrivate does not cover it.
var cgnat = netip.MustParsePrefix("100.64.0.0/10")

// IsGloballyRoutable reports whether an address could plausibly be reached from the
// internet: not loopback, not unspecified, not link-local, not multicast and not
// RFC 1918 / ULA private.
//
// This is the exporter's ONE such classifier. internal/logship/enrich calls it to
// decide whether an interface looks like a WAN, and Enrichable below builds on it.
// It lives HERE rather than in enrich because enrich imports internal/options, and
// options needs geoip for DatabasePath — putting it the other way round is an import
// cycle.
//
// Carrier-grade NAT space is deliberately INCLUDED: it is what many ISPs hand a WAN,
// and netip does not classify it as private. Enrichable is where it is excluded, for
// a different reason — see there.
//
// An IPv4-mapped IPv6 address is unwrapped first: ::ffff:192.168.1.1 is a private
// address wearing a v6 costume, and netip's predicates would not see through it.
func IsGloballyRoutable(addr netip.Addr) bool {
	addr = addr.Unmap()
	if !addr.IsValid() {
		return false
	}
	return !addr.IsLoopback() && !addr.IsUnspecified() && !addr.IsPrivate() &&
		!addr.IsLinkLocalUnicast() && !addr.IsLinkLocalMulticast() &&
		!addr.IsInterfaceLocalMulticast() && !addr.IsMulticast()
}

// Enrichable reports whether addr is worth a database lookup: globally routable by
// IsGloballyRoutable, and outside carrier-grade NAT space.
//
// The CGNAT delta between the two is deliberate and they must not be merged. A
// 100.64/10 address configured on an interface is evidence of a WAN, which is why
// IsGloballyRoutable accepts it; but MaxMind publishes no record for RFC 6598 space,
// so geolocating one can only ever be a miss. Skipping it here keeps the miss counter
// meaning "the database does not know this public address" rather than being padded
// with addresses no database could ever know.
//
// The final IsGlobalUnicast check is what rejects the remaining reserved space
// (0.0.0.0/8, 240.0.0.0/4 and friends) that the predicates above do not name.
func Enrichable(addr netip.Addr) bool {
	if !addr.IsValid() {
		return false
	}
	addr = addr.Unmap()
	if !IsGloballyRoutable(addr) || cgnat.Contains(addr) {
		return false
	}
	return addr.IsGlobalUnicast()
}
