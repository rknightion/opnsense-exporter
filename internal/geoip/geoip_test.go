package geoip

import (
	"net/netip"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

const (
	countryFixture = "testdata/GeoIP2-Country-Test.mmdb"
	asnFixture     = "testdata/GeoLite2-ASN-Test.mmdb"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := Open(Options{CountryPath: countryFixture, ASNPath: asnFixture})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(db.Close)
	return db
}

func TestLookupCountryAndASN(t *testing.T) {
	db := openTestDB(t)

	res, ok := db.Lookup(netip.MustParseAddr("81.2.69.142"))
	if !ok {
		t.Fatal("expected a hit for 81.2.69.142")
	}
	if res.CountryISO != "GB" {
		t.Errorf("CountryISO = %q, want GB", res.CountryISO)
	}
	if res.ContinentCode != "EU" {
		t.Errorf("ContinentCode = %q, want EU", res.ContinentCode)
	}

	res, ok = db.Lookup(netip.MustParseAddr("1.0.0.1"))
	if !ok {
		t.Fatal("expected a hit for 1.0.0.1")
	}
	if res.ASN != 15169 {
		t.Errorf("ASN = %d, want 15169", res.ASN)
	}
	if res.ASOrg == "" {
		t.Error("ASOrg is empty, want the Google organization string")
	}
}

// 12.81.96.1 carries an ASN with NO organization. A record whose org is blank must
// still be a hit, or every such address reads as unknown.
func TestLookupASNWithoutOrganization(t *testing.T) {
	db := openTestDB(t)
	res, ok := db.Lookup(netip.MustParseAddr("12.81.96.1"))
	if !ok {
		t.Fatal("expected a hit for 12.81.96.1")
	}
	if res.ASN != 7018 {
		t.Errorf("ASN = %d, want 7018", res.ASN)
	}
	if res.ASOrg != "" {
		t.Errorf("ASOrg = %q, want empty for this fixture record", res.ASOrg)
	}
}

// 2a02:d500:: has a continent but NO country object at all, which is the shape that
// makes the registered_country fallback in countryFrom load-bearing.
func TestLookupContinentWithoutCountry(t *testing.T) {
	db := openTestDB(t)
	res, ok := db.Lookup(netip.MustParseAddr("2a02:d500::"))
	if !ok {
		t.Fatal("expected a hit for 2a02:d500::")
	}
	if res.ContinentCode != "EU" {
		t.Errorf("ContinentCode = %q, want EU", res.ContinentCode)
	}
}

func TestLookupMissIsNotAHit(t *testing.T) {
	db := openTestDB(t)
	if _, ok := db.Lookup(netip.MustParseAddr("4.4.4.4")); ok {
		t.Error("4.4.4.4 is absent from both fixtures; want a miss")
	}
	st := db.Stats()
	if st.CountryMisses == 0 || st.ASNMisses == 0 {
		t.Errorf("a miss must be counted on both databases: %+v", st)
	}
}

func TestEnrichableSkipsNonGlobalAddresses(t *testing.T) {
	cases := []struct {
		addr string
		want bool
	}{
		{"8.8.8.8", true},
		{"2001:4860:4860::8888", true},
		{"192.168.1.1", false},
		{"10.0.0.1", false},
		{"172.16.0.1", false},
		{"127.0.0.1", false},
		{"169.254.1.1", false},
		{"224.0.0.251", false},
		{"fe80::1", false},
		{"fd00::1", false},
		{"::1", false},
		{"0.0.0.0", false},
		// CGNAT: an ISP-handed WAN address. MaxMind holds no record for
		// 100.64.0.0/10, so a lookup can only ever miss.
		{"100.64.0.1", false},
		// An IPv4-mapped v6 address is a v4 address in a costume; netip's own
		// predicates do not see through it.
		{"::ffff:192.168.1.1", false},
		{"::ffff:8.8.8.8", true},
	}
	for _, tc := range cases {
		if got := Enrichable(netip.MustParseAddr(tc.addr)); got != tc.want {
			t.Errorf("Enrichable(%s) = %v, want %v", tc.addr, got, tc.want)
		}
	}
	if Enrichable(netip.Addr{}) {
		t.Error("Enrichable(invalid) = true, want false")
	}
}

func TestLookupSkipsAndCountsNonGlobal(t *testing.T) {
	db := openTestDB(t)
	if _, ok := db.Lookup(netip.MustParseAddr("192.168.1.10")); ok {
		t.Error("a private address must never be looked up")
	}
	if st := db.Stats(); st.Skipped != 1 {
		t.Errorf("Skipped = %d, want 1", st.Skipped)
	}
}

// A nil *DB is the value handed out when enrichment is off. It must satisfy Lookup
// and report a miss rather than panicking.
func TestNilDBIsUsable(t *testing.T) {
	var db *DB
	if _, ok := db.Lookup(netip.MustParseAddr("8.8.8.8")); ok {
		t.Error("nil DB reported a hit")
	}
	if !db.Empty() {
		t.Error("nil DB must report Empty")
	}
	if changed, err := db.Reload(); changed || err != nil {
		t.Errorf("nil DB Reload = (%v, %v), want (false, nil)", changed, err)
	}
	db.Close()
	var _ Lookup = db
}

// A path that does not exist yet is remembered, not an error: a cold start whose
// scheduled download has not landed must not fail.
func TestOpenMissingPathIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	db, err := Open(Options{CountryPath: filepath.Join(dir, "nope.mmdb")})
	if err != nil {
		t.Fatalf("Open on a missing path returned %v, want nil", err)
	}
	t.Cleanup(db.Close)
	if !db.Empty() {
		t.Error("no database should be loaded")
	}
}

// A path that exists but is not a MaxMind database IS an error — the operator
// pointed at something real and wrong — yet the DB is still usable.
func TestOpenGarbageFileErrorsButStaysUsable(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.mmdb")
	if err := os.WriteFile(bad, []byte("not an mmdb"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := Open(Options{CountryPath: bad, ASNPath: asnFixture})
	if err == nil {
		t.Fatal("Open on a garbage file returned no error")
	}
	t.Cleanup(db.Close)
	if _, ok := db.Lookup(netip.MustParseAddr("1.0.0.1")); !ok {
		t.Error("the ASN database that DID load must still serve lookups")
	}
}

func TestReloadHotSwapsAChangedFile(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "country.mmdb")

	db, err := Open(Options{CountryPath: dest})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(db.Close)
	if _, ok := db.Lookup(netip.MustParseAddr("81.2.69.142")); ok {
		t.Fatal("nothing is installed yet; want a miss")
	}

	installFixture(t, countryFixture, dest)
	changed, err := db.Reload()
	if err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if !changed {
		t.Fatal("Reload did not report the new file")
	}
	if _, ok := db.Lookup(netip.MustParseAddr("81.2.69.142")); !ok {
		t.Error("the reloaded database does not serve lookups")
	}

	// An untouched file must not be re-read.
	if changed, err := db.Reload(); changed || err != nil {
		t.Errorf("second Reload = (%v, %v), want (false, nil)", changed, err)
	}
	if st := db.Stats(); st.CountryReloads != 1 {
		t.Errorf("CountryReloads = %d, want 1", st.CountryReloads)
	}
}

// A bad replacement leaves the currently-loaded database serving. Fail-open means a
// broken update costs freshness, never availability.
func TestReloadKeepsServingAfterABadUpdate(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "country.mmdb")
	installFixture(t, countryFixture, dest)

	db, err := Open(Options{CountryPath: dest})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(db.Close)

	if err := os.WriteFile(dest, []byte("truncated garbage"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Reload(); err == nil {
		t.Fatal("Reload of a corrupt file reported no error")
	}
	if _, ok := db.Lookup(netip.MustParseAddr("81.2.69.142")); !ok {
		t.Error("the previously loaded database stopped serving after a bad update")
	}
	if st := db.Stats(); st.ReloadFailures == 0 {
		t.Error("a failed reload must be counted")
	}
}

// This is the test that motivated reading the file into the heap instead of mmapping
// it: with maxminddb.Open, truncating the file under a concurrent lookup faults with
// SIGBUS and takes the process down. With OpenBytes the reader owns a heap slice, so
// the swap is merely a swap.
func TestReloadUnderConcurrentLookupsDoesNotFault(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "country.mmdb")
	installFixture(t, countryFixture, dest)

	db, err := Open(Options{CountryPath: dest})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(db.Close)

	stop := make(chan struct{})
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			addr := netip.MustParseAddr("81.2.69.142")
			for {
				select {
				case <-stop:
					return
				default:
					db.Lookup(addr)
				}
			}
		}()
	}
	for range 10 {
		// Truncate in place, the exact thing a `curl -o db.mmdb` does.
		if err := os.WriteFile(dest, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, _ = db.Reload()
		installFixture(t, countryFixture, dest)
		_, _ = db.Reload()
	}
	close(stop)
	wg.Wait()
}

func TestStatsReportsDatabaseIdentity(t *testing.T) {
	db := openTestDB(t)
	st := db.Stats()
	if st.CountryType == "" || st.ASNType == "" {
		t.Errorf("database types not reported: %+v", st)
	}
	if st.CountryBuildTime.IsZero() || st.ASNBuildTime.IsZero() {
		t.Errorf("build times not reported: %+v", st)
	}
	if st.CountryPath != countryFixture || st.ASNPath != asnFixture {
		t.Errorf("paths not reported: %+v", st)
	}
}

// A corrupt or hostile file can carry a build epoch past math.MaxInt64. Converting
// that unchecked wraps negative and reads as 1901, which would fire every staleness
// alert ever written against it forever.
func TestBuildTimeRejectsAbsurdEpoch(t *testing.T) {
	if got := buildTime(1 << 63); !got.IsZero() {
		t.Errorf("buildTime(2^63) = %v, want the zero time", got)
	}
	if got := buildTime(1700000000); got.Unix() != 1700000000 {
		t.Errorf("buildTime lost a sane epoch: %v", got)
	}
}

func TestResultEmpty(t *testing.T) {
	if !(Result{}).Empty() {
		t.Error("zero Result must be Empty")
	}
	if (Result{CountryISO: "GB"}).Empty() {
		t.Error("a Result with a country is not Empty")
	}
}

func TestOversizeDatabaseIsRefused(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "huge.mmdb")
	f, err := os.Create(dest) //nolint:gosec // dest is a t.TempDir path
	if err != nil {
		t.Fatal(err)
	}
	// Sparse: no bytes are actually written, so this costs nothing on disk.
	if err := f.Truncate(maxDatabaseBytes + 1); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(Options{CountryPath: dest}); err == nil {
		t.Fatal("an oversize file was accepted")
	}
}

func installFixture(t *testing.T, src, dest string) {
	t.Helper()
	b, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dest, b, 0o600); err != nil {
		t.Fatal(err)
	}
	// Move the mtime forward so Reload's (mtime, size) change check fires even when
	// the filesystem's timestamp granularity is coarse.
	now := time.Now().Add(time.Duration(-len(b)) * time.Nanosecond)
	if err := os.Chtimes(dest, now, now); err != nil {
		t.Fatal(err)
	}
}
