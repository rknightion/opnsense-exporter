package geoip

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeFetcher records what was asked for and installs a file on demand, so the
// schedule can be exercised with no HTTP server.
type fakeFetcher struct {
	mu       sync.Mutex
	calls    []string
	install  func(edition string) error
	err      error
	updated  bool
	fetchedC chan struct{}
}

func (f *fakeFetcher) Fetch(_ context.Context, edition string) (DownloadResult, error) {
	f.mu.Lock()
	f.calls = append(f.calls, edition)
	f.mu.Unlock()
	if f.fetchedC != nil {
		select {
		case f.fetchedC <- struct{}{}:
		default:
		}
	}
	if f.err != nil {
		return DownloadResult{Edition: edition}, f.err
	}
	if f.install != nil {
		if err := f.install(edition); err != nil {
			return DownloadResult{Edition: edition}, err
		}
	}
	return DownloadResult{Edition: edition, Updated: f.updated}, nil
}

func (f *fakeFetcher) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelError}))
}

// Run downloads at START rather than waiting a whole interval: a fresh container
// would otherwise run a full day with no database at all.
func TestUpdaterDownloadsAtStartAndLoadsTheResult(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "country.mmdb")
	db, err := Open(Options{CountryPath: dest})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	f := &fakeFetcher{
		updated: true,
		install: func(string) error {
			b, err := os.ReadFile(countryFixture)
			if err != nil {
				return err
			}
			return os.WriteFile(dest, b, 0o600)
		},
	}
	u := NewUpdater(UpdaterOptions{
		DB: db, Fetcher: f, Editions: []string{"GeoLite2-Country"},
		Logger: quietLogger(),
	})

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { u.Run(ctx); close(done) }()

	deadline := time.After(5 * time.Second)
	for {
		if _, ok := db.Lookup(netip.MustParseAddr("81.2.69.142")); ok {
			break
		}
		select {
		case <-deadline:
			t.Fatal("the database never became queryable after the initial download")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	cancel()
	<-done

	if f.callCount() == 0 {
		t.Error("no download was attempted at start")
	}
	if st := db.Stats(); st.DownloadsUpdated == 0 {
		t.Errorf("an installed update must be counted: %+v", st)
	}
}

// A failed download is logged and retried, never fatal: degraded enrichment must not
// become a degraded exporter.
func TestUpdaterSurvivesAFailedDownload(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "country.mmdb")
	installFixture(t, countryFixture, dest)
	db, err := Open(Options{CountryPath: dest})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	f := &fakeFetcher{err: errors.New("network is down")}
	u := NewUpdater(UpdaterOptions{
		DB: db, Fetcher: f, Editions: []string{"GeoLite2-Country"}, Logger: quietLogger(),
	})
	u.update(t.Context())

	if _, ok := db.Lookup(netip.MustParseAddr("81.2.69.142")); !ok {
		t.Error("the installed database stopped serving after a failed download")
	}
	if st := db.Stats(); st.DownloadsFailed != 1 {
		t.Errorf("DownloadsFailed = %d, want 1", st.DownloadsFailed)
	}
}

// A 304 is a success that installed nothing — the healthy steady state, and worth
// telling apart from an update that replaced a file.
func TestUpdaterCountsAnUnmodifiedDownload(t *testing.T) {
	db, err := Open(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	u := NewUpdater(UpdaterOptions{
		DB: db, Fetcher: &fakeFetcher{updated: false}, Editions: []string{"GeoLite2-ASN"},
		Logger: quietLogger(),
	})
	u.update(t.Context())
	st := db.Stats()
	if st.DownloadsUnmodified != 1 || st.DownloadsUpdated != 0 || st.DownloadsFailed != 0 {
		t.Errorf("unmodified download not counted correctly: %+v", st)
	}
}

// The operator-managed path: no fetcher at all, and the reload tick alone picks up a
// file something else wrote.
func TestUpdaterReloadsWithoutAFetcher(t *testing.T) {
	dir := t.TempDir()
	dest := filepath.Join(dir, "country.mmdb")
	db, err := Open(Options{CountryPath: dest})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	u := NewUpdater(UpdaterOptions{DB: db, ReloadInterval: 5 * time.Millisecond, Logger: quietLogger()})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { u.Run(ctx); close(done) }()

	installFixture(t, countryFixture, dest)

	deadline := time.After(5 * time.Second)
	for {
		if _, ok := db.Lookup(netip.MustParseAddr("81.2.69.142")); ok {
			break
		}
		select {
		case <-deadline:
			t.Fatal("the reload tick never picked up the operator-written database")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	cancel()
	<-done
}

// Zero intervals mean "no repeat", so Run must still do its one startup pass and then
// block on ctx rather than spinning.
func TestUpdaterWithNoIntervalsStopsOnContextCancel(t *testing.T) {
	db, err := Open(Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	u := NewUpdater(UpdaterOptions{DB: db, Logger: quietLogger()})
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { u.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return on context cancel")
	}
}

// A persisted recent check plus an installed database means a restart costs MaxMind
// nothing. This is the whole point: a container that redeploys on every merge can
// exhaust a daily download quota through startup passes alone, without ever fetching
// a new build.
func TestUpdaterSkipsTheStartupFetchWhenTheDatabaseWasCheckedRecently(t *testing.T) {
	dir := t.TempDir()
	dest := DatabasePath(dir, "GeoLite2-Country")
	installFixture(t, countryFixture, dest)
	if err := recordCheck(dir, "GeoLite2-Country", checkResultUnmodified, time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	db, err := Open(Options{CountryPath: dest})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	f := &fakeFetcher{}
	var logs bytes.Buffer
	u := NewUpdater(UpdaterOptions{
		DB: db, Fetcher: f, Editions: []string{"GeoLite2-Country"},
		DownloadInterval: 24 * time.Hour, DownloadDir: dir,
		Logger: slog.New(slog.NewTextHandler(&logs, &slog.HandlerOptions{Level: slog.LevelInfo})),
	})
	u.update(t.Context())

	if n := f.callCount(); n != 0 {
		t.Errorf("startup fetches = %d, want 0: a database checked an hour ago must cost no request", n)
	}
	// A silent skip is indistinguishable from a dead updater, which is the failure
	// mode this whole feature could otherwise introduce.
	for _, want := range []string{"download skipped", "GeoLite2-Country", "last_checked=", "next_check_in="} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("the skip log does not say %q: %s", want, logs.String())
		}
	}
}

// The deferral is per edition and needs BOTH halves. A record with nothing installed
// is a state file that outlived its database (a wiped volume, a deleted file), and a
// record older than the interval is simply due.
func TestUpdaterStillFetchesAtStartWhenTheDeferralDoesNotApply(t *testing.T) {
	cases := []struct {
		name      string
		installed bool
		checkedAt time.Time
		result    string
	}{
		{name: "database missing", installed: false, checkedAt: time.Now().Add(-time.Hour), result: checkResultUnmodified},
		{name: "check older than the interval", installed: true, checkedAt: time.Now().Add(-25 * time.Hour), result: checkResultUnmodified},
		{name: "no record at all", installed: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			dest := DatabasePath(dir, "GeoLite2-Country")
			if tc.installed {
				installFixture(t, countryFixture, dest)
			}
			if tc.result != "" {
				if err := recordCheck(dir, "GeoLite2-Country", tc.result, tc.checkedAt); err != nil {
					t.Fatal(err)
				}
			}
			db, err := Open(Options{CountryPath: dest})
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()

			f := &fakeFetcher{}
			u := NewUpdater(UpdaterOptions{
				DB: db, Fetcher: f, Editions: []string{"GeoLite2-Country"},
				DownloadInterval: 24 * time.Hour, DownloadDir: dir, Logger: quietLogger(),
			})
			u.update(t.Context())

			if n := f.callCount(); n != 1 {
				t.Errorf("startup fetches = %d, want 1", n)
			}
		})
	}
}

// The state must survive a restart on a persisted directory, and must not be the
// installed file's mtime: Fetch stamps that with MaxMind's Last-Modified, so a
// current database can carry a mtime days old and would re-download every start.
func TestUpdaterRecordsTheCheckSoTheNextStartSkipsIt(t *testing.T) {
	dir := t.TempDir()
	dest := DatabasePath(dir, "GeoLite2-Country")
	buildTime := time.Now().Add(-72 * time.Hour)

	run := func(f *fakeFetcher) {
		db, err := Open(Options{CountryPath: dest})
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		u := NewUpdater(UpdaterOptions{
			DB: db, Fetcher: f, Editions: []string{"GeoLite2-Country"},
			DownloadInterval: 24 * time.Hour, DownloadDir: dir, Logger: quietLogger(),
		})
		u.update(t.Context())
	}

	first := &fakeFetcher{
		updated: true,
		install: func(string) error {
			b, err := os.ReadFile(countryFixture)
			if err != nil {
				return err
			}
			if err := os.WriteFile(dest, b, 0o600); err != nil {
				return err
			}
			// What install() does: the mtime is MaxMind's BUILD time, not now.
			return os.Chtimes(dest, buildTime, buildTime)
		},
	}
	run(first)
	if first.callCount() != 1 {
		t.Fatalf("first start fetches = %d, want 1", first.callCount())
	}

	// A second process over the same persisted directory: same files, no memory.
	second := &fakeFetcher{}
	run(second)
	if n := second.callCount(); n != 0 {
		t.Errorf("restart fetches = %d, want 0: the recorded check must survive the process", n)
	}
	if fi, err := os.Stat(dest); err != nil {
		t.Fatal(err)
	} else if age := time.Since(fi.ModTime()); age < 24*time.Hour {
		t.Fatalf("the fixture's mtime is only %s old, so this test would pass on the mtime alone", age)
	}
}

// A 429 is the account's daily limit, not a broken key: its own counter, and no
// retry before the next interval — retrying is what exhausted the quota.
func TestUpdaterCountsAndDefersARateLimitedDownload(t *testing.T) {
	dir := t.TempDir()
	dest := DatabasePath(dir, "GeoLite2-Country")
	installFixture(t, countryFixture, dest)
	db, err := Open(Options{CountryPath: dest})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	f := &fakeFetcher{err: fmt.Errorf("fetch geoip database GeoLite2-Country: %w", ErrRateLimited)}
	u := NewUpdater(UpdaterOptions{
		DB: db, Fetcher: f, Editions: []string{"GeoLite2-Country"},
		DownloadInterval: 24 * time.Hour, DownloadDir: dir, Logger: quietLogger(),
	})
	u.update(t.Context())

	st := db.Stats()
	if st.DownloadsRateLimited != 1 || st.DownloadsFailed != 0 {
		t.Errorf("a 429 must be counted under its own result, not failure: %+v", st)
	}

	// The restart that would otherwise re-ask an already-exhausted quota.
	u2 := NewUpdater(UpdaterOptions{
		DB: db, Fetcher: f, Editions: []string{"GeoLite2-Country"},
		DownloadInterval: 24 * time.Hour, DownloadDir: dir, Logger: quietLogger(),
	})
	u2.update(t.Context())
	if n := f.callCount(); n != 1 {
		t.Errorf("fetches = %d, want 1: a rate-limited edition must not be retried before the interval", n)
	}
}

// A generic failure records nothing, so the next start retries: a transport error, a
// 401 or a 5xx costs no download quota, and deferring one would turn a blip into a
// day of missing updates.
func TestUpdaterDoesNotDeferAfterAGenericFailure(t *testing.T) {
	dir := t.TempDir()
	dest := DatabasePath(dir, "GeoLite2-Country")
	installFixture(t, countryFixture, dest)
	db, err := Open(Options{CountryPath: dest})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	f := &fakeFetcher{err: errors.New("network is down")}
	opts := UpdaterOptions{
		DB: db, Fetcher: f, Editions: []string{"GeoLite2-Country"},
		DownloadInterval: 24 * time.Hour, DownloadDir: dir, Logger: quietLogger(),
	}
	NewUpdater(opts).update(t.Context())
	NewUpdater(opts).update(t.Context())

	if n := f.callCount(); n != 2 {
		t.Errorf("fetches = %d, want 2: a failure that burns no quota must be retried at the next start", n)
	}
}

// The deferral must not become a permanent skip. A container restarting more often
// than the download interval would never download at all if the first tick were a
// whole interval after start rather than after the last recorded check.
func TestUpdaterSchedulesTheNextCheckFromTheLastRecordedOne(t *testing.T) {
	dir := t.TempDir()
	installFixture(t, countryFixture, DatabasePath(dir, "GeoLite2-Country"))
	if err := recordCheck(dir, "GeoLite2-Country", checkResultUnmodified, time.Now().Add(-23*time.Hour)); err != nil {
		t.Fatal(err)
	}
	u := NewUpdater(UpdaterOptions{
		DB: nil, Fetcher: &fakeFetcher{}, Editions: []string{"GeoLite2-Country"},
		DownloadInterval: 24 * time.Hour, DownloadDir: dir, Logger: quietLogger(),
	})
	d := u.nextDownloadDelay()
	if d <= 0 || d > 2*time.Hour {
		t.Errorf("next download delay = %s, want roughly an hour (24h interval, checked 23h ago)", d)
	}
}
