package geoip

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
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
