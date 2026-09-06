package geoip

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"time"
)

// Fetcher is the narrow view of the MaxMind downloader the updater needs, so the
// schedule can be tested without an HTTP server. *Downloader satisfies it.
type Fetcher interface {
	Fetch(ctx context.Context, edition string) (DownloadResult, error)
}

// UpdaterOptions configures an Updater.
type UpdaterOptions struct {
	// DB is the database set to reload. Required.
	DB *DB
	// Fetcher downloads databases from MaxMind. Nil disables downloading, which is
	// the operator-managed path: something else (a geoipupdate cron, a sidecar, a
	// mounted volume) writes the files and the reload tick notices.
	Fetcher Fetcher
	// Editions are the MaxMind edition IDs to download. Ignored when Fetcher is nil.
	Editions []string
	// DownloadDir is where the downloader installs databases (--geoip.download.dir).
	// It is also where the "when did we last ask MaxMind?" record lives, which is what
	// lets a restart inside DownloadInterval skip the startup fetch. Empty disables
	// that entirely: every start then asks, which is the right thing when nothing is
	// persisted anyway.
	DownloadDir string
	// DownloadInterval is how often to ask MaxMind for a newer database. Zero
	// disables the repeat (the initial download at start still runs).
	DownloadInterval time.Duration
	// ReloadInterval is how often to re-stat the configured paths and hot-swap a
	// changed file. Zero disables it.
	ReloadInterval time.Duration
	// Logger receives the update loop's INFO/WARN lines. Nil uses slog.Default.
	Logger *slog.Logger
}

// Updater keeps a DB current: it downloads fresh databases from MaxMind (when
// configured) and hot-swaps any file that has changed on disk.
//
// The two schedules are deliberately independent, because they answer different
// questions. DownloadInterval is "has MaxMind published a newer build?" — a network
// question, answered with a conditional request, worth asking daily since GeoLite2
// rebuilds twice a week. ReloadInterval is "has the file on disk changed?" — a local
// stat, and the only thing that makes the operator-managed path work at all. Setting
// one does not imply the other.
type Updater struct {
	db               *DB
	fetcher          Fetcher
	editions         []string
	downloadDir      string
	downloadInterval time.Duration
	reloadInterval   time.Duration
	logger           *slog.Logger
}

// NewUpdater returns an Updater; call Run to start it.
func NewUpdater(opts UpdaterOptions) *Updater {
	logger := opts.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Updater{
		db:               opts.DB,
		fetcher:          opts.Fetcher,
		editions:         opts.Editions,
		downloadDir:      opts.DownloadDir,
		downloadInterval: opts.DownloadInterval,
		reloadInterval:   opts.ReloadInterval,
		logger:           logger,
	}
}

// Run drives the update loop until ctx is canceled. It never returns an error: a
// failed download or reload is logged and retried on the next tick, because degraded
// enrichment must never become a degraded exporter.
func (u *Updater) Run(ctx context.Context) {
	// Download at start rather than waiting a whole interval: a fresh container would
	// otherwise run a full day with no database at all. update itself defers any
	// edition that was already checked inside the interval, so a restart-heavy
	// deployment costs MaxMind nothing.
	u.update(ctx)

	// A timer rather than a ticker, because the first wake is not always a whole
	// interval away: an edition deferred at start is due at checked_at+interval, and a
	// ticker would push that to start+interval. A container that restarts more often
	// than the interval would then never download at all — the deferral would become
	// a permanent skip.
	var downloadTimer *time.Timer
	var downloadC, reloadC <-chan time.Time
	if u.downloadInterval > 0 && u.fetcher != nil {
		downloadTimer = time.NewTimer(u.nextDownloadDelay())
		defer downloadTimer.Stop()
		downloadC = downloadTimer.C
	}
	if u.reloadInterval > 0 {
		t := time.NewTicker(u.reloadInterval)
		defer t.Stop()
		reloadC = t.C
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-downloadC:
			u.update(ctx)
			downloadTimer.Reset(u.nextDownloadDelay())
		case <-reloadC:
			u.reload()
		}
	}
}

// nextDownloadDelay is how long until the earliest edition is due another check. It
// is never zero or negative — an edition with no record was just attempted, so it is
// due in a full interval — and never longer than one interval, which also absorbs a
// state file whose timestamp is in the future after a clock step.
func (u *Updater) nextDownloadDelay() time.Duration {
	delay := u.downloadInterval
	st := loadCheckState(u.downloadDir)
	now := time.Now()
	for _, edition := range u.editions {
		rec, ok := st.Editions[edition]
		if !ok || !deferrable(rec.Result) {
			continue
		}
		// +1s so the timer fires just after the record goes stale rather than in the
		// same instant: the record carries wall-clock seconds and the timer runs on
		// the monotonic clock, and firing a hair early would defer the pass again.
		remaining := u.downloadInterval - now.Sub(rec.CheckedAt) + time.Second
		if remaining > 0 && remaining < delay {
			delay = remaining
		}
	}
	return delay
}

// deferrable reports whether a recorded outcome means MaxMind answered, and so that
// asking again before the interval is waste. A 429 counts: the quota is already
// exhausted, so an immediate retry cannot succeed.
func deferrable(result string) bool {
	switch result {
	case checkResultUpdated, checkResultUnmodified, checkResultRateLimited:
		return true
	default:
		return false
	}
}

// update runs one download pass (when a fetcher is configured) and then reloads
// whatever changed on disk.
func (u *Updater) update(ctx context.Context) {
	if u.fetcher != nil {
		st := loadCheckState(u.downloadDir)
		for _, edition := range u.editions {
			if u.deferCheck(st, edition) {
				continue
			}
			res, err := u.fetcher.Fetch(ctx, edition)
			u.db.ObserveDownload(res, err)
			switch {
			case errors.Is(err, ErrRateLimited):
				// A distinct line from the generic failure below: this is not a broken
				// key or blocked egress, it is the daily download quota, and the fix is
				// to stop asking rather than to investigate connectivity.
				u.record(edition, checkResultRateLimited)
				u.logger.Warn("geoip database download refused by MaxMind's download limit; "+
					"keeping the installed database and not retrying before the next interval",
					"edition", edition, "retry_interval", u.downloadInterval, "error", err)
			case err != nil:
				// WARN, not ERROR: the previously installed database keeps serving,
				// so this degrades freshness, not availability. Nothing is recorded:
				// a transport error, a 401 or a 5xx burns no download quota, so the
				// next start is welcome to try again.
				u.logger.Warn("geoip database download failed; keeping the installed database",
					"edition", edition, "error", err)
			case res.Updated:
				u.record(edition, checkResultUpdated)
				u.logger.Info("geoip database updated",
					"edition", edition, "path", res.Path, "build_time", res.BuildTime)
			default:
				u.record(edition, checkResultUnmodified)
				u.logger.Debug("geoip database is already current", "edition", edition)
			}
		}
	}
	u.reload()
}

// deferCheck reports whether edition can be left alone this pass, and logs why. It
// says yes only when a database is actually installed AND MaxMind answered for it
// inside the interval — a missing edition, or one whose last answered check has aged
// out, is always fetched.
func (u *Updater) deferCheck(st checkState, edition string) bool {
	if u.downloadDir == "" || u.downloadInterval <= 0 {
		return false
	}
	rec, ok := st.Editions[edition]
	if !ok || !deferrable(rec.Result) {
		return false
	}
	if _, err := os.Stat(DatabasePath(u.downloadDir, edition)); err != nil {
		return false
	}
	age := time.Since(rec.CheckedAt)
	if age < 0 || age >= u.downloadInterval {
		return false
	}
	u.logger.Info("geoip database download skipped; MaxMind was already asked inside the download "+
		"interval and the database is installed",
		"edition", edition, "last_checked", rec.CheckedAt, "last_result", rec.Result,
		"next_check_in", (u.downloadInterval - age).Round(time.Second))
	return true
}

// record persists one edition's answered check. A failure here is logged and ignored:
// the database is installed and serving, and the only cost is that the next start
// asks MaxMind again.
func (u *Updater) record(edition, result string) {
	if err := recordCheck(u.downloadDir, edition, result, time.Now()); err != nil {
		u.logger.Warn("geoip download state could not be recorded; the next start will re-check",
			"edition", edition, "error", err)
	}
}

func (u *Updater) reload() {
	changed, err := u.db.Reload()
	if err != nil {
		u.logger.Warn("geoip database reload failed; keeping the loaded database", "error", err)
		return
	}
	if changed {
		s := u.db.Stats()
		u.logger.Info("geoip databases reloaded",
			"country_build_time", s.CountryBuildTime, "asn_build_time", s.ASNBuildTime)
	}
}
