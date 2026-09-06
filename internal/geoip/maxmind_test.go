package geoip

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// buildArchive returns a gzipped tar holding one .mmdb member, the shape MaxMind
// publishes. name is the member path INSIDE the archive, which Fetch must never use
// to build a destination path.
func buildArchive(t *testing.T, name string, body []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: name, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// maxmindServer stands in for download.maxmind.com. It serves one archive, answers
// the checksum suffix, honours If-Modified-Since, and records the credentials it saw.
type maxmindServer struct {
	archive      []byte
	lastModified time.Time
	requests     int
	gotUser      string
	gotPass      string
	// unauthorized makes every request 401, for the credential-failure path.
	unauthorized bool
	// rateLimited makes every request 429, the exhausted-daily-limit path.
	rateLimited bool
}

func (m *maxmindServer) handler(t *testing.T) http.HandlerFunc {
	t.Helper()
	return func(w http.ResponseWriter, r *http.Request) {
		m.requests++
		m.gotUser, m.gotPass, _ = r.BasicAuth()
		if m.unauthorized {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if m.rateLimited {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		switch r.URL.Query().Get("suffix") {
		case "tar.gz.sha256":
			sum := sha256.Sum256(m.archive)
			fmt.Fprintf(w, "%s  GeoLite2-Country.tar.gz\n", hex.EncodeToString(sum[:]))
		case "tar.gz":
			if ims := r.Header.Get("If-Modified-Since"); ims != "" {
				if since, err := http.ParseTime(ims); err == nil && !m.lastModified.After(since) {
					w.WriteHeader(http.StatusNotModified)
					return
				}
			}
			w.Header().Set("Last-Modified", m.lastModified.UTC().Format(http.TimeFormat))
			_, _ = w.Write(m.archive)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}
}

func TestFetchInstallsAndThen304s(t *testing.T) {
	payload, err := os.ReadFile(countryFixture)
	if err != nil {
		t.Fatal(err)
	}
	// A member path that would escape the directory if the NAME were ever used to
	// build the destination. It must be ignored: the destination is always
	// <Dir>/<Edition>.mmdb.
	srv := &maxmindServer{
		archive:      buildArchive(t, "../../../etc/evil.mmdb", payload),
		lastModified: time.Now().Add(-time.Hour).Truncate(time.Second),
	}
	ts := httptest.NewServer(srv.handler(t))
	defer ts.Close()

	dir := t.TempDir()
	d := &Downloader{
		AccountID: "acct", LicenseKey: "key",
		Endpoint: ts.URL, Dir: dir, Timeout: 10 * time.Second,
	}

	res, err := d.Fetch(t.Context(), "GeoLite2-Country")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !res.Updated {
		t.Error("first Fetch did not report an update")
	}
	want := filepath.Join(dir, "GeoLite2-Country.mmdb")
	if res.Path != want {
		t.Errorf("Path = %q, want %q", res.Path, want)
	}
	if _, err := os.Stat(want); err != nil {
		t.Fatalf("database not installed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "..", "..", "..", "etc", "evil.mmdb")); err == nil {
		t.Fatal("the archive member's name escaped the destination directory")
	}
	if srv.gotUser != "acct" || srv.gotPass != "key" {
		t.Errorf("basic auth = %q/%q, want acct/key", srv.gotUser, srv.gotPass)
	}

	// The installed file's mtime IS the conditional-request state, so the second run
	// must 304 and install nothing.
	res, err = d.Fetch(t.Context(), "GeoLite2-Country")
	if err != nil {
		t.Fatalf("second Fetch: %v", err)
	}
	if res.Updated {
		t.Error("second Fetch reported an update; want a 304")
	}

	// The installed database must actually load.
	db, err := Open(Options{CountryPath: want})
	if err != nil {
		t.Fatalf("the installed database does not open: %v", err)
	}
	db.Close()
}

func TestFetchRejectsABadChecksum(t *testing.T) {
	srv := &maxmindServer{archive: buildArchive(t, "x.mmdb", []byte("payload"))}
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("suffix") == "tar.gz.sha256" {
			fmt.Fprint(w, strings.Repeat("a", 64)+"  x.tar.gz\n")
			return
		}
		_, _ = w.Write(srv.archive)
	}))
	defer ts.Close()

	dir := t.TempDir()
	d := &Downloader{Endpoint: ts.URL, Dir: dir}
	if _, err := d.Fetch(t.Context(), "GeoLite2-Country"); err == nil {
		t.Fatal("a mismatched checksum was accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "GeoLite2-Country.mmdb")); err == nil {
		t.Error("a database was installed despite the checksum failure")
	}
}

func TestFetchOnHTTPErrorInstallsNothing(t *testing.T) {
	srv := &maxmindServer{unauthorized: true}
	ts := httptest.NewServer(srv.handler(t))
	defer ts.Close()

	dir := t.TempDir()
	d := &Downloader{Endpoint: ts.URL, Dir: dir}
	_, err := d.Fetch(t.Context(), "GeoLite2-Country")
	if err == nil {
		t.Fatal("a 401 was treated as success")
	}
	if strings.Contains(err.Error(), "key") {
		t.Errorf("the error may not echo a credential: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "GeoLite2-Country.mmdb")); err == nil {
		t.Error("a database was installed after a 401")
	}
}

// A 429 is its own error, not one more "HTTP nnn" string: it is the one failure that
// says the account's daily limit is spent rather than that the key or the network is
// broken, and the caller defers on it instead of retrying.
func TestFetchReportsAnExhaustedDownloadLimit(t *testing.T) {
	srv := &maxmindServer{rateLimited: true}
	ts := httptest.NewServer(srv.handler(t))
	defer ts.Close()

	dir := t.TempDir()
	d := &Downloader{Endpoint: ts.URL, Dir: dir}
	_, err := d.Fetch(t.Context(), "GeoLite2-Country")
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("Fetch error = %v, want one wrapping ErrRateLimited", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "GeoLite2-Country.mmdb")); err == nil {
		t.Error("a database was installed after a 429")
	}
}

func TestFetchRefusesANonRegularArchiveMember(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := tw.WriteHeader(&tar.Header{
		Name: "GeoLite2-Country.mmdb", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd",
	}); err != nil {
		t.Fatal(err)
	}
	_ = tw.Close()
	_ = gz.Close()

	srv := &maxmindServer{archive: buf.Bytes()}
	ts := httptest.NewServer(srv.handler(t))
	defer ts.Close()

	d := &Downloader{Endpoint: ts.URL, Dir: t.TempDir()}
	if _, err := d.Fetch(t.Context(), "GeoLite2-Country"); err == nil {
		t.Fatal("a symlink archive member was accepted")
	}
}

func TestFetchRefusesAnOversizeMember(t *testing.T) {
	srv := &maxmindServer{archive: buildArchive(t, "a.mmdb", bytes.Repeat([]byte("x"), 4096))}
	ts := httptest.NewServer(srv.handler(t))
	defer ts.Close()

	d := &Downloader{Endpoint: ts.URL, Dir: t.TempDir(), MaxBytes: 16}
	if _, err := d.Fetch(t.Context(), "GeoLite2-Country"); err == nil {
		t.Fatal("an oversize archive member was accepted")
	}
}

func TestExtractBoundsAggregateMembersBeforeDatabase(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for i := 0; i < maxArchiveMembers+1; i++ {
		if err := tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("readme-%d", i), Mode: 0o644, Typeflag: tar.TypeReg}); err != nil {
			t.Fatal(err)
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	archive := filepath.Join(t.TempDir(), "many.tar.gz")
	if err := os.WriteFile(archive, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	d := &Downloader{Dir: t.TempDir(), MaxBytes: 1 << 20}
	_, err := d.extract(t.Context(), archive, filepath.Join(d.Dir, "db.mmdb"), "test")
	if err == nil || !strings.Contains(err.Error(), "member limit") {
		t.Fatalf("extract error = %v, want member limit", err)
	}
}

func TestValidateEdition(t *testing.T) {
	for _, ok := range []string{"GeoLite2-Country", "GeoLite2-ASN", "GeoIP2_City", "abc123"} {
		if err := ValidateEdition(ok); err != nil {
			t.Errorf("ValidateEdition(%q) = %v, want nil", ok, err)
		}
	}
	for _, bad := range []string{"", "../etc/passwd", "a/b", "a b", "a?suffix=x", "a%2f"} {
		if err := ValidateEdition(bad); err == nil {
			t.Errorf("ValidateEdition(%q) = nil, want an error", bad)
		}
	}
}

func TestDatabasePath(t *testing.T) {
	if got := DatabasePath("/var/lib/geoip", "GeoLite2-ASN"); got != "/var/lib/geoip/GeoLite2-ASN.mmdb" {
		t.Errorf("DatabasePath = %q", got)
	}
}

func TestFetchRejectsAnUnsafeEditionBeforeAnyRequest(t *testing.T) {
	var hits int
	ts := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer ts.Close()
	d := &Downloader{Endpoint: ts.URL, Dir: t.TempDir()}
	if _, err := d.Fetch(context.Background(), "../../etc/passwd"); err == nil {
		t.Fatal("an unsafe edition was accepted")
	}
	if hits != 0 {
		t.Errorf("a request was made for an unsafe edition (%d hits)", hits)
	}
}
