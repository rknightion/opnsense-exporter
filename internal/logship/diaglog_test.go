package logship

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/prometheus/common/promslog"
	"github.com/rknightion/opnsense-exporter/internal/options"
	"github.com/rknightion/opnsense-exporter/opnsense"
)

func diagTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newDiagLogTestClient points a real *opnsense.Client at an httptest server,
// mirroring internal/collector/testhelpers_test.go's newCollectorTestClient —
// FetchDiagLog is only reachable through the real client's endpoint registry.
func newDiagLogTestClient(t *testing.T, server *httptest.Server) *opnsense.Client {
	t.Helper()
	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse server URL: %v", err)
	}
	cfg := options.OPNSenseConfig{Protocol: "http", Host: u.Host, APIKey: "test", APISecret: "test"}
	client, err := opnsense.NewClient(cfg, "test", promslog.NewNopLogger())
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	return &client
}

func newTestDiagLogSource(client *opnsense.Client, scopes []options.DiagLogScope, now func() time.Time) *diagLogSource {
	return &diagLogSource{
		client:  client,
		log:     diagTestLogger(),
		scopes:  scopes,
		cursors: make(map[string]*diagLogCursor),
		now:     now,
	}
}

func diagLogPage(rows []map[string]any, totalRows int) []byte {
	body := map[string]any{
		"filters":    "",
		"rows":       rows,
		"total_rows": totalRows,
		"origin":     "test",
		"rowCount":   len(rows),
		"total":      totalRows,
		"current":    1,
	}
	b, _ := json.Marshal(body)
	return b
}

func auditRow(ts, line string) map[string]any {
	return map[string]any{
		"timestamp":    ts,
		"parser":       "SysLogFormatRFC5424",
		"facility":     4,
		"severity":     "Informational",
		"process_name": "configd.py",
		"pid":          "1307",
		"rnum":         1,
		"line":         line,
	}
}

func TestDiagLogSource_Name(t *testing.T) {
	s := newTestDiagLogSource(nil, nil, time.Now)
	if s.Name() != "diaglog" {
		t.Errorf("Name() = %q, want diaglog", s.Name())
	}
}

// A scope with no prior cursor must bootstrap to "now" WITHOUT making any HTTP
// request — replaying a scope's full retained log on every restart is exactly
// the "expensive" behaviour the source is designed to avoid.
func TestDiagLogSource_FirstPollBootstrapsWithoutFetching(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatalf("unexpected request on bootstrap poll: %s", r.URL.Path)
	}))
	defer server.Close()

	client := newDiagLogTestClient(t, server)
	fixedNow := time.Date(2026, 7, 13, 20, 0, 0, 0, time.UTC)
	s := newTestDiagLogSource(client, []options.DiagLogScope{{Module: "core", Scope: "audit"}}, func() time.Time { return fixedNow })

	records, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("Poll returned error: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("bootstrap poll should emit no records, got %d", len(records))
	}

	data, ok := s.SaveState()
	if !ok {
		t.Fatal("expected cursor state to persist after bootstrap")
	}
	var blob map[string]int64
	if err := json.Unmarshal(data, &blob); err != nil {
		t.Fatalf("decode state: %v", err)
	}
	if blob["core/audit"] != fixedNow.Unix() {
		t.Errorf("cursor = %d, want %d", blob["core/audit"], fixedNow.Unix())
	}
}

// After bootstrap, a second poll fetches from the cursor and emits records
// oldest-first with the expected attributes.
func TestDiagLogSource_SecondPollEmitsNewRows(t *testing.T) {
	fixedNow := time.Date(2026, 7, 13, 20, 0, 0, 0, time.UTC)
	var gotBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/diagnostics/log/core/audit" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		gotBody, _ = io.ReadAll(r.Body)
		w.Write(diagLogPage([]map[string]any{
			auditRow("2026-07-13T20:00:05", " action allowed system.diag.log for user root"),
			auditRow("2026-07-13T20:00:03", " user root@127.0.0.1 changed configuration to /conf/backup/config-1.xml in /api/relayd/settings/set/virtualserver /api/relayd/settings/set/virtualserver made changes"),
		}, 2))
	}))
	defer server.Close()

	client := newDiagLogTestClient(t, server)
	s := newTestDiagLogSource(client, []options.DiagLogScope{{Module: "core", Scope: "audit"}}, func() time.Time { return fixedNow })

	if _, err := s.Poll(context.Background()); err != nil {
		t.Fatalf("bootstrap poll error: %v", err)
	}

	records, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("second poll error: %v", err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2: %+v", len(records), records)
	}

	var req map[string]any
	if err := json.Unmarshal(gotBody, &req); err != nil {
		t.Fatalf("decode request body: %v", err)
	}
	if int64(req["validFrom"].(float64)) != fixedNow.Unix() {
		t.Errorf("validFrom = %v, want %d", req["validFrom"], fixedNow.Unix())
	}

	// Oldest first.
	first, second := records[0], records[1]
	if first.Body != "user root@127.0.0.1 changed configuration to /conf/backup/config-1.xml in /api/relayd/settings/set/virtualserver /api/relayd/settings/set/virtualserver made changes" {
		t.Errorf("unexpected body: %q", first.Body)
	}
	if first.Attributes["module"] != "core" || first.Attributes["scope"] != "audit" {
		t.Errorf("unexpected attributes: %+v", first.Attributes)
	}
	if first.Attributes["config_user"] != "root@127.0.0.1" || first.Attributes["config_revision"] != "/conf/backup/config-1.xml" || first.Attributes["config_uri"] != "/api/relayd/settings/set/virtualserver" {
		t.Errorf("config-change attrs not parsed: %+v", first.Attributes)
	}
	if first.Attributes["process_name"] != "configd.py" || first.Attributes["pid"] != "1307" || first.Attributes["facility"] != "4" {
		t.Errorf("unexpected process/pid/facility attrs: %+v", first.Attributes)
	}
	if first.Severity != SeverityInfo {
		t.Errorf("severity = %v, want SeverityInfo", first.Severity)
	}
	if !first.Timestamp.Before(second.Timestamp) {
		t.Errorf("expected oldest-first ordering, got %v then %v", first.Timestamp, second.Timestamp)
	}
	if second.Attributes["config_user"] != "" {
		t.Errorf("non-config-change line should not get config_* attrs: %+v", second.Attributes)
	}
}

// The inclusive validFrom boundary means the newest row from one poll is
// returned again by the next poll; the source must not re-emit it, while still
// emitting anything genuinely new at the same or a later second.
func TestDiagLogSource_BoundaryDedup(t *testing.T) {
	fixedNow := time.Date(2026, 7, 13, 20, 0, 0, 0, time.UTC)
	call := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call++
		switch call {
		case 1:
			// Second poll overall (first is the no-fetch bootstrap): one row.
			w.Write(diagLogPage([]map[string]any{
				auditRow("2026-07-13T20:00:05", " line-A"),
			}, 1))
		case 2:
			// Third poll: the same boundary row again, plus one genuinely new
			// row a second later.
			w.Write(diagLogPage([]map[string]any{
				auditRow("2026-07-13T20:00:06", " line-B"),
				auditRow("2026-07-13T20:00:05", " line-A"),
			}, 2))
		default:
			t.Fatalf("unexpected extra call %d", call)
		}
	}))
	defer server.Close()

	client := newDiagLogTestClient(t, server)
	s := newTestDiagLogSource(client, []options.DiagLogScope{{Module: "core", Scope: "audit"}}, func() time.Time { return fixedNow })

	if _, err := s.Poll(context.Background()); err != nil { // bootstrap
		t.Fatalf("bootstrap error: %v", err)
	}
	recs1, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll 2 error: %v", err)
	}
	if len(recs1) != 1 || recs1[0].Body != "line-A" {
		t.Fatalf("poll 2 = %+v, want exactly [line-A]", recs1)
	}

	recs2, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll 3 error: %v", err)
	}
	if len(recs2) != 1 || recs2[0].Body != "line-B" {
		t.Fatalf("poll 3 = %+v, want exactly [line-B] (line-A deduped)", recs2)
	}
}

// A scope that currently has no matching rows must not error or crash.
func TestDiagLogSource_EmptyScopeNoRecords(t *testing.T) {
	fixedNow := time.Date(2026, 7, 13, 20, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(diagLogPage(nil, 0))
	}))
	defer server.Close()

	client := newDiagLogTestClient(t, server)
	s := newTestDiagLogSource(client, []options.DiagLogScope{{Module: "core", Scope: "portalauth"}}, func() time.Time { return fixedNow })

	if _, err := s.Poll(context.Background()); err != nil { // bootstrap
		t.Fatalf("bootstrap error: %v", err)
	}
	recs, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll error: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("expected no records, got %+v", recs)
	}
}

// Multiple configured scopes are multiplexed within one Poll call, each
// tagged with its own module/scope attributes, hitting distinct endpoints.
func TestDiagLogSource_MultiScopeMultiplexed(t *testing.T) {
	fixedNow := time.Date(2026, 7, 13, 20, 0, 0, 0, time.UTC)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/diagnostics/log/core/audit", func(w http.ResponseWriter, r *http.Request) {
		w.Write(diagLogPage([]map[string]any{auditRow("2026-07-13T20:00:05", " audit-line")}, 1))
	})
	mux.HandleFunc("/api/diagnostics/log/core/gateways", func(w http.ResponseWriter, r *http.Request) {
		w.Write(diagLogPage([]map[string]any{auditRow("2026-07-13T20:00:05", " gateway-line")}, 1))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newDiagLogTestClient(t, server)
	scopes := []options.DiagLogScope{{Module: "core", Scope: "audit"}, {Module: "core", Scope: "gateways"}}
	s := newTestDiagLogSource(client, scopes, func() time.Time { return fixedNow })

	if _, err := s.Poll(context.Background()); err != nil { // bootstrap both
		t.Fatalf("bootstrap error: %v", err)
	}
	recs, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll error: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("got %d records, want 2: %+v", len(recs), recs)
	}
	byScope := map[string]Record{}
	for _, r := range recs {
		byScope[r.Attributes["scope"]] = r
	}
	if byScope["audit"].Body != "audit-line" || byScope["gateways"].Body != "gateway-line" {
		t.Errorf("scope-tagged bodies wrong: %+v", byScope)
	}
}

// One scope failing must not discard another scope's records.
func TestDiagLogSource_PartialScopeFailureStillEmitsOthers(t *testing.T) {
	fixedNow := time.Date(2026, 7, 13, 20, 0, 0, 0, time.UTC)
	mux := http.NewServeMux()
	mux.HandleFunc("/api/diagnostics/log/core/audit", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	})
	mux.HandleFunc("/api/diagnostics/log/core/gateways", func(w http.ResponseWriter, r *http.Request) {
		w.Write(diagLogPage([]map[string]any{auditRow("2026-07-13T20:00:05", " gateway-line")}, 1))
	})
	server := httptest.NewServer(mux)
	defer server.Close()

	client := newDiagLogTestClient(t, server)
	scopes := []options.DiagLogScope{{Module: "core", Scope: "audit"}, {Module: "core", Scope: "gateways"}}
	s := newTestDiagLogSource(client, scopes, func() time.Time { return fixedNow })

	if _, err := s.Poll(context.Background()); err != nil { // bootstrap both
		t.Fatalf("bootstrap error: %v", err)
	}
	recs, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("expected nil error on partial success, got %v", err)
	}
	if len(recs) != 1 || recs[0].Attributes["scope"] != "gateways" {
		t.Fatalf("expected only the gateways record, got %+v", recs)
	}
}

// When EVERY configured scope fails, Poll must surface an error (for
// logs_poll_errors_total visibility) rather than silently reporting success.
func TestDiagLogSource_AllScopesFailReturnsError(t *testing.T) {
	fixedNow := time.Date(2026, 7, 13, 20, 0, 0, 0, time.UTC)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("boom"))
	}))
	defer server.Close()

	client := newDiagLogTestClient(t, server)
	s := newTestDiagLogSource(client, []options.DiagLogScope{{Module: "core", Scope: "audit"}}, func() time.Time { return fixedNow })

	if _, err := s.Poll(context.Background()); err != nil { // bootstrap
		t.Fatalf("bootstrap error: %v", err)
	}
	recs, err := s.Poll(context.Background())
	if err == nil {
		t.Fatal("expected an error when every scope fails")
	}
	if len(recs) != 0 {
		t.Errorf("expected no records, got %+v", recs)
	}
}

// A scope whose backlog exceeds the page cap must still advance the cursor to
// the newest row it DID see (freshness over completeness), and log a warning
// (verified indirectly here by exercising the path without panicking/erroring;
// the exact warning text is not asserted to keep this test resilient to
// wording changes).
func TestDiagLogSource_PageCapTruncatesWithoutError(t *testing.T) {
	fixedNow := time.Date(2026, 7, 13, 20, 0, 0, 0, time.UTC)
	pageCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		pageCalls++
		rows := []map[string]any{auditRow(fmt.Sprintf("2026-07-13T20:00:%02d", 59-pageCalls), " line")}
		// Report far more total_rows than diagLogMaxPagesPerScope*diagLogPageSize
		// could ever drain, forcing truncation on every call.
		w.Write(diagLogPage(rows, diagLogMaxPagesPerScope*diagLogPageSize+1000))
	}))
	defer server.Close()

	client := newDiagLogTestClient(t, server)
	s := newTestDiagLogSource(client, []options.DiagLogScope{{Module: "core", Scope: "audit"}}, func() time.Time { return fixedNow })

	if _, err := s.Poll(context.Background()); err != nil { // bootstrap
		t.Fatalf("bootstrap error: %v", err)
	}
	pageCalls = 0
	recs, err := s.Poll(context.Background())
	if err != nil {
		t.Fatalf("poll error: %v", err)
	}
	if pageCalls != diagLogMaxPagesPerScope {
		t.Errorf("expected exactly %d page requests, got %d", diagLogMaxPagesPerScope, pageCalls)
	}
	if len(recs) != diagLogMaxPagesPerScope {
		t.Errorf("expected %d records (one per page), got %d", diagLogMaxPagesPerScope, len(recs))
	}
}

func TestDiagLogSource_LoadStateRoundTrip(t *testing.T) {
	s := newTestDiagLogSource(nil, []options.DiagLogScope{{Module: "core", Scope: "audit"}}, time.Now)
	s.LoadState([]byte(`{"core/audit": 1752345678}`))

	s.mu.Lock()
	cur, ok := s.cursors["core/audit"]
	s.mu.Unlock()
	if !ok || cur.LastEpoch != 1752345678 {
		t.Fatalf("LoadState did not restore cursor: %+v", s.cursors)
	}

	data, ok := s.SaveState()
	if !ok {
		t.Fatal("expected SaveState to report data present")
	}
	var blob map[string]int64
	if err := json.Unmarshal(data, &blob); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if blob["core/audit"] != 1752345678 {
		t.Errorf("round-tripped cursor = %d, want 1752345678", blob["core/audit"])
	}
}

func TestDiagLogSource_LoadStateCorruptDataIsNonFatal(t *testing.T) {
	s := newTestDiagLogSource(nil, nil, time.Now)
	s.LoadState([]byte(`not json`))
	if _, ok := s.SaveState(); ok {
		t.Error("expected no cursors after a corrupt LoadState")
	}
}

func TestDiagLogSource_SaveStateEmptyBeforeAnyPoll(t *testing.T) {
	s := newTestDiagLogSource(nil, nil, time.Now)
	if _, ok := s.SaveState(); ok {
		t.Error("expected SaveState to report nothing to persist before any Poll")
	}
}

func TestDiagLogSeverityMap(t *testing.T) {
	cases := []struct {
		in   string
		want Severity
	}{
		{"Emergency", SeverityFatal},
		{"Alert", SeverityFatal},
		{"Critical", SeverityFatal},
		{"Error", SeverityError},
		{"Warning", SeverityWarn},
		{"Notice", SeverityInfo},
		{"Informational", SeverityInfo},
		{"Debug", SeverityDebug},
		{"", SeverityInfo},
		{"SomethingUnknown", SeverityInfo},
	}
	for _, tc := range cases {
		if got := diagLogSeverityMap[tc.in]; got != tc.want && (tc.want != SeverityInfo || diagLogSeverityMap[tc.in] != 0) {
			t.Errorf("severity(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestDiagLogAuditConfigChangeRegex(t *testing.T) {
	cases := []struct {
		line     string
		wantUser string
		wantRev  string
		wantURI  string
		wantOK   bool
	}{
		{
			line:     " user root@127.0.0.1 changed configuration to /conf/backup/config-1783966326.1603.xml in /api/relayd/settings/set/virtualserver /api/relayd/settings/set/virtualserver made changes",
			wantUser: "root@127.0.0.1", wantRev: "/conf/backup/config-1783966326.1603.xml", wantURI: "/api/relayd/settings/set/virtualserver", wantOK: true,
		},
		{
			line:     " user (root) changed configuration to /conf/backup/config-1783966140.0959.xml in /usr/local/opnsense/scripts/nginx/ngx_autoblock.php /usr/local/opnsense/scripts/nginx/ngx_autoblock.php made changes",
			wantUser: "(root)", wantRev: "/conf/backup/config-1783966140.0959.xml", wantURI: "/usr/local/opnsense/scripts/nginx/ngx_autoblock.php", wantOK: true,
		},
		{line: " action allowed system.diag.log for user root", wantOK: false},
	}
	for _, tc := range cases {
		m := diagLogAuditConfigChange.FindStringSubmatch(tc.line)
		if tc.wantOK && m == nil {
			t.Errorf("expected match for %q", tc.line)
			continue
		}
		if !tc.wantOK {
			if m != nil {
				t.Errorf("expected no match for %q, got %v", tc.line, m)
			}
			continue
		}
		if m[1] != tc.wantUser || m[2] != tc.wantRev || m[3] != tc.wantURI {
			t.Errorf("line %q: got user=%q rev=%q uri=%q, want user=%q rev=%q uri=%q", tc.line, m[1], m[2], m[3], tc.wantUser, tc.wantRev, tc.wantURI)
		}
	}
}

func TestParseDiagLogTimestamp(t *testing.T) {
	epoch, ok := parseDiagLogTimestamp("2026-07-13T20:22:11")
	if !ok {
		t.Fatal("expected ok=true")
	}
	want := time.Date(2026, 7, 13, 20, 22, 11, 0, time.UTC).Unix()
	if epoch != want {
		t.Errorf("epoch = %d, want %d", epoch, want)
	}

	if _, ok := parseDiagLogTimestamp("not-a-timestamp"); ok {
		t.Error("expected ok=false for garbage input")
	}
}
