package opnsense

import (
	"net/http"
	"testing"
)

const haproxyCountersFixture = `[
  {"pxname":"web_frontend","svname":"FRONTEND","qcur":"","qmax":"","scur":"3","smax":"10","slim":"2000","stot":"5000","bin":"123456","bout":"654321","dreq":"7","dresp":"0","ereq":"42","econ":"","eresp":"","wretr":"","wredis":"","status":"OPEN","weight":"","act":"","bck":"","chkfail":"","chkdown":"","lastchg":"","downtime":"","qlimit":"","pid":"1","iid":"2","sid":"0","throttle":"","lbtot":"","tracked":"","type":"0","rate":"1","rate_lim":"0","rate_max":"5","check_status":"","check_code":"","check_duration":"","hrsp_1xx":"0","hrsp_2xx":"4800","hrsp_3xx":"100","hrsp_4xx":"80","hrsp_5xx":"20","hrsp_other":"0","id":"web_frontend/FRONTEND"},
  {"pxname":"web_backend","svname":"srv1","qcur":"0","qmax":"2","scur":"2","smax":"8","slim":"","stot":"3000","bin":"100000","bout":"500000","dreq":"","dresp":"0","ereq":"","econ":"3","eresp":"5","wretr":"9","wredis":"1","status":"UP","weight":"100","act":"1","bck":"0","chkfail":"2","chkdown":"1","lastchg":"3600","downtime":"120","qlimit":"","pid":"1","iid":"3","sid":"1","throttle":"","lbtot":"2990","tracked":"","type":"2","rate":"1","rate_lim":"","rate_max":"4","check_status":"L4OK","check_code":"","check_duration":"0","hrsp_1xx":"0","hrsp_2xx":"2900","hrsp_3xx":"50","hrsp_4xx":"40","hrsp_5xx":"10","hrsp_other":"0","id":"web_backend/srv1"},
  {"pxname":"web_backend","svname":"BACKEND","qcur":"1","qmax":"3","scur":"2","smax":"8","slim":"200","stot":"3000","bin":"100000","bout":"500000","dreq":"0","dresp":"0","ereq":"","econ":"3","eresp":"5","wretr":"9","wredis":"1","status":"UP","weight":"100","act":"1","bck":"0","chkfail":"","chkdown":"","lastchg":"3600","downtime":"120","qlimit":"","pid":"1","iid":"3","sid":"0","throttle":"","lbtot":"2990","tracked":"","type":"1","rate":"1","rate_lim":"","rate_max":"4","check_status":"","check_code":"","check_duration":"","hrsp_1xx":"0","hrsp_2xx":"2900","hrsp_3xx":"50","hrsp_4xx":"40","hrsp_5xx":"10","hrsp_other":"0","id":"web_backend/BACKEND"},
  {"pxname":"web_frontend","svname":"sock-1","type":"3","scur":"0","stot":"0","status":"OPEN","id":"web_frontend/sock-1"},
  [""]
]`

const haproxyInfoFixture = `{"Name":"HAProxy","Version":"2.8.3","Uptime_sec":"86400","CurrConns":"4","CumConns":"9876","CumReq":"55555","Idle_pct":"99","Tasks":"42"}`

// haproxyTablesFixture mirrors a real dev-box capture (issue #201,
// captures/haproxy/stats_tables.json): a frontend stick-table with used>0.
const haproxyTablesFixture = `[{"table":"bk-heavy","type":"ip","size":"51200","used":"1"},{"table":"bk-gui","type":"ip","size":"51200","used":"0"},{"table":"ft-heavy","type":"ip","size":"102400","used":"1"}]`

// haproxyCountersPopulatedFixture is a trimmed-down replica of a real dev-box
// capture (issue #201, captures/haproxy/stats_counters_populated.json): a
// FRONTEND row + a 2-server HTTP backend, carrying the qtime/ctime/rtime/ttime,
// slim, req_tot, lbtot, cli_abrt/srv_abrt and chkdown/lastchg fields added for
// #201. Trimmed to the fields this package parses.
const haproxyCountersPopulatedFixture = `[
  {"pxname":"ft-heavy","svname":"FRONTEND","scur":"0","stot":"179","slim":"117337","dreq":"0","ereq":"0","req_tot":"179","status":"OPEN","type":"0","qtime":"","ctime":"","rtime":"","ttime":"","cli_abrt":"","srv_abrt":"","lbtot":"","hrsp_2xx":"179","id":"ft-heavy/FRONTEND"},
  {"pxname":"bk-heavy","svname":"heavy-1","qcur":"0","scur":"0","stot":"179","bin":"14678","bout":"34368","status":"UP","weight":"1","act":"1","bck":"0","chkfail":"0","chkdown":"0","lastchg":"54","downtime":"0","type":"2","qtime":"0","ctime":"0","rtime":"1","ttime":"1","lbtot":"1","id":"bk-heavy/heavy-1"},
  {"pxname":"bk-heavy","svname":"heavy-2","qcur":"0","scur":"0","stot":"0","bin":"0","bout":"0","status":"UP","weight":"1","act":"1","bck":"0","chkfail":"0","chkdown":"0","lastchg":"54","downtime":"0","type":"2","qtime":"0","ctime":"0","rtime":"0","ttime":"0","lbtot":"0","id":"bk-heavy/heavy-2"},
  {"pxname":"bk-heavy","svname":"BACKEND","qcur":"0","scur":"0","stot":"179","bin":"14678","bout":"34368","slim":"11734","status":"UP","weight":"2","act":"2","bck":"0","lastchg":"54","downtime":"0","type":"1","qtime":"0","ctime":"0","rtime":"1","ttime":"1","lbtot":"1","cli_abrt":"0","srv_abrt":"0","req_tot":"179","hrsp_2xx":"179","id":"bk-heavy/BACKEND"}
]`

// haproxyInfoPopulatedFixture mirrors captures/haproxy/stats_info_populated.json,
// carrying the Maxconn/CurrSslConns fields added for #201.
const haproxyInfoPopulatedFixture = `{"Name":"HAProxy","Version":"3.2.21-dbe43be37","Uptime_sec":"53","CurrConns":"0","CumConns":"232","CumReq":"232","Idle_pct":"100","Maxconn":"117337","CurrSslConns":"0"}`

// haproxyCountersChkdownFixture mirrors captures/haproxy/stats_counters_chkdown.json:
// a live UP->DOWN transition captured by killing one backend server
// (heavy-2: status UP->DOWN, chkdown 0->1, lastchg 54->12, downtime 0->12).
const haproxyCountersChkdownFixture = `[
  {"pxname":"bk-heavy","svname":"heavy-2","qcur":"0","scur":"0","stot":"0","bin":"0","bout":"0","status":"DOWN","weight":"1","act":"1","bck":"0","chkfail":"1","chkdown":"1","lastchg":"12","downtime":"12","type":"2","qtime":"0","ctime":"0","rtime":"0","ttime":"0","lbtot":"0","id":"bk-heavy/heavy-2"}
]`

// haproxyRegisterHandlers registers the statistics handlers on an existing mux.
func haproxyRegisterHandlers(t *testing.T, mux *http.ServeMux, counters, info string) {
	t.Helper()
	mux.HandleFunc("/api/haproxy/statistics/counters", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(counters))
	})
	mux.HandleFunc("/api/haproxy/statistics/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(info))
	})
}

// haproxyRegisterAllHandlers additionally registers the stick-table endpoint
// (issue #201), for tests that need it populated rather than 404-tolerated.
func haproxyRegisterAllHandlers(t *testing.T, mux *http.ServeMux, counters, info, tables string) {
	t.Helper()
	haproxyRegisterHandlers(t, mux, counters, info)
	mux.HandleFunc("/api/haproxy/statistics/tables", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(tables))
	})
}

func TestFetchHAProxyStats_Normal(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	haproxyRegisterHandlers(t, mux, haproxyCountersFixture, haproxyInfoFixture)

	data, err := client.FetchHAProxyStats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true when counters endpoint responds")
	}
	if len(data.Frontends) != 1 || len(data.Backends) != 1 || len(data.Servers) != 1 {
		t.Fatalf("expected 1 frontend, 1 backend, 1 server; got %d/%d/%d",
			len(data.Frontends), len(data.Backends), len(data.Servers))
	}

	fe := data.Frontends[0]
	if fe.Name != "web_frontend" || fe.StatusUp != 1 || fe.CurrentSessions != 3 ||
		fe.SessionsTotal != 5000 || fe.BytesIn != 123456 || fe.BytesOut != 654321 ||
		fe.RequestErrors != 42 || fe.RequestsDenied != 7 {
		t.Errorf("frontend parsed wrong: %+v", fe)
	}
	if fe.ResponsesByCode["2xx"] != 4800 || fe.ResponsesByCode["5xx"] != 20 {
		t.Errorf("frontend responses parsed wrong: %+v", fe.ResponsesByCode)
	}

	be := data.Backends[0]
	if be.Name != "web_backend" || be.StatusUp != 1 || be.QueueCurrent != 1 ||
		be.ConnectionErrors != 3 || be.ResponseErrors != 5 || be.Retries != 9 ||
		be.Redispatches != 1 || be.ActiveServers != 1 || be.BackupServers != 0 {
		t.Errorf("backend parsed wrong: %+v", be)
	}

	srv := data.Servers[0]
	if srv.Backend != "web_backend" || srv.Name != "srv1" || srv.StatusUp != 1 ||
		srv.CheckFailures != 2 || srv.DowntimeSeconds != 120 || srv.Weight != 100 {
		t.Errorf("server parsed wrong: %+v", srv)
	}

	if !data.HasInfo || data.Info.UptimeSeconds != 86400 || data.Info.CurrentConnections != 4 ||
		data.Info.ConnectionsTotal != 9876 || data.Info.RequestsTotal != 55555 || data.Info.IdlePercent != 99 {
		t.Errorf("info parsed wrong: %+v (HasInfo=%v)", data.Info, data.HasInfo)
	}
}

// TestHAProxyResponses_EmptyVsZero guards #164: HAProxy leaves the hrsp_* cells
// empty for tcp-mode proxies (stat not applicable), which must be omitted — while
// a genuine "0" is preserved as a real zero, distinct from "not applicable".
func TestHAProxyResponses_EmptyVsZero(t *testing.T) {
	// tcp-mode proxy: all hrsp_* empty → no codes at all.
	tcp := haproxyResponses(haproxyStatRow{})
	if len(tcp) != 0 {
		t.Errorf("tcp-mode (empty hrsp cells) should yield no response codes, got %v", tcp)
	}

	// http proxy with genuine zeros and real values.
	http := haproxyResponses(haproxyStatRow{
		Hrsp1xx: "0", Hrsp2xx: "4800", Hrsp5xx: "20",
		// 3xx/4xx/other left empty (not applicable for this shape).
	})
	if v, ok := http["1xx"]; !ok || v != 0 {
		t.Errorf(`genuine "0" for 1xx must be preserved as 0, got (%v, present=%v)`, v, ok)
	}
	if v, ok := http["2xx"]; !ok || v != 4800 {
		t.Errorf("2xx should be 4800, got (%v, present=%v)", v, ok)
	}
	if _, ok := http["3xx"]; ok {
		t.Error("empty 3xx cell must be omitted")
	}
	if _, ok := http["4xx"]; ok {
		t.Error("empty 4xx cell must be omitted")
	}
}

func TestFetchHAProxyStats_PluginAbsent404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchHAProxyStats()
	if err != nil {
		t.Fatalf("expected nil error on 404 (feature absent), got: %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on 404 (plugin absent)")
	}
	if len(data.Frontends)+len(data.Backends)+len(data.Servers) != 0 || data.HasInfo {
		t.Errorf("expected empty data on 404, got: %+v", data)
	}
}

func TestFetchHAProxyStats_ServiceStoppedNullBodies(t *testing.T) {
	// queryStats.php exits with plain text when haproxy is down; the controller
	// json_decodes that to null and the API returns JSON "null".
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/haproxy/statistics/counters", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`null`))
	})
	mux.HandleFunc("/api/haproxy/statistics/info", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`null`))
	})

	data, err := client.FetchHAProxyStats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Error("expected Present=true for null bodies (plugin installed, service stopped)")
	}
	if len(data.Frontends)+len(data.Backends)+len(data.Servers) != 0 || data.HasInfo {
		t.Errorf("expected empty data for null bodies, got: %+v", data)
	}
}

// mustFloat dereferences a *float64 or fails the test — helper for asserting
// on the new #201 optional fields, which must never silently be nil for a
// populated fixture.
func mustFloat(t *testing.T, name string, v *float64) float64 {
	t.Helper()
	if v == nil {
		t.Fatalf("%s: expected non-nil value, got nil", name)
	}
	return *v
}

// TestFetchHAProxyStats_StickTables guards issue #201 part 1: stick-table
// occupancy from api/haproxy/statistics/tables, using a real dev-box capture
// (ft-heavy used=1, a stick table actually holding an entry).
func TestFetchHAProxyStats_StickTables(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	haproxyRegisterAllHandlers(t, mux, haproxyCountersFixture, haproxyInfoFixture, haproxyTablesFixture)

	data, err := client.FetchHAProxyStats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.StickTables) != 3 {
		t.Fatalf("expected 3 stick tables, got %d: %+v", len(data.StickTables), data.StickTables)
	}

	byName := map[string]HAProxyStickTable{}
	for _, tbl := range data.StickTables {
		byName[tbl.Table] = tbl
	}
	heavy, ok := byName["ft-heavy"]
	if !ok {
		t.Fatal("expected ft-heavy stick table")
	}
	if heavy.Type != "ip" || heavy.Size != 102400 || heavy.Used != 1 {
		t.Errorf("ft-heavy parsed wrong: %+v", heavy)
	}
	gui, ok := byName["bk-gui"]
	if !ok {
		t.Fatal("expected bk-gui stick table")
	}
	if gui.Used != 0 {
		t.Errorf("bk-gui should have used=0 (empty table), got %+v", gui)
	}
}

// TestFetchHAProxyStats_StickTablesAbsent404 guards backward compatibility:
// an older os-haproxy build without the tables route (or the endpoint 404ing
// for any other reason) must not fail the whole scrape — it tolerates the
// 404 like the info fetch does, leaving StickTables empty.
func TestFetchHAProxyStats_StickTablesAbsent404(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	haproxyRegisterHandlers(t, mux, haproxyCountersFixture, haproxyInfoFixture)
	// tables endpoint deliberately NOT registered -> mux answers 404.

	data, err := client.FetchHAProxyStats()
	if err != nil {
		t.Fatalf("expected nil error when tables endpoint 404s, got: %v", err)
	}
	if !data.Present {
		t.Error("expected Present=true: counters/info still succeeded")
	}
	if len(data.Frontends) != 1 || len(data.Backends) != 1 || len(data.Servers) != 1 {
		t.Error("expected counters/info data to still be populated despite tables 404")
	}
	if len(data.StickTables) != 0 {
		t.Errorf("expected no stick tables on 404, got %+v", data.StickTables)
	}
}

// TestFetchHAProxyStats_ExtendedFields guards issue #201 part 2: the
// qtime/ctime/rtime/ttime rolling averages, slim/req_tot/lbtot/cli_abrt/
// srv_abrt, and the info-level Maxconn/CurrSslConns fields, using a trimmed
// replica of a real dev-box capture (stats_counters_populated.json).
func TestFetchHAProxyStats_ExtendedFields(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	haproxyRegisterAllHandlers(t, mux,
		haproxyCountersPopulatedFixture, haproxyInfoPopulatedFixture, haproxyTablesFixture)

	data, err := client.FetchHAProxyStats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Frontends) != 1 || len(data.Backends) != 1 || len(data.Servers) != 2 {
		t.Fatalf("expected 1 frontend, 1 backend, 2 servers; got %d/%d/%d",
			len(data.Frontends), len(data.Backends), len(data.Servers))
	}

	fe := data.Frontends[0]
	if mustFloat(t, "frontend.RequestsTotal", fe.RequestsTotal) != 179 {
		t.Errorf("frontend RequestsTotal wrong: %v", fe.RequestsTotal)
	}
	if mustFloat(t, "frontend.SessionLimit", fe.SessionLimit) != 117337 {
		t.Errorf("frontend SessionLimit wrong: %v", fe.SessionLimit)
	}

	be := data.Backends[0]
	if mustFloat(t, "backend.ResponseTimeAvg", be.ResponseTimeAvg) != 0.001 {
		t.Errorf("backend ResponseTimeAvg wrong (rtime=1ms should be 0.001s): %v", *be.ResponseTimeAvg)
	}
	if mustFloat(t, "backend.TotalTimeAvg", be.TotalTimeAvg) != 0.001 {
		t.Errorf("backend TotalTimeAvg wrong: %v", *be.TotalTimeAvg)
	}
	if mustFloat(t, "backend.QueueTimeAvg", be.QueueTimeAvg) != 0 {
		t.Errorf("backend QueueTimeAvg wrong: %v", *be.QueueTimeAvg)
	}
	if mustFloat(t, "backend.SelectedTotal", be.SelectedTotal) != 1 {
		t.Errorf("backend SelectedTotal (lbtot) wrong: %v", *be.SelectedTotal)
	}
	if mustFloat(t, "backend.ClientAborts", be.ClientAborts) != 0 {
		t.Errorf("backend ClientAborts wrong: %v", *be.ClientAborts)
	}
	if mustFloat(t, "backend.ServerAborts", be.ServerAborts) != 0 {
		t.Errorf("backend ServerAborts wrong: %v", *be.ServerAborts)
	}

	var heavy1, heavy2 *HAProxyServer
	for i := range data.Servers {
		switch data.Servers[i].Name {
		case "heavy-1":
			heavy1 = &data.Servers[i]
		case "heavy-2":
			heavy2 = &data.Servers[i]
		}
	}
	if heavy1 == nil || heavy2 == nil {
		t.Fatalf("expected servers heavy-1 and heavy-2, got %+v", data.Servers)
	}
	if mustFloat(t, "heavy1.ResponseTimeAvg", heavy1.ResponseTimeAvg) != 0.001 {
		t.Errorf("heavy-1 ResponseTimeAvg wrong: %v", *heavy1.ResponseTimeAvg)
	}
	if mustFloat(t, "heavy1.CheckDowns", heavy1.CheckDowns) != 0 {
		t.Errorf("heavy-1 CheckDowns wrong: %v", *heavy1.CheckDowns)
	}
	if mustFloat(t, "heavy1.LastStateChangeSeconds", heavy1.LastStateChangeSeconds) != 54 {
		t.Errorf("heavy-1 LastStateChangeSeconds wrong: %v", *heavy1.LastStateChangeSeconds)
	}
	if mustFloat(t, "heavy2.ResponseTimeAvg", heavy2.ResponseTimeAvg) != 0 {
		t.Errorf("heavy-2 ResponseTimeAvg wrong: %v", *heavy2.ResponseTimeAvg)
	}

	if !data.HasInfo {
		t.Fatal("expected HasInfo=true")
	}
	if mustFloat(t, "info.ConnectionLimit", data.Info.ConnectionLimit) != 117337 {
		t.Errorf("info ConnectionLimit (Maxconn) wrong: %v", *data.Info.ConnectionLimit)
	}
	if mustFloat(t, "info.SslCurrentConnections", data.Info.SslCurrentConnections) != 0 {
		t.Errorf("info SslCurrentConnections wrong: %v", *data.Info.SslCurrentConnections)
	}
}

// TestFetchHAProxyStats_CheckDownTransition guards the live DOWN transition
// captured for #201 (stats_counters_chkdown.json): killing a backend server
// flips status UP->DOWN, chkdown 0->1, and lastchg/downtime reset+advance.
func TestFetchHAProxyStats_CheckDownTransition(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	haproxyRegisterAllHandlers(t, mux,
		haproxyCountersChkdownFixture, haproxyInfoPopulatedFixture, haproxyTablesFixture)

	data, err := client.FetchHAProxyStats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(data.Servers))
	}
	srv := data.Servers[0]
	if srv.StatusUp != 0 {
		t.Errorf("expected StatusUp=0 for DOWN status, got %v", srv.StatusUp)
	}
	if mustFloat(t, "server.CheckDowns", srv.CheckDowns) != 1 {
		t.Errorf("expected CheckDowns=1 (chkdown transitioned), got %v", *srv.CheckDowns)
	}
	if mustFloat(t, "server.LastStateChangeSeconds", srv.LastStateChangeSeconds) != 12 {
		t.Errorf("expected LastStateChangeSeconds=12 (reset on transition), got %v", *srv.LastStateChangeSeconds)
	}
	if srv.DowntimeSeconds != 12 {
		t.Errorf("expected DowntimeSeconds=12 (accruing since the transition), got %v", srv.DowntimeSeconds)
	}
}

// TestHAProxyOptFloat_EmptyVsZero guards #164 for the new #201 fields:
// FRONTEND rows leave qtime/ctime/rtime/ttime/lbtot/cli_abrt/srv_abrt empty
// (they only apply to backend/server rows) — that must stay nil, never a
// fabricated 0, while a genuine "0" cell is preserved.
func TestHAProxyOptFloat_EmptyVsZero(t *testing.T) {
	if v := haproxyOptFloat(""); v != nil {
		t.Errorf("empty cell should yield nil, got %v", *v)
	}
	if v := haproxyOptFloat("0"); v == nil || *v != 0 {
		t.Errorf(`genuine "0" cell should yield a real 0, got %v`, v)
	}
	if v := haproxyMillisToSeconds(""); v != nil {
		t.Errorf("empty ms cell should yield nil, got %v", *v)
	}
	if v := haproxyMillisToSeconds("1500"); v == nil || *v != 1.5 {
		t.Errorf("1500ms should convert to 1.5s, got %v", v)
	}
}
