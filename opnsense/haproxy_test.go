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
