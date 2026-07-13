package opnsense

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Fixtures sanitised from live OPNsense 26.7 captures (dev-box, TESTLAN,
// 3 ET Open rulesets, one real GPL ATTACK_RESPONSE alert).

const idsStatusFixture = `{"status":"running","widget":{"caption_restart":"Restart","caption_start":"Start","caption_stop":"Stop"}}`

// idsSettingsModeFixture is the 26.7 shape: general.mode selector, no general.ips.
const idsSettingsModeFixture = `{"ids":{"general":{"enabled":"1","promisc":"0",
  "mode":{"pcap":{"value":"PCAP live mode (IDS)","selected":0},
          "netmap":{"value":"Netmap (IPS)","selected":1},
          "divert":{"value":"Divert (IPS)","selected":0}},
  "interfaces":{"opt1":{"value":"TESTLAN","selected":1}}}}}`

// idsSettingsLegacyFixture is the <=26.1 shape: boolean general.ips, no mode.
const idsSettingsLegacyFixture = `{"ids":{"general":{"enabled":"1","promisc":"1","ips":"1"}}}`

// idsSettingsPassiveFixture is pcap IDS mode with promiscuous off.
const idsSettingsPassiveFixture = `{"ids":{"general":{"enabled":"1","promisc":"0",
  "mode":{"pcap":{"value":"PCAP live mode (IDS)","selected":1},
          "netmap":{"value":"Netmap (IPS)","selected":0},
          "divert":{"value":"Divert (IPS)","selected":0}}}}}`

const idsAlertLogsFixture = `[{"size":1994,"modified":"2026/07/13 18:15","filename":"eve.json","sequence":null},
  {"size":10485760,"modified":"2026/07/06 00:00","filename":"eve.json.1","sequence":1}]`

const idsRulesetsFixture = `{"total":3,"rowCount":3,"current":1,"rows":[
  {"description":"abuse.ch/Feodo Tracker","filename":"abuse.ch.feodotracker.rules","modified_local":null,"enabled":"0"},
  {"description":"ET attack response","filename":"emerging-attack_response.rules","modified_local":"2026/07/13 18:11","enabled":"1"},
  {"description":"ET scan","filename":"emerging-scan.rules","modified_local":"2026/07/13 18:11","enabled":"1"}]}`

const idsInstalledRulesFixture = `{"rows":[{"sid":2000499}],"rowCount":1,"total":1966,"current":1}`

func TestFetchIDS_Populated(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/ids/service/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(idsStatusFixture))
	})
	mux.HandleFunc("/api/ids/settings/get", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(idsSettingsModeFixture))
	})
	mux.HandleFunc("/api/ids/service/get_alert_logs", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(idsAlertLogsFixture))
	})
	mux.HandleFunc("/api/ids/settings/list_rulesets", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(idsRulesetsFixture))
	})
	mux.HandleFunc("/api/ids/settings/searchInstalledRules", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if got := r.FormValue("rowCount"); got != "1" {
			t.Errorf("searchInstalledRules rowCount = %q, want 1 (count-only)", got)
		}
		w.Write([]byte(idsInstalledRulesFixture))
	})

	info, err := client.FetchIDS()
	if err != nil {
		t.Fatalf("FetchIDS: %v", err)
	}
	if info.Status != "running" {
		t.Errorf("Status = %q, want running", info.Status)
	}
	if !info.IPSMode {
		t.Error("IPSMode = false, want true (netmap selected)")
	}
	if info.PromiscuousMode {
		t.Error("PromiscuousMode = true, want false")
	}
	if len(info.AlertLogs) != 2 {
		t.Fatalf("AlertLogs = %d, want 2", len(info.AlertLogs))
	}
	if info.AlertLogs[0].Filename != "eve.json" || info.AlertLogs[0].SizeBytes != 1994 {
		t.Errorf("AlertLogs[0] = %+v", info.AlertLogs[0])
	}
	if info.InstalledRulesTotal != 1966 {
		t.Errorf("InstalledRulesTotal = %v, want 1966", info.InstalledRulesTotal)
	}
	if len(info.Rulesets) != 3 {
		t.Fatalf("Rulesets = %d, want 3", len(info.Rulesets))
	}
	// Disabled + never-downloaded ruleset.
	if info.Rulesets[0].Enabled || info.Rulesets[0].HasLastUpdated {
		t.Errorf("Rulesets[0] = %+v, want disabled + no timestamp", info.Rulesets[0])
	}
	// Enabled + downloaded ruleset carries a parsed timestamp.
	if !info.Rulesets[1].Enabled || !info.Rulesets[1].HasLastUpdated {
		t.Errorf("Rulesets[1] = %+v, want enabled + timestamp", info.Rulesets[1])
	}
	wantTS := float64(time.Date(2026, 7, 13, 18, 11, 0, 0, time.UTC).Unix())
	if info.Rulesets[1].LastUpdated != wantTS {
		t.Errorf("Rulesets[1].LastUpdated = %v, want %v", info.Rulesets[1].LastUpdated, wantTS)
	}
}

// TestFetchIDS_LegacyIPSField proves the <=26.1 boolean general.ips is honoured.
func TestFetchIDS_LegacyIPSField(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/ids/service/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"status":"running"}`))
	})
	mux.HandleFunc("/api/ids/settings/get", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(idsSettingsLegacyFixture))
	})
	mux.HandleFunc("/api/ids/service/get_alert_logs", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/api/ids/settings/list_rulesets", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	mux.HandleFunc("/api/ids/settings/searchInstalledRules", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})

	info, err := client.FetchIDS()
	if err != nil {
		t.Fatalf("FetchIDS: %v", err)
	}
	if !info.IPSMode {
		t.Error("IPSMode = false, want true (legacy ips=1)")
	}
	if !info.PromiscuousMode {
		t.Error("PromiscuousMode = false, want true (promisc=1)")
	}
	if len(info.AlertLogs) != 0 || len(info.Rulesets) != 0 || info.InstalledRulesTotal != 0 {
		t.Errorf("expected fully empty structures, got %+v", info)
	}
}

// TestFetchIDS_PassiveIDS proves pcap mode reports IPSMode=false.
func TestFetchIDS_PassiveIDS(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/ids/service/status", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"status":"disabled"}`))
	})
	mux.HandleFunc("/api/ids/settings/get", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(idsSettingsPassiveFixture))
	})
	mux.HandleFunc("/api/ids/service/get_alert_logs", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`[]`))
	})
	mux.HandleFunc("/api/ids/settings/list_rulesets", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"total":0,"rowCount":0,"current":1,"rows":[]}`))
	})
	mux.HandleFunc("/api/ids/settings/searchInstalledRules", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})

	info, err := client.FetchIDS()
	if err != nil {
		t.Fatalf("FetchIDS: %v", err)
	}
	if info.IPSMode {
		t.Error("IPSMode = true, want false (pcap IDS mode)")
	}
	if info.Status != "disabled" {
		t.Errorf("Status = %q, want disabled", info.Status)
	}
}

func TestFetchIDSRecentAlerts_WindowAndActions(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	now := time.Now()
	// Two alerts in-window (one allowed, one blocked), one stale (out of window).
	inA := now.Add(-2 * time.Minute).Format("2006-01-02T15:04:05.000000-0700")
	inB := now.Add(-5 * time.Minute).Format("2006-01-02T15:04:05.000000-0700")
	stale := now.Add(-2 * time.Hour).Format("2006-01-02T15:04:05.000000-0700")
	body := fmt.Sprintf(`{"filters":[],"origin":"eve.json","rowCount":3,"total":4,"current":1,"rows":[
	  {"timestamp":%q,"alert_sid":2100498,"alert_action":"allowed"},
	  {"timestamp":%q,"alert_sid":2000001,"alert_action":"blocked"},
	  {"timestamp":%q,"alert_sid":2000002,"alert_action":"allowed"}]}`, inA, inB, stale)

	var gotRowCount string
	mux.HandleFunc("/api/ids/service/query_alerts", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotRowCount = r.FormValue("rowCount")
		w.Write([]byte(body))
	})

	act, err := client.FetchIDSRecentAlerts(15 * time.Minute)
	if err != nil {
		t.Fatalf("FetchIDSRecentAlerts: %v", err)
	}
	if gotRowCount != "500" {
		t.Errorf("query_alerts rowCount = %q, want 500 (capped)", gotRowCount)
	}
	if act.ByAction["allowed"] != 1 {
		t.Errorf("allowed = %v, want 1 (stale alert excluded)", act.ByAction["allowed"])
	}
	if act.ByAction["blocked"] != 1 {
		t.Errorf("blocked = %v, want 1", act.ByAction["blocked"])
	}
}

// TestFetchIDSRecentAlerts_EmptyKeepsSeries proves both action keys stay present
// (0) with no alerts, so the gauge never disappears.
func TestFetchIDSRecentAlerts_EmptyKeepsSeries(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/ids/service/query_alerts", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"filters":[],"origin":"eve.json","rowCount":0,"total":0,"current":1,"rows":[]}`))
	})

	act, err := client.FetchIDSRecentAlerts(15 * time.Minute)
	if err != nil {
		t.Fatalf("FetchIDSRecentAlerts: %v", err)
	}
	for _, action := range []string{"allowed", "blocked"} {
		if v, ok := act.ByAction[action]; !ok || v != 0 {
			t.Errorf("ByAction[%q] = (%v, present=%v), want 0/present", action, v, ok)
		}
	}
}

// idsAlertRecordFixture is the live capture from the #203 provisioning box
// (dev-box, TESTLAN): one real GPL ATTACK_RESPONSE alert with a full eve
// record, including fields FetchIDSAlertRecords does not model as typed
// fields (the nested "flow" object, "app_proto", "event_type", "ip_v",
// "pkt_src", "direction", "filepos", "fileid") — these must still survive
// verbatim in Body.
const idsAlertRecordFixture = `{"filters":[],"rows":[{"timestamp":"2026-07-13T18:15:59.475210+0100",` +
	`"flow_id":2219106199071770,"in_iface":"vtnet2","event_type":"alert","src_ip":"52.85.47.113",` +
	`"src_port":80,"dest_ip":"172.16.9.50","dest_port":57018,"proto":"TCP","ip_v":4,` +
	`"pkt_src":"wire/pcap","alert":"GPL ATTACK_RESPONSE id check returned root","app_proto":"http",` +
	`"direction":"to_client","flow":{"pkts_toserver":5,"pkts_toclient":4,"bytes_toserver":430,` +
	`"bytes_toclient":810,"start":"2026-07-13T18:15:59.451139+0100","src_ip":"172.16.9.50",` +
	`"dest_ip":"52.85.47.113","src_port":57018,"dest_port":80},"filepos":1993,"fileid":"",` +
	`"alert_sid":2100498,"alert_action":"allowed"}],"origin":"eve.json","rowCount":1,"total":1,"current":1}`

func TestFetchIDSAlertRecords_FullRecord(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	var gotRowCount string
	mux.HandleFunc("/api/ids/service/query_alerts", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		gotRowCount = r.FormValue("rowCount")
		w.Write([]byte(idsAlertRecordFixture))
	})

	records, err := client.FetchIDSAlertRecords()
	if err != nil {
		t.Fatalf("FetchIDSAlertRecords: %v", err)
	}
	if gotRowCount != "500" {
		t.Errorf("query_alerts rowCount = %q, want 500 (shared cap with FetchIDSRecentAlerts)", gotRowCount)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1", len(records))
	}

	r := records[0]
	wantTS, perr := time.Parse("2006-01-02T15:04:05.999999-0700", "2026-07-13T18:15:59.475210+0100")
	if perr != nil {
		t.Fatalf("test fixture timestamp parse: %v", perr)
	}
	if !r.Timestamp.Equal(wantTS) {
		t.Errorf("Timestamp = %v, want %v", r.Timestamp, wantTS)
	}
	if r.FlowID != 2219106199071770 {
		t.Errorf("FlowID = %d, want 2219106199071770", r.FlowID)
	}
	if r.AlertSID != 2100498 {
		t.Errorf("AlertSID = %d, want 2100498", r.AlertSID)
	}
	if r.AlertAction != "allowed" {
		t.Errorf("AlertAction = %q, want allowed", r.AlertAction)
	}
	if r.Signature != "GPL ATTACK_RESPONSE id check returned root" {
		t.Errorf("Signature = %q", r.Signature)
	}
	if r.SrcIP != "52.85.47.113" || r.DestIP != "172.16.9.50" {
		t.Errorf("SrcIP/DestIP = %q/%q", r.SrcIP, r.DestIP)
	}
	if r.InIface != "vtnet2" {
		t.Errorf("InIface = %q, want vtnet2", r.InIface)
	}
	if r.Proto != "TCP" {
		t.Errorf("Proto = %q, want TCP", r.Proto)
	}

	// Body must carry the FULL record verbatim, including fields no typed field
	// above models (this is "ship full alert records", not a lossy subset).
	for _, want := range []string{
		`"flow_id":2219106199071770`, `"app_proto":"http"`, `"event_type":"alert"`,
		`"filepos":1993`, `"fileid":""`, `"ip_v":4`, `"pkt_src":"wire/pcap"`,
		`"direction":"to_client"`, `"flow":{`, `"pkts_toserver":5`,
	} {
		if !strings.Contains(r.Body, want) {
			t.Errorf("Body missing %q; got %s", want, r.Body)
		}
	}
	// Body must be compact (no indentation/newlines).
	if strings.ContainsAny(r.Body, "\n\t") {
		t.Errorf("Body is not compact: %s", r.Body)
	}
}

func TestFetchIDSAlertRecords_DropsRowWithoutTimestamp(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/ids/service/query_alerts", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"rows":[
		  {"timestamp":"","alert_sid":1,"alert_action":"allowed"},
		  {"timestamp":"2026-07-13T18:15:59.475210+0100","alert_sid":2,"alert_action":"blocked","flow_id":42}
		],"rowCount":2,"total":2,"current":1}`))
	})

	records, err := client.FetchIDSAlertRecords()
	if err != nil {
		t.Fatalf("FetchIDSAlertRecords: %v", err)
	}
	if len(records) != 1 {
		t.Fatalf("records = %d, want 1 (the timestamp-less row must be dropped)", len(records))
	}
	if records[0].AlertSID != 2 {
		t.Errorf("surviving record AlertSID = %d, want 2", records[0].AlertSID)
	}
}

func TestFetchIDSAlertRecords_Empty(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/ids/service/query_alerts", func(w http.ResponseWriter, _ *http.Request) {
		w.Write([]byte(`{"rows":[],"rowCount":0,"total":0,"current":1}`))
	})

	records, err := client.FetchIDSAlertRecords()
	if err != nil {
		t.Fatalf("FetchIDSAlertRecords: %v", err)
	}
	if len(records) != 0 {
		t.Fatalf("records = %d, want 0", len(records))
	}
}

func TestParseIDSAlertTime(t *testing.T) {
	cases := map[string]bool{
		"2026-07-13T18:15:59.475210+0100": true,
		"2026-07-13T18:15:59+0100":        true,
		"2026-07-13T18:15:59.475210Z":     true,
		"":                                false,
		"not-a-time":                      false,
	}
	for in, wantOK := range cases {
		if _, ok := parseIDSAlertTime(in); ok != wantOK {
			t.Errorf("parseIDSAlertTime(%q) ok = %v, want %v", in, ok, wantOK)
		}
	}
}
