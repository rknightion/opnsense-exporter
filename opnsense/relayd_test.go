package opnsense

import (
	"net/http"
	"testing"
)

// relaydPopulatedResponse is the real capture from a dev-box heavy topology
// (issue #202): one redirect virtual server ("relay-vs"), one table
// ("relay-table:8080", 2 hosts), both hosts up at 100.00% availability.
const relaydPopulatedResponse = `{
	"result": "ok",
	"rows": [
		{
			"id": "1",
			"type": "redirect",
			"name": "relay-vs",
			"status": "active",
			"uuid": "b02d1b47-0c4e-4067-8c3a-d1fdfe97c8a9",
			"listen_address": "172.16.9.1",
			"listen_startport": "9090",
			"listen_endport": "",
			"tables": {
				"1": {
					"name": "relay-table:8080",
					"status": "active (2 hosts)",
					"uuid": "8fd9bbcd-38cd-46c4-ba1e-81f698d47b04",
					"hosts": {
						"1": {
							"properties": [
								{"uuid": "df4935f0-fda1-4cf0-b69b-2dbc20572a19", "name": "relay-h1", "enabled": "1"}
							],
							"name": "172.16.9.99",
							"avlblty": "100.00%",
							"status": "up"
						},
						"2": {
							"properties": [
								{"uuid": "34bcb6df-9373-458e-b255-a3a8de28d70c", "name": "relay-h2", "enabled": "1"}
							],
							"name": "172.16.9.98",
							"avlblty": "100.00%",
							"status": "up"
						}
					}
				}
			}
		}
	]
}`

func TestFetchRelaydStatus_Populated(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/relayd/status/sum", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		if wait := r.URL.Query().Get("wait"); wait != "" {
			t.Errorf("expected no wait param, got %q", wait)
		}
		w.Write([]byte(relaydPopulatedResponse))
	})

	data, err := client.FetchRelaydStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if !data.HasData {
		t.Fatal("expected HasData=true")
	}
	if len(data.VirtualServers) != 1 {
		t.Fatalf("expected 1 virtual server, got %d", len(data.VirtualServers))
	}

	vs := data.VirtualServers[0]
	if vs.Name != "relay-vs" {
		t.Errorf("expected name 'relay-vs', got %q", vs.Name)
	}
	if vs.Type != "redirect" {
		t.Errorf("expected type 'redirect', got %q", vs.Type)
	}
	if vs.Active != 1 {
		t.Errorf("expected virtualserver Active=1 for status 'active', got %v", vs.Active)
	}
	if len(vs.Tables) != 1 {
		t.Fatalf("expected 1 table, got %d", len(vs.Tables))
	}

	table := vs.Tables[0]
	if table.Name != "relay-table" {
		t.Errorf("expected table name 'relay-table' (port suffix stripped), got %q", table.Name)
	}
	if table.Active != 1 {
		t.Errorf("expected table Active=1 for status 'active (2 hosts)', got %v", table.Active)
	}
	if len(table.Hosts) != 2 {
		t.Fatalf("expected 2 hosts, got %d", len(table.Hosts))
	}

	byAddress := map[string]RelaydHost{}
	for _, h := range table.Hosts {
		byAddress[h.Address] = h
	}

	h1, ok := byAddress["172.16.9.99"]
	if !ok {
		t.Fatal("expected host with address 172.16.9.99")
	}
	if h1.Name != "relay-h1" {
		t.Errorf("expected friendly name 'relay-h1', got %q", h1.Name)
	}
	if h1.Up != 1 {
		t.Errorf("expected Up=1 for status 'up', got %v", h1.Up)
	}
	if !h1.HasAvailability {
		t.Fatal("expected HasAvailability=true")
	}
	if h1.AvailabilityPercent != 100.0 {
		t.Errorf("expected AvailabilityPercent=100.0, got %v", h1.AvailabilityPercent)
	}

	h2, ok := byAddress["172.16.9.98"]
	if !ok {
		t.Fatal("expected host with address 172.16.9.98")
	}
	if h2.Name != "relay-h2" {
		t.Errorf("expected friendly name 'relay-h2', got %q", h2.Name)
	}
}

// TestFetchRelaydStatus_StoppedNoTopology guards the dev-box-confirmed baseline
// shape: relayd stays STOPPED with configtest "no actions, nothing to do" until
// a real topology exists, and status/sum answers {"result":"failed"} with no
// rows — present but no data, not an error.
func TestFetchRelaydStatus_StoppedNoTopology(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/relayd/status/sum", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"result":"failed"}`))
	})

	data, err := client.FetchRelaydStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Error("expected Present=true (plugin installed, just no data)")
	}
	if data.HasData {
		t.Error("expected HasData=false for result:\"failed\"")
	}
	if len(data.VirtualServers) != 0 {
		t.Errorf("expected 0 virtual servers, got %d", len(data.VirtualServers))
	}
}

// TestFetchRelaydStatus_PluginAbsent guards the os-relayd-not-installed case:
// the endpoint 404s and must be treated as "feature absent", not an error.
func TestFetchRelaydStatus_PluginAbsent(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/relayd/status/sum", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("Not Found"))
	})

	data, err := client.FetchRelaydStatus()
	if err != nil {
		t.Fatalf("expected nil error for 404 (plugin absent), got %v", err)
	}
	if data.Present {
		t.Error("expected Present=false for 404")
	}
	if len(data.VirtualServers) != 0 {
		t.Errorf("expected 0 virtual servers, got %d", len(data.VirtualServers))
	}
}

func TestFetchRelaydStatus_ServerError(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/relayd/status/sum", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})

	_, err := client.FetchRelaydStatus()
	if err == nil {
		t.Fatal("expected error for 500 response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

// TestFetchRelaydStatus_HostStateVocabulary confirms every relayctl host
// status string verified from net/relayd's StatusController + OpenBSD
// relayctl.c source (print_host_status/print_availability): "up" is the only
// value mapped to a healthy 1; "down", "unknown", the PHP-renamed "stopped",
// and the backfill sentinel "-" (a host configured into the table but not
// reported live by relayd) all map to 0, alongside any future/unrecognised
// string (free-text-ish field, fixed fallback).
func TestFetchRelaydStatus_HostStateVocabulary(t *testing.T) {
	cases := []struct {
		status  string
		avlblty string // JSON literal: quoted string, or the bare word null
		wantUp  float64
		wantAvl bool
	}{
		{"up", `"100.00%"`, 1, true},
		{"down", `"0.00%"`, 0, true},
		{"unknown", `""`, 0, false},   // zero checks performed yet (host_check_cnt == 0)
		{"stopped", `null`, 0, false}, // PHP renames a live "disabled" host status to "stopped"
		{"-", `null`, 0, false},       // backfilled: configured host relayd never reported
	}

	for _, tc := range cases {
		t.Run(tc.status, func(t *testing.T) {
			server, mux, client := newTestClientWithMux(t)
			defer server.Close()

			body := `{"result":"ok","rows":[{"id":"1","type":"redirect","name":"vs","status":"active",` +
				`"tables":{"1":{"name":"tbl","status":"active (1 hosts)","hosts":{"1":{` +
				`"properties":[{"uuid":"u1","name":"h1","enabled":"1"}],` +
				`"name":"10.0.0.1","avlblty":` + tc.avlblty + `,"status":"` + tc.status + `"}}}}}]}`

			mux.HandleFunc("/api/relayd/status/sum", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(body))
			})

			data, err := client.FetchRelaydStatus()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			host := data.VirtualServers[0].Tables[0].Hosts[0]
			if host.Up != tc.wantUp {
				t.Errorf("status %q: expected Up=%v, got %v", tc.status, tc.wantUp, host.Up)
			}
			if host.HasAvailability != tc.wantAvl {
				t.Errorf("status %q: expected HasAvailability=%v, got %v", tc.status, tc.wantAvl, host.HasAvailability)
			}
		})
	}
}

// TestFetchRelaydStatus_VirtualServerAndTableStateVocabulary confirms the
// OpenBSD relayctl.c print_rdr_status/print_relay_status/print_table_status
// vocabulary: only a status starting with "active" (covers the redirect's
// "active (using backup table)" and the table's "active (N hosts)") maps to
// a healthy 1.
func TestFetchRelaydStatus_VirtualServerAndTableStateVocabulary(t *testing.T) {
	cases := []struct {
		vsStatus    string
		tableStatus string
		wantVSUp    float64
		wantTblUp   float64
	}{
		{"active", "active (2 hosts)", 1, 1},
		{"active (using backup table)", "active (2 hosts)", 1, 1},
		{"disabled", "disabled", 0, 0},
		{"down", "empty", 0, 0},
	}

	for _, tc := range cases {
		t.Run(tc.vsStatus+"/"+tc.tableStatus, func(t *testing.T) {
			server, mux, client := newTestClientWithMux(t)
			defer server.Close()

			body := `{"result":"ok","rows":[{"id":"1","type":"redirect","name":"vs","status":"` + tc.vsStatus + `",` +
				`"tables":{"1":{"name":"tbl:80","status":"` + tc.tableStatus + `","hosts":{}}}}]}`

			mux.HandleFunc("/api/relayd/status/sum", func(w http.ResponseWriter, r *http.Request) {
				w.Write([]byte(body))
			})

			data, err := client.FetchRelaydStatus()
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			vs := data.VirtualServers[0]
			if vs.Active != tc.wantVSUp {
				t.Errorf("vs status %q: expected Active=%v, got %v", tc.vsStatus, tc.wantVSUp, vs.Active)
			}
			if vs.Tables[0].Active != tc.wantTblUp {
				t.Errorf("table status %q: expected Active=%v, got %v", tc.tableStatus, tc.wantTblUp, vs.Tables[0].Active)
			}
			if vs.Tables[0].Name != "tbl" {
				t.Errorf("expected table name 'tbl' (port suffix stripped), got %q", vs.Tables[0].Name)
			}
		})
	}
}
