package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchIPsecPhase1_Success(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	// Phase1 endpoint (GET)
	mux.HandleFunc("/api/ipsec/sessions/search_phase1", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET for phase1, got %s", r.Method)
		}
		w.Write([]byte(`{
			"rows": [
				{
					"phase1desc": "Office VPN",
					"connected": true,
					"ikeid": "100",
					"name": "office-vpn",
					"install-time": "3600",
					"bytes-in": 123456,
					"bytes-out": 654321,
					"packets-in": 1000,
					"packets-out": 2000
				},
				{
					"phase1desc": "Backup VPN",
					"connected": false,
					"ikeid": "200",
					"name": "backup-vpn",
					"install-time": "invalid",
					"bytes-in": 0,
					"bytes-out": 0,
					"packets-in": 0,
					"packets-out": 0
				}
			],
			"rowCount": 2,
			"total": 2,
			"current": 1
		}`))
	})

	// Phase2 endpoint (POST) - returns data based on ikeid
	mux.HandleFunc("/api/ipsec/sessions/search_phase2", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST for phase2, got %s", r.Method)
		}
		// Return different data based on the request (all calls get same response for simplicity)
		w.Write([]byte(`{
			"rows": [
				{
					"phase2desc": "Tunnel 1",
					"name": "tunnel-1",
					"spi-in": "0xaabbccdd",
					"spi-out": "0x11223344",
					"install-time": "1800",
					"rekey-time": "900",
					"life-time": "3600",
					"bytes-in": "50000",
					"bytes-out": "40000",
					"packets-in": "500",
					"packets-out": "400"
				},
				{
					"phase2desc": "Tunnel 2",
					"name": "tunnel-2",
					"spi-in": "0xeeff0011",
					"spi-out": "0x22334455",
					"install-time": "invalid",
					"rekey-time": "",
					"life-time": "7200",
					"bytes-in": "abc",
					"bytes-out": "0",
					"packets-in": "0",
					"packets-out": "0"
				}
			]
		}`))
	})

	data, err := client.FetchIPsecPhase1()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.Rows) != 2 {
		t.Fatalf("expected 2 phase1 rows, got %d", len(data.Rows))
	}

	// First phase1: connected
	p1 := data.Rows[0]
	if p1.Phase1desc != "Office VPN" {
		t.Errorf("expected Phase1desc 'Office VPN', got %q", p1.Phase1desc)
	}
	if p1.Connected != 1 {
		t.Errorf("expected Connected=1 (true), got %d", p1.Connected)
	}
	if p1.IkeId != "100" {
		t.Errorf("expected IkeId '100', got %q", p1.IkeId)
	}
	if p1.InstallTime != 3600 {
		t.Errorf("expected InstallTime=3600, got %d", p1.InstallTime)
	}
	if p1.BytesIn != 123456 {
		t.Errorf("expected BytesIn=123456, got %d", p1.BytesIn)
	}
	if p1.BytesOut != 654321 {
		t.Errorf("expected BytesOut=654321, got %d", p1.BytesOut)
	}

	// Check phase2 data
	if len(p1.Phase2) != 2 {
		t.Fatalf("expected 2 phase2 entries, got %d", len(p1.Phase2))
	}

	ph2_1 := p1.Phase2[0]
	if ph2_1.Phase2desc != "Tunnel 1" {
		t.Errorf("expected Phase2desc 'Tunnel 1', got %q", ph2_1.Phase2desc)
	}
	if ph2_1.InstallTime != 1800 {
		t.Errorf("expected Phase2 InstallTime=1800, got %d", ph2_1.InstallTime)
	}
	if ph2_1.RekeyTime != 900 {
		t.Errorf("expected Phase2 RekeyTime=900, got %d", ph2_1.RekeyTime)
	}
	if ph2_1.BytesIn != 50000 {
		t.Errorf("expected Phase2 BytesIn=50000, got %d", ph2_1.BytesIn)
	}
	if ph2_1.PacketsOut != 400 {
		t.Errorf("expected Phase2 PacketsOut=400, got %d", ph2_1.PacketsOut)
	}

	// Check invalid values fall back to 0
	ph2_2 := p1.Phase2[1]
	if ph2_2.InstallTime != 0 {
		t.Errorf("expected Phase2 InstallTime=0 for 'invalid', got %d", ph2_2.InstallTime)
	}
	if ph2_2.RekeyTime != 0 {
		t.Errorf("expected Phase2 RekeyTime=0 for empty string, got %d", ph2_2.RekeyTime)
	}
	if ph2_2.BytesIn != 0 {
		t.Errorf("expected Phase2 BytesIn=0 for 'abc', got %d", ph2_2.BytesIn)
	}

	// Second phase1: not connected
	p2 := data.Rows[1]
	if p2.Connected != 0 {
		t.Errorf("expected Connected=0 (false), got %d", p2.Connected)
	}
	if p2.InstallTime != 0 {
		t.Errorf("expected InstallTime=0 for 'invalid', got %d", p2.InstallTime)
	}
}

func TestFetchIPsecPhase1_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchIPsecPhase1()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

func TestFetchIPsecPhase2_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.Write([]byte(`{
			"rows": [
				{
					"phase2desc": "Tunnel A",
					"name": "tunnel-a",
					"spi-in": "0x1234",
					"spi-out": "0x5678",
					"install-time": "100",
					"rekey-time": "50",
					"life-time": "200",
					"bytes-in": "1000",
					"bytes-out": "2000",
					"packets-in": "10",
					"packets-out": "20"
				}
			]
		}`))
	})
	defer server.Close()

	data, err := client.FetchIPsecPhase2("42")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data.Rows) != 1 {
		t.Fatalf("expected 1 row, got %d", len(data.Rows))
	}
	if data.Rows[0].Phase2desc != "Tunnel A" {
		t.Errorf("expected Phase2desc 'Tunnel A', got %q", data.Rows[0].Phase2desc)
	}
}

// IPsec mode-cfg pool tests

const ipsecPoolsPopulatedFixture = `{
	"pools": {
		"defaultv4": {"name": "defaultv4", "net": "10.18.0.0/24", "online": 1, "offline": 2, "size": 254}
	},
	"leases": []
}`

const ipsecPoolsUnconfiguredFixture = `{"pools": []}`

func TestFetchIPsecPools_Normal(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/ipsec/leases/pools", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(ipsecPoolsPopulatedFixture))
	})

	data, err := client.FetchIPsecPools()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Pools) != 1 {
		t.Fatalf("expected 1 pool, got %d", len(data.Pools))
	}
	p := data.Pools[0]
	if p.Name != "defaultv4" {
		t.Errorf("expected pool name 'defaultv4', got %q", p.Name)
	}
	if p.Net != "10.18.0.0/24" {
		t.Errorf("expected net '10.18.0.0/24', got %q", p.Net)
	}
	if p.Online != 1 {
		t.Errorf("expected Online=1, got %v", p.Online)
	}
	if p.Offline != 2 {
		t.Errorf("expected Offline=2, got %v", p.Offline)
	}
	if p.Size != 254 {
		t.Errorf("expected Size=254, got %v", p.Size)
	}
}

func TestFetchIPsecPools_UnconfiguredArray(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/ipsec/leases/pools", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(ipsecPoolsUnconfiguredFixture))
	})

	data, err := client.FetchIPsecPools()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Pools) != 0 {
		t.Errorf("expected 0 pools for unconfigured (array) response, got %d", len(data.Pools))
	}
}

// leases fixture: the `leases` array served alongside pool rows by
// api/ipsec/leases/pools (identical payload to the leases/search endpoint).
const ipsecPoolsWithLeasesFixture = `{
	"pools": {
		"testpool": {"name": "testpool", "net": "10.97.0.1", "online": 1, "offline": 0, "size": 254}
	},
	"leases": [
		{"pool": "testpool", "address": "10.97.0.1", "online": true, "user": "ctclient"},
		{"pool": "testpool", "address": "10.97.0.2", "online": false, "user": "roamer"}
	]
}`

func TestFetchIPsecPools_Leases(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/ipsec/leases/pools", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(ipsecPoolsWithLeasesFixture))
	})

	data, err := client.FetchIPsecPools()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Pools) != 1 {
		t.Fatalf("expected 1 pool, got %d", len(data.Pools))
	}
	if len(data.Leases) != 2 {
		t.Fatalf("expected 2 leases, got %d", len(data.Leases))
	}
	// Sorted by (pool, user): "ctclient" before "roamer".
	if data.Leases[0].User != "ctclient" || !data.Leases[0].Online {
		t.Errorf("lease[0] wrong: %+v", data.Leases[0])
	}
	if data.Leases[1].User != "roamer" || data.Leases[1].Online {
		t.Errorf("lease[1] wrong: %+v", data.Leases[1])
	}
	if data.Leases[0].Pool != "testpool" {
		t.Errorf("expected pool 'testpool', got %q", data.Leases[0].Pool)
	}
}

// established-tunnel SAD fixture — two real SAs (one per direction) from a live
// box, reqid 1, addtime_diff/hard/soft populated, spi as a hex string, no nat.
const ipsecSadEstablishedFixture = `{"total":2,"rowCount":2,"current":1,"rows":[
	{"src":"172.16.9.1","dst":"172.16.9.100","satype":"esp","spi":"c6524517","mode":"tunnel","reqid":1,"state":"mature","addtime_diff":45,"addtime_hard":3960,"addtime_soft":3306,"ikeid":null,"phase1desc":null,"phase2desc":null},
	{"src":"172.16.9.100","dst":"172.16.9.1","satype":"esp","spi":"cac34f73","mode":"tunnel","reqid":1,"state":"mature","addtime_diff":45,"addtime_hard":3960,"addtime_soft":3548,"ikeid":null,"phase1desc":null,"phase2desc":null}
]}`

// the "No SAD entries." placeholder the PHP parser emits when setkey has nothing
// to report — a single synthetic row with satype/spi null.
const ipsecSadEmptyFixture = `{"total":1,"rowCount":1,"current":1,"rows":[
	{"src":"No","dst":"SAD","satype":null,"spi":null,"nat":"ntries","id":"x","ikeid":null,"phase1desc":null,"phase2desc":null}
]}`

func TestFetchIPsecSAD_Established(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/ipsec/sad/search", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(ipsecSadEstablishedFixture))
	})

	data, err := client.FetchIPsecSAD()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Entries) != 2 {
		t.Fatalf("expected 2 SA entries, got %d", len(data.Entries))
	}
	e := data.Entries[0]
	if e.SAType != "esp" {
		t.Errorf("expected satype esp, got %q", e.SAType)
	}
	if e.ReqID != "1" {
		t.Errorf("expected reqid '1' (int→string), got %q", e.ReqID)
	}
	if e.AgeSeconds != 45 {
		t.Errorf("expected age 45, got %d", e.AgeSeconds)
	}
	if e.LifetimeHard != 3960 || e.LifetimeSoft != 3306 {
		t.Errorf("expected lifetimes 3960/3306, got %d/%d", e.LifetimeHard, e.LifetimeSoft)
	}
	if e.NATTraversal {
		t.Errorf("expected no NAT-T (nat field absent), got true")
	}
	if e.IkeID != "" {
		t.Errorf("expected empty ikeid (null join), got %q", e.IkeID)
	}
}

func TestFetchIPsecSAD_EmptyPlaceholder(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/ipsec/sad/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(ipsecSadEmptyFixture))
	})

	data, err := client.FetchIPsecSAD()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Entries) != 0 {
		t.Errorf("expected the 'No SAD entries.' placeholder row to be discarded, got %d entries", len(data.Entries))
	}
}

func TestFetchIPsecSAD_NATTraversal(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/ipsec/sad/search", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"rows":[{"src":"a","dst":"b","satype":"esp","spi":"deadbeef","reqid":2,"nat":"4500","addtime_diff":10,"addtime_hard":3600,"addtime_soft":3000,"ikeid":null,"phase1desc":null,"phase2desc":null}]}`))
	})

	data, err := client.FetchIPsecSAD()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Entries) != 1 {
		t.Fatalf("expected 1 entry, got %d", len(data.Entries))
	}
	if !data.Entries[0].NATTraversal {
		t.Error("expected NAT-T true when the nat field is present")
	}
}

func TestFetchIPsecSAD_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchIPsecSAD()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
}

const ipsecSpdEstablishedFixture = `{"total":2,"rowCount":2,"current":1,"rows":[
	{"src":"10.97.0.1","dst":"192.168.77.0/24","dir":"in","type":"ipsec","proto":"esp","mode":"tunnel","reqid":"1","spid":"1","seq":"1","pid":"71071","ikeid":null,"phase1desc":null,"phase2desc":null},
	{"src":"192.168.77.0/24","dst":"10.97.0.1","dir":"out","type":"ipsec","proto":"esp","mode":"tunnel","reqid":"1","spid":"2","seq":"0","pid":"71071","ikeid":null,"phase1desc":null,"phase2desc":null}
]}`

func TestFetchIPsecSPD_Established(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/ipsec/spd/search", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(ipsecSpdEstablishedFixture))
	})

	data, err := client.FetchIPsecSPD()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data.Directions) != 2 {
		t.Fatalf("expected 2 policy directions, got %d", len(data.Directions))
	}
	got := map[string]int{}
	for _, d := range data.Directions {
		got[d]++
	}
	if got["in"] != 1 || got["out"] != 1 {
		t.Errorf("expected one in + one out, got %v", got)
	}
}

func TestFetchIPsecLegacyStatus(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/ipsec/legacy_subsystem/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{"enabled":true,"isDirty":false}`))
	})

	data, err := client.FetchIPsecLegacyStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Enabled {
		t.Error("expected Enabled true")
	}
	if data.IsDirty {
		t.Error("expected IsDirty false")
	}
}

func TestFetchIPsecPools_404(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchIPsecPools()
	if err != nil {
		t.Fatalf("expected nil error on 404 (feature absent), got: %v", err)
	}
	if len(data.Pools) != 0 {
		t.Errorf("expected 0 pools on 404, got %d", len(data.Pools))
	}
}
