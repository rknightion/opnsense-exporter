package opnsense

import (
	"net/http"
	"testing"
	"time"
)

func TestFetchNetflowIsEnabled_Enabled(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{"netflow": 1, "local": 1}`))
	})
	defer server.Close()

	data, err := client.FetchNetflowIsEnabled()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Netflow {
		t.Error("expected Netflow to be true")
	}
	if !data.Local {
		t.Error("expected Local to be true")
	}
}

func TestFetchNetflowIsEnabled_Disabled(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"netflow": 0, "local": 0}`))
	})
	defer server.Close()

	data, err := client.FetchNetflowIsEnabled()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Netflow {
		t.Error("expected Netflow to be false")
	}
	if data.Local {
		t.Error("expected Local to be false")
	}
}

func TestFetchNetflowIsEnabled_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchNetflowIsEnabled()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

func TestFetchNetflowStatus_Active(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{"status": "active", "collectors": "12"}`))
	})
	defer server.Close()

	data, err := client.FetchNetflowStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Active {
		t.Error("expected Active to be true")
	}
	if data.Collectors != 12 {
		t.Errorf("expected Collectors=12, got %d", data.Collectors)
	}
}

func TestFetchNetflowStatus_Inactive(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"status": "stopped", "collectors": "0"}`))
	})
	defer server.Close()

	data, err := client.FetchNetflowStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.Active {
		t.Error("expected Active to be false")
	}
	if data.Collectors != 0 {
		t.Errorf("expected Collectors=0, got %d", data.Collectors)
	}
}

func TestFetchNetflowStatus_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchNetflowStatus()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

func TestFetchNetflowCacheStats_Success(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{
			"netflow_igb0": {"Pkts": 2724171, "if": "igb0", "SrcIPaddresses": 539, "DstIPaddresses": 562},
			"netflow_pppoe0": {"Pkts": 0, "if": "pppoe0", "SrcIPaddresses": 0, "DstIPaddresses": 0},
			"ksocket_netflow_igb0": {"Pkts": 0, "if": "netflow_igb0", "SrcIPaddresses": 0, "DstIPaddresses": 0},
			"ksocket_netflow_pppoe0": {"Pkts": 0, "if": "netflow_pppoe0", "SrcIPaddresses": 0, "DstIPaddresses": 0}
		}`))
	})
	defer server.Close()

	data, err := client.FetchNetflowCacheStats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(data) != 2 {
		t.Fatalf("expected 2 entries (ksocket filtered), got %d", len(data))
	}

	byIface := make(map[string]NetflowCacheStats)
	for _, entry := range data {
		byIface[entry.Interface] = entry
	}

	igb0 := byIface["igb0"]
	if igb0.Packets != 2724171 {
		t.Errorf("igb0.Packets = %d; want 2724171", igb0.Packets)
	}
	if igb0.SrcIPAddresses != 539 {
		t.Errorf("igb0.SrcIPAddresses = %d; want 539", igb0.SrcIPAddresses)
	}
	if igb0.DstIPAddresses != 562 {
		t.Errorf("igb0.DstIPAddresses = %d; want 562", igb0.DstIPAddresses)
	}

	pppoe0 := byIface["pppoe0"]
	if pppoe0.Packets != 0 {
		t.Errorf("pppoe0.Packets = %d; want 0", pppoe0.Packets)
	}
}

func TestFetchNetflowCacheStats_Empty(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{}`))
	})
	defer server.Close()

	data, err := client.FetchNetflowCacheStats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected 0 entries, got %d", len(data))
	}
}

// TestFetchNetflowCacheStats_EmptyArray pins the shape a box with a genuinely
// empty netflow cache sends: PHP's json_encode renders an empty associative
// array as [], not {}. Captured live from the devel testbed (VM 102, OPNsense
// 27.1.a_40) on 2026-07-28, where it was the only failing collector in an
// otherwise clean scrape (#499).
func TestFetchNetflowCacheStats_EmptyArray(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[]`))
	})
	defer server.Close()

	data, err := client.FetchNetflowCacheStats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(data) != 0 {
		t.Errorf("expected 0 entries, got %d", len(data))
	}
}

// A populated array has no upstream encoding path — cache entries are always
// keyed by node name, never by index — so it must surface as drift rather than
// be silently absorbed into an empty result.
func TestFetchNetflowCacheStats_NonEmptyArrayIsAnError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`[{"Pkts": 1, "if": "igb0", "SrcIPaddresses": 1, "DstIPaddresses": 1}]`))
	})
	defer server.Close()

	_, err := client.FetchNetflowCacheStats()
	if err == nil {
		t.Fatal("expected an error for a populated array payload")
	}
}

func TestFetchNetflowCacheStats_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchNetflowCacheStats()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

// liveGetconfigPayload is the reference box's real api/diagnostics/netflow/getconfig
// response, captured 2026-07-24 (1,002 bytes, HTTP 200). Trimmed of nothing: the
// asymmetry is the point. InterfaceField/OptionField members serialize as
// {value,selected} option dicts while collect.enable - a BooleanField - serializes
// as a BARE STRING, and the two timeouts are strings rather than numbers. A struct
// that assumes one shape throughout does not decode this.
const liveGetconfigPayload = `{"netflow": {"capture": {"interfaces": {"opt7": {"value": "AAISP", "selected": 1}, ` +
	`"opt4": {"value": "CAM", "selected": 1}, "opt2": {"value": "IOT", "selected": 1}, ` +
	`"lan": {"value": "LAN", "selected": 1}, "opt3": {"value": "MGMT", "selected": 1}, ` +
	`"opt1": {"value": "tailscale", "selected": 0}, "opt6": {"value": "VIRGIN", "selected": 1}, ` +
	`"opt5": {"value": "zenoverlay", "selected": 0}}, "egress_only": {"opt7": {"value": "AAISP", "selected": 1}, ` +
	`"opt4": {"value": "CAM", "selected": 0}, "opt2": {"value": "IOT", "selected": 0}, ` +
	`"lan": {"value": "LAN", "selected": 0}, "opt3": {"value": "MGMT", "selected": 0}, ` +
	`"opt1": {"value": "tailscale", "selected": 0}, "opt6": {"value": "VIRGIN", "selected": 1}, ` +
	`"opt5": {"value": "zenoverlay", "selected": 0}}, "version": {"v5": {"value": "v5", "selected": 0}, ` +
	`"v9": {"value": "v9", "selected": 1}}, "targets": {"10.0.0.5:9995": {"value": "10.0.0.5:9995", "selected": 1}, ` +
	`"162.159.65.1:2055": {"value": "162.159.65.1:2055", "selected": 1}, ` +
	`"10.0.0.5:2055": {"value": "10.0.0.5:2055", "selected": 1}}}, "collect": {"enable": "0"}, ` +
	`"activeTimeout": "1800", "inactiveTimeout": "15"}}`

func TestFetchNetflowCaptureConfig_LivePayload(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		_, _ = w.Write([]byte(liveGetconfigPayload))
	})
	defer server.Close()

	cfg, err := client.FetchNetflowCaptureConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The KEY is the OPNsense ident (opt7) and the VALUE is the descriptive name
	// (AAISP). The descriptive name is what every flow metric carries as its
	// interface label, so that is what has to come back - joining on the ident
	// would produce a metric that can never be lined up against the volume series.
	want := map[string]bool{
		"AAISP": true, "CAM": true, "IOT": true, "LAN": true, "MGMT": true, "VIRGIN": true,
		"tailscale": false, "zenoverlay": false,
	}
	if len(cfg.Interfaces) != len(want) {
		t.Fatalf("got %d interfaces, want %d: %+v", len(cfg.Interfaces), len(want), cfg.Interfaces)
	}
	for name, selected := range want {
		got, ok := cfg.Interfaces[name]
		if !ok {
			t.Errorf("interface %q missing", name)
			continue
		}
		if got != selected {
			t.Errorf("interface %q selected = %v, want %v", name, got, selected)
		}
	}

	if cfg.ActiveTimeout != 1800*time.Second {
		t.Errorf("ActiveTimeout = %v, want 30m", cfg.ActiveTimeout)
	}
	if cfg.InactiveTimeout != 15*time.Second {
		t.Errorf("InactiveTimeout = %v, want 15s", cfg.InactiveTimeout)
	}
}

// A box with netflow never configured still answers 200: the InterfaceField
// enumerates every interface regardless, all with selected=0. That must read as
// "nothing is expected to export", NOT as an error and NOT as an empty config that
// silently disables the check.
func TestFetchNetflowCaptureConfig_UnconfiguredBoxIsNotAnError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"netflow":{"capture":{"interfaces":{` +
			`"lan":{"value":"LAN","selected":0},"opt1":{"value":"WAN","selected":0}},` +
			`"targets":{}},"collect":{"enable":"0"},"activeTimeout":"1800","inactiveTimeout":"15"}}`))
	})
	defer server.Close()

	cfg, err := client.FetchNetflowCaptureConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Interfaces) != 2 {
		t.Fatalf("got %d interfaces, want 2", len(cfg.Interfaces))
	}
	for name, selected := range cfg.Interfaces {
		if selected {
			t.Errorf("interface %q reads selected on an unconfigured box", name)
		}
	}
}

// An empty response must yield no interfaces rather than a phantom entry — the
// collector emits one series per entry, so a fabricated one is a fabricated metric.
func TestFetchNetflowCaptureConfig_EmptyResponse(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{}`))
	})
	defer server.Close()

	cfg, err := client.FetchNetflowCaptureConfig()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cfg.Interfaces) != 0 {
		t.Errorf("got %d interfaces from an empty response, want 0", len(cfg.Interfaces))
	}
	if cfg.ActiveTimeout != 0 || cfg.InactiveTimeout != 0 {
		t.Errorf("timeouts = %v/%v from an empty response, want 0/0", cfg.ActiveTimeout, cfg.InactiveTimeout)
	}
}
