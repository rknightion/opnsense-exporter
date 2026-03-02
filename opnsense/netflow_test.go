package opnsense

import (
	"net/http"
	"testing"
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
