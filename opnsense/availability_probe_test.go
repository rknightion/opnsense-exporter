package opnsense

import (
	"net/http"
	"testing"
	"time"
)

// TestFetchSMARTAvailable_PluginPresent covers the feature-availability prober
// (#517): the list call alone must report availability without ever calling
// smartInfo (which would run smartctl -a per disk and could wake a spun-down
// device — the exact per-poll cost --exporter.enable-smart defaults off for).
func TestFetchSMARTAvailable_PluginPresent(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST for smart list, got %s", r.Method)
		}
		_, _ = w.Write([]byte(`{"devices":["ada0","nvme0"]}`))
	})
	mux.HandleFunc("/api/smart/service/info", func(w http.ResponseWriter, _ *http.Request) {
		t.Error("smartInfo must not be called by FetchSMARTAvailable")
		w.WriteHeader(http.StatusInternalServerError)
	})

	available, err := client.FetchSMARTAvailable()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !available {
		t.Error("expected available=true")
	}
}

func TestFetchSMARTAvailable_PluginAbsent(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})

	available, err := client.FetchSMARTAvailable()
	if err != nil {
		t.Fatalf("expected no error for an absent plugin, got %v", err)
	}
	if available {
		t.Error("expected available=false")
	}
}

func TestFetchSMARTAvailable_EmptyDeviceListStillAvailable(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/smart/service/list", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"devices":[]}`))
	})

	available, err := client.FetchSMARTAvailable()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !available {
		t.Error("expected available=true even with zero devices (the plugin answered)")
	}
}

// TestFetchVnstatAvailable_PluginPresent mirrors the SMART case: the probe
// must never call get_json_data (which the collector's own opt-in cost gate
// exists to bound — one extra call PER interface vnstat tracks).
func TestFetchVnstatAvailable_PluginPresent(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/vnstat/service/interface_list", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET for interface_list, got %s", r.Method)
		}
		_, _ = w.Write([]byte(`{"interfaces":["vtnet1","vtnet2"]}`))
	})
	mux.HandleFunc("/api/vnstat/service/get_json_data", func(w http.ResponseWriter, _ *http.Request) {
		t.Error("get_json_data must not be called by FetchVnstatAvailable")
		w.WriteHeader(http.StatusInternalServerError)
	})

	available, err := client.FetchVnstatAvailable()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !available {
		t.Error("expected available=true")
	}
}

func TestFetchVnstatAvailable_PluginAbsent(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/vnstat/service/interface_list", func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "not found", http.StatusNotFound)
	})

	available, err := client.FetchVnstatAvailable()
	if err != nil {
		t.Fatalf("expected no error for an absent plugin, got %v", err)
	}
	if available {
		t.Error("expected available=false")
	}
}

// TestWithoutCache_BypassesNegativeCache is the load-bearing behaviour #517
// decision D depends on: a client whose absent-TTL cache already holds a
// cached 404 for an endpoint must still reach the box (and see the plugin now
// answering) once WithoutCache() is used, rather than replaying the stale 404
// for the length of --exporter.cache-ttl's absent counterpart.
func TestWithoutCache_BypassesNegativeCache(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	pluginInstalled := false
	mux.HandleFunc("/api/vnstat/service/interface_list", func(w http.ResponseWriter, _ *http.Request) {
		if !pluginInstalled {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(`{"interfaces":[]}`))
	})

	// Prime the negative cache with a long TTL, as main.go does for every
	// PluginGatedEndpoints() entry.
	client.SetEndpointAbsentTTL("vnstatInterfaceList", time.Hour)
	available, err := client.FetchVnstatAvailable()
	if err != nil {
		t.Fatalf("unexpected error priming the cache: %v", err)
	}
	if available {
		t.Fatal("expected available=false before the plugin is installed")
	}

	// The plugin is now installed, but the ordinary (cached) client must keep
	// replaying the stale 404 until the TTL expires.
	pluginInstalled = true
	available, err = client.FetchVnstatAvailable()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if available {
		t.Fatal("expected the cached client to still replay the stale 404")
	}

	// WithoutCache must see the box's real, current state.
	available, err = client.WithoutCache().FetchVnstatAvailable()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !available {
		t.Error("expected WithoutCache() to bypass the stale negative cache entry and see available=true")
	}

	// And the original client's cache must be untouched by the bypass call.
	available, err = client.FetchVnstatAvailable()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if available {
		t.Error("expected the original client's cache to be unaffected by a WithoutCache() clone")
	}
}
