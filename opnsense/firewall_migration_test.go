package opnsense

import (
	"net/http"
	"testing"
)

func TestFetchFirewallMigration_Populated(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/firewall/migration/countRules", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("rules method = %s, want GET", r.Method)
		}
		_, _ = w.Write([]byte(`{"status":"ok","count":7}`))
	})
	mux.HandleFunc("/api/firewall/migration/countOutbound", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("outbound method = %s, want GET", r.Method)
		}
		_, _ = w.Write([]byte(`{"status":"ok","count":3}`))
	})

	data, err := client.FetchFirewallMigration()
	if err != nil {
		t.Fatalf("FetchFirewallMigration: %v", err)
	}
	if !data.Present || !data.LegacyRulesPresent || !data.LegacyOutboundNATPresent {
		t.Fatalf("presence = %+v, want all true", data)
	}
	if data.LegacyRules != 7 || data.LegacyOutboundNATRules != 3 {
		t.Errorf("counts = rules %d outbound %d, want 7/3", data.LegacyRules, data.LegacyOutboundNATRules)
	}
}

func TestFetchFirewallMigration_AbsentEndpointsAreSilent(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/firewall/migration/countRules", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/api/firewall/migration/countOutbound", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	data, err := client.FetchFirewallMigration()
	if err != nil {
		t.Fatalf("expected nil error for absent migration endpoints, got %v", err)
	}
	if data.Present || data.LegacyRulesPresent || data.LegacyOutboundNATPresent {
		t.Errorf("absent result = %+v, want no present counters", data)
	}
}

func TestFetchFirewallMigration_PartialEndpointAbsence(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/firewall/migration/countRules", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	mux.HandleFunc("/api/firewall/migration/countOutbound", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","count":2}`))
	})

	data, err := client.FetchFirewallMigration()
	if err != nil {
		t.Fatalf("FetchFirewallMigration: %v", err)
	}
	if !data.Present || data.LegacyRulesPresent || !data.LegacyOutboundNATPresent || data.LegacyOutboundNATRules != 2 {
		t.Errorf("partial result = %+v, want only outbound count present", data)
	}
}

func TestFetchFirewallMigration_NonOKEnvelopeIsSilent(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/firewall/migration/countRules", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"failed","count":99}`))
	})
	mux.HandleFunc("/api/firewall/migration/countOutbound", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","count":1}`))
	})

	data, err := client.FetchFirewallMigration()
	if err != nil {
		t.Fatalf("FetchFirewallMigration: %v", err)
	}
	if data.LegacyRulesPresent || data.LegacyRules != 0 {
		t.Errorf("failed rules envelope = %+v, want omitted", data)
	}
	if !data.LegacyOutboundNATPresent || data.LegacyOutboundNATRules != 1 {
		t.Errorf("outbound result = %+v, want count 1", data)
	}
}

func TestFetchFirewallMigration_ServerErrorPropagates(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/firewall/migration/countRules", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	mux.HandleFunc("/api/firewall/migration/countOutbound", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"status":"ok","count":1}`))
	})

	_, err := client.FetchFirewallMigration()
	if err == nil || err.StatusCode != http.StatusInternalServerError {
		t.Fatalf("FetchFirewallMigration error = %v, want HTTP 500", err)
	}
}
