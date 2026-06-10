package opnsense

import (
	"net/http"
	"testing"
)

const qfeedsStatsFixture = `{
	"feeds": [
		{
			"name": "malware_ip",
			"total_entries": 437283,
			"packets_blocked": 18646,
			"bytes_blocked": 949357,
			"addresses_blocked": 3815,
			"updated_at": "2026-06-09T22:40:00Z",
			"next_update": "2026-06-09T23:00:58Z",
			"licensed": true
		}
	],
	"totals": {
		"entries": 437283,
		"addresses_blocked": 3815,
		"packets_blocked": 18646,
		"bytes_blocked": 949357
	},
	"license": {
		"name": "Premium",
		"expiry_date": "2027-02-08T13:53:37Z"
	}
}`

func TestFetchQFeedsStats_Success(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()

	mux.HandleFunc("/api/qfeeds/settings/stats", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(qfeedsStatsFixture))
	})

	data, err := client.FetchQFeedsStats()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.Present {
		t.Fatal("expected Present=true")
	}
	if len(data.Feeds) != 1 {
		t.Fatalf("expected 1 feed, got %d", len(data.Feeds))
	}
	f := data.Feeds[0]
	if f.Name != "malware_ip" || f.Entries != 437283 || f.PacketsBlocked != 18646 ||
		f.BytesBlocked != 949357 || f.AddressesBlocked != 3815 {
		t.Errorf("unexpected feed values: %+v", f)
	}
	if !f.HasLastUpdate || f.LastUpdateSeconds != 1781044800 { // 2026-06-09T22:40:00Z
		t.Errorf("unexpected LastUpdate: has=%v val=%v", f.HasLastUpdate, f.LastUpdateSeconds)
	}
	if !f.HasNextUpdate {
		t.Error("expected HasNextUpdate=true")
	}
	if data.TotalEntries != 437283 || data.TotalPacketsBlocked != 18646 {
		t.Errorf("unexpected totals: %+v", data)
	}
	if data.LicenseName != "Premium" || !data.HasLicenseExpiry || data.LicenseExpirySeconds != 1802094817 { // 2027-02-08T13:53:37Z
		t.Errorf("unexpected license: name=%q has=%v val=%v",
			data.LicenseName, data.HasLicenseExpiry, data.LicenseExpirySeconds)
	}
}

func TestFetchQFeedsStats_PluginAbsent(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	defer server.Close()

	data, err := client.FetchQFeedsStats()
	if err != nil {
		t.Fatalf("expected nil error on 404, got %v", err)
	}
	if data.Present {
		t.Error("expected Present=false on 404")
	}
}
