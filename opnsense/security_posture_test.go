package opnsense

import (
	"net/http"
	"reflect"
	"testing"
)

func TestFetchSecurityPosture_UsesExistingCoreEndpoints(t *testing.T) {
	server, mux, client := newTestClientWithMux(t)
	defer server.Close()
	mux.HandleFunc("/api/core/firmware/status", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("firmware method = %s, want GET", r.Method)
		}
		_, _ = w.Write([]byte(`{
			"last_check":"2026-09-01T00:00:00", "connection":"ok", "repository":"ok",
			"upgrade_packages":[{"name":"openssl", "current_version":"3.0.1", "new_version":"3.0.2"}]
		}`))
	})
	mux.HandleFunc("/api/trust/cert/search", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("certificates method = %s, want GET", r.Method)
		}
		_, _ = w.Write([]byte(`{"total":1,"rows":[{"valid_to":"1798761600"}]}`))
	})
	mux.HandleFunc("/api/auth/user/search_api_key", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("API key method = %s, want GET", r.Method)
		}
		_, _ = w.Write([]byte(`{"rows":[{"username":"ops","key":"not-decoded","id":"not-decoded"}]}`))
	})

	got, err := client.FetchSecurityPosture()
	if err != nil {
		t.Fatalf("FetchSecurityPosture: %v", err)
	}
	if !got.Firmware.CheckPresent || got.Firmware.Connection != "ok" || got.Firmware.Repository != "ok" {
		t.Errorf("firmware = %+v, want stored healthy check", got.Firmware)
	}
	if len(got.Firmware.UpgradePackageDetails) != 1 || got.Firmware.UpgradePackageDetails[0].NewVersion != "3.0.2" {
		t.Errorf("upgrade package details = %+v", got.Firmware.UpgradePackageDetails)
	}
	if len(got.Certificates.Certificates) != 1 || !got.Certificates.Certificates[0].HasValidTo {
		t.Errorf("certificates = %+v", got.Certificates)
	}
	if want := []APIKeyOwner{{Owner: "ops", Count: 1}}; !reflect.DeepEqual(got.APIKeyOwners, want) {
		t.Errorf("APIKeyOwners = %#v, want %#v", got.APIKeyOwners, want)
	}
}
