package opnsense

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// TestFetchFirewallGeoIPStatus_NeverConfigured mirrors the "never touched
// GeoIP" shape captured against a live OPNsense 26.7-devel box before any
// GeoIP alias existed: usages=0, address_count=0, file_count=0, timestamp
// null, address_sources both null.
func TestFetchFirewallGeoIPStatus_NeverConfigured(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET, got %s", r.Method)
		}
		w.Write([]byte(`{"alias":{"geoip":{"url":"","usages":0,"address_count":0,"file_count":0,"timestamp":null,"locations_filename":null,"address_sources":{"IPv4":null,"IPv6":null}}}}`))
	})
	defer server.Close()

	data, err := client.FetchFirewallGeoIPStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.AliasUsages != 0 {
		t.Errorf("expected AliasUsages=0, got %v", data.AliasUsages)
	}
	if data.AddressCount != 0 {
		t.Errorf("expected AddressCount=0, got %v", data.AddressCount)
	}
	if data.FileCount != 0 {
		t.Errorf("expected FileCount=0, got %v", data.FileCount)
	}
	if data.HasLastUpdateTimestamp {
		t.Errorf("expected HasLastUpdateTimestamp=false for a null timestamp, got true (value=%v)", data.LastUpdateTimestamp)
	}
}

// TestFetchFirewallGeoIPStatus_AliasConfiguredNoKey mirrors the captured
// "alias exists but no MaxMind/ipinfo key configured" shape: usages goes to
// 1 (a real geoip alias exists) while address_count/file_count/timestamp stay
// at their never-downloaded values, because usages (alias config) and the
// downloaded-DB state are independent signals.
func TestFetchFirewallGeoIPStatus_AliasConfiguredNoKey(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"alias":{"geoip":{"url":"","usages":1,"address_count":0,"file_count":0,"timestamp":null,"locations_filename":null,"address_sources":{"IPv4":null,"IPv6":null}}}}`))
	})
	defer server.Close()

	data, err := client.FetchFirewallGeoIPStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.AliasUsages != 1 {
		t.Errorf("expected AliasUsages=1, got %v", data.AliasUsages)
	}
	if data.AddressCount != 0 || data.FileCount != 0 {
		t.Errorf("expected AddressCount/FileCount=0, got %v/%v", data.AddressCount, data.FileCount)
	}
	if data.HasLastUpdateTimestamp {
		t.Errorf("expected HasLastUpdateTimestamp=false, got true")
	}
}

// TestFetchFirewallGeoIPStatus_DownloadedFresh covers the populated shape once
// a MaxMind/ipinfo key is configured and the box has downloaded the database:
// a real ISO-8601 timestamp (naive, no timezone, whole seconds — the zip
// source path's shape) plus non-zero address/file counts.
func TestFetchFirewallGeoIPStatus_DownloadedFresh(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"alias":{"geoip":{"url":"https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip&license_key=SECRETKEY123","usages":2,"subscription":false,"address_count":123456,"file_count":250,"timestamp":"2026-07-01T12:34:56","locations_filename":"GeoLite2-Country-Locations-en.csv","address_sources":{"IPv4":"GeoLite2-Country-Blocks-IPv4.csv","IPv6":"GeoLite2-Country-Blocks-IPv6.csv"}}}}`))
	})
	defer server.Close()

	data, err := client.FetchFirewallGeoIPStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.AliasUsages != 2 {
		t.Errorf("expected AliasUsages=2, got %v", data.AliasUsages)
	}
	if data.AddressCount != 123456 {
		t.Errorf("expected AddressCount=123456, got %v", data.AddressCount)
	}
	if data.FileCount != 250 {
		t.Errorf("expected FileCount=250, got %v", data.FileCount)
	}
	if !data.HasLastUpdateTimestamp {
		t.Fatalf("expected HasLastUpdateTimestamp=true")
	}
	const wantUnix = 1782909296 // 2026-07-01T12:34:56 UTC
	if data.LastUpdateTimestamp != wantUnix {
		t.Errorf("expected LastUpdateTimestamp=%d, got %v", wantUnix, data.LastUpdateTimestamp)
	}
}

// TestFetchFirewallGeoIPStatus_TimestampWithMicroseconds covers the
// gzip-source path's shape (e.g. ipinfo), which uses
// datetime.datetime.now().isoformat() and so can carry microseconds.
func TestFetchFirewallGeoIPStatus_TimestampWithMicroseconds(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"alias":{"geoip":{"url":"","usages":1,"address_count":10,"file_count":2,"timestamp":"2026-07-01T12:34:56.789123","locations_filename":null,"address_sources":{"IPv4":null,"IPv6":null}}}}`))
	})
	defer server.Close()

	data, err := client.FetchFirewallGeoIPStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !data.HasLastUpdateTimestamp {
		t.Fatalf("expected HasLastUpdateTimestamp=true for a microsecond-precision timestamp")
	}
}

// TestFetchFirewallGeoIPStatus_UnparseableTimestamp ensures a timestamp shape
// that fails every known layout degrades to "no timestamp" rather than
// failing the whole fetch or reporting epoch 0.
func TestFetchFirewallGeoIPStatus_UnparseableTimestamp(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"alias":{"geoip":{"url":"","usages":0,"address_count":0,"file_count":0,"timestamp":"not-a-date","locations_filename":null,"address_sources":{"IPv4":null,"IPv6":null}}}}`))
	})
	defer server.Close()

	data, err := client.FetchFirewallGeoIPStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if data.HasLastUpdateTimestamp {
		t.Errorf("expected HasLastUpdateTimestamp=false for an unparseable timestamp, got true (value=%v)", data.LastUpdateTimestamp)
	}
}

// TestFetchFirewallGeoIPStatus_ServerError covers the plain error path.
func TestFetchFirewallGeoIPStatus_ServerError(t *testing.T) {
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("error"))
	})
	defer server.Close()

	_, err := client.FetchFirewallGeoIPStatus()
	if err == nil {
		t.Fatal("expected error for server error response")
	}
	if err.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", err.StatusCode)
	}
}

// TestFetchFirewallGeoIPStatus_NeverLeaksLicenseKey is the SECURITY assertion
// (#221) for the SUCCESS path: even when the raw body carries the MaxMind URL
// with an embedded license key, nothing about FetchFirewallGeoIPStatus's
// decoded GeoIPStatus can expose it — there is no URL field on the struct at
// all. The error paths are covered separately and concretely by
// TestFetchFirewallGeoIPStatus_ErrorPathRedactsLicenseKey below; they are NOT
// implied by this test.
func TestFetchFirewallGeoIPStatus_NeverLeaksLicenseKey(t *testing.T) {
	const licenseKey = "SECRETKEY123"
	server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"alias":{"geoip":{"url":"https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip&license_key=` + licenseKey + `","usages":1,"address_count":1,"file_count":1,"timestamp":"2026-07-01T12:34:56","locations_filename":null,"address_sources":{"IPv4":null,"IPv6":null}}}}`))
	})
	defer server.Close()

	data, err := client.FetchFirewallGeoIPStatus()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// GeoIPStatus has no URL-shaped field to begin with, but assert on its
	// string representation too, so this test fails loudly if a future change
	// ever adds one back.
	repr := fmt.Sprintf("%+v", data)
	if strings.Contains(repr, licenseKey) {
		t.Fatalf("GeoIPStatus leaked the MaxMind license key: %s", repr)
	}
}

// TestFetchFirewallGeoIPStatus_ErrorPathRedactsLicenseKey is the #305
// regression test: the geoip payload carries a field literally named "url"
// whose VALUE embeds "&license_key=<secret>". Redacting by key name alone
// never matched it, so on any non-2xx (readResponse) or malformed-JSON body
// (unmarshalBody) the live MaxMind credential was copied verbatim into
// APICallError.Message — which internal/collector/firewall.go logs. Both
// error paths must scrub it.
func TestFetchFirewallGeoIPStatus_ErrorPathRedactsLicenseKey(t *testing.T) {
	const licenseKey = "SECRETKEY123"
	const geoipURL = `https://download.maxmind.com/geoip/databases/GeoLite2-Country-CSV/download?suffix=zip&license_key=` + licenseKey

	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{
			name:   "non-2xx body",
			status: http.StatusInternalServerError,
			body:   `{"errorMessage":"failed to refresh geoip alias","alias":{"geoip":{"url":"` + geoipURL + `","usages":1}}}`,
		},
		{
			name:   "malformed json body",
			status: http.StatusOK,
			// Unterminated JSON: forces the unmarshalBody error path, which
			// dumps the body into the error message.
			body: `{"alias":{"geoip":{"url":"` + geoipURL + `","usages":`,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server, client := newTestClientWithServer(t, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				w.Write([]byte(tc.body))
			})
			defer server.Close()

			_, err := client.FetchFirewallGeoIPStatus()
			if err == nil {
				t.Fatal("expected an error")
			}
			if strings.Contains(err.Error(), licenseKey) || strings.Contains(err.Message, licenseKey) {
				t.Fatalf("MaxMind license key leaked into the error: %s", err.Error())
			}
			if !strings.Contains(err.Message, "REDACTED") {
				t.Errorf("expected a REDACTED marker in the error message, got: %s", err.Message)
			}
		})
	}
}
